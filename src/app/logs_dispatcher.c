////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n 
//
//  Copyright 2016 Nicolas Correia, Adrien Chevalier
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.//
//
//	File :		main.c
//	Abstract :	Main function for zer0m0n 
//	Revision : 	v1.1
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//		
/////////////////////////////////////////////////////////////////////////////

#include "logs_dispatcher.h"
#include "pipe.h"
#include "monitor.h"
#include "bson.h"
#include "parsing.h"
#include "config.h"
#include "log.h"
#include "misc.h"
#include "hooking.h"
#include "hook-info.h"
#include "native.h"
#include "memory.h"


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      Description : initializes the filter communication port and creates few threads
//
//      Parameters : 
//      Return value :
//      Process :
//              initializes the critical section object, the file linked list and the filter communication port
//              creates few threads which will receive the logs from kernel
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(void)
{
	THREAD_CONTEXT context;
	HANDLE hThreads[NUMBER_OF_THREADS];
	int i;

	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(LoadLibrary("ntdll.dll"), "RtlInitUnicodeString");
	if(RtlInitUnicodeString == NULL)
		return -1;

	InitializeCriticalSection(&l_mutex);

	FilterConnectCommunicationPort(L"\\FilterPort", 0, NULL, 0, NULL, &context.hPort);
	if(context.hPort == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "[-] Cannot connect to filter communication port\n");
		exit(EXIT_FAILURE);
	}
	printf("[+] Connected to filter communication port\n");

	context.completion = CreateIoCompletionPort(context.hPort, NULL, 0, NUMBER_OF_THREADS);
	if(context.completion == NULL)
	{
		fprintf(stderr, "[-] Error creating completion port : %d\n", (int)GetLastError());
		exit(EXIT_FAILURE);
	}

	// creates NUMBER_OF_THREADS threads
	for(i=0; i<NUMBER_OF_THREADS; i++)
	{
		hThreads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)parse_logs, &context, 0, NULL);
		if(hThreads[i] == NULL)
		{
			fprintf(stderr, "[-] Error creating thread\n");
			exit(EXIT_FAILURE);
		}		
	}
	
	if(WaitForMultipleObjects(NUMBER_OF_THREADS, hThreads, TRUE, INFINITE) == WAIT_FAILED)
	{
		fprintf(stderr, "[-] Failed to wait for threads : %x\n", (int)GetLastError());
		exit(EXIT_FAILURE);
	}

	for(i=0; i<NUMBER_OF_THREADS; i++)
	{
		if(!CloseHandle(hThreads[i]))
		{
			fprintf(stderr, "[-] Failed to close handle\n");
			exit(EXIT_FAILURE);
		}
	}
}

//////////////////////////////////////////////////////////////////////////
//		Description: Grant debug privileges
//
//////////////////////////////////////////////////////////////////////////
void grant_debug_privileges(uint32_t pid)
{
	HANDLE token_handle, process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (OpenProcessToken(process_handle, TOKEN_ALL_ACCESS,
		&token_handle) == 0) {
		printf("[-] Error obtaining process token: %ld\n", GetLastError());
		return;
	}

	LUID original_luid;
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &original_luid) == 0) {
		printf("[-] Error obtaining original luid: %ld\n", GetLastError());
		CloseHandle(process_handle);
		return;
	}

	TOKEN_PRIVILEGES token_privileges;
	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid = original_luid;
	token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (AdjustTokenPrivileges(token_handle, FALSE, &token_privileges, 0, NULL,
		NULL) == 0) {
		printf("[-] Error adjusting token privileges: %ld\n", GetLastError());
	}

	CloseHandle(token_handle);
	CloseHandle(process_handle);
}

//////////////////////////////////////////////////////////////////////////
//		Description: Dummy hook & unhook routines
//////////////////////////////////////////////////////////////////////////
void monitor_hook(const char *library, void *module_handle)
{
	UNREFERENCED_PARAMETER(library);
	UNREFERENCED_PARAMETER(module_handle);
	return;
}

void monitor_unhook(const char *library, void *module_handle)
{
	UNREFERENCED_PARAMETER(library);
	UNREFERENCED_PARAMETER(module_handle);
	return;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//      Description : retrieve logs from kernel, parse them and send them to the cuckoo machine host
//
//      Parameters : 
//      Return value :
//      Process :
//              Gets the main cuckoo parameters.
//              Connects to filter communication port then loops while receiving data from the zer0m0n driver.
//              When a new process is detected, analyzer.py is notified and the new PID is added to the
//              monitored processes list along with a new socket, which will be used for this PID.
//              Logs are parsed, then directly sent to the Cuckoo host.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define ERROR_ABANDONED_WAIT_0           735L
VOID parse_logs(PTHREAD_CONTEXT p)
{
	config_t cfg;
	PKERNEL_MESSAGE msg = NULL;
	LPOVERLAPPED pOvlp = NULL;
	PWCHAR pw_pathfile = NULL;
	LOG log;
	THREAD_CONTEXT context;
	int size, i, ptr_msg;
	DWORD outsize;
	ULONG_PTR key;
	BOOL result;
	HRESULT hr;
	last_error_t lasterror;

	context = *p;

	msg = malloc(sizeof(KERNEL_MESSAGE));
	if(msg == NULL)
		exit(EXIT_FAILURE);

	log.sig_func = 0;
	log.procname = NULL;
	log.fmt = NULL;
	log.arguments = NULL;

	// Since we are opening target process with different user account (guest)
	// we will not be able to get the process handle without SeDebugPrivilege
	// In other words, if SeDebugPrivilege is not enabled in this process, g_target_process == NULL
	grant_debug_privileges(GetCurrentProcessId());

	while(TRUE)
	{
		
		memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));
		hr = FilterGetMessage(context.hPort, &msg->MessageHeader, sizeof(KERNEL_MESSAGE), &msg->Ovlp);
		if(hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
			break;
		result = GetQueuedCompletionStatus(context.completion, &outsize, &key, &pOvlp, INFINITE);
		if(!result) 
		{
			hr = HRESULT_FROM_WIN32(GetLastError());
			if((hr == E_HANDLE) || (hr == HRESULT_FROM_WIN32(ERROR_ABANDONED_WAIT_0)))
				hr = S_OK;
			break;
		}

		msg = CONTAINING_RECORD(pOvlp, KERNEL_MESSAGE, Ovlp);
		if(!msg)
			break;
		
		// 0x0A : message delimiter
		i=0;
		while(msg->message[i] != 0x0A)
			i++;
		msg->message[i] = 0x0;
	
		// initialize pointer to the beginning of the log
		ptr_msg = 0;
		
		// get PID
		size = getsize(0, msg->message, 0x2C);
		log.pid = retrieve_int(msg->message, size);
		ptr_msg = size+1;
		if(isProcessMonitoredByPid(log.pid) == -1)
		{
			EnterCriticalSection(&l_mutex);

			// We only do pre-intiailization the log pipe config once
			if(!init)
			{
				// Code referred from cuckoo-monitor/src/monitor.c
				config_read(&cfg, log.pid);
				// Save thread identifier for initialization in native_init
				log.tid = cfg.sample_tid;
				pipe_init(cfg.pipe_name, log.pid);
				// Dummy hook init, to initialize capstone 
				hook_init(GetModuleHandleA("kernel32.dll"));
				// Needed for some native APIs
				native_init(TRUE, &log);
				// Needed to initialize Capstone
				hook_init2();
				misc_init(cfg.shutdown_mutex);
				// Register dummy hook routine called during DLL load via callback (LdrRegisterDllNotification)
				misc_set_hook_library(&monitor_hook, &monitor_unhook);
			}

			// get process name
			size = getsize(ptr_msg, msg->message, 0x2C);
			log.procname = malloc(size+1);
			log.procname[size] = 0x0;
			memcpy(log.procname, msg->message+ptr_msg, size);
			ptr_msg += size+1;
			printf("[+] procname : %s\n", log.procname);

			// We only initialize the log pipe config once
			if (!init)
			{
				// Notifies behavior.py about the new process event within log_init
				log_init(cfg.logpipe, cfg.track);
				// Notifies analyzer.py monitoring list
				pipe("KPROCESS:%d", log.pid);
				init = 1;
				printf("[+] pipename : %s\n", cfg.logpipe);
				printf("[+] Log initialization ok\n");
			}
			// The first process will be logged within log_init
			else if ((log.pid != 4) && init)	
			{
#if __x86_64__
				int is_64bit = 1;
#else
				int is_64bit = 0;
#endif
				FILETIME st;
				uint32_t pid, ppid;
				wchar_t *module_path = NULL;
				wchar_t *command_line = NULL;
				HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, log.pid);
				GetSystemTimeAsFileTime(&st);
				// Notifies analyzer.py monitoring list
				pipe("KPROCESS:%d", log.pid);
				// Notifies behavior.py there is a new process event
				if (process_handle)
				{
					pid = (uint32_t)log.pid;
					ppid = parent_process_identifier(process_handle);
					command_line = commandline_from_process_handle(process_handle);
					module_path = get_unicode_buffer();
					memset(module_path, 0, (MAX_PATH_W + 1) * sizeof(wchar_t));
					MultiByteToWideChar(CP_THREAD_ACP, MB_PRECOMPOSED, log.procname, strlen(log.procname), module_path, (MAX_PATH_W + 1) * sizeof(wchar_t));
					log_api(sig_index_process(), 1, 0, 0, NULL,
						st.dwLowDateTime,
						st.dwHighDateTime,
						pid,            // pid
						ppid,           // ppid
						module_path,    // module path
						command_line,   // command line
						is_64bit,       // 64bit
						cfg.track,      // track
						NULL);          // loaded modules

					free_unicode_buffer(module_path);
					free_unicode_buffer(command_line);
					CloseHandle(process_handle);
				}
				else
				{
					printf("[-] Failed to get process handle (0x%x)\n", (unsigned int)GetLastError());
				}
			}

			// Adds to logs_dispatcher monitoring list
			if(startMonitoringProcess(log.pid) == -1)
				printf("[-] Could not add %d\n",log.pid);

			printf("[+] New PID %d\n",log.pid);	
			LeaveCriticalSection(&l_mutex);
		}
		else
		{
			// skip process name
			size = getsize(ptr_msg, msg->message, 0x2C);
			ptr_msg += size+1;
		}

		// retrieve function signature
		size = getsize(ptr_msg, msg->message, 0x2C);
		log.sig_func = retrieve_int(msg->message+ptr_msg, size);

		// retrieve success status
		ptr_msg += size+1;
		log.success = retrieve_int(msg->message+ptr_msg, 1);

		// retrieve return value
		ptr_msg += 2;
		size = getsize(ptr_msg, msg->message, 0x2C);
		log.ret = retrieve_int(msg->message+ptr_msg, size);

		// retrieve format parameters 
		// FIXME: This can be dropped in the later version
		ptr_msg += size+1;
		size = getsize(ptr_msg, msg->message, 0x2C);
		log.fmt = malloc(size+1);
		log.fmt[size] = 0x0;
		memcpy(log.fmt, msg->message+ptr_msg, size);


		// retrieve arguments
		log.nb_arguments = strlen(log.fmt);
		if(log.nb_arguments)
			log.arguments = (PARAMETERS*)malloc(log.nb_arguments * sizeof(PARAMETERS));
		
		// for the moment, we only have 10 arguments/values maximum to log
		set_last_error(&lasterror);
		switch(log.nb_arguments)
		{
			case 0:
				log_api(log.sig_func,log.success,log.ret,0,&lasterror);
			break;
			
			case 1:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value);
			break;
			
			case 2:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				if((log.sig_func == SIG_ntoskrnl_NtDeleteFile) || (log.sig_func == SIG_kernel32_DeleteFileW) || (log.sig_func == SIG_ntoskrnl_NtClose)) // don't log the last argument which is the filepath to dump !
					log_api(log.sig_func,log.success,log.ret,0,&lasterror,"s",log.arguments[0].value);
				else
					log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value);
			break;
			
			case 3:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value);
			
			break;

			case 4:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value);
			break;

			case 5:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value);
			break;

			case 6:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value);
			break;

			case 7:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value);
			break;

			case 8:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value,log.arguments[7].value);
			break;

			case 9:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value,log.arguments[7].value,log.arguments[8].value);
			break;

			case 10:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,&lasterror,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value,log.arguments[7].value,log.arguments[8].value,log.arguments[9].value);
			break;

			default:
				break;
		}

		// if NtDeleteFile() is called, notifies cuckoo that a file has to be dumped
		if(((log.sig_func == SIG_ntoskrnl_NtDeleteFile) || (log.sig_func == SIG_kernel32_DeleteFileW) || (log.sig_func == SIG_ntoskrnl_NtClose)) && !log.ret)
		{
			pw_pathfile = (PWCHAR)malloc(1024*sizeof(WCHAR));
			mbstowcs(pw_pathfile, log.arguments[1].value, strlen(log.arguments[1].value)+1);
			pipe("FILE_DEL:%Z", pw_pathfile);
			free(pw_pathfile);
		}
				
		// notifies analyzer.py that a process has terminated
		/*
		if((log.sig_func == SIG_ntdll_NtTerminateProcess) && !log.ret)
			pipe("KTERMINATE:%d", atoi(log.arguments[1].value));
		*/
		if(log.procname)
		{
			free(log.procname);
			log.procname = NULL;
		}
		if(log.fmt)
		{
			free(log.fmt);
			log.fmt = NULL;
		}

		if(log.arguments)
		{
			for(i=0; i<log.nb_arguments; i++)
			{
				free(log.arguments[i].arg);
				free(log.arguments[i].value);
			}
			free(log.arguments);
			log.arguments = NULL;
		}

		memset(msg, 0, sizeof(KERNEL_MESSAGE));
	}
	free(msg);
	cleanMonitoredProcessList();
}


