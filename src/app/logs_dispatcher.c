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
#include "hook-info.h"


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
		fprintf(stderr, "[-] Error creating completion port : %d\n", GetLastError());
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
		fprintf(stderr, "[-] Failed to wait for threads\n");
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

	context = *p;

	msg = malloc(sizeof(KERNEL_MESSAGE));
	if(msg == NULL)
		exit(EXIT_FAILURE);

	log.sig_func = 0;
	log.procname = NULL;
	log.fmt = NULL;
	log.arguments = NULL;

	while(TRUE)
	{
		
		memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));
		hr = FilterGetMessage(context.hPort,&msg->MessageHeader, sizeof(KERNEL_MESSAGE), &msg->Ovlp);
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
			if(isProcessMonitoredByPid(log.pid) == -1)
			{
				// notifies analyzer.py
				if((log.pid != 4) && init)
				{
					pipe("KPROCESS:%d", log.pid);
				}

				if(!init)
				{
					config_read(&cfg, log.pid);
					pipe_init(cfg.pipe_name);
					init_func();
					init = 1;
					printf("init ok\n");
				}

				// get process name
				size = getsize(ptr_msg, msg->message, 0x2C);
				log.procname = malloc(size+1);
				log.procname[size] = 0x0;
				memcpy(log.procname, msg->message+ptr_msg, size);
				ptr_msg += size+1;
				printf("procname : %s\n", log.procname);
				printf("pipename : %s\n", cfg.logpipe);
				log_init(cfg.logpipe, log.pid, log.procname);

				if(startMonitoringProcess(log.pid) == -1)
					printf("[!] Could not add %d\n",log.pid);
				
				printf("[+] New PID %d\n",log.pid);	
			}
			else
			{
				// skip process name
				size = getsize(ptr_msg, msg->message, 0x2C);
				ptr_msg += size+1;
			}
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
		switch(log.nb_arguments)
		{
			case 0:
				log_api(log.sig_func,log.success,log.ret, 0, NULL,log.fmt);
			break;
			
			case 1:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value);
			break;
			
			case 2:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				if((log.sig_func == SIG_ntdll_NtDeleteFile) || (log.sig_func == SIG_kernel32_DeleteFileW) || (log.sig_func == SIG_ntdll_NtClose)) // don't log the last argument which is the filepath to dump !
					log_api(log.sig_func,log.success,log.ret,0,NULL,"s",log.arguments[0].value);
				else
					log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value);
			break;
			
			case 3:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value);
			
			break;

			case 4:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value);
			break;

			case 5:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value);
			break;

			case 6:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value);
			break;

			case 7:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value);
			break;

			case 8:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value,log.arguments[7].value);
			break;

			case 9:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value,log.arguments[7].value,log.arguments[8].value);
			break;

			case 10:
				retrieve_parameters(log.nb_arguments, msg->message, ptr_msg, size, log.arguments);
				log_api(log.sig_func,log.success,log.ret,0,NULL,log.fmt,log.arguments[0].value,log.arguments[1].value,log.arguments[2].value,log.arguments[3].value,log.arguments[4].value,log.arguments[5].value,log.arguments[6].value,log.arguments[7].value,log.arguments[8].value,log.arguments[9].value);
			break;

			default:
				break;
		}

		// if NtDeleteFile() called, notifies cuckoo that a file has to be dumped
		if(((log.sig_func == SIG_ntdll_NtDeleteFile) || (log.sig_func == SIG_kernel32_DeleteFileW) || (log.sig_func == SIG_ntdll_NtClose)) && !log.ret)
		{
			pw_pathfile = (PWCHAR)malloc(1024*sizeof(WCHAR));
			mbstowcs(pw_pathfile, log.arguments[1].value, strlen(log.arguments[1].value)+1);
			pipe("FILE_DEL:%Z", pw_pathfile);
			free(pw_pathfile);
		}

		// notifies analyzer.py that a process has terminated
		if((log.sig_func == SIG_ntdll_NtTerminateProcess) && !log.ret)
			pipe("KTERMINATE:%d", atoi(log.arguments[1].value));

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


