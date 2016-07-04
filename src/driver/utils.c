#include "utils.h"
#include "monitor.h"
#include "hook_reg.h"
#include "query_information.h"
#include "main.h"

NTSTATUS reg_get_key(HANDLE KeyHandle, PWCHAR regkey)
{
	ULONG buffer_length, length;
	KEY_NAME_INFORMATION *key_name_information;
	
	buffer_length = sizeof(KEY_NAME_INFORMATION) + MAX_SIZE * sizeof(wchar_t);	
	key_name_information = PoolAlloc(buffer_length);
	if(key_name_information == NULL)
		return STATUS_NO_MEMORY;
	
	if(!NT_SUCCESS(ZwQueryKey(KeyHandle, KeyNameInformation, key_name_information, buffer_length, &length)))
	{
		PoolFree(key_name_information);
		return STATUS_INVALID_PARAMETER;
	}
	
	length = key_name_information->NameLength / sizeof(wchar_t);
	RtlCopyMemory(&regkey[0], key_name_information->Name, length * sizeof(wchar_t));
	regkey[length] = 0;
	
	if(key_name_information != NULL)
		PoolFree(key_name_information);
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		wcsstr case-insensitive version (scans "haystack" for "needle").
//	Parameters :
//		_in_ PWCHAR *haystack :	PWCHAR string to be scanned.
//		_in_ PWCHAR *needle :	PWCHAR string to find.
//	Return value :
//		PWCHAR : NULL if not found, otherwise "needle" first occurence pointer in "haystack".
//	Notes : http://www.codeproject.com/Articles/383185/SSE-accelerated-case-insensitive-substring-search
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2)
{
    const wchar_t *s1, *s2;
    const wchar_t l = towlower(*wcs2);
    const wchar_t u = towupper(*wcs2);
    
    if (!*wcs2)
        return wcs1;
    
    for (; *wcs1; ++wcs1)
    {
        if (*wcs1 == l || *wcs1 == u)
        {
            s1 = wcs1 + 1;
            s2 = wcs2 + 1;
            
            while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
                ++s1, ++s2;
            
            if (!*s2)
                return wcs1;
        }
    }
 
    return NULL;
} 

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Parses received PIDs and adds them in the hidden list.
//	Parameters :
//		IRP buffer data.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS on success.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS parse_pids(PCHAR pids)
{
	PCHAR start = NULL, current = NULL, data = NULL;
	size_t len;
	ULONG pid;
	NTSTATUS status;
	
	if(pids == NULL)
		return STATUS_INVALID_PARAMETER;
	
	status = RtlStringCbLengthA(pids, MAX_SIZE, &len);
	if(!NT_SUCCESS(status))
		return status;
	
	data = PoolAlloc(len+1);
	if(data == NULL)
		return STATUS_NO_MEMORY;
	
	status = RtlStringCbPrintfA(data, len+1, "%s", pids);
	if(!NT_SUCCESS(status))
	{
		PoolFree(data);
		return status;
	}
	
	start = data;
	current = data;
	
	while(*current != 0x00)
	{
		if(*current == ',' && current!=start)
		{
			*current = 0x00;
			status = RtlCharToInteger(start, 10, &pid);
			if(NT_SUCCESS(status) && pid!=0)
			{
				Dbg("pid to hide : %d\n", pid);
				AddProcessToHideToList(pid);
			}
			start = current+1;
		}
		current++;
	}
	
	if(start != current)
	{
		status = RtlCharToInteger(start, 10, &pid);
		if(NT_SUCCESS(status) && pid!=0)
		{
			Dbg("pid to hide : %d\n", pid);
			AddProcessToHideToList(pid);
		}
	}	
	PoolFree(data);
	
	return STATUS_SUCCESS;
}

VOID Resolve_FunctionsAddr()
{
	UNICODE_STRING usFuncName;
	
	RtlInitUnicodeString(&usFuncName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = MmGetSystemRoutineAddress(&usFuncName);

	RtlInitUnicodeString(&usFuncName, L"ZwQueryInformationProcess");
	ZwQueryInformationProcess = MmGetSystemRoutineAddress(&usFuncName);
	
	RtlInitUnicodeString(&usFuncName, L"ZwQueryInformationThread");
	ZwQueryInformationThread = MmGetSystemRoutineAddress(&usFuncName);
		
	RtlInitUnicodeString(&usFuncName, L"ZwQuerySection");
	ZwQuerySection = MmGetSystemRoutineAddress(&usFuncName);
}	

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the thread identifier from its handle.
//	Parameters :
//		_in_ HANDLE hThread : Thread handle.
//	Return value :
//		ULONG : Thread Identifier or NULL if failure.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getPIDByThreadHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION teb;
	
	if(hThread)
		if(NT_SUCCESS(ZwQueryInformationThread(hThread, 0, &teb, sizeof(teb), NULL)))
			return (ULONG)teb.ClientId.UniqueProcess;
	
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the thread identifier from its handle.
//	Parameters :
//		_in_ HANDLE hThread : Thread handle.
//	Return value :
//		ULONG : Thread Identifier or NULL if failure.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getTIDByHandle(HANDLE hThread)
{
	THREAD_BASIC_INFORMATION teb;
	
	if(hThread)
		if(NT_SUCCESS(ZwQueryInformationThread(hThread, 0, &teb, sizeof(teb), NULL)))
			return (ULONG)teb.ClientId.UniqueThread;
	
	return 0;
}
	
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the process identifier from its handle.
//	Parameters :
//		_in_opt_ HANDLE hProc :	Process handle. If NULL, retrieves current process identifier.
//	Return value :
//		ULONG : -1 if an error was encountered, otherwise, process identifier.
//	TODO :
//		Place function retrieval at startup / dynamic import.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getPIDByHandle(HANDLE hProc)
{
	PROCESS_BASIC_INFORMATION peb;
	
	if(hProc)
		if(NT_SUCCESS(ZwQueryInformationProcess(hProc, 0, &peb, sizeof(PROCESS_BASIC_INFORMATION), NULL)))
			return (ULONG)peb.UniqueProcessId;
	
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Copy the content of src buffer to dst buffer
//	Parameters :
//		_out_ PWCHAR dst : the buffer of destination
//		_in_  PUCHAR src : the buffer to be copied
//		_in_  ULONG size : the size of the src buffer  	
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID CopyBuffer(PWCHAR dst, PUCHAR src, ULONG_PTR size)
{
	ULONG i, n = 0;
	if(dst && src && size)
	{
		RtlZeroMemory(dst, BUFFER_LOG_MAX);
		for(i=0; i<size; i++)
		{
			if(i >= (BUFFER_LOG_MAX/2))
				break;
			
			if((src[i] >= 0x20) && (src[i] <= 0x7E) && (src[i] != 0x2C))
			{
				RtlStringCchPrintfW(&dst[n], (BUFFER_LOG_MAX/2)-n-1, L"%c", src[i]);
				n++;
			}
			else
			{
				RtlStringCchPrintfW(&dst[n], (BUFFER_LOG_MAX/2)-n-1, L"\\x%02x", src[i]);
				n+=4;
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Move the file given as parameter to the cuckoo directory
//	Parameters :
//		_in_  UNICODE_STRING filepath : the file to be moved
//		_out_ PUNICODE_STRING filepath_to_dump : the new pathfile (after the file has been moved)  	
//	Return value :
//		STATUS_SUCCESS if the file has correctly been moved, otherwise return error message
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS dump_file(UNICODE_STRING filepath, PUNICODE_STRING filepath_to_dump)
{
	NTSTATUS status;
	PWCHAR ptr_filename = NULL;
	PWCHAR filename = NULL;
	PWCHAR newpath = NULL;
	HANDLE hFile = NULL;
	PFILE_RENAME_INFORMATION pRenameInformation = NULL;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING fullpath;
	IO_STATUS_BLOCK iosb;
	DWORD i;
	
	filename = PoolAlloc(MAX_SIZE);
	if(!filename)
		return STATUS_NO_MEMORY;
		
	if(!NT_SUCCESS(RtlStringCchPrintfW(filename, MAX_SIZE, L"%wZ", &filepath)))
		return STATUS_INVALID_PARAMETER;
		
	i = wcslen(filename);
	while(filename[i] != 0x5C)
		i--;	
	i++;	
	ptr_filename = filename+i;
	
	if(!ptr_filename)
		return STATUS_INVALID_PARAMETER;
		
	newpath = PoolAlloc(MAX_SIZE);
	if(!newpath)
		return STATUS_NO_MEMORY;
		
	RtlStringCchPrintfW(newpath, MAX_SIZE, L"%ws\\%ws", cuckooPath, ptr_filename);
	RtlInitUnicodeString(&fullpath, newpath);
	
	if(filepath_to_dump == NULL)
		return STATUS_INVALID_PARAMETER;
	
	RtlCopyUnicodeString(filepath_to_dump, &fullpath); 
	InitializeObjectAttributes(&objAttr, &filepath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwCreateFile(&hFile, (SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE), &objAttr, &iosb, 0, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);	
	if(!NT_SUCCESS(status))
		return STATUS_INVALID_PARAMETER;
	
	pRenameInformation = PoolAlloc(sizeof(FILE_RENAME_INFORMATION) + 2048);
	
	pRenameInformation->ReplaceIfExists = TRUE;
	pRenameInformation->RootDirectory = NULL;
	RtlCopyMemory(pRenameInformation->FileName, fullpath.Buffer, 2048);
	pRenameInformation->FileNameLength = wcslen(pRenameInformation->FileName)*sizeof(WCHAR);
	
	status = ZwSetInformationFile(hFile, &iosb, pRenameInformation, sizeof(FILE_RENAME_INFORMATION)+pRenameInformation->FileNameLength, FileRenameInformation);
	
	if(!NT_SUCCESS(status))
		return STATUS_INVALID_PARAMETER;
	ZwClose(hFile);
	
	PoolFree(filename);
	PoolFree(newpath);
	PoolFree(pRenameInformation);
	
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the process name from its handle.
//	Parameters :
//		_in_opt_ HANDLE hProc : Process ID
//		_out_ PUNICODE_STRING : Caller allocated UNICODE_STRING, process name.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS getProcNameByPID(ULONG pid, PUNICODE_STRING procName)
{
	NTSTATUS status;
	HANDLE hProcess;
	PEPROCESS eProcess = NULL;
	ULONG returnedLength;
	UNICODE_STRING func;
	PVOID buffer = NULL;
	PUNICODE_STRING imageName = NULL;

	if(pid == 0 || procName == NULL)
		return STATUS_INVALID_PARAMETER;

	if(pid == 4)
	{
		RtlInitUnicodeString(&func, L"System");
		RtlCopyUnicodeString(procName, &func);
		return STATUS_SUCCESS;
	}

	status = PsLookupProcessByProcessId((HANDLE)pid, &eProcess);
	if(!NT_SUCCESS(status))
		return status;

	status = ObOpenObjectByPointer(eProcess,0, NULL, 0,0,KernelMode,&hProcess);
	if(!NT_SUCCESS(status))
		return status;

	ObDereferenceObject(eProcess);
	ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &returnedLength);

	buffer = PoolAlloc(returnedLength);
	if(!buffer)
		return STATUS_NO_MEMORY;

	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buffer, returnedLength, &returnedLength);
	if(NT_SUCCESS(status))
	{
		imageName = (PUNICODE_STRING)buffer;
		if(procName->MaximumLength > imageName->Length)
			RtlCopyUnicodeString(procName, imageName);
		else
			status = STATUS_BUFFER_TOO_SMALL;
	}
	PoolFree(buffer);
	return status;
}