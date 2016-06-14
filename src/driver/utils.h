#ifndef __UTILS_H
#define __UTILS_H

#include <fltkernel.h>

#define BUFFER_LOG_MAX 	256

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS	ExitStatus;
    PVOID	TebBaseAddress;
    CLIENT_ID	ClientId;
    ULONG	AffinityMask;
    ULONG	Priority;
    ULONG	BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

VOID Resolve_FunctionsAddr();
NTSTATUS parse_pids(PCHAR pids);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the thread identifier from its handle.
//	Parameters :
//		_in_ HANDLE hThread : Thread handle.
//	Return value :
//		ULONG : Thread Identifier or NULL if failure.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getTIDByHandle(HANDLE hThread);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the thread identifier from its handle.
//	Parameters :
//		_in_ HANDLE hThread : Thread handle.
//	Return value :
//		ULONG : Thread Identifier or NULL if failure.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getPIDByThreadHandle(HANDLE hThread);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the process identifier from its handle.
//	Parameters :
//		_in_opt_ HANDLE hProc :	Process handle. If NULL, retrieves current process identifier.
//	Return value :
//		ULONG : -1 if an error was encountered, otherwise, process identifier.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG getPIDByHandle(HANDLE hProc);

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
VOID CopyBuffer(PWCHAR dst, PUCHAR src, ULONG_PTR size);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieves and returns the process name from its handle.
//	Parameters :
//		_in_opt_ HANDLE hProc : Process ID
//		_out_ PUNICODE_STRING : Caller allocated UNICODE_STRING, process name.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS getProcNameByPID(ULONG pid, PUNICODE_STRING procName);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Move the file given as parameter to the cuckoo directory
//	Parameters :
//		_in_  UNICODE_STRING filepath : the file to be moved
//		_out_ PUNICODE_STRING filepath_to_dump : the new pathfile (after the file has been moved)  	
//	Return value :
//		STATUS_SUCCESS if the file has correctly been moved, otherwise return error message
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS dump_file(UNICODE_STRING filepath, PUNICODE_STRING filepath_to_dump);

#endif


