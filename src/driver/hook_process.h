#ifndef __HOOK_PROCESS_H
#define __HOOK_PROCESS_H

/////////////////////////////////////////////////////////////////////////////		
// HOOKED PROCESS FUNCTIONS RELATED STRUCTS
/////////////////////////////////////////////////////////////////////////////	
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  UCHAR           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _INITIAL_TEB {
        PVOID StackBase;
        PVOID StackLimit;
        PVOID StackCommit;
        PVOID StackCommitMax;
        PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef enum _SYSDBG_COMMAND {
    SysDbgQueryModuleInformation=1,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset; 
	ULONG NumberOfThreads; 
	LARGE_INTEGER Reserved[3]; 
	LARGE_INTEGER CreateTime; 
	LARGE_INTEGER UserTime; 
	LARGE_INTEGER KernelTime; 
	UNICODE_STRING ImageName; 
	KPRIORITY BasePriority; 
	HANDLE ProcessId; 
	HANDLE InheritedFromProcessId; 
	ULONG HandleCount; 
	ULONG Reserved2[2];
	ULONG PrivatePageCount; 
	VM_COUNTERS VirtualMemoryCounters; 
	IO_COUNTERS IoCounters; 
	PVOID Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;	

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////
typedef NTSTATUS(*NTTERMINATEPROCESS)(HANDLE, NTSTATUS);
typedef NTSTATUS(*NTCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*NTCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
typedef NTSTATUS(*NTCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);
typedef NTSTATUS(*NTWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(*NTOPENPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*NTRESUMETHREAD)(HANDLE, PULONG);
typedef NTSTATUS(*NTSETCONTEXTHREAD)(HANDLE, PCONTEXT);
typedef NTSTATUS(*NTCREATETHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);
typedef NTSTATUS(*NTCREATETHREADEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, BOOLEAN, ULONG, ULONG, ULONG, PVOID);
typedef NTSTATUS(*NTCREATESECTION)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(*NTSYSTEMDEBUGCONTROL)(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTQUEUEAPCTHREAD)(HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG);
typedef NTSTATUS(*NTOPENTHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTDEBUGACTIVEPROCESS)(HANDLE, HANDLE);

NTTERMINATEPROCESS Orig_NtTerminateProcess;
NTCREATEPROCESS Orig_NtCreateProcess;
NTCREATEPROCESSEX Orig_NtCreateProcessEx;
NTCREATEUSERPROCESS Orig_NtCreateUserProcess;
NTWRITEVIRTUALMEMORY Orig_NtWriteVirtualMemory;
NTREADVIRTUALMEMORY Orig_NtReadVirtualMemory;
NTMAPVIEWOFSECTION Orig_NtMapViewOfSection;
NTOPENPROCESS Orig_NtOpenProcess;
NTRESUMETHREAD Orig_NtResumeThread;
NTSETCONTEXTHREAD Orig_NtSetContextThread;
NTCREATETHREAD Orig_NtCreateThread;
NTCREATETHREADEX Orig_NtCreateThreadEx;
NTSYSTEMDEBUGCONTROL Orig_NtSystemDebugControl;
NTQUEUEAPCTHREAD Orig_NtQueueApcThread;
NTCREATESECTION Orig_NtCreateSection;
NTOPENTHREAD Orig_NtOpenThread;
NTQUERYSYSTEMINFORMATION Orig_NtQuerySystemInformation;
NTDEBUGACTIVEPROCESS Orig_NtDebugActiveProcess;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtSystemDebugControl(__in SYSDBG_COMMAND Command,
									 __in_opt PVOID InputBuffer,
									 __in ULONG InputBufferLength,
									 __out_opt PVOID OutputBuffer,
									 __in ULONG OutputBufferLength,
									 __out_opt PULONG ReturnLength);

NTSTATUS Hooked_NtCreateSection(__out PHANDLE SectionHandle,
								__in ACCESS_MASK DesiredAccess,
								__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								__in_opt PLARGE_INTEGER MaximumSize,
								__in ULONG SectionPageProtection,
								__in ULONG AllocationAttributes,
								__in_opt HANDLE FileHandle);

NTSTATUS Hooked_NtDebugActiveProcess(__in HANDLE ProcessHandle,
									 __in HANDLE DebugHandle);

NTSTATUS Hooked_NtQuerySystemInformation(__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
										 __inout PVOID SystemInformation,
										 __in ULONG SystemInformationLength,
										 __out_opt PULONG ReturnLength);

NTSTATUS Hooked_NtOpenThread(__out PHANDLE ThreadHandle,
							 __in ACCESS_MASK DesiredAccess,
							 __in POBJECT_ATTRIBUTES ObjectAttributes,
							 __in PCLIENT_ID ClientId);

NTSTATUS Hooked_NtQueueApcThread(__in HANDLE ThreadHandle,
								 __in PIO_APC_ROUTINE Apcroutine,
								 __in_opt PVOID ApcRoutineContext,
								 __in_opt PIO_STATUS_BLOCK ApcStatusBlock,
								 __in_opt ULONG ApcReserved);

NTSTATUS Hooked_NtCreateThread(__out PHANDLE ThreadHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in POBJECT_ATTRIBUTES ObjectAttributes,
							   __in HANDLE ProcessHandle,
							   __out PCLIENT_ID ClientId,
							   __in PCONTEXT ThreadContext,
							   __in PINITIAL_TEB InitialTeb,
							   __in BOOLEAN CreateSuspended);
							   
NTSTATUS Hooked_NtCreateThreadEx(__out PHANDLE ThreadHandle,
								 __in ACCESS_MASK DesiredAccess,
								 __in POBJECT_ATTRIBUTES ObjectAttributes,
								 __in HANDLE ProcessHandle,
								 __in PVOID lpStartAddress,
								 __in PVOID lpParameter,
								 __in BOOLEAN CreateSuspended,
								 __in ULONG StackZeroBits,
								 __in ULONG SizeOfStackCommit,
								 __in ULONG SizeOfStackReserve,
								 __out PVOID lpBytesBuffer);

NTSTATUS Hooked_NtSetContextThread(__in HANDLE ThreadHandle,
								   __in PCONTEXT Context);

NTSTATUS Hooked_NtResumeThread(__in HANDLE ThreadHandle,
							   __out_opt PULONG SuspendCount);

NTSTATUS Hooked_NtOpenProcess(__out PHANDLE ProcessHandle,
							  __in ACCESS_MASK DesiredAccess,
							  __in POBJECT_ATTRIBUTES ObjectAttributes,
							  __in_opt PCLIENT_ID ClientId);

NTSTATUS Hooked_NtMapViewOfSection(__in HANDLE SectionHandle,
								   __in HANDLE ProcessHandle,
								   __inout PVOID *BaseAddress,
								   __in ULONG_PTR ZeroBits,
								   __in SIZE_T CommitSize,
								   __inout_opt PLARGE_INTEGER SectionOffset,
								   __inout PSIZE_T ViewSize,
								   __in SECTION_INHERIT InheritDisposition,
								   __in ULONG AllocationType,
								   __in ULONG Win32Protect);

NTSTATUS Hooked_NtWriteVirtualMemory(__in HANDLE ProcessHandle,
									 __in PVOID BaseAddress,
									 __in PVOID Buffer,
									 __in ULONG NumberOfBytesToWrite,
									 __out_opt PULONG NumberOfBytesWritten);

NTSTATUS Hooked_NtReadVirtualMemory(__in HANDLE ProcessHandle,
									__in PVOID BaseAddress,
									__out PVOID Buffer,
									__in ULONG NumberOfBytesToRead,
									__out_opt PULONG NumberOfBytesReaded);

NTSTATUS Hooked_NtTerminateProcess( __in_opt HANDLE ProcessHandle, 
									__in NTSTATUS ExitStatus);
									
NTSTATUS Hooked_NtCreateProcess(__out PHANDLE ProcessHandle,
								__in ACCESS_MASK DesiredAccess,
								__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								__in HANDLE ParentProcess,
								__in BOOLEAN InheritObjectTable,
								__in_opt HANDLE SectionHandle,
								__in_opt HANDLE DebugPort,
								__in_opt HANDLE ExceptionPort);
								
NTSTATUS Hooked_NtCreateProcessEx(__out PHANDLE ProcessHandle,
								  __in ACCESS_MASK DesiredAccess,
								  __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
								  __in HANDLE ParentProcess,
								  __in ULONG Flags,
								  __in_opt HANDLE SectionHandle,
								  __in_opt HANDLE DebugPort,
								  __in_opt HANDLE ExceptionPort,
								  __in BOOLEAN InJob);
								  
NTSTATUS Hooked_NtCreateUserProcess(__out PHANDLE ProcessHandle,
									__out PHANDLE ThreadHandle,
									__in ACCESS_MASK ProcessDesiredAccess,
									__in ACCESS_MASK ThreadDesiredAccess,
									__in_opt POBJECT_ATTRIBUTES ProcessObjectAttributes,
									__in_opt POBJECT_ATTRIBUTES ThreadObjectAttributes,
									__in ULONG ProcessFlags,
									__in ULONG ThreadFlags,
									__in_opt PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
									__inout PVOID CreateInfo,
									__in_opt PVOID AttributeList);


#endif