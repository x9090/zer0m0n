#include "hooking.h"
#include "hook_misc.h"
#include "monitor.h"
#include "utils.h"
#include "main.h"
#include "comm.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs mutex creation
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Process :
//		logs mutex handle, desired access, mutex name and initial owner
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtCreateMutant(__out PHANDLE MutantHandle,
							   __in ACCESS_MASK DesiredAccess,
							   __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
							   __in BOOLEAN InitialOwner)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kMutantHandle;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = Orig_NtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
	
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("Call NtCreateMutant\n");
			
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		__try
		{

			ProbeForRead(MutantHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		
			kMutantHandle = *MutantHandle;
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
			kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);
			RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);	
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, L"0,-1,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssss,MutantHandle->0x%08x,DesiredAccess->0x%08x,InitialOwner->%d,MutantName->%wZ", kMutantHandle, DesiredAccess, InitialOwner, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssss,MutantHandle->0x%08x,DesiredAccess->0x%08x,InitialOwner->%d,MutantName->%wZ", statusCall, kMutantHandle, DesiredAccess, InitialOwner, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, L"1,0,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtCreateMutant, L"0,-1,ssss,MutantHandle->0,DesiredAccess->0,InitialOwner->0,MutantName->ERROR");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;
}
