#include "hooking.h"
#include "hook_reg.h"
#include "monitor.h"
#include "utils.h"
#include "main.h"
#include "comm.h"

NTSTATUS Hooked_NtOpenKey(__out PHANDLE KeyHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes)
{
	return Orig_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Hide VBOX keys.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069%28v=vs.85%29.aspx
//	Process :
//		if a malware tries to identify VirtualBox by querying the key "Identifier", "SystemBiosVersion" 
//		or "VideoBiosVersion")
//		for "HKLM\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
// 		and "HKLM\\HARDWARE\\Description\\System", we return fake informations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQueryValueKey( __in HANDLE KeyHandle, 
								 __in PUNICODE_STRING ValueName,
								 __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
								 __out_opt PVOID KeyValueInformation,
								 __in ULONG Length,
								 __out PULONG ResultLength)
{
	
	NTSTATUS statusCall, status, exceptionCode;
	ULONG currentProcessId, regtype = REG_NONE, regkey_len = 0;
	USHORT log_lvl = LOG_ERROR;
	ULONG sizeNeeded = 0;
	PWCHAR parameter = NULL;
	UNICODE_STRING regkey;
	UNICODE_STRING kValueName;
	PKEY_NAME_INFORMATION nameInformation = NULL;
	KEY_VALUE_BASIC_INFORMATION *info = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtQueryValueKey\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		kValueName.Buffer = NULL;
		
		__try
		{
			ProbeForRead(ValueName, sizeof(UNICODE_STRING), 1);
			
			kValueName.Length = ValueName->Length;
			kValueName.MaximumLength = ValueName->MaximumLength;
			kValueName.Buffer = PoolAlloc(ValueName->MaximumLength);
			RtlCopyUnicodeString(&kValueName, ValueName);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sssss,KeyHandle->ERROR,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, L"0,-1,sssss,KeyHandle->ERROR,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		// get the registry key name from the KeyHandle
		if(NT_SUCCESS(ZwQueryKey(KeyHandle, KeyNameInformation, NULL, 0, &sizeNeeded)))
		{
			nameInformation = PoolAlloc(sizeNeeded * sizeof(WCHAR));
			if(nameInformation)
			{
				RtlZeroMemory(nameInformation, sizeNeeded * sizeof(WCHAR));
				if(NT_SUCCESS(ZwQueryKey(KeyHandle, KeyNameInformation, nameInformation, sizeNeeded * sizeof(WCHAR), &regkey_len)))
				{
					Dbg("regkey : %ws\n", nameInformation->Name);
					regkey.MaximumLength = MAX_SIZE;
					regkey.Length = MAX_SIZE;
					regkey.Buffer = PoolAlloc(MAX_SIZE);
					RtlInitUnicodeString(&regkey, nameInformation->Name);
				}
				PoolFree(nameInformation);
			}
		}
		else
			RtlInitUnicodeString(&regkey, L"nopz");
			
		if(NT_SUCCESS(statusCall))
		{
			info = (KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation;
			regtype = info->Type;

			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sssss,KeyHandle->0x%08x,KeyValueInformationClass->%d,RegKey->%wZ,ValueName->%wZ,RegType->%d", KeyHandle, KeyValueInformationClass, &regkey, &kValueName, regtype)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,0x%08x,sssss,KeyHandle->0x%08x,KeyValueInformationClass->%d,RegKey->%wZ,ValueName->%wZ,RegType->%d", statusCall, KeyHandle, KeyValueInformationClass, &regkey, &kValueName, regtype)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, L"1,0,sssss,KeyHandle->ERROR,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, L"0,-1,sssss,KeyHandle->ERROR,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;	
}								 
