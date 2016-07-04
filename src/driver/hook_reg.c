#include "hooking.h"
#include "hook_reg.h"
#include "monitor.h"
#include "utils.h"
#include "main.h"
#include "comm.h"

NTSTATUS Hooked_NtSetValueKey(__in HANDLE KeyHandle,
							  __in PUNICODE_STRING ValueName,
							  __in_opt ULONG TitleIndex,
							  __in ULONG Type,
							  __in_opt PVOID Data,
							  __in ULONG DataSize)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	UNICODE_STRING kValueName;
	PUCHAR kBuffer = NULL;
	PWCHAR buff = NULL;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtSetValueKey\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		kValueName.Buffer = NULL;
		
		__try
		{
			ProbeForRead(ValueName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(Data, DataSize, 1);
			kBuffer = Data;
			kValueName.Length = ValueName->Length;
			kValueName.MaximumLength = ValueName->MaximumLength;
			kValueName.Buffer = PoolAlloc(ValueName->MaximumLength);
			RtlCopyUnicodeString(&kValueName, ValueName);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssssss,KeyHandle->0,TitleIndex->0,Type->0,Type->0,Data->ERROR,ValueName->ERROR", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtSetValueKey, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtSetValueKey, L"0,-1,ssssss,KeyHandle->0,TitleIndex->0,Type->0,Type->0,Data->ERROR,ValueName->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}

		// logs data
		buff = PoolAlloc(BUFFER_LOG_MAX);
		CopyBuffer(buff, kBuffer, DataSize);
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssssss,KeyHandle->0x%08x,TitleIndex->%d,Type->%d,Type->%d,Data->%ws,ValueName->%wZ", KeyHandle, TitleIndex, Type, Type, buff, &kValueName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssssss,KeyHandle->0x%08x,TitleIndex->%d,Type->%d,Type->%d,Data->%ws,ValueName->%wZ", statusCall, KeyHandle, TitleIndex, Type, Type, buff, &kValueName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtSetValueKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtSetValueKey, L"1,0,ssssss,KeyHandle->0,TitleIndex->0,Type->0,Type->0,Data->ERROR,ValueName->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtSetValueKey, L"0,-1,ssssss,KeyHandle->0,TitleIndex->0,Type->0,Type->0,Data->ERROR,ValueName->ERROR");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}


NTSTATUS Hooked_NtDeleteValueKey(__in HANDLE KeyHandle,
								 __in PUNICODE_STRING ValueName)
{
	NTSTATUS statusCall, exceptionCode;
	UNICODE_STRING kValueName;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtDeleteValueKey(KeyHandle, ValueName);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtDeleteValueKey\n");
		
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
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ss,KeyHandle->0,ValueName->ERROR", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteValueKey, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteValueKey, L"0,-1,ss,KeyHandle->0,ValueName->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ss,KeyHandle->0x%08x,ValueName->%wZ", KeyHandle, &kValueName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ss,KeyHandle->0x%08x,ValueName->%wZ", statusCall, KeyHandle, &kValueName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteValueKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteValueKey, L"1,0,ss,KeyHandle->0,ValueName->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteValueKey, L"0,-1,ss,KeyHandle->0,ValueName->ERROR");
			break;
		}
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}

NTSTATUS Hooked_NtDeleteKey(__in HANDLE KeyHandle)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	PWCHAR regkey = NULL;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtDeleteKey(KeyHandle);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtDeleteKey\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		
		// get the registry key name from the KeyHandle
		regkey = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		if(!NT_SUCCESS(reg_get_key(KeyHandle, regkey)))
			regkey = L"";
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ss,KeyHandle->0x%08x,RegKey->%ws", KeyHandle, regkey)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ss,KeyHandle->0x%08x,RegKey->%ws", KeyHandle, regkey)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteKey, L"1,0,ss,KeyHandle->0,RegKey->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtDeleteKey, L"0,-1,ss,KeyHandle->0,RegKey->ERROR");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
		if(regkey != NULL)
			PoolFree(regkey);
	}
	return statusCall;		
}

NTSTATUS Hooked_NtOpenKeyEx(__out PHANDLE KeyHandle,
						    __in ACCESS_MASK DesiredAccess,
						    __in POBJECT_ATTRIBUTES ObjectAttributes,
							__in ULONG OpenOptions)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kKeyHandle = 0;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtOpenKeyEx\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		kObjectName.Buffer = NULL;
		
		__try
		{
			ProbeForRead(KeyHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
			
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
			kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);

			RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			kKeyHandle = *KeyHandle;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,ssss,KeyHandle->0,DesiredAccess->0,OpenOptions->0,regkey->ERROR", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKeyEx, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKeyEx, L"0,-1,ssss,KeyHandle->0,DesiredAccess->0,OpenOptions->0,regkey->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,ssss,KeyHandle->0x%08x,DesiredAccess->0x%08x,OpenOptions->%d,regkey->%wZ", kKeyHandle, DesiredAccess, OpenOptions, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,ssss,KeyHandle->0x%08x,DesiredAccess->0x%08x,OpenOptions->%d,regkey->%wZ", statusCall, kKeyHandle, DesiredAccess, OpenOptions, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKeyEx, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKeyEx, L"1,0,ssss,KeyHandle->0,DesiredAccess->0,OpenOptions->0,ObjectAttributes->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKeyEx, L"0,-1,ssss,KeyHandle->0,DesiredAccess->0,OpenOptions->0,ObjectAttributes->ERROR");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}

NTSTATUS Hooked_NtOpenKey(__out PHANDLE KeyHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kKeyHandle = 0;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtOpenKey\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		kObjectName.Buffer = NULL;
		
		__try
		{
			ProbeForRead(KeyHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
			
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
			kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);

			RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			kKeyHandle = *KeyHandle;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sss,KeyHandle->0,DesiredAccess->0,regkey->ERROR", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKey, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKey, L"0,-1,sss,KeyHandle->0,DesiredAccess->0,regkey->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sss,KeyHandle->0x%08x,DesiredAccess->0x%08x,regkey->%wZ", kKeyHandle, DesiredAccess, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,sss,KeyHandle->0x%08x,DesiredAccess->0x%08x,regkey->%wZ", statusCall, kKeyHandle, DesiredAccess,&kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKey, L"1,0,sss,KeyHandle->0,DesiredAccess->0,regkey->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtOpenKey, L"0,-1,sss,KeyHandle->0,DesiredAccess->0,regkey->ERROR");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
}


NTSTATUS Hooked_NtCreateKey(__out PHANDLE KeyHandle,
							__in ACCESS_MASK DesiredAccess,
							__in POBJECT_ATTRIBUTES ObjectAttributes,
							__in ULONG TitleIndex,
							__in_opt PUNICODE_STRING Class,
							__in ULONG CreateOptions,
							__out_opt PULONG Disposition)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kKeyHandle = 0;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	ULONG kDisposition = 0;
	UNICODE_STRING kObjectName;
	UNICODE_STRING kClass;
	
	PAGED_CODE();
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
		
	statusCall = Orig_NtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
		
	if(IsProcessInList(currentProcessId, pMonitoredProcessListHead) && (ExGetPreviousMode() != KernelMode))
	{
		Dbg("call NtCreateKey\n");
		
		parameter = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		kObjectName.Buffer = NULL;
		kClass.Buffer = NULL;
		
		__try
		{
			ProbeForRead(KeyHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
			
			if(Class)
			{
				ProbeForRead(Class, sizeof(UNICODE_STRING), 1);
				kClass.Length = Class->Length;
				kClass.MaximumLength = Class->MaximumLength;
				kClass.Buffer = PoolAlloc(Class->MaximumLength);
				RtlCopyUnicodeString(&kClass, Class);
			}
			if(Disposition)
			{
				ProbeForRead(Disposition, sizeof(ULONG), 1);
				kDisposition = *Disposition;
			}

			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
			kObjectName.Buffer = PoolAlloc(kObjectName.MaximumLength);

			RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			kKeyHandle = *KeyHandle;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sssssss,KeyHandle->0,DesiredAccess->0,TitleIndex->0,CreateOptions->0,Disposition->0,regkey->ERROR,class->ERROR", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtCreateKey, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtCreateKey, L"0,-1,sssssss,KeyHandle->0,DesiredAccess->0,TitleIndex->0,CreateOptions->0,Disposition->0,regkey->ERROR,class->ERROR");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sssssss,KeyHandle->0x%08x,DesiredAccess->0x%08x,TitleIndex->%d,CreateOptions->%d,Disposition->%d,regkey->%wZ,class->%wZ", kKeyHandle, DesiredAccess, TitleIndex, CreateOptions, kDisposition, &kObjectName, &kClass)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,sssssss,KeyHandle->0x%08x,DesiredAccess->0x%08x,TitleIndex->%d,CreateOptions->%d,Disposition->%d,regkey->%wZ,class->%wZ", statusCall, kKeyHandle, DesiredAccess, TitleIndex, CreateOptions, kDisposition, &kObjectName, &kClass)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtCreateKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtCreateKey, L"1,0,sssssss,KeyHandle->0,DesiredAccess->0,TitleIndex->0,CreateOptions->0,Disposition->0,regkey->ERROR,class->ERROR");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtCreateKey, L"0,-1,sssssss,KeyHandle->0,DesiredAccess->0,TitleIndex->0,CreateOptions->0,Disposition->0,regkey->ERROR,class->ERROR");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
	}
	return statusCall;		
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
	NTSTATUS statusCall, exceptionCode;
	UNICODE_STRING kValueName;
	ULONG currentProcessId, regtype = REG_NONE;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	PWCHAR regkey = NULL;
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
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"0,%d,sssss,KeyHandle->0,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0", exceptionCode)))
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, parameter);
			else 
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, L"0,-1,sssss,KeyHandle->0,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0");
			if(parameter != NULL)
				PoolFree(parameter);
			return statusCall;
		}
		
		// get the registry key name from the KeyHandle
		regkey = PoolAlloc(MAX_SIZE * sizeof(WCHAR));
		if(!NT_SUCCESS(reg_get_key(KeyHandle, regkey)))
			regkey = L"";
			
		if(NT_SUCCESS(statusCall))
		{
			info = (KEY_VALUE_BASIC_INFORMATION*)KeyValueInformation;
			regtype = info->Type;

			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE, L"1,0,sssss,KeyHandle->0x%08x,KeyValueInformationClass->%d,RegKey->%ws,ValueName->%wZ,RegType->%d", KeyHandle, KeyValueInformationClass, regkey, &kValueName, regtype)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAX_SIZE,  L"0,%d,sssss,KeyHandle->0x%08x,KeyValueInformationClass->%d,RegKey->%ws,ValueName->%wZ,RegType->%d", statusCall, KeyHandle, KeyValueInformationClass, regkey, &kValueName, regtype)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, L"1,0,sssss,KeyHandle->0,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0");
			break;
			default:
				sendLogs(currentProcessId, SIG_ntdll_NtQueryValueKey, L"0,-1,sssss,KeyHandle->0,KeyValueInformationClass->0,RegKey->ERROR,ValueName->ERROR,RegType->0");
			break;
		}
		
		if(parameter != NULL)
			PoolFree(parameter);
		if(regkey != NULL)
			PoolFree(regkey);
	}
	return statusCall;	
}								 
