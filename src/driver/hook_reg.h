#ifndef __HOOK_REG_H
#define __HOOK_REG_H


/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////
typedef NTSTATUS(*NTQUERYVALUEKEY)(HANDLE,PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTOPENKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

NTQUERYVALUEKEY Orig_NtQueryValueKey;
NTOPENKEY Orig_NtOpenKey;

// manque NtDeleteKey
// manque NtSetValueKey
// manque NtDeleteValueKey
// manque NtRenameKey
// manque NtEnumerateKey
// manque NtEnumerateValueKey
// manque NtQueryKey
// manque NtQueryValueKey
// manque NtCreateKey
// manque NtCreateKeyEx
// manque NtOpenKey
// manque NtOpenKeyEx

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQueryValueKey( __in HANDLE KeyHandle, 
								 __in PUNICODE_STRING ValueName,
								 __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
								 __out_opt PVOID KeyValueInformation,
								 __in ULONG Length,
								 __out PULONG ResultLength);
									
NTSTATUS Hooked_NtOpenKey(__out PHANDLE KeyHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes);
						  
#endif