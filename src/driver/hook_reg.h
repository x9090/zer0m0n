#ifndef __HOOK_REG_H
#define __HOOK_REG_H

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////
typedef NTSTATUS(*NTQUERYVALUEKEY)(HANDLE,PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*NTOPENKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(*NTOPENKEYEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
typedef NTSTATUS(*NTCREATEKEY)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS(*NTDELETEKEY)(HANDLE);
typedef NTSTATUS(*NTDELETEVALUEKEY)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS(*NTSETVALUEKEY)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);

NTCREATEKEY Orig_NtCreateKey;
NTQUERYVALUEKEY Orig_NtQueryValueKey;
NTOPENKEY Orig_NtOpenKey;
NTOPENKEYEX Orig_NtOpenKeyEx;
NTDELETEKEY Orig_NtDeleteKey;
NTDELETEVALUEKEY Orig_NtDeleteValueKey;
NTSETVALUEKEY Orig_NtSetValueKey;


// manque NtRenameKey
// manque NtEnumerateKey
// manque NtEnumerateValueKey
// manque NtQueryKey


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

NTSTATUS Hooked_NtSetValueKey(__in HANDLE KeyHandle,
							  __in PUNICODE_STRING ValueName,
							  __in_opt ULONG TitleIndex,
							  __in ULONG Type,
							  __in_opt PVOID Data,
							  __in ULONG DataSize);

NTSTATUS Hooked_NtDeleteValueKey(__in HANDLE KeyHandle,
								 __in PUNICODE_STRING ValueName);

NTSTATUS Hooked_NtDeleteKey(__in HANDLE KeyHandle);

NTSTATUS Hooked_NtQueryValueKey( __in HANDLE KeyHandle, 
								 __in PUNICODE_STRING ValueName,
								 __in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
								 __out_opt PVOID KeyValueInformation,
								 __in ULONG Length,
								 __out PULONG ResultLength);
									
NTSTATUS Hooked_NtOpenKey(__out PHANDLE KeyHandle,
						  __in ACCESS_MASK DesiredAccess,
						  __in POBJECT_ATTRIBUTES ObjectAttributes);
						  
NTSTATUS Hooked_NtOpenKeyEx(__out PHANDLE KeyHandle,
						    __in ACCESS_MASK DesiredAccess,
						    __in POBJECT_ATTRIBUTES ObjectAttributes,
							__in ULONG OpenOptions);
							
NTSTATUS Hooked_NtCreateKey(__out PHANDLE KeyHandle,
							__in ACCESS_MASK DesiredAccess,
							__in POBJECT_ATTRIBUTES ObjectAttributes,
							__in ULONG TitleIndex,
							__in_opt PUNICODE_STRING Class,
							__in ULONG CreateOptions,
							__out_opt PULONG Disposition);
						  
#endif