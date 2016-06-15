#ifndef __HOOK_FILE_H
#define __HOOK_FILE_H

#define FILE_SHARE_READ 			0x00000001
#define INVALID_FILE_ATTRIBUTES 	-1
/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////
typedef NTSTATUS(*NTWRITEFILE)(HANDLE,HANDLE,PVOID,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG);
typedef NTSTATUS(*NTCREATEFILE)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef NTSTATUS(*NTREADFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(*NTDELETEFILE)(POBJECT_ATTRIBUTES);
typedef NTSTATUS(*NTOPENFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef NTSTATUS(*NTSETINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(*NTCLOSE)(HANDLE);
typedef NTSTATUS(*NTDEVICEIOCONTROLFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(*NTQUERYATTRIBUTESFILE)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);

NTWRITEFILE Orig_NtWriteFile;
NTCREATEFILE Orig_NtCreateFile;
NTREADFILE Orig_NtReadFile;
NTDELETEFILE Orig_NtDeleteFile;
NTOPENFILE Orig_NtOpenFile;
NTSETINFORMATIONFILE Orig_NtSetInformationFile;
NTCLOSE Orig_NtClose;
NTDEVICEIOCONTROLFILE Orig_NtDeviceIoControlFile;
NTQUERYATTRIBUTESFILE Orig_NtQueryAttributesFile;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////
NTSTATUS Hooked_NtQueryAttributesFile(__in POBJECT_ATTRIBUTES ObjectAttributes,
									  __out PFILE_BASIC_INFORMATION FileInformation);

NTSTATUS Hooked_NtDeviceIoControlFile(__in HANDLE FileHandle,
									  __in_opt HANDLE Event,
									  __in_opt PIO_APC_ROUTINE ApcRoutine,
									  __in_opt PVOID ApcContext,
									  __out PIO_STATUS_BLOCK IoStatusBlock,
									  __in ULONG IoControlCode,
									  __in_opt PVOID InputBuffer,
									  __in ULONG InputBufferLength,
									  __out_opt PVOID OutputBuffer,
									  __in ULONG OutputBufferLength);

NTSTATUS Hooked_NtSetInformationFile(__in HANDLE FileHandle,
									  __out PIO_STATUS_BLOCK IoStatusBlock,
									  __in PVOID FileInformation,
									  __in ULONG Length,
									  __in FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS Hooked_NtWriteFile( __in HANDLE FileHandle, 
							 __in_opt HANDLE Event, 
							 __in_opt PVOID ApcRoutine, 
							 __in_opt PVOID ApcContext, 
							 __out PIO_STATUS_BLOCK IoStatusBlock, 
							 __in PVOID Buffer, 
							 __in ULONG Length, 
							 __in_opt PLARGE_INTEGER ByteOffset, 
							 __in_opt PULONG Key);

NTSTATUS Hooked_NtCreateFile(__out PHANDLE FileHandle, 
							 __in ACCESS_MASK DesiredAccess, 
							 __in POBJECT_ATTRIBUTES ObjectAttributes, 
							 __out PIO_STATUS_BLOCK IoStatusBlock, 
							 __in_opt PLARGE_INTEGER AllocationSize, 
							 __in ULONG FileAttributes, 
							 __in ULONG ShareAccess, 
							 __in ULONG CreateDisposition, 
							 __in ULONG CreateOptions,
							 __in PVOID EaBuffer,
							 __in ULONG EaLength);		

NTSTATUS Hooked_NtReadFile(__in HANDLE FileHandle,
						   __in_opt HANDLE Event,
						   __in_opt PIO_APC_ROUTINE ApcRoutine,
						   __in_opt PVOID ApcContext,
						   __out PIO_STATUS_BLOCK IoStatusBlock,
						   __out PVOID Buffer,
						   __in ULONG Length,
						   __in_opt PLARGE_INTEGER ByteOffset,
						   __in_opt PULONG Key);
						   
NTSTATUS Hooked_NtOpenFile(__out PHANDLE FileHandle,
						   __in ACCESS_MASK DesiredAccess,
						   __in POBJECT_ATTRIBUTES ObjectAttributes,
						   __out PIO_STATUS_BLOCK IoStatusBlock,
						   __in ULONG ShareAccess,
						   __in ULONG OpenOptions);

NTSTATUS Hooked_NtDeleteFile(__in POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS Hooked_NtClose(__in HANDLE Handle);
						   
#endif