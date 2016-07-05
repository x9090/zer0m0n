#include <stdio.h>
#include <stdint.h>

#include "hook-info.h"

static const flag_t g_api_flags[MONITOR_HOOKCNT][8] = {
    [SIG____process__] = {
        FLAG_NONE,
    },
    [SIG____anomaly__] = {
        FLAG_NONE,
    },
    [SIG____exception__] = {
        FLAG_NONE,
    },
    [SIG____missing__] = {
        FLAG_NONE,
    },
    [SIG_advapi32_ControlService] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CreateServiceA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CreateServiceW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CryptAcquireContextA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CryptAcquireContextW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CryptCreateHash] = {
        FLAG_ALG_ID,
        FLAG_NONE,
    },
    [SIG_advapi32_CryptDecrypt] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CryptEncrypt] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CryptExportKey] = {
        FLAG_NONE,
    },
    [SIG_advapi32_CryptGenKey] = {
        FLAG_ALG_ID,
        FLAG_NONE,
    },
    [SIG_advapi32_CryptHashData] = {
        FLAG_NONE,
    },
    [SIG_advapi32_DeleteService] = {
        FLAG_NONE,
    },
    [SIG_advapi32_EnumServicesStatusA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_EnumServicesStatusW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_GetUserNameA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_GetUserNameW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_LookupAccountSidW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_LookupPrivilegeValueW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_OpenSCManagerA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_OpenSCManagerW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_OpenServiceA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_OpenServiceW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegCloseKey] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegCreateKeyExA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegCreateKeyExW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegDeleteKeyA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegDeleteKeyW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegDeleteValueA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegDeleteValueW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegEnumKeyExA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegEnumKeyExW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegEnumKeyW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegEnumValueA] = {
        FLAG_RegEnumValueA_lpType,
        FLAG_NONE,
    },
    [SIG_advapi32_RegEnumValueW] = {
        FLAG_RegEnumValueW_lpType,
        FLAG_NONE,
    },
    [SIG_advapi32_RegOpenKeyExA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegOpenKeyExW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegQueryInfoKeyA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegQueryInfoKeyW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_RegQueryValueExA] = {
        FLAG_RegQueryValueExA_lpType,
        FLAG_NONE,
    },
    [SIG_advapi32_RegQueryValueExW] = {
        FLAG_RegQueryValueExW_lpType,
        FLAG_NONE,
    },
    [SIG_advapi32_RegSetValueExA] = {
        FLAG_RegSetValueExA_dwType,
        FLAG_NONE,
    },
    [SIG_advapi32_RegSetValueExW] = {
        FLAG_RegSetValueExW_dwType,
        FLAG_NONE,
    },
    [SIG_advapi32_StartServiceA] = {
        FLAG_NONE,
    },
    [SIG_advapi32_StartServiceW] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CertControlStore] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CertCreateCertificateContext] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CertOpenStore] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CertOpenSystemStoreA] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CertOpenSystemStoreW] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptDecodeMessage] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptDecodeObjectEx] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptDecryptMessage] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptEncryptMessage] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptHashMessage] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptProtectData] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptProtectMemory] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptUnprotectData] = {
        FLAG_NONE,
    },
    [SIG_crypt32_CryptUnprotectMemory] = {
        FLAG_NONE,
    },
    [SIG_dnsapi_DnsQuery_A] = {
        FLAG_NONE,
    },
    [SIG_dnsapi_DnsQuery_UTF8] = {
        FLAG_NONE,
    },
    [SIG_dnsapi_DnsQuery_W] = {
        FLAG_NONE,
    },
    [SIG_iphlpapi_GetAdaptersAddresses] = {
        FLAG_NONE,
    },
    [SIG_iphlpapi_GetAdaptersInfo] = {
        FLAG_NONE,
    },
    [SIG_iphlpapi_GetBestInterfaceEx] = {
        FLAG_NONE,
    },
    [SIG_iphlpapi_GetInterfaceInfo] = {
        FLAG_NONE,
    },
    [SIG_jscript_COleScript_Compile] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CopyFileA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CopyFileExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CopyFileW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateDirectoryExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateDirectoryW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateProcessInternalW] = {
        FLAG_CreateProcessInternalW_creation_flags,
        FLAG_NONE,
    },
    [SIG_kernel32_CreateRemoteThread] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateThread] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateToolhelp32Snapshot] = {
        FLAG_NONE,
    },
    [SIG_kernel32_DeleteFileW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_DeviceIoControl] = {
        FLAG_DeviceIoControl_dwIoControlCode,
        FLAG_NONE,
    },
    [SIG_kernel32_FindFirstFileExA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_FindFirstFileExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_FindResourceA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_FindResourceExA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_FindResourceExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_FindResourceW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetComputerNameA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetComputerNameW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetDiskFreeSpaceExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetDiskFreeSpaceW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileAttributesExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileAttributesW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileInformationByHandle] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileInformationByHandleEx] = {
        FLAG_FILE_INFO_BY_HANDLE_CLASS,
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileSize] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileSizeEx] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetFileType] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetLocalTime] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetNativeSystemInfo] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetShortPathNameW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemDirectoryA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemDirectoryW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemInfo] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemTime] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemTimeAsFileTime] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemWindowsDirectoryA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetSystemWindowsDirectoryW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetTempPathW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetTickCount] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetVolumeNameForVolumeMountPointW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetVolumePathNameW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GetVolumePathNamesForVolumeNameW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_IsDebuggerPresent] = {
        FLAG_NONE,
    },
    [SIG_kernel32_LoadResource] = {
        FLAG_NONE,
    },
    [SIG_kernel32_Module32FirstW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_Module32NextW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_MoveFileWithProgressW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_OutputDebugStringA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_Process32FirstW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_Process32NextW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_ReadProcessMemory] = {
        FLAG_NONE,
    },
    [SIG_kernel32_RemoveDirectoryA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_RemoveDirectoryW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SearchPathW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SetEndOfFile] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SetErrorMode] = {
        FLAG_SetErrorMode_uMode,
        FLAG_NONE,
    },
    [SIG_kernel32_SetFileAttributesW] = {
        FLAG_SetFileAttributesW_dwFileAttributes,
        FLAG_NONE,
    },
    [SIG_kernel32_SetFileInformationByHandle] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SetFilePointer] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SetFilePointerEx] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SetUnhandledExceptionFilter] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SizeofResource] = {
        FLAG_NONE,
    },
    [SIG_kernel32_Thread32First] = {
        FLAG_NONE,
    },
    [SIG_kernel32_Thread32Next] = {
        FLAG_NONE,
    },
    [SIG_kernel32_WriteConsoleA] = {
        FLAG_NONE,
    },
    [SIG_kernel32_WriteConsoleW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_WriteProcessMemory] = {
        FLAG_NONE,
    },
    [SIG_mshtml_CDocument_write] = {
        FLAG_NONE,
    },
    [SIG_mshtml_CElement_put_innerHTML] = {
        FLAG_NONE,
    },
    [SIG_mshtml_CHyperlink_SetUrlComponent] = {
        FLAG_NONE,
    },
    [SIG_mshtml_CIFrameElement_CreateElement] = {
        FLAG_NONE,
    },
    [SIG_mshtml_CScriptElement_put_src] = {
        FLAG_NONE,
    },
    [SIG_mshtml_CWindow_AddTimeoutCode] = {
        FLAG_NONE,
    },
    [SIG_msvcrt_system] = {
        FLAG_NONE,
    },
    [SIG_ncrypt_PRF] = {
        FLAG_NONE,
    },
    [SIG_ncrypt_Ssl3GenerateKeyMaterial] = {
        FLAG_NONE,
    },
    [SIG_netapi32_NetGetJoinInformation] = {
        FLAG_NONE,
    },
    [SIG_netapi32_NetShareEnum] = {
        FLAG_NONE,
    },
    [SIG_netapi32_NetUserGetInfo] = {
        FLAG_NONE,
    },
    [SIG_netapi32_NetUserGetLocalGroups] = {
        FLAG_NONE,
    },
    [SIG_ntdll_LdrGetDllHandle] = {
        FLAG_NONE,
    },
    [SIG_ntdll_LdrGetProcedureAddress] = {
        FLAG_NONE,
    },
    [SIG_ntdll_LdrLoadDll] = {
        FLAG_NONE,
    },
    [SIG_ntdll_LdrUnloadDll] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtAllocateVirtualMemory] = {
        FLAG_NtAllocateVirtualMemory_Protect,
        FLAG_NtAllocateVirtualMemory_AllocationType,
        FLAG_NONE,
    },
    [SIG_ntdll_NtClose] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateDirectoryObject] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateFile] = {
        FLAG_NtCreateFile_DesiredAccess,
        FLAG_NtCreateFile_FileAttributes,
        FLAG_NtCreateFile_ShareAccess,
        FLAG_NtCreateFile_CreateDisposition,
        FLAG_NtCreateFile_CreateOptions,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateKey] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateMutant] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateProcessEx] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateSection] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateThreadEx] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtCreateUserProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtDelayExecution] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtDeleteFile] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtDeleteKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtDeleteValueKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtDeviceIoControlFile] = {
        FLAG_NtDeviceIoControlFile_IoControlCode,
        FLAG_NONE,
    },
    [SIG_ntdll_NtDuplicateObject] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtEnumerateKey] = {
        FLAG_KEY_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntdll_NtEnumerateValueKey] = {
        FLAG_KEY_VALUE_INFORMATION_CLASS,
        FLAG_NtEnumerateValueKey_reg_type,
        FLAG_NONE,
    },
    [SIG_ntdll_NtFreeVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtGetContextThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtLoadDriver] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtLoadKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtLoadKey2] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtLoadKeyEx] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtMakePermanentObject] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtMakeTemporaryObject] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtMapViewOfSection] = {
        FLAG_NtMapViewOfSection_AllocationType,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenDirectoryObject] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenFile] = {
        FLAG_NtOpenFile_DesiredAccess,
        FLAG_NtOpenFile_ShareAccess,
        FLAG_NtOpenFile_OpenOptions,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenKey] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenKeyEx] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenSection] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtProtectVirtualMemory] = {
        FLAG_NtProtectVirtualMemory_NewAccessProtection,
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryAttributesFile] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryDirectoryFile] = {
        FLAG_FILE_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryFullAttributesFile] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryInformationFile] = {
        FLAG_FILE_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryKey] = {
        FLAG_KEY_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryMultipleValueKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtQuerySystemTime] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueryValueKey] = {
        FLAG_KEY_VALUE_INFORMATION_CLASS,
        FLAG_NtQueryValueKey_reg_type,
        FLAG_NONE,
    },
    [SIG_ntdll_NtQueueApcThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtReadFile] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtReadVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtRenameKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtReplaceKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtResumeThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtSaveKey] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtSaveKeyEx] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtSetContextThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtSetInformationFile] = {
        FLAG_FILE_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntdll_NtSetValueKey] = {
        FLAG_NtSetValueKey_Type,
        FLAG_NONE,
    },
    [SIG_ntdll_NtSuspendThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtTerminateProcess] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtTerminateThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtUnloadDriver] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtUnmapViewOfSection] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtWriteFile] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtWriteVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlAddVectoredContinueHandler] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlAddVectoredExceptionHandler] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlCompressBuffer] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlCreateUserProcess] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlCreateUserThread] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlDecompressBuffer] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlDecompressFragment] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlDispatchException] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlRemoveVectoredContinueHandler] = {
        FLAG_NONE,
    },
    [SIG_ntdll_RtlRemoveVectoredExceptionHandler] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoCreateInstance] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoInitializeEx] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoInitializeSecurity] = {
        FLAG_NONE,
    },
    [SIG_ole32_OleInitialize] = {
        FLAG_NONE,
    },
    [SIG_rpcrt4_UuidCreate] = {
        FLAG_NONE,
    },
    [SIG_secur32_GetUserNameExA] = {
        FLAG_NONE,
    },
    [SIG_secur32_GetUserNameExW] = {
        FLAG_NONE,
    },
    [SIG_shell32_ReadCabinetState] = {
        FLAG_NONE,
    },
    [SIG_shell32_SHGetFolderPathW] = {
        FLAG_SHGetFolderPathW_nFolder,
        FLAG_NONE,
    },
    [SIG_shell32_SHGetSpecialFolderLocation] = {
        FLAG_NONE,
    },
    [SIG_shell32_ShellExecuteExW] = {
        FLAG_NONE,
    },
    [SIG_srvcli_NetShareEnum] = {
        FLAG_NONE,
    },
    [SIG_urlmon_ObtainUserAgentString] = {
        FLAG_NONE,
    },
    [SIG_urlmon_URLDownloadToFileW] = {
        FLAG_NONE,
    },
    [SIG_user32_DrawTextExA] = {
        FLAG_NONE,
    },
    [SIG_user32_DrawTextExW] = {
        FLAG_NONE,
    },
    [SIG_user32_EnumWindows] = {
        FLAG_NONE,
    },
    [SIG_user32_ExitWindowsEx] = {
        FLAG_NONE,
    },
    [SIG_user32_FindWindowA] = {
        FLAG_NONE,
    },
    [SIG_user32_FindWindowExA] = {
        FLAG_NONE,
    },
    [SIG_user32_FindWindowExW] = {
        FLAG_NONE,
    },
    [SIG_user32_FindWindowW] = {
        FLAG_NONE,
    },
    [SIG_user32_GetAsyncKeyState] = {
        FLAG_NONE,
    },
    [SIG_user32_GetCursorPos] = {
        FLAG_NONE,
    },
    [SIG_user32_GetForegroundWindow] = {
        FLAG_NONE,
    },
    [SIG_user32_GetKeyState] = {
        FLAG_NONE,
    },
    [SIG_user32_GetKeyboardState] = {
        FLAG_NONE,
    },
    [SIG_user32_GetSystemMetrics] = {
        FLAG_GetSystemMetrics_nIndex,
        FLAG_NONE,
    },
    [SIG_user32_LoadStringA] = {
        FLAG_NONE,
    },
    [SIG_user32_LoadStringW] = {
        FLAG_NONE,
    },
    [SIG_user32_MessageBoxTimeoutA] = {
        FLAG_NONE,
    },
    [SIG_user32_MessageBoxTimeoutW] = {
        FLAG_NONE,
    },
    [SIG_user32_SendNotifyMessageA] = {
        FLAG_NONE,
    },
    [SIG_user32_SendNotifyMessageW] = {
        FLAG_NONE,
    },
    [SIG_user32_SetWindowsHookExA] = {
        FLAG_SetWindowsHookExA_idHook,
        FLAG_NONE,
    },
    [SIG_user32_SetWindowsHookExW] = {
        FLAG_SetWindowsHookExW_idHook,
        FLAG_NONE,
    },
    [SIG_user32_UnhookWindowsHookEx] = {
        FLAG_NONE,
    },
    [SIG_wininet_DeleteUrlCacheEntryA] = {
        FLAG_NONE,
    },
    [SIG_wininet_DeleteUrlCacheEntryW] = {
        FLAG_NONE,
    },
    [SIG_wininet_HttpOpenRequestA] = {
        FLAG_NONE,
    },
    [SIG_wininet_HttpOpenRequestW] = {
        FLAG_NONE,
    },
    [SIG_wininet_HttpQueryInfoA] = {
        FLAG_NONE,
    },
    [SIG_wininet_HttpSendRequestA] = {
        FLAG_NONE,
    },
    [SIG_wininet_HttpSendRequestW] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetCloseHandle] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetConnectA] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetConnectW] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetCrackUrlA] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetCrackUrlW] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetGetConnectedState] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetGetConnectedStateExA] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetGetConnectedStateExW] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetOpenA] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetOpenUrlA] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetOpenUrlW] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetOpenW] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetQueryOptionA] = {
        FLAG_InternetQueryOptionA_dwOption,
        FLAG_NONE,
    },
    [SIG_wininet_InternetReadFile] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetSetOptionA] = {
        FLAG_InternetSetOptionA_dwOption,
        FLAG_NONE,
    },
    [SIG_wininet_InternetSetStatusCallback] = {
        FLAG_NONE,
    },
    [SIG_wininet_InternetWriteFile] = {
        FLAG_NONE,
    },
    [SIG_winmm_timeGetTime] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_ConnectEx] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_GetAddrInfoW] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_TransmitFile] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSAAccept] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSAConnect] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSARecv] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSARecvFrom] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSASend] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSASendTo] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSASocketA] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSASocketW] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_WSAStartup] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_accept] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_bind] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_closesocket] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_connect] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_getaddrinfo] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_gethostbyname] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_getsockname] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_ioctlsocket] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_listen] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_recv] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_recvfrom] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_select] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_send] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_sendto] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_setsockopt] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_shutdown] = {
        FLAG_NONE,
    },
    [SIG_ws2_32_socket] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtSystemDebugControl] = {
        FLAG_NONE,
    },
    [SIG_ntdll_NtDebugActiveProcess] = {
        FLAG_NONE,
    },  
};

static const char *g_api_flagnames[MONITOR_HOOKCNT][8] = {
    [SIG____process__] = {
        NULL,
    },
    [SIG____anomaly__] = {
        NULL,
    },
    [SIG____exception__] = {
        NULL,
    },
    [SIG____missing__] = {
        NULL,
    },
    [SIG_advapi32_ControlService] = {
        NULL,
    },
    [SIG_advapi32_CreateServiceA] = {
        NULL,
    },
    [SIG_advapi32_CreateServiceW] = {
        NULL,
    },
    [SIG_advapi32_CryptAcquireContextA] = {
        NULL,
    },
    [SIG_advapi32_CryptAcquireContextW] = {
        NULL,
    },
    [SIG_advapi32_CryptCreateHash] = {
        "algorithm_identifier",
        NULL,
    },
    [SIG_advapi32_CryptDecrypt] = {
        NULL,
    },
    [SIG_advapi32_CryptEncrypt] = {
        NULL,
    },
    [SIG_advapi32_CryptExportKey] = {
        NULL,
    },
    [SIG_advapi32_CryptGenKey] = {
        "algorithm_identifier",
        NULL,
    },
    [SIG_advapi32_CryptHashData] = {
        NULL,
    },
    [SIG_advapi32_DeleteService] = {
        NULL,
    },
    [SIG_advapi32_EnumServicesStatusA] = {
        NULL,
    },
    [SIG_advapi32_EnumServicesStatusW] = {
        NULL,
    },
    [SIG_advapi32_GetUserNameA] = {
        NULL,
    },
    [SIG_advapi32_GetUserNameW] = {
        NULL,
    },
    [SIG_advapi32_LookupAccountSidW] = {
        NULL,
    },
    [SIG_advapi32_LookupPrivilegeValueW] = {
        NULL,
    },
    [SIG_advapi32_OpenSCManagerA] = {
        NULL,
    },
    [SIG_advapi32_OpenSCManagerW] = {
        NULL,
    },
    [SIG_advapi32_OpenServiceA] = {
        NULL,
    },
    [SIG_advapi32_OpenServiceW] = {
        NULL,
    },
    [SIG_advapi32_RegCloseKey] = {
        NULL,
    },
    [SIG_advapi32_RegCreateKeyExA] = {
        NULL,
    },
    [SIG_advapi32_RegCreateKeyExW] = {
        NULL,
    },
    [SIG_advapi32_RegDeleteKeyA] = {
        NULL,
    },
    [SIG_advapi32_RegDeleteKeyW] = {
        NULL,
    },
    [SIG_advapi32_RegDeleteValueA] = {
        NULL,
    },
    [SIG_advapi32_RegDeleteValueW] = {
        NULL,
    },
    [SIG_advapi32_RegEnumKeyExA] = {
        NULL,
    },
    [SIG_advapi32_RegEnumKeyExW] = {
        NULL,
    },
    [SIG_advapi32_RegEnumKeyW] = {
        NULL,
    },
    [SIG_advapi32_RegEnumValueA] = {
        "reg_type",
        NULL,
    },
    [SIG_advapi32_RegEnumValueW] = {
        "reg_type",
        NULL,
    },
    [SIG_advapi32_RegOpenKeyExA] = {
        NULL,
    },
    [SIG_advapi32_RegOpenKeyExW] = {
        NULL,
    },
    [SIG_advapi32_RegQueryInfoKeyA] = {
        NULL,
    },
    [SIG_advapi32_RegQueryInfoKeyW] = {
        NULL,
    },
    [SIG_advapi32_RegQueryValueExA] = {
        "reg_type",
        NULL,
    },
    [SIG_advapi32_RegQueryValueExW] = {
        "reg_type",
        NULL,
    },
    [SIG_advapi32_RegSetValueExA] = {
        "reg_type",
        NULL,
    },
    [SIG_advapi32_RegSetValueExW] = {
        "reg_type",
        NULL,
    },
    [SIG_advapi32_StartServiceA] = {
        NULL,
    },
    [SIG_advapi32_StartServiceW] = {
        NULL,
    },
    [SIG_crypt32_CertControlStore] = {
        NULL,
    },
    [SIG_crypt32_CertCreateCertificateContext] = {
        NULL,
    },
    [SIG_crypt32_CertOpenStore] = {
        NULL,
    },
    [SIG_crypt32_CertOpenSystemStoreA] = {
        NULL,
    },
    [SIG_crypt32_CertOpenSystemStoreW] = {
        NULL,
    },
    [SIG_crypt32_CryptDecodeMessage] = {
        NULL,
    },
    [SIG_crypt32_CryptDecodeObjectEx] = {
        NULL,
    },
    [SIG_crypt32_CryptDecryptMessage] = {
        NULL,
    },
    [SIG_crypt32_CryptEncryptMessage] = {
        NULL,
    },
    [SIG_crypt32_CryptHashMessage] = {
        NULL,
    },
    [SIG_crypt32_CryptProtectData] = {
        NULL,
    },
    [SIG_crypt32_CryptProtectMemory] = {
        NULL,
    },
    [SIG_crypt32_CryptUnprotectData] = {
        NULL,
    },
    [SIG_crypt32_CryptUnprotectMemory] = {
        NULL,
    },
    [SIG_dnsapi_DnsQuery_A] = {
        NULL,
    },
    [SIG_dnsapi_DnsQuery_UTF8] = {
        NULL,
    },
    [SIG_dnsapi_DnsQuery_W] = {
        NULL,
    },
    [SIG_iphlpapi_GetAdaptersAddresses] = {
        NULL,
    },
    [SIG_iphlpapi_GetAdaptersInfo] = {
        NULL,
    },
    [SIG_iphlpapi_GetBestInterfaceEx] = {
        NULL,
    },
    [SIG_iphlpapi_GetInterfaceInfo] = {
        NULL,
    },
    [SIG_jscript_COleScript_Compile] = {
        NULL,
    },
    [SIG_kernel32_CopyFileA] = {
        NULL,
    },
    [SIG_kernel32_CopyFileExW] = {
        NULL,
    },
    [SIG_kernel32_CopyFileW] = {
        NULL,
    },
    [SIG_kernel32_CreateDirectoryExW] = {
        NULL,
    },
    [SIG_kernel32_CreateDirectoryW] = {
        NULL,
    },
    [SIG_kernel32_CreateProcessInternalW] = {
        "creation_flags",
        NULL,
    },
    [SIG_kernel32_CreateRemoteThread] = {
        NULL,
    },
    [SIG_kernel32_CreateThread] = {
        NULL,
    },
    [SIG_kernel32_CreateToolhelp32Snapshot] = {
        NULL,
    },
    [SIG_kernel32_DeleteFileW] = {
        NULL,
    },
    [SIG_kernel32_DeviceIoControl] = {
        "control_code",
        NULL,
    },
    [SIG_kernel32_FindFirstFileExA] = {
        NULL,
    },
    [SIG_kernel32_FindFirstFileExW] = {
        NULL,
    },
    [SIG_kernel32_FindResourceA] = {
        NULL,
    },
    [SIG_kernel32_FindResourceExA] = {
        NULL,
    },
    [SIG_kernel32_FindResourceExW] = {
        NULL,
    },
    [SIG_kernel32_FindResourceW] = {
        NULL,
    },
    [SIG_kernel32_GetComputerNameA] = {
        NULL,
    },
    [SIG_kernel32_GetComputerNameW] = {
        NULL,
    },
    [SIG_kernel32_GetDiskFreeSpaceExW] = {
        NULL,
    },
    [SIG_kernel32_GetDiskFreeSpaceW] = {
        NULL,
    },
    [SIG_kernel32_GetFileAttributesExW] = {
        NULL,
    },
    [SIG_kernel32_GetFileAttributesW] = {
        NULL,
    },
    [SIG_kernel32_GetFileInformationByHandle] = {
        NULL,
    },
    [SIG_kernel32_GetFileInformationByHandleEx] = {
        "information_class",
        NULL,
    },
    [SIG_kernel32_GetFileSize] = {
        NULL,
    },
    [SIG_kernel32_GetFileSizeEx] = {
        NULL,
    },
    [SIG_kernel32_GetFileType] = {
        NULL,
    },
    [SIG_kernel32_GetLocalTime] = {
        NULL,
    },
    [SIG_kernel32_GetNativeSystemInfo] = {
        NULL,
    },
    [SIG_kernel32_GetShortPathNameW] = {
        NULL,
    },
    [SIG_kernel32_GetSystemDirectoryA] = {
        NULL,
    },
    [SIG_kernel32_GetSystemDirectoryW] = {
        NULL,
    },
    [SIG_kernel32_GetSystemInfo] = {
        NULL,
    },
    [SIG_kernel32_GetSystemTime] = {
        NULL,
    },
    [SIG_kernel32_GetSystemTimeAsFileTime] = {
        NULL,
    },
    [SIG_kernel32_GetSystemWindowsDirectoryA] = {
        NULL,
    },
    [SIG_kernel32_GetSystemWindowsDirectoryW] = {
        NULL,
    },
    [SIG_kernel32_GetTempPathW] = {
        NULL,
    },
    [SIG_kernel32_GetTickCount] = {
        NULL,
    },
    [SIG_kernel32_GetVolumeNameForVolumeMountPointW] = {
        NULL,
    },
    [SIG_kernel32_GetVolumePathNameW] = {
        NULL,
    },
    [SIG_kernel32_GetVolumePathNamesForVolumeNameW] = {
        NULL,
    },
    [SIG_kernel32_IsDebuggerPresent] = {
        NULL,
    },
    [SIG_kernel32_LoadResource] = {
        NULL,
    },
    [SIG_kernel32_Module32FirstW] = {
        NULL,
    },
    [SIG_kernel32_Module32NextW] = {
        NULL,
    },
    [SIG_kernel32_MoveFileWithProgressW] = {
        NULL,
    },
    [SIG_kernel32_OutputDebugStringA] = {
        NULL,
    },
    [SIG_kernel32_Process32FirstW] = {
        NULL,
    },
    [SIG_kernel32_Process32NextW] = {
        NULL,
    },
    [SIG_kernel32_ReadProcessMemory] = {
        NULL,
    },
    [SIG_kernel32_RemoveDirectoryA] = {
        NULL,
    },
    [SIG_kernel32_RemoveDirectoryW] = {
        NULL,
    },
    [SIG_kernel32_SearchPathW] = {
        NULL,
    },
    [SIG_kernel32_SetEndOfFile] = {
        NULL,
    },
    [SIG_kernel32_SetErrorMode] = {
        "mode",
        NULL,
    },
    [SIG_kernel32_SetFileAttributesW] = {
        "file_attributes",
        NULL,
    },
    [SIG_kernel32_SetFileInformationByHandle] = {
        NULL,
    },
    [SIG_kernel32_SetFilePointer] = {
        NULL,
    },
    [SIG_kernel32_SetFilePointerEx] = {
        NULL,
    },
    [SIG_kernel32_SetUnhandledExceptionFilter] = {
        NULL,
    },
    [SIG_kernel32_SizeofResource] = {
        NULL,
    },
    [SIG_kernel32_Thread32First] = {
        NULL,
    },
    [SIG_kernel32_Thread32Next] = {
        NULL,
    },
    [SIG_kernel32_WriteConsoleA] = {
        NULL,
    },
    [SIG_kernel32_WriteConsoleW] = {
        NULL,
    },
    [SIG_kernel32_WriteProcessMemory] = {
        NULL,
    },
    [SIG_mshtml_CDocument_write] = {
        NULL,
    },
    [SIG_mshtml_CElement_put_innerHTML] = {
        NULL,
    },
    [SIG_mshtml_CHyperlink_SetUrlComponent] = {
        NULL,
    },
    [SIG_mshtml_CIFrameElement_CreateElement] = {
        NULL,
    },
    [SIG_mshtml_CScriptElement_put_src] = {
        NULL,
    },
    [SIG_mshtml_CWindow_AddTimeoutCode] = {
        NULL,
    },
    [SIG_msvcrt_system] = {
        NULL,
    },
    [SIG_ncrypt_PRF] = {
        NULL,
    },
    [SIG_ncrypt_Ssl3GenerateKeyMaterial] = {
        NULL,
    },
    [SIG_netapi32_NetGetJoinInformation] = {
        NULL,
    },
    [SIG_netapi32_NetShareEnum] = {
        NULL,
    },
    [SIG_netapi32_NetUserGetInfo] = {
        NULL,
    },
    [SIG_netapi32_NetUserGetLocalGroups] = {
        NULL,
    },
    [SIG_ntdll_LdrGetDllHandle] = {
        NULL,
    },
    [SIG_ntdll_LdrGetProcedureAddress] = {
        NULL,
    },
    [SIG_ntdll_LdrLoadDll] = {
        NULL,
    },
    [SIG_ntdll_LdrUnloadDll] = {
        NULL,
    },
    [SIG_ntdll_NtAllocateVirtualMemory] = {
        "protection",
        "allocation_type",
        NULL,
    },
    [SIG_ntdll_NtClose] = {
        NULL,
    },
    [SIG_ntdll_NtCreateDirectoryObject] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtCreateFile] = {
        "desired_access",
        "file_attributes",
        "share_access",
        "create_disposition",
        "create_options",
        NULL,
    },
    [SIG_ntdll_NtCreateKey] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtCreateMutant] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtCreateProcess] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtCreateProcessEx] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtCreateSection] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtCreateThread] = {
        NULL,
    },
    [SIG_ntdll_NtCreateThreadEx] = {
        NULL,
    },
    [SIG_ntdll_NtCreateUserProcess] = {
        "desired_access_process",
        "desired_access_thread",
        NULL,
    },
    [SIG_ntdll_NtDelayExecution] = {
        NULL,
    },
    [SIG_ntdll_NtDeleteFile] = {
        NULL,
    },
    [SIG_ntdll_NtDeleteKey] = {
        NULL,
    },
    [SIG_ntdll_NtDeleteValueKey] = {
        NULL,
    },
    [SIG_ntdll_NtDeviceIoControlFile] = {
        "control_code",
        NULL,
    },
    [SIG_ntdll_NtDuplicateObject] = {
        NULL,
    },
    [SIG_ntdll_NtEnumerateKey] = {
        "information_class",
        NULL,
    },
    [SIG_ntdll_NtEnumerateValueKey] = {
        "information_class",
        "reg_type",
        NULL,
    },
    [SIG_ntdll_NtFreeVirtualMemory] = {
        NULL,
    },
    [SIG_ntdll_NtGetContextThread] = {
        NULL,
    },
    [SIG_ntdll_NtLoadDriver] = {
        NULL,
    },
    [SIG_ntdll_NtLoadKey] = {
        NULL,
    },
    [SIG_ntdll_NtLoadKey2] = {
        NULL,
    },
    [SIG_ntdll_NtLoadKeyEx] = {
        NULL,
    },
    [SIG_ntdll_NtMakePermanentObject] = {
        NULL,
    },
    [SIG_ntdll_NtMakeTemporaryObject] = {
        NULL,
    },
    [SIG_ntdll_NtMapViewOfSection] = {
        "allocation_type",
        NULL,
    },
    [SIG_ntdll_NtOpenDirectoryObject] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtOpenFile] = {
        "desired_access",
        "share_access",
        "open_options",
        NULL,
    },
    [SIG_ntdll_NtOpenKey] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtOpenKeyEx] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtOpenProcess] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtOpenSection] = {
        "desired_access",
        NULL,
    },
    [SIG_ntdll_NtOpenThread] = {
        NULL,
    },
    [SIG_ntdll_NtProtectVirtualMemory] = {
        "protection",
        NULL,
    },
    [SIG_ntdll_NtQueryAttributesFile] = {
        NULL,
    },
    [SIG_ntdll_NtQueryDirectoryFile] = {
        "information_class",
        NULL,
    },
    [SIG_ntdll_NtQueryFullAttributesFile] = {
        NULL,
    },
    [SIG_ntdll_NtQueryInformationFile] = {
        "information_class",
        NULL,
    },
    [SIG_ntdll_NtQueryKey] = {
        "information_class",
        NULL,
    },
    [SIG_ntdll_NtQueryMultipleValueKey] = {
        NULL,
    },
    [SIG_ntdll_NtQuerySystemTime] = {
        NULL,
    },
    [SIG_ntdll_NtQueryValueKey] = {
        "information_class",
        "reg_type",
        NULL,
    },
    [SIG_ntdll_NtQueueApcThread] = {
        NULL,
    },
    [SIG_ntdll_NtReadFile] = {
        NULL,
    },
    [SIG_ntdll_NtReadVirtualMemory] = {
        NULL,
    },
    [SIG_ntdll_NtRenameKey] = {
        NULL,
    },
    [SIG_ntdll_NtReplaceKey] = {
        NULL,
    },
    [SIG_ntdll_NtResumeThread] = {
        NULL,
    },
    [SIG_ntdll_NtSaveKey] = {
        NULL,
    },
    [SIG_ntdll_NtSaveKeyEx] = {
        NULL,
    },
    [SIG_ntdll_NtSetContextThread] = {
        NULL,
    },
    [SIG_ntdll_NtSetInformationFile] = {
        "information_class",
        NULL,
    },
    [SIG_ntdll_NtSetValueKey] = {
        "reg_type",
        NULL,
    },
    [SIG_ntdll_NtSuspendThread] = {
        NULL,
    },
    [SIG_ntdll_NtTerminateProcess] = {
        NULL,
    },
    [SIG_ntdll_NtTerminateThread] = {
        NULL,
    },
    [SIG_ntdll_NtUnloadDriver] = {
        NULL,
    },
    [SIG_ntdll_NtUnmapViewOfSection] = {
        NULL,
    },
    [SIG_ntdll_NtWriteFile] = {
        NULL,
    },
    [SIG_ntdll_NtWriteVirtualMemory] = {
        NULL,
    },
    [SIG_ntdll_RtlAddVectoredContinueHandler] = {
        NULL,
    },
    [SIG_ntdll_RtlAddVectoredExceptionHandler] = {
        NULL,
    },
    [SIG_ntdll_RtlCompressBuffer] = {
        NULL,
    },
    [SIG_ntdll_RtlCreateUserProcess] = {
        NULL,
    },
    [SIG_ntdll_RtlCreateUserThread] = {
        NULL,
    },
    [SIG_ntdll_RtlDecompressBuffer] = {
        NULL,
    },
    [SIG_ntdll_RtlDecompressFragment] = {
        NULL,
    },
    [SIG_ntdll_RtlDispatchException] = {
        NULL,
    },
    [SIG_ntdll_RtlRemoveVectoredContinueHandler] = {
        NULL,
    },
    [SIG_ntdll_RtlRemoveVectoredExceptionHandler] = {
        NULL,
    },
    [SIG_ole32_CoCreateInstance] = {
        NULL,
    },
    [SIG_ole32_CoInitializeEx] = {
        NULL,
    },
    [SIG_ole32_CoInitializeSecurity] = {
        NULL,
    },
    [SIG_ole32_OleInitialize] = {
        NULL,
    },
    [SIG_rpcrt4_UuidCreate] = {
        NULL,
    },
    [SIG_secur32_GetUserNameExA] = {
        NULL,
    },
    [SIG_secur32_GetUserNameExW] = {
        NULL,
    },
    [SIG_shell32_ReadCabinetState] = {
        NULL,
    },
    [SIG_shell32_SHGetFolderPathW] = {
        "folder",
        NULL,
    },
    [SIG_shell32_SHGetSpecialFolderLocation] = {
        NULL,
    },
    [SIG_shell32_ShellExecuteExW] = {
        NULL,
    },
    [SIG_srvcli_NetShareEnum] = {
        NULL,
    },
    [SIG_urlmon_ObtainUserAgentString] = {
        NULL,
    },
    [SIG_urlmon_URLDownloadToFileW] = {
        NULL,
    },
    [SIG_user32_DrawTextExA] = {
        NULL,
    },
    [SIG_user32_DrawTextExW] = {
        NULL,
    },
    [SIG_user32_EnumWindows] = {
        NULL,
    },
    [SIG_user32_ExitWindowsEx] = {
        NULL,
    },
    [SIG_user32_FindWindowA] = {
        NULL,
    },
    [SIG_user32_FindWindowExA] = {
        NULL,
    },
    [SIG_user32_FindWindowExW] = {
        NULL,
    },
    [SIG_user32_FindWindowW] = {
        NULL,
    },
    [SIG_user32_GetAsyncKeyState] = {
        NULL,
    },
    [SIG_user32_GetCursorPos] = {
        NULL,
    },
    [SIG_user32_GetForegroundWindow] = {
        NULL,
    },
    [SIG_user32_GetKeyState] = {
        NULL,
    },
    [SIG_user32_GetKeyboardState] = {
        NULL,
    },
    [SIG_user32_GetSystemMetrics] = {
        "index",
        NULL,
    },
    [SIG_user32_LoadStringA] = {
        NULL,
    },
    [SIG_user32_LoadStringW] = {
        NULL,
    },
    [SIG_user32_MessageBoxTimeoutA] = {
        NULL,
    },
    [SIG_user32_MessageBoxTimeoutW] = {
        NULL,
    },
    [SIG_user32_SendNotifyMessageA] = {
        NULL,
    },
    [SIG_user32_SendNotifyMessageW] = {
        NULL,
    },
    [SIG_user32_SetWindowsHookExA] = {
        "hook_identifier",
        NULL,
    },
    [SIG_user32_SetWindowsHookExW] = {
        "hook_identifier",
        NULL,
    },
    [SIG_user32_UnhookWindowsHookEx] = {
        NULL,
    },
    [SIG_wininet_DeleteUrlCacheEntryA] = {
        NULL,
    },
    [SIG_wininet_DeleteUrlCacheEntryW] = {
        NULL,
    },
    [SIG_wininet_HttpOpenRequestA] = {
        NULL,
    },
    [SIG_wininet_HttpOpenRequestW] = {
        NULL,
    },
    [SIG_wininet_HttpQueryInfoA] = {
        NULL,
    },
    [SIG_wininet_HttpSendRequestA] = {
        NULL,
    },
    [SIG_wininet_HttpSendRequestW] = {
        NULL,
    },
    [SIG_wininet_InternetCloseHandle] = {
        NULL,
    },
    [SIG_wininet_InternetConnectA] = {
        NULL,
    },
    [SIG_wininet_InternetConnectW] = {
        NULL,
    },
    [SIG_wininet_InternetCrackUrlA] = {
        NULL,
    },
    [SIG_wininet_InternetCrackUrlW] = {
        NULL,
    },
    [SIG_wininet_InternetGetConnectedState] = {
        NULL,
    },
    [SIG_wininet_InternetGetConnectedStateExA] = {
        NULL,
    },
    [SIG_wininet_InternetGetConnectedStateExW] = {
        NULL,
    },
    [SIG_wininet_InternetOpenA] = {
        NULL,
    },
    [SIG_wininet_InternetOpenUrlA] = {
        NULL,
    },
    [SIG_wininet_InternetOpenUrlW] = {
        NULL,
    },
    [SIG_wininet_InternetOpenW] = {
        NULL,
    },
    [SIG_wininet_InternetQueryOptionA] = {
        "option",
        NULL,
    },
    [SIG_wininet_InternetReadFile] = {
        NULL,
    },
    [SIG_wininet_InternetSetOptionA] = {
        "option",
        NULL,
    },
    [SIG_wininet_InternetSetStatusCallback] = {
        NULL,
    },
    [SIG_wininet_InternetWriteFile] = {
        NULL,
    },
    [SIG_winmm_timeGetTime] = {
        NULL,
    },
    [SIG_ws2_32_ConnectEx] = {
        NULL,
    },
    [SIG_ws2_32_GetAddrInfoW] = {
        NULL,
    },
    [SIG_ws2_32_TransmitFile] = {
        NULL,
    },
    [SIG_ws2_32_WSAAccept] = {
        NULL,
    },
    [SIG_ws2_32_WSAConnect] = {
        NULL,
    },
    [SIG_ws2_32_WSARecv] = {
        NULL,
    },
    [SIG_ws2_32_WSARecvFrom] = {
        NULL,
    },
    [SIG_ws2_32_WSASend] = {
        NULL,
    },
    [SIG_ws2_32_WSASendTo] = {
        NULL,
    },
    [SIG_ws2_32_WSASocketA] = {
        NULL,
    },
    [SIG_ws2_32_WSASocketW] = {
        NULL,
    },
    [SIG_ws2_32_WSAStartup] = {
        NULL,
    },
    [SIG_ws2_32_accept] = {
        NULL,
    },
    [SIG_ws2_32_bind] = {
        NULL,
    },
    [SIG_ws2_32_closesocket] = {
        NULL,
    },
    [SIG_ws2_32_connect] = {
        NULL,
    },
    [SIG_ws2_32_getaddrinfo] = {
        NULL,
    },
    [SIG_ws2_32_gethostbyname] = {
        NULL,
    },
    [SIG_ws2_32_getsockname] = {
        NULL,
    },
    [SIG_ws2_32_ioctlsocket] = {
        NULL,
    },
    [SIG_ws2_32_listen] = {
        NULL,
    },
    [SIG_ws2_32_recv] = {
        NULL,
    },
    [SIG_ws2_32_recvfrom] = {
        NULL,
    },
    [SIG_ws2_32_select] = {
        NULL,
    },
    [SIG_ws2_32_send] = {
        NULL,
    },
    [SIG_ws2_32_sendto] = {
        NULL,
    },
    [SIG_ws2_32_setsockopt] = {
        NULL,
    },
    [SIG_ws2_32_shutdown] = {
        NULL,
    },
    [SIG_ws2_32_socket] = {
        NULL,
    },
    [SIG_ntdll_NtSystemDebugControl] = {
        NULL,
    },
    [SIG_ntdll_NtDebugActiveProcess] = {
        NULL,
    },
};


static const char *g_explain_apinames[] = {
    "__process__",
    "__anomaly__",
    "__exception__",
    "__missing__",
    "ControlService",
    "CreateServiceA",
    "CreateServiceW",
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptCreateHash",
    "CryptDecrypt",
    "CryptEncrypt",
    "CryptExportKey",
    "CryptGenKey",
    "CryptHashData",
    "DeleteService",
    "EnumServicesStatusA",
    "EnumServicesStatusW",
    "GetUserNameA",
    "GetUserNameW",
    "LookupAccountSidW",
    "LookupPrivilegeValueW",
    "OpenSCManagerA",
    "OpenSCManagerW",
    "OpenServiceA",
    "OpenServiceW",
    "RegCloseKey",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegDeleteKeyA",
    "RegDeleteKeyW",
    "RegDeleteValueA",
    "RegDeleteValueW",
    "RegEnumKeyExA",
    "RegEnumKeyExW",
    "RegEnumKeyW",
    "RegEnumValueA",
    "RegEnumValueW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegQueryInfoKeyA",
    "RegQueryInfoKeyW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "RegSetValueExA",
    "RegSetValueExW",
    "StartServiceA",
    "StartServiceW",
    "CertControlStore",
    "CertCreateCertificateContext",
    "CertOpenStore",
    "CertOpenSystemStoreA",
    "CertOpenSystemStoreW",
    "CryptDecodeMessage",
    "CryptDecodeObjectEx",
    "CryptDecryptMessage",
    "CryptEncryptMessage",
    "CryptHashMessage",
    "CryptProtectData",
    "CryptProtectMemory",
    "CryptUnprotectData",
    "CryptUnprotectMemory",
    "DnsQuery_A",
    "DnsQuery_UTF8",
    "DnsQuery_W",
    "GetAdaptersAddresses",
    "GetAdaptersInfo",
    "GetBestInterfaceEx",
    "GetInterfaceInfo",
    "COleScript_Compile",
    "CopyFileA",
    "CopyFileExW",
    "CopyFileW",
    "CreateDirectoryExW",
    "CreateDirectoryW",
    "CreateProcessInternalW",
    "CreateRemoteThread",
    "CreateThread",
    "CreateToolhelp32Snapshot",
    "DeleteFileW",
    "DeviceIoControl",
    "FindFirstFileExA",
    "FindFirstFileExW",
    "FindResourceA",
    "FindResourceExA",
    "FindResourceExW",
    "FindResourceW",
    "GetComputerNameA",
    "GetComputerNameW",
    "GetDiskFreeSpaceExW",
    "GetDiskFreeSpaceW",
    "GetFileAttributesExW",
    "GetFileAttributesW",
    "GetFileInformationByHandle",
    "GetFileInformationByHandleEx",
    "GetFileSize",
    "GetFileSizeEx",
    "GetFileType",
    "GetLocalTime",
    "GetNativeSystemInfo",
    "GetShortPathNameW",
    "GetSystemDirectoryA",
    "GetSystemDirectoryW",
    "GetSystemInfo",
    "GetSystemTime",
    "GetSystemTimeAsFileTime",
    "GetSystemWindowsDirectoryA",
    "GetSystemWindowsDirectoryW",
    "GetTempPathW",
    "GetTickCount",
    "GetVolumeNameForVolumeMountPointW",
    "GetVolumePathNameW",
    "GetVolumePathNamesForVolumeNameW",
    "IsDebuggerPresent",
    "LoadResource",
    "Module32FirstW",
    "Module32NextW",
    "MoveFileWithProgressW",
    "OutputDebugStringA",
    "Process32FirstW",
    "Process32NextW",
    "ReadProcessMemory",
    "RemoveDirectoryA",
    "RemoveDirectoryW",
    "SearchPathW",
    "SetEndOfFile",
    "SetErrorMode",
    "SetFileAttributesW",
    "SetFileInformationByHandle",
    "SetFilePointer",
    "SetFilePointerEx",
    "SetUnhandledExceptionFilter",
    "SizeofResource",
    "Thread32First",
    "Thread32Next",
    "WriteConsoleA",
    "WriteConsoleW",
    "WriteProcessMemory",
    "CDocument_write",
    "CElement_put_innerHTML",
    "CHyperlink_SetUrlComponent",
    "CIFrameElement_CreateElement",
    "CScriptElement_put_src",
    "CWindow_AddTimeoutCode",
    "system",
    "PRF",
    "Ssl3GenerateKeyMaterial",
    "NetGetJoinInformation",
    "NetShareEnum",
    "NetUserGetInfo",
    "NetUserGetLocalGroups",
    "LdrGetDllHandle",
    "LdrGetProcedureAddress",
    "LdrLoadDll",
    "LdrUnloadDll",
    "NtAllocateVirtualMemory",
    "NtClose",
    "NtCreateDirectoryObject",
    "NtCreateFile",
    "NtCreateKey",
    "NtCreateMutant",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtCreateSection",
    "NtCreateThread",
    "NtCreateThreadEx",
    "NtCreateUserProcess",
    "NtDelayExecution",
    "NtDeleteFile",
    "NtDeleteKey",
    "NtDeleteValueKey",
    "NtDeviceIoControlFile",
    "NtDuplicateObject",
    "NtEnumerateKey",
    "NtEnumerateValueKey",
    "NtFreeVirtualMemory",
    "NtGetContextThread",
    "NtLoadDriver",
    "NtLoadKey",
    "NtLoadKey2",
    "NtLoadKeyEx",
    "NtMakePermanentObject",
    "NtMakeTemporaryObject",
    "NtMapViewOfSection",
    "NtOpenDirectoryObject",
    "NtOpenFile",
    "NtOpenKey",
    "NtOpenKeyEx",
    "NtOpenProcess",
    "NtOpenSection",
    "NtOpenThread",
    "NtProtectVirtualMemory",
    "NtQueryAttributesFile",
    "NtQueryDirectoryFile",
    "NtQueryFullAttributesFile",
    "NtQueryInformationFile",
    "NtQueryKey",
    "NtQueryMultipleValueKey",
    "NtQuerySystemTime",
    "NtQueryValueKey",
    "NtQueueApcThread",
    "NtReadFile",
    "NtReadVirtualMemory",
    "NtRenameKey",
    "NtReplaceKey",
    "NtResumeThread",
    "NtSaveKey",
    "NtSaveKeyEx",
    "NtSetContextThread",
    "NtSetInformationFile",
    "NtSetValueKey",
    "NtSuspendThread",
    "NtTerminateProcess",
    "NtTerminateThread",
    "NtUnloadDriver",
    "NtUnmapViewOfSection",
    "NtWriteFile",
    "NtWriteVirtualMemory",
    "RtlAddVectoredContinueHandler",
    "RtlAddVectoredExceptionHandler",
    "RtlCompressBuffer",
    "RtlCreateUserProcess",
    "RtlCreateUserThread",
    "RtlDecompressBuffer",
    "RtlDecompressFragment",
    "RtlDispatchException",
    "RtlRemoveVectoredContinueHandler",
    "RtlRemoveVectoredExceptionHandler",
    "CoCreateInstance",
    "CoInitializeEx",
    "CoInitializeSecurity",
    "OleInitialize",
    "UuidCreate",
    "GetUserNameExA",
    "GetUserNameExW",
    "ReadCabinetState",
    "SHGetFolderPathW",
    "SHGetSpecialFolderLocation",
    "ShellExecuteExW",
    "NetShareEnum",
    "ObtainUserAgentString",
    "URLDownloadToFileW",
    "DrawTextExA",
    "DrawTextExW",
    "EnumWindows",
    "ExitWindowsEx",
    "FindWindowA",
    "FindWindowExA",
    "FindWindowExW",
    "FindWindowW",
    "GetAsyncKeyState",
    "GetCursorPos",
    "GetForegroundWindow",
    "GetKeyState",
    "GetKeyboardState",
    "GetSystemMetrics",
    "LoadStringA",
    "LoadStringW",
    "MessageBoxTimeoutA",
    "MessageBoxTimeoutW",
    "SendNotifyMessageA",
    "SendNotifyMessageW",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "UnhookWindowsHookEx",
    "DeleteUrlCacheEntryA",
    "DeleteUrlCacheEntryW",
    "HttpOpenRequestA",
    "HttpOpenRequestW",
    "HttpQueryInfoA",
    "HttpSendRequestA",
    "HttpSendRequestW",
    "InternetCloseHandle",
    "InternetConnectA",
    "InternetConnectW",
    "InternetCrackUrlA",
    "InternetCrackUrlW",
    "InternetGetConnectedState",
    "InternetGetConnectedStateExA",
    "InternetGetConnectedStateExW",
    "InternetOpenA",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "InternetOpenW",
    "InternetQueryOptionA",
    "InternetReadFile",
    "InternetSetOptionA",
    "InternetSetStatusCallback",
    "InternetWriteFile",
    "timeGetTime",
    "ConnectEx",
    "GetAddrInfoW",
    "TransmitFile",
    "WSAAccept",
    "WSAConnect",
    "WSARecv",
    "WSARecvFrom",
    "WSASend",
    "WSASendTo",
    "WSASocketA",
    "WSASocketW",
    "WSAStartup",
    "accept",
    "bind",
    "closesocket",
    "connect",
    "getaddrinfo",
    "gethostbyname",
    "getsockname",
    "ioctlsocket",
    "listen",
    "recv",
    "recvfrom",
    "select",
    "send",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
    "NtSystemDebugControl",
    "NtDebugActiveProcess",
    NULL,
};

static const char *g_explain_categories[] = {
    // __process__
    "__notification__",
    // __anomaly__
    "__notification__",
    // __exception__
    "__notification__",
    // __missing__
    "__notification__",
    // ControlService
    "services",
    // CreateServiceA
    "services",
    // CreateServiceW
    "services",
    // CryptAcquireContextA
    "crypto",
    // CryptAcquireContextW
    "crypto",
    // CryptCreateHash
    "crypto",
    // CryptDecrypt
    "crypto",
    // CryptEncrypt
    "crypto",
    // CryptExportKey
    "crypto",
    // CryptGenKey
    "crypto",
    // CryptHashData
    "crypto",
    // DeleteService
    "services",
    // EnumServicesStatusA
    "services",
    // EnumServicesStatusW
    "services",
    // GetUserNameA
    "misc",
    // GetUserNameW
    "misc",
    // LookupAccountSidW
    "misc",
    // LookupPrivilegeValueW
    "system",
    // OpenSCManagerA
    "services",
    // OpenSCManagerW
    "services",
    // OpenServiceA
    "services",
    // OpenServiceW
    "services",
    // RegCloseKey
    "registry",
    // RegCreateKeyExA
    "registry",
    // RegCreateKeyExW
    "registry",
    // RegDeleteKeyA
    "registry",
    // RegDeleteKeyW
    "registry",
    // RegDeleteValueA
    "registry",
    // RegDeleteValueW
    "registry",
    // RegEnumKeyExA
    "registry",
    // RegEnumKeyExW
    "registry",
    // RegEnumKeyW
    "registry",
    // RegEnumValueA
    "registry",
    // RegEnumValueW
    "registry",
    // RegOpenKeyExA
    "registry",
    // RegOpenKeyExW
    "registry",
    // RegQueryInfoKeyA
    "registry",
    // RegQueryInfoKeyW
    "registry",
    // RegQueryValueExA
    "registry",
    // RegQueryValueExW
    "registry",
    // RegSetValueExA
    "registry",
    // RegSetValueExW
    "registry",
    // StartServiceA
    "services",
    // StartServiceW
    "services",
    // CertControlStore
    "certificate",
    // CertCreateCertificateContext
    "certificate",
    // CertOpenStore
    "certificate",
    // CertOpenSystemStoreA
    "certificate",
    // CertOpenSystemStoreW
    "certificate",
    // CryptDecodeMessage
    "crypto",
    // CryptDecodeObjectEx
    "crypto",
    // CryptDecryptMessage
    "crypto",
    // CryptEncryptMessage
    "crypto",
    // CryptHashMessage
    "crypto",
    // CryptProtectData
    "crypto",
    // CryptProtectMemory
    "crypto",
    // CryptUnprotectData
    "crypto",
    // CryptUnprotectMemory
    "crypto",
    // DnsQuery_A
    "network",
    // DnsQuery_UTF8
    "network",
    // DnsQuery_W
    "network",
    // GetAdaptersAddresses
    "network",
    // GetAdaptersInfo
    "network",
    // GetBestInterfaceEx
    "network",
    // GetInterfaceInfo
    "network",
    // COleScript_Compile
    "iexplore",
    // CopyFileA
    "file",
    // CopyFileExW
    "file",
    // CopyFileW
    "file",
    // CreateDirectoryExW
    "file",
    // CreateDirectoryW
    "file",
    // CreateProcessInternalW
    "process",
    // CreateRemoteThread
    "process",
    // CreateThread
    "process",
    // CreateToolhelp32Snapshot
    "process",
    // DeleteFileW
    "file",
    // DeviceIoControl
    "file",
    // FindFirstFileExA
    "file",
    // FindFirstFileExW
    "file",
    // FindResourceA
    "resource",
    // FindResourceExA
    "resource",
    // FindResourceExW
    "resource",
    // FindResourceW
    "resource",
    // GetComputerNameA
    "misc",
    // GetComputerNameW
    "misc",
    // GetDiskFreeSpaceExW
    "misc",
    // GetDiskFreeSpaceW
    "misc",
    // GetFileAttributesExW
    "file",
    // GetFileAttributesW
    "file",
    // GetFileInformationByHandle
    "file",
    // GetFileInformationByHandleEx
    "file",
    // GetFileSize
    "file",
    // GetFileSizeEx
    "file",
    // GetFileType
    "file",
    // GetLocalTime
    "synchronisation",
    // GetNativeSystemInfo
    "system",
    // GetShortPathNameW
    "file",
    // GetSystemDirectoryA
    "file",
    // GetSystemDirectoryW
    "file",
    // GetSystemInfo
    "system",
    // GetSystemTime
    "synchronisation",
    // GetSystemTimeAsFileTime
    "synchronisation",
    // GetSystemWindowsDirectoryA
    "file",
    // GetSystemWindowsDirectoryW
    "file",
    // GetTempPathW
    "file",
    // GetTickCount
    "synchronisation",
    // GetVolumeNameForVolumeMountPointW
    "file",
    // GetVolumePathNameW
    "file",
    // GetVolumePathNamesForVolumeNameW
    "file",
    // IsDebuggerPresent
    "system",
    // LoadResource
    "resource",
    // Module32FirstW
    "process",
    // Module32NextW
    "process",
    // MoveFileWithProgressW
    "file",
    // OutputDebugStringA
    "system",
    // Process32FirstW
    "process",
    // Process32NextW
    "process",
    // ReadProcessMemory
    "process",
    // RemoveDirectoryA
    "file",
    // RemoveDirectoryW
    "file",
    // SearchPathW
    "file",
    // SetEndOfFile
    "file",
    // SetErrorMode
    "system",
    // SetFileAttributesW
    "file",
    // SetFileInformationByHandle
    "file",
    // SetFilePointer
    "file",
    // SetFilePointerEx
    "file",
    // SetUnhandledExceptionFilter
    "exception",
    // SizeofResource
    "resource",
    // Thread32First
    "process",
    // Thread32Next
    "process",
    // WriteConsoleA
    "misc",
    // WriteConsoleW
    "misc",
    // WriteProcessMemory
    "process",
    // CDocument_write
    "iexplore",
    // CElement_put_innerHTML
    "iexplore",
    // CHyperlink_SetUrlComponent
    "iexplore",
    // CIFrameElement_CreateElement
    "iexplore",
    // CScriptElement_put_src
    "iexplore",
    // CWindow_AddTimeoutCode
    "iexplore",
    // system
    "process",
    // PRF
    "crypto",
    // Ssl3GenerateKeyMaterial
    "crypto",
    // NetGetJoinInformation
    "netapi",
    // NetShareEnum
    "netapi",
    // NetUserGetInfo
    "netapi",
    // NetUserGetLocalGroups
    "netapi",
    // LdrGetDllHandle
    "system",
    // LdrGetProcedureAddress
    "system",
    // LdrLoadDll
    "system",
    // LdrUnloadDll
    "system",
    // NtAllocateVirtualMemory
    "process",
    // NtClose
    "system",
    // NtCreateDirectoryObject
    "file",
    // NtCreateFile
    "file",
    // NtCreateKey
    "registry",
    // NtCreateMutant
    "synchronisation",
    // NtCreateProcess
    "process",
    // NtCreateProcessEx
    "process",
    // NtCreateSection
    "process",
    // NtCreateThread
    "process",
    // NtCreateThreadEx
    "process",
    // NtCreateUserProcess
    "process",
    // NtDelayExecution
    "synchronisation",
    // NtDeleteFile
    "file",
    // NtDeleteKey
    "registry",
    // NtDeleteValueKey
    "registry",
    // NtDeviceIoControlFile
    "file",
    // NtDuplicateObject
    "system",
    // NtEnumerateKey
    "registry",
    // NtEnumerateValueKey
    "registry",
    // NtFreeVirtualMemory
    "process",
    // NtGetContextThread
    "process",
    // NtLoadDriver
    "system",
    // NtLoadKey
    "registry",
    // NtLoadKey2
    "registry",
    // NtLoadKeyEx
    "registry",
    // NtMakePermanentObject
    "process",
    // NtMakeTemporaryObject
    "process",
    // NtMapViewOfSection
    "process",
    // NtOpenDirectoryObject
    "file",
    // NtOpenFile
    "file",
    // NtOpenKey
    "registry",
    // NtOpenKeyEx
    "registry",
    // NtOpenProcess
    "process",
    // NtOpenSection
    "process",
    // NtOpenThread
    "process",
    // NtProtectVirtualMemory
    "process",
    // NtQueryAttributesFile
    "file",
    // NtQueryDirectoryFile
    "file",
    // NtQueryFullAttributesFile
    "file",
    // NtQueryInformationFile
    "file",
    // NtQueryKey
    "registry",
    // NtQueryMultipleValueKey
    "registry",
    // NtQuerySystemTime
    "synchronisation",
    // NtQueryValueKey
    "registry",
    // NtQueueApcThread
    "process",
    // NtReadFile
    "file",
    // NtReadVirtualMemory
    "process",
    // NtRenameKey
    "registry",
    // NtReplaceKey
    "registry",
    // NtResumeThread
    "process",
    // NtSaveKey
    "registry",
    // NtSaveKeyEx
    "registry",
    // NtSetContextThread
    "process",
    // NtSetInformationFile
    "file",
    // NtSetValueKey
    "registry",
    // NtSuspendThread
    "process",
    // NtTerminateProcess
    "process",
    // NtTerminateThread
    "process",
    // NtUnloadDriver
    "system",
    // NtUnmapViewOfSection
    "process",
    // NtWriteFile
    "file",
    // NtWriteVirtualMemory
    "process",
    // RtlAddVectoredContinueHandler
    "exception",
    // RtlAddVectoredExceptionHandler
    "exception",
    // RtlCompressBuffer
    "system",
    // RtlCreateUserProcess
    "process",
    // RtlCreateUserThread
    "process",
    // RtlDecompressBuffer
    "system",
    // RtlDecompressFragment
    "system",
    // RtlDispatchException
    "exception",
    // RtlRemoveVectoredContinueHandler
    "exception",
    // RtlRemoveVectoredExceptionHandler
    "exception",
    // CoCreateInstance
    "ole",
    // CoInitializeEx
    "ole",
    // CoInitializeSecurity
    "misc",
    // OleInitialize
    "ole",
    // UuidCreate
    "misc",
    // GetUserNameExA
    "misc",
    // GetUserNameExW
    "misc",
    // ReadCabinetState
    "misc",
    // SHGetFolderPathW
    "misc",
    // SHGetSpecialFolderLocation
    "misc",
    // ShellExecuteExW
    "process",
    // NetShareEnum
    "netapi",
    // ObtainUserAgentString
    "network",
    // URLDownloadToFileW
    "network",
    // DrawTextExA
    "ui",
    // DrawTextExW
    "ui",
    // EnumWindows
    "misc",
    // ExitWindowsEx
    "system",
    // FindWindowA
    "ui",
    // FindWindowExA
    "ui",
    // FindWindowExW
    "ui",
    // FindWindowW
    "ui",
    // GetAsyncKeyState
    "system",
    // GetCursorPos
    "misc",
    // GetForegroundWindow
    "ui",
    // GetKeyState
    "system",
    // GetKeyboardState
    "system",
    // GetSystemMetrics
    "misc",
    // LoadStringA
    "ui",
    // LoadStringW
    "ui",
    // MessageBoxTimeoutA
    "ui",
    // MessageBoxTimeoutW
    "ui",
    // SendNotifyMessageA
    "system",
    // SendNotifyMessageW
    "system",
    // SetWindowsHookExA
    "system",
    // SetWindowsHookExW
    "system",
    // UnhookWindowsHookEx
    "system",
    // DeleteUrlCacheEntryA
    "network",
    // DeleteUrlCacheEntryW
    "network",
    // HttpOpenRequestA
    "network",
    // HttpOpenRequestW
    "network",
    // HttpQueryInfoA
    "network",
    // HttpSendRequestA
    "network",
    // HttpSendRequestW
    "network",
    // InternetCloseHandle
    "network",
    // InternetConnectA
    "network",
    // InternetConnectW
    "network",
    // InternetCrackUrlA
    "network",
    // InternetCrackUrlW
    "network",
    // InternetGetConnectedState
    "network",
    // InternetGetConnectedStateExA
    "network",
    // InternetGetConnectedStateExW
    "network",
    // InternetOpenA
    "network",
    // InternetOpenUrlA
    "network",
    // InternetOpenUrlW
    "network",
    // InternetOpenW
    "network",
    // InternetQueryOptionA
    "network",
    // InternetReadFile
    "network",
    // InternetSetOptionA
    "network",
    // InternetSetStatusCallback
    "network",
    // InternetWriteFile
    "network",
    // timeGetTime
    "synchronisation",
    // ConnectEx
    "network",
    // GetAddrInfoW
    "network",
    // TransmitFile
    "network",
    // WSAAccept
    "network",
    // WSAConnect
    "network",
    // WSARecv
    "network",
    // WSARecvFrom
    "network",
    // WSASend
    "network",
    // WSASendTo
    "network",
    // WSASocketA
    "network",
    // WSASocketW
    "network",
    // WSAStartup
    "network",
    // accept
    "network",
    // bind
    "network",
    // closesocket
    "network",
    // connect
    "network",
    // getaddrinfo
    "network",
    // gethostbyname
    "network",
    // getsockname
    "network",
    // ioctlsocket
    "network",
    // listen
    "network",
    // recv
    "network",
    // recvfrom
    "network",
    // select
    "network",
    // send
    "network",
    // sendto
    "network",
    // setsockopt
    "network",
    // shutdown
    "network",
    // socket
    "network",
    // NtSystemDebugControl
    "process",
    // NtDebugActiveProcess
    "process",
};


static const char *g_explain_paramnames[][16] = {
    // __process__
    {
        "time_low",
        "time_high",
        "pid",
        "ppid",
        "module_path",
        "command_line",
        "is_64bit",
    },
    // __anomaly__
    {
        "tid",
        "subcategory",
        "function_name",
        "message",
    },
    // __exception__
    {
        "exception",
        "registers",
        "stacktrace",
    },
    // __missing__
    {
        "function_name",
    },
    // ControlService
    {
        "service_handle",
        "control_code",
    },
    // CreateServiceA
    {
        "service_manager_handle",
        "service_name",
        "display_name",
        "desired_access",
        "service_type",
        "start_type",
        "error_control",
        "service_start_name",
        "password",
        "filepath",
    },
    // CreateServiceW
    {
        "service_manager_handle",
        "service_name",
        "display_name",
        "desired_access",
        "service_type",
        "start_type",
        "error_control",
        "service_start_name",
        "password",
        "filepath",
    },
    // CryptAcquireContextA
    {
        "crypto_handle",
        "container",
        "provider",
        "provider_type",
        "flags",
    },
    // CryptAcquireContextW
    {
        "crypto_handle",
        "container",
        "provider",
        "provider_type",
        "flags",
    },
    // CryptCreateHash
    {
        "provider_handle",
        "algorithm_identifier",
        "crypto_handle",
        "flags",
        "hash_handle",
    },
    // CryptDecrypt
    {
        "key_handle",
        "hash_handle",
        "final",
        "flags",
        "buffer",
    },
    // CryptEncrypt
    {
        "key_handle",
        "hash_handle",
        "final",
        "flags",
        "buffer",
    },
    // CryptExportKey
    {
        "crypto_handle",
        "crypto_export_handle",
        "blob_type",
        "flags",
        "buffer",
    },
    // CryptGenKey
    {
        "provider_handle",
        "algorithm_identifier",
        "flags",
        "crypto_handle",
    },
    // CryptHashData
    {
        "hash_handle",
        "flags",
        "buffer",
    },
    // DeleteService
    {
        "service_handle",
    },
    // EnumServicesStatusA
    {
        "service_handle",
        "service_type",
        "service_status",
    },
    // EnumServicesStatusW
    {
        "service_handle",
        "service_type",
        "service_status",
    },
    // GetUserNameA
    {
        "user_name",
    },
    // GetUserNameW
    {
        "user_name",
    },
    // LookupAccountSidW
    {
        "system_name",
        "account_name",
        "domain_name",
    },
    // LookupPrivilegeValueW
    {
        "system_name",
        "privilege_name",
    },
    // OpenSCManagerA
    {
        "machine_name",
        "database_name",
        "desired_access",
    },
    // OpenSCManagerW
    {
        "machine_name",
        "database_name",
        "desired_access",
    },
    // OpenServiceA
    {
        "service_manager_handle",
        "service_name",
        "desired_access",
    },
    // OpenServiceW
    {
        "service_manager_handle",
        "service_name",
        "desired_access",
    },
    // RegCloseKey
    {
        "key_handle",
    },
    // RegCreateKeyExA
    {
        "base_handle",
        "class",
        "options",
        "access",
        "key_handle",
        "disposition",
        "regkey",
    },
    // RegCreateKeyExW
    {
        "base_handle",
        "class",
        "options",
        "access",
        "key_handle",
        "disposition",
        "regkey",
    },
    // RegDeleteKeyA
    {
        "key_handle",
        "regkey",
    },
    // RegDeleteKeyW
    {
        "key_handle",
        "regkey",
    },
    // RegDeleteValueA
    {
        "key_handle",
        "regkey",
    },
    // RegDeleteValueW
    {
        "key_handle",
        "regkey",
    },
    // RegEnumKeyExA
    {
        "key_handle",
        "index",
        "key_name",
        "class",
        "regkey",
    },
    // RegEnumKeyExW
    {
        "key_handle",
        "index",
        "key_name",
        "class",
        "regkey",
    },
    // RegEnumKeyW
    {
        "key_handle",
        "index",
        "key_name",
        "regkey",
    },
    // RegEnumValueA
    {
        "key_handle",
        "index",
        "reg_type",
        "regkey",
        "value",
    },
    // RegEnumValueW
    {
        "key_handle",
        "index",
        "reg_type",
        "regkey",
        "value",
    },
    // RegOpenKeyExA
    {
        "base_handle",
        "options",
        "access",
        "key_handle",
        "regkey",
    },
    // RegOpenKeyExW
    {
        "base_handle",
        "options",
        "access",
        "key_handle",
        "regkey",
    },
    // RegQueryInfoKeyA
    {
        "key_handle",
        "class",
        "subkey_count",
        "subkey_max_length",
        "class_max_length",
        "value_count",
        "value_name_max_length",
        "value_max_length",
    },
    // RegQueryInfoKeyW
    {
        "key_handle",
        "class",
        "subkey_count",
        "subkey_max_length",
        "class_max_length",
        "value_count",
        "value_name_max_length",
        "value_max_length",
    },
    // RegQueryValueExA
    {
        "key_handle",
        "reg_type",
        "regkey",
        "value",
    },
    // RegQueryValueExW
    {
        "key_handle",
        "reg_type",
        "regkey",
        "value",
    },
    // RegSetValueExA
    {
        "key_handle",
        "reg_type",
        "regkey",
        "value",
    },
    // RegSetValueExW
    {
        "key_handle",
        "reg_type",
        "regkey",
        "value",
    },
    // StartServiceA
    {
        "service_handle",
        "arguments",
    },
    // StartServiceW
    {
        "service_handle",
        "arguments",
    },
    // CertControlStore
    {
        "cert_store",
        "flags",
        "control_type",
    },
    // CertCreateCertificateContext
    {
        "encoding",
        "certificate",
    },
    // CertOpenStore
    {
        "encoding_type",
        "flags",
        "store_provider",
    },
    // CertOpenSystemStoreA
    {
        "store_name",
    },
    // CertOpenSystemStoreW
    {
        "store_name",
    },
    // CryptDecodeMessage
    {
        "buffer",
    },
    // CryptDecodeObjectEx
    {
        "encoding_type",
        "flags",
        "struct_type",
        "buffer",
    },
    // CryptDecryptMessage
    {
        "buffer",
    },
    // CryptEncryptMessage
    {
        "buffer",
    },
    // CryptHashMessage
    {
        "buffer",
    },
    // CryptProtectData
    {
        "buffer",
        "description",
        "flags",
    },
    // CryptProtectMemory
    {
        "buffer",
        "flags",
    },
    // CryptUnprotectData
    {
        "flags",
        "description",
        "entropy",
        "buffer",
    },
    // CryptUnprotectMemory
    {
        "flags",
        "buffer",
    },
    // DnsQuery_A
    {
        "hostname",
        "dns_type",
        "options",
    },
    // DnsQuery_UTF8
    {
        "dns_type",
        "options",
        "hostname",
    },
    // DnsQuery_W
    {
        "hostname",
        "dns_type",
        "options",
    },
    // GetAdaptersAddresses
    {
        "family",
        "flags",
    },
    // GetAdaptersInfo
    {
    },
    // GetBestInterfaceEx
    {
    },
    // GetInterfaceInfo
    {
    },
    // COleScript_Compile
    {
        "script",
        "type",
    },
    // CopyFileA
    {
        "fail_if_exists",
        "oldfilepath",
        "newfilepath",
    },
    // CopyFileExW
    {
        "flags",
        "oldfilepath",
        "newfilepath",
    },
    // CopyFileW
    {
        "fail_if_exists",
        "oldfilepath",
        "newfilepath",
    },
    // CreateDirectoryExW
    {
        "dirpath",
    },
    // CreateDirectoryW
    {
        "dirpath",
    },
    // CreateProcessInternalW
    {
        "command_line",
        "inherit_handles",
        "current_directory",
        "filepath",
        "creation_flags",
        "process_identifier",
        "thread_identifier",
        "process_handle",
        "thread_handle",
    },
    // CreateRemoteThread
    {
        "process_handle",
        "stack_size",
        "function_address",
        "parameter",
        "flags",
        "thread_identifier",
    },
    // CreateThread
    {
        "stack_size",
        "function_address",
        "parameter",
        "flags",
        "thread_identifier",
    },
    // CreateToolhelp32Snapshot
    {
        "flags",
        "process_identifier",
    },
    // DeleteFileW
    {
        "filepath",
    },
    // DeviceIoControl
    {
        "input_buffer",
        "device_handle",
        "control_code",
        "output_buffer",
    },
    // FindFirstFileExA
    {
        "filepath",
    },
    // FindFirstFileExW
    {
        "filepath",
    },
    // FindResourceA
    {
        "module_handle",
        "name",
        "type",
    },
    // FindResourceExA
    {
        "module_handle",
        "language_identifier",
        "name",
        "type",
    },
    // FindResourceExW
    {
        "module_handle",
        "language_identifier",
        "name",
        "type",
    },
    // FindResourceW
    {
        "module_handle",
        "name",
        "type",
    },
    // GetComputerNameA
    {
        "computer_name",
    },
    // GetComputerNameW
    {
        "computer_name",
    },
    // GetDiskFreeSpaceExW
    {
        "root_path",
        "free_bytes_available",
        "total_number_of_bytes",
        "total_number_of_free_bytes",
    },
    // GetDiskFreeSpaceW
    {
        "root_path",
        "sectors_per_cluster",
        "bytes_per_sector",
        "number_of_free_clusters",
        "total_number_of_clusters",
    },
    // GetFileAttributesExW
    {
        "info_level",
        "filepath",
    },
    // GetFileAttributesW
    {
        "filepath",
        "file_attributes",
    },
    // GetFileInformationByHandle
    {
        "file_handle",
    },
    // GetFileInformationByHandleEx
    {
        "file_handle",
        "information_class",
    },
    // GetFileSize
    {
        "file_handle",
        "file_size_low",
    },
    // GetFileSizeEx
    {
        "file_handle",
        "file_size",
    },
    // GetFileType
    {
        "file_handle",
    },
    // GetLocalTime
    {
    },
    // GetNativeSystemInfo
    {
        "processor_count",
    },
    // GetShortPathNameW
    {
        "filepath",
        "shortpath",
    },
    // GetSystemDirectoryA
    {
        "dirpath",
    },
    // GetSystemDirectoryW
    {
        "dirpath",
    },
    // GetSystemInfo
    {
        "processor_count",
    },
    // GetSystemTime
    {
    },
    // GetSystemTimeAsFileTime
    {
    },
    // GetSystemWindowsDirectoryA
    {
        "dirpath",
    },
    // GetSystemWindowsDirectoryW
    {
        "dirpath",
    },
    // GetTempPathW
    {
        "dirpath",
    },
    // GetTickCount
    {
    },
    // GetVolumeNameForVolumeMountPointW
    {
        "volume_mount_point",
        "volume_name",
    },
    // GetVolumePathNameW
    {
        "filepath",
        "volume_path_name",
    },
    // GetVolumePathNamesForVolumeNameW
    {
        "volume_name",
        "volume_path_name",
    },
    // IsDebuggerPresent
    {
    },
    // LoadResource
    {
        "module_handle",
        "resource_handle",
        "pointer",
    },
    // Module32FirstW
    {
        "snapshot_handle",
    },
    // Module32NextW
    {
        "snapshot_handle",
    },
    // MoveFileWithProgressW
    {
        "flags",
        "oldfilepath",
        "newfilepath",
    },
    // OutputDebugStringA
    {
        "string",
    },
    // Process32FirstW
    {
        "snapshot_handle",
        "process_name",
        "process_identifier",
    },
    // Process32NextW
    {
        "snapshot_handle",
        "process_name",
        "process_identifier",
    },
    // ReadProcessMemory
    {
        "process_handle",
        "base_address",
        "buffer",
    },
    // RemoveDirectoryA
    {
        "dirpath",
    },
    // RemoveDirectoryW
    {
        "dirpath",
    },
    // SearchPathW
    {
        "searchpath",
        "filename",
        "extension",
        "filepath",
    },
    // SetEndOfFile
    {
        "file_handle",
    },
    // SetErrorMode
    {
        "mode",
    },
    // SetFileAttributesW
    {
        "file_attributes",
        "filepath",
    },
    // SetFileInformationByHandle
    {
        "file_handle",
        "information_class",
    },
    // SetFilePointer
    {
        "file_handle",
        "move_method",
        "offset",
    },
    // SetFilePointerEx
    {
        "file_handle",
        "offset",
        "move_method",
    },
    // SetUnhandledExceptionFilter
    {
    },
    // SizeofResource
    {
        "module_handle",
        "resource_handle",
        "resource_size",
    },
    // Thread32First
    {
        "snapshot_handle",
    },
    // Thread32Next
    {
        "snapshot_handle",
    },
    // WriteConsoleA
    {
        "console_handle",
        "buffer",
    },
    // WriteConsoleW
    {
        "console_handle",
        "buffer",
    },
    // WriteProcessMemory
    {
        "process_handle",
        "base_address",
        "buffer",
    },
    // CDocument_write
    {
        "lines",
    },
    // CElement_put_innerHTML
    {
        "html",
    },
    // CHyperlink_SetUrlComponent
    {
        "component",
        "index",
    },
    // CIFrameElement_CreateElement
    {
        "attributes",
    },
    // CScriptElement_put_src
    {
        "url",
    },
    // CWindow_AddTimeoutCode
    {
        "argument",
        "milliseconds",
        "code",
        "repeat",
    },
    // system
    {
        "command",
    },
    // PRF
    {
        "type",
        "client_random",
        "server_random",
        "master_secret",
    },
    // Ssl3GenerateKeyMaterial
    {
        "client_random",
        "server_random",
        "master_secret",
    },
    // NetGetJoinInformation
    {
        "server",
        "name",
    },
    // NetShareEnum
    {
        "servername",
        "level",
    },
    // NetUserGetInfo
    {
        "server_name",
        "username",
        "level",
    },
    // NetUserGetLocalGroups
    {
        "servername",
        "username",
        "level",
        "flags",
    },
    // LdrGetDllHandle
    {
        "module_address",
        "module_name",
    },
    // LdrGetProcedureAddress
    {
        "module_address",
        "function_name",
        "ordinal",
        "function_address",
    },
    // LdrLoadDll
    {
        "flags",
        "module_address",
        "module_name",
        "basename",
    },
    // LdrUnloadDll
    {
        "module_address",
    },
    // NtAllocateVirtualMemory
    {
        "process_handle",
        "base_address",
        "region_size",
        "allocation_type",
        "protection",
    },
    // NtClose
    {
        "handle",
    },
    // NtCreateDirectoryObject
    {
        "directory_handle",
        "desired_access",
        "dirpath",
    },
    // NtCreateFile
    {
        "file_handle",
        "desired_access",
        "file_attributes",
        "create_disposition",
        "create_options",
        "share_access",
        "filepath",
    },
    // NtCreateKey
    {
        "key_handle",
        "desired_access",
        "index",
        "options",
        "disposition",
        "regkey",
        "class",
    },
    // NtCreateMutant
    {
        "mutant_handle",
        "desired_access",
        "initial_owner",
        "mutant_name",
    },
    // NtCreateProcess
    {
        "process_handle",
        "desired_access",
        "inherit_handles",
        "filepath",
    },
    // NtCreateProcessEx
    {
        "process_handle",
        "desired_access",
        "flags",
        "filepath",
    },
    // NtCreateSection
    {
        "section_handle",
        "desired_access",
        "protection",
        "file_handle",
        "object_handle",
        "section_name",
    },
    // NtCreateThread
    {
        "thread_handle",
        "access",
        "process_handle",
        "suspended",
        "thread_name",
    },
    // NtCreateThreadEx
    {
        "thread_handle",
        "access",
        "thread_name",
        "process_handle",
        "function_address",
        "parameter",
        "suspended",
        "stack_zero_bits",
    },
    // NtCreateUserProcess
    {
        "process_handle",
        "thread_handle",
        "desired_access_process",
        "desired_access_thread",
        "flags_process",
        "flags_thread",
        "filepath",
        "command_line",
    },
    // NtDelayExecution
    {
        "milliseconds",
    },
    // NtDeleteFile
    {
        "filepath",
    },
    // NtDeleteKey
    {
        "key_handle",
        "regkey",
    },
    // NtDeleteValueKey
    {
        "key_handle",
        "regkey",
    },
    // NtDeviceIoControlFile
    {
        "input_buffer",
        "file_handle",
        "control_code",
        "output_buffer",
    },
    // NtDuplicateObject
    {
        "source_process_handle",
        "source_handle",
        "target_process_handle",
        "target_handle",
        "desired_access",
        "handle_attributes",
        "options",
        "source_process_identifier",
        "target_process_identifier",
    },
    // NtEnumerateKey
    {
        "key_handle",
        "index",
        "information_class",
        "buffer",
        "regkey",
    },
    // NtEnumerateValueKey
    {
        "key_handle",
        "index",
        "information_class",
        "regkey",
        "key_name",
        "reg_type",
        "value",
    },
    // NtFreeVirtualMemory
    {
        "process_handle",
        "base_address",
        "size",
        "free_type",
    },
    // NtGetContextThread
    {
        "thread_handle",
    },
    // NtLoadDriver
    {
        "driver_service_name",
    },
    // NtLoadKey
    {
        "filepath",
        "regkey",
    },
    // NtLoadKey2
    {
        "flags",
        "filepath",
        "regkey",
    },
    // NtLoadKeyEx
    {
        "flags",
        "trust_class_key",
        "filepath",
        "regkey",
    },
    // NtMakePermanentObject
    {
        "handle",
    },
    // NtMakeTemporaryObject
    {
        "handle",
    },
    // NtMapViewOfSection
    {
        "section_handle",
        "process_handle",
        "base_address",
        "commit_size",
        "section_offset",
        "view_size",
        "allocation_type",
        "win32_protect",
        "buffer",
    },
    // NtOpenDirectoryObject
    {
        "directory_handle",
        "desired_access",
        "dirpath",
    },
    // NtOpenFile
    {
        "file_handle",
        "desired_access",
        "open_options",
        "share_access",
        "filepath",
    },
    // NtOpenKey
    {
        "key_handle",
        "desired_access",
        "regkey",
    },
    // NtOpenKeyEx
    {
        "key_handle",
        "desired_access",
        "options",
        "regkey",
    },
    // NtOpenProcess
    {
        "process_handle",
        "desired_access",
        "process_identifier",
    },
    // NtOpenSection
    {
        "section_handle",
        "desired_access",
        "section_name",
    },
    // NtOpenThread
    {
        "thread_handle",
        "access",
        "thread_name",
        "process_identifier",
    },
    // NtProtectVirtualMemory
    {
        "process_handle",
        "base_address",
        "length",
        "protection",
    },
    // NtQueryAttributesFile
    {
        "filepath",
    },
    // NtQueryDirectoryFile
    {
        "file_handle",
        "information_class",
        "file_information",
        "dirpath",
    },
    // NtQueryFullAttributesFile
    {
        "filepath",
    },
    // NtQueryInformationFile
    {
        "file_handle",
        "information_class",
        "file_information",
    },
    // NtQueryKey
    {
        "key_handle",
        "information_class",
        "buffer",
        "regkey",
    },
    // NtQueryMultipleValueKey
    {
        "KeyHandle",
        "EntryCount",
        "buffer",
        "regkey",
    },
    // NtQuerySystemTime
    {
    },
    // NtQueryValueKey
    {
        "key_handle",
        "information_class",
        "regkey",
        "value",
        "reg_type",
    },
    // NtQueueApcThread
    {
        "thread_handle",
        "function_address",
        "parameter",
        "process_identifier",
    },
    // NtReadFile
    {
        "file_handle",
        "length",
        "offset",
        "buffer",
    },
    // NtReadVirtualMemory
    {
        "process_handle",
        "base_address",
        "buffer",
    },
    // NtRenameKey
    {
        "key_handle",
        "new_name",
        "regkey",
    },
    // NtReplaceKey
    {
        "key_handle",
        "newfilepath",
        "backupfilepath",
        "regkey",
    },
    // NtResumeThread
    {
        "thread_handle",
        "suspend_count",
    },
    // NtSaveKey
    {
        "key_handle",
        "file_handle",
        "regkey",
        "filepath",
    },
    // NtSaveKeyEx
    {
        "key_handle",
        "file_handle",
        "format",
        "regkey",
        "filepath",
    },
    // NtSetContextThread
    {
        "thread_handle",
    },
    // NtSetInformationFile
    {
        "file_handle",
        "original_name",
        "renamed_name",
        "information_class",
    },
    // NtSetValueKey
    {
        "key_handle",
        "index",
        "reg_type",
        "reg_type",
        "value",
        "regkey",
    },
    // NtSuspendThread
    {
        "thread_handle",
        "previous_suspend_count",
    },
    // NtTerminateProcess
    {
        "process_handle",
        "status_code",
    },
    // NtTerminateThread
    {
        "thread_handle",
        "status_code",
    },
    // NtUnloadDriver
    {
        "driver_service_name",
    },
    // NtUnmapViewOfSection
    {
        "process_handle",
        "base_address",
        "region_size",
    },
    // NtWriteFile
    {
        "file_handle",
        "buffer",
        "offset",
    },
    // NtWriteVirtualMemory
    {
        "process_handle",
        "base_address",
        "buffer",
    },
    // RtlAddVectoredContinueHandler
    {
        "FirstHandler",
    },
    // RtlAddVectoredExceptionHandler
    {
        "FirstHandler",
    },
    // RtlCompressBuffer
    {
        "uncompressed",
        "format",
        "input_size",
        "output_size",
        "compressed",
    },
    // RtlCreateUserProcess
    {
        "flags",
        "inherit_handles",
        "filepath",
    },
    // RtlCreateUserThread
    {
        "process_handle",
        "suspended",
        "function_address",
        "parameter",
        "thread_handle",
    },
    // RtlDecompressBuffer
    {
        "compressed",
        "format",
        "input_size",
        "output_size",
        "uncompressed",
    },
    // RtlDecompressFragment
    {
        "compressed",
        "format",
        "input_size",
        "offset",
        "output_size",
        "uncompressed",
    },
    // RtlDispatchException
    {
    },
    // RtlRemoveVectoredContinueHandler
    {
    },
    // RtlRemoveVectoredExceptionHandler
    {
    },
    // CoCreateInstance
    {
        "rclsid",
        "class_context",
        "riid",
    },
    // CoInitializeEx
    {
        "options",
    },
    // CoInitializeSecurity
    {
    },
    // OleInitialize
    {
    },
    // UuidCreate
    {
        "uuid",
    },
    // GetUserNameExA
    {
        "name_format",
        "name",
    },
    // GetUserNameExW
    {
        "name_format",
        "name",
    },
    // ReadCabinetState
    {
    },
    // SHGetFolderPathW
    {
        "owner_handle",
        "folder",
        "token_handle",
        "flags",
        "dirpath",
    },
    // SHGetSpecialFolderLocation
    {
        "window_handle",
        "folder_index",
    },
    // ShellExecuteExW
    {
        "filepath",
        "parameters",
        "show_type",
    },
    // NetShareEnum
    {
        "servername",
        "level",
    },
    // ObtainUserAgentString
    {
        "option",
        "user_agent",
    },
    // URLDownloadToFileW
    {
        "url",
        "filepath",
    },
    // DrawTextExA
    {
        "string",
    },
    // DrawTextExW
    {
        "string",
    },
    // EnumWindows
    {
    },
    // ExitWindowsEx
    {
        "flags",
        "reason",
    },
    // FindWindowA
    {
        "window_name",
        "class_name",
    },
    // FindWindowExA
    {
        "parent_hwnd",
        "child_after_hwnd",
        "window_name",
        "class_name",
    },
    // FindWindowExW
    {
        "parent_hwnd",
        "child_after_hwnd",
        "window_name",
        "class_name",
    },
    // FindWindowW
    {
        "window_name",
        "class_name",
    },
    // GetAsyncKeyState
    {
        "key_code",
    },
    // GetCursorPos
    {
        "x",
        "y",
    },
    // GetForegroundWindow
    {
    },
    // GetKeyState
    {
        "key_code",
    },
    // GetKeyboardState
    {
    },
    // GetSystemMetrics
    {
        "index",
    },
    // LoadStringA
    {
        "module_handle",
        "id",
        "string",
    },
    // LoadStringW
    {
        "module_handle",
        "id",
        "string",
    },
    // MessageBoxTimeoutA
    {
        "window_handle",
        "text",
        "caption",
        "flags",
        "language_identifier",
    },
    // MessageBoxTimeoutW
    {
        "window_handle",
        "text",
        "caption",
        "flags",
        "language_identifier",
    },
    // SendNotifyMessageA
    {
        "window_handle",
        "message",
        "process_identifier",
    },
    // SendNotifyMessageW
    {
        "window_handle",
        "message",
        "process_identifier",
    },
    // SetWindowsHookExA
    {
        "hook_identifier",
        "callback_function",
        "module_address",
        "thread_identifier",
    },
    // SetWindowsHookExW
    {
        "hook_identifier",
        "callback_function",
        "module_address",
        "thread_identifier",
    },
    // UnhookWindowsHookEx
    {
        "hook_handle",
    },
    // DeleteUrlCacheEntryA
    {
        "url",
    },
    // DeleteUrlCacheEntryW
    {
        "url",
    },
    // HttpOpenRequestA
    {
        "connect_handle",
        "http_method",
        "path",
        "http_version",
        "referer",
        "flags",
    },
    // HttpOpenRequestW
    {
        "connect_handle",
        "http_method",
        "path",
        "http_version",
        "referer",
        "flags",
    },
    // HttpQueryInfoA
    {
        "request_handle",
        "info_level",
        "index",
        "buffer",
    },
    // HttpSendRequestA
    {
        "request_handle",
        "headers",
        "post_data",
    },
    // HttpSendRequestW
    {
        "request_handle",
        "headers",
        "post_data",
    },
    // InternetCloseHandle
    {
        "internet_handle",
    },
    // InternetConnectA
    {
        "internet_handle",
        "hostname",
        "port",
        "username",
        "password",
        "service",
        "flags",
    },
    // InternetConnectW
    {
        "internet_handle",
        "hostname",
        "port",
        "username",
        "password",
        "service",
        "flags",
    },
    // InternetCrackUrlA
    {
        "flags",
        "url",
    },
    // InternetCrackUrlW
    {
        "flags",
        "url",
    },
    // InternetGetConnectedState
    {
        "flags",
    },
    // InternetGetConnectedStateExA
    {
        "flags",
        "connection_name",
    },
    // InternetGetConnectedStateExW
    {
        "flags",
        "connection_name",
    },
    // InternetOpenA
    {
        "user_agent",
        "access_type",
        "proxy_name",
        "proxy_bypass",
        "flags",
    },
    // InternetOpenUrlA
    {
        "internet_handle",
        "url",
        "flags",
        "headers",
    },
    // InternetOpenUrlW
    {
        "hInternet",
        "url",
        "flags",
        "headers",
    },
    // InternetOpenW
    {
        "user_agent",
        "access_type",
        "proxy_name",
        "proxy_bypass",
        "flags",
    },
    // InternetQueryOptionA
    {
        "internet_handle",
        "option",
    },
    // InternetReadFile
    {
        "request_handle",
        "buffer",
    },
    // InternetSetOptionA
    {
        "internet_handle",
        "option",
    },
    // InternetSetStatusCallback
    {
        "internet_handle",
        "callback",
    },
    // InternetWriteFile
    {
        "request_handle",
        "buffer",
    },
    // timeGetTime
    {
    },
    // ConnectEx
    {
        "socket",
        "ip_address",
        "port",
        "buffer",
    },
    // GetAddrInfoW
    {
        "hostname",
        "service_name",
    },
    // TransmitFile
    {
        "socket",
        "file_handle",
        "nNumberOfBytesToWrite",
        "nNumberOfBytesPerSend",
    },
    // WSAAccept
    {
        "socket",
        "ip_address",
        "port",
    },
    // WSAConnect
    {
        "s",
        "ip_address",
        "port",
    },
    // WSARecv
    {
        "socket",
        "buffer",
    },
    // WSARecvFrom
    {
        "socket",
        "ip_address",
        "port",
        "buffer",
    },
    // WSASend
    {
        "socket",
        "buffer",
    },
    // WSASendTo
    {
        "socket",
        "ip_address",
        "port",
        "buffer",
    },
    // WSASocketA
    {
        "af",
        "type",
        "protocol",
        "flags",
        "socket",
    },
    // WSASocketW
    {
        "af",
        "type",
        "protocol",
        "flags",
        "socket",
    },
    // WSAStartup
    {
        "wVersionRequested",
    },
    // accept
    {
        "socket",
        "ip_address",
        "port",
    },
    // bind
    {
        "socket",
        "ip_address",
        "port",
    },
    // closesocket
    {
        "socket",
    },
    // connect
    {
        "socket",
        "ip_address",
        "port",
    },
    // getaddrinfo
    {
        "hostname",
        "service_name",
    },
    // gethostbyname
    {
        "hostname",
    },
    // getsockname
    {
        "s",
        "ip_address",
        "port",
    },
    // ioctlsocket
    {
        "socket",
        "cmd",
        "argp",
    },
    // listen
    {
        "socket",
        "backlog",
    },
    // recv
    {
        "socket",
        "buffer",
    },
    // recvfrom
    {
        "socket",
        "flags",
        "ip_address",
        "port",
        "buffer",
    },
    // select
    {
        "socket",
    },
    // send
    {
        "socket",
        "sent",
        "buffer",
    },
    // sendto
    {
        "socket",
        "flags",
        "ip_address",
        "port",
        "sent",
        "buffer",
    },
    // setsockopt
    {
        "socket",
        "level",
        "optname",
        "buffer",
    },
    // shutdown
    {
        "socket",
        "how",
    },
    // socket
    {
        "af",
        "type",
        "protocol",
        "socket",
    },
    // NtSystemDebugControl
    {
        "command",
    },
    // NtDebugActiveProcess
    {
        "process_handle",
        "debug_handle",
    },
};


static const char *g_explain_paramtypes[] = {
    // __process__
    "iiiiusi",
    // __anomaly__
    "isss",
    // __exception__
    "zzz",
    // __missing__
    "s",
    // ControlService
    "pi",
    // CreateServiceA
    "pssiiiissu",
    // CreateServiceW
    "puuiiiiuuu",
    // CryptAcquireContextA
    "Pssii",
    // CryptAcquireContextW
    "Puuii",
    // CryptCreateHash
    "pxpiP",
    // CryptDecrypt
    "ppiib",
    // CryptEncrypt
    "ppiib",
    // CryptExportKey
    "ppiib",
    // CryptGenKey
    "pxiP",
    // CryptHashData
    "pib",
    // DeleteService
    "p",
    // EnumServicesStatusA
    "pii",
    // EnumServicesStatusW
    "pii",
    // GetUserNameA
    "S",
    // GetUserNameW
    "U",
    // LookupAccountSidW
    "uuu",
    // LookupPrivilegeValueW
    "uu",
    // OpenSCManagerA
    "ssi",
    // OpenSCManagerW
    "uui",
    // OpenServiceA
    "psi",
    // OpenServiceW
    "pui",
    // RegCloseKey
    "p",
    // RegCreateKeyExA
    "psixPIu",
    // RegCreateKeyExW
    "puixPIu",
    // RegDeleteKeyA
    "pu",
    // RegDeleteKeyW
    "pu",
    // RegDeleteValueA
    "pu",
    // RegDeleteValueW
    "pu",
    // RegEnumKeyExA
    "pissu",
    // RegEnumKeyExW
    "piuuu",
    // RegEnumKeyW
    "piuu",
    // RegEnumValueA
    "piIur",
    // RegEnumValueW
    "piIuR",
    // RegOpenKeyExA
    "pixPu",
    // RegOpenKeyExW
    "pixPu",
    // RegQueryInfoKeyA
    "psIIIIII",
    // RegQueryInfoKeyW
    "puIIIIII",
    // RegQueryValueExA
    "pIur",
    // RegQueryValueExW
    "pIuR",
    // RegSetValueExA
    "piur",
    // RegSetValueExW
    "piuR",
    // StartServiceA
    "pa",
    // StartServiceW
    "pA",
    // CertControlStore
    "pii",
    // CertCreateCertificateContext
    "ib",
    // CertOpenStore
    "iis",
    // CertOpenSystemStoreA
    "s",
    // CertOpenSystemStoreW
    "u",
    // CryptDecodeMessage
    "b",
    // CryptDecodeObjectEx
    "iisb",
    // CryptDecryptMessage
    "b",
    // CryptEncryptMessage
    "b",
    // CryptHashMessage
    "b",
    // CryptProtectData
    "bui",
    // CryptProtectMemory
    "bi",
    // CryptUnprotectData
    "iubb",
    // CryptUnprotectMemory
    "ib",
    // DnsQuery_A
    "sii",
    // DnsQuery_UTF8
    "iis",
    // DnsQuery_W
    "uii",
    // GetAdaptersAddresses
    "ii",
    // GetAdaptersInfo
    "",
    // GetBestInterfaceEx
    "",
    // GetInterfaceInfo
    "",
    // COleScript_Compile
    "uu",
    // CopyFileA
    "iuu",
    // CopyFileExW
    "iuu",
    // CopyFileW
    "iuu",
    // CreateDirectoryExW
    "u",
    // CreateDirectoryW
    "u",
    // CreateProcessInternalW
    "uiuuiiipp",
    // CreateRemoteThread
    "pippiI",
    // CreateThread
    "ippiI",
    // CreateToolhelp32Snapshot
    "ii",
    // DeleteFileW
    "s",
    // DeviceIoControl
    "bpib",
    // FindFirstFileExA
    "u",
    // FindFirstFileExW
    "u",
    // FindResourceA
    "pss",
    // FindResourceExA
    "piss",
    // FindResourceExW
    "piuu",
    // FindResourceW
    "puu",
    // GetComputerNameA
    "S",
    // GetComputerNameW
    "U",
    // GetDiskFreeSpaceExW
    "uQQQ",
    // GetDiskFreeSpaceW
    "uIIII",
    // GetFileAttributesExW
    "iu",
    // GetFileAttributesW
    "ui",
    // GetFileInformationByHandle
    "p",
    // GetFileInformationByHandleEx
    "pi",
    // GetFileSize
    "pi",
    // GetFileSizeEx
    "pQ",
    // GetFileType
    "p",
    // GetLocalTime
    "",
    // GetNativeSystemInfo
    "i",
    // GetShortPathNameW
    "uu",
    // GetSystemDirectoryA
    "S",
    // GetSystemDirectoryW
    "U",
    // GetSystemInfo
    "i",
    // GetSystemTime
    "",
    // GetSystemTimeAsFileTime
    "",
    // GetSystemWindowsDirectoryA
    "S",
    // GetSystemWindowsDirectoryW
    "U",
    // GetTempPathW
    "U",
    // GetTickCount
    "",
    // GetVolumeNameForVolumeMountPointW
    "uu",
    // GetVolumePathNameW
    "uu",
    // GetVolumePathNamesForVolumeNameW
    "uu",
    // IsDebuggerPresent
    "",
    // LoadResource
    "ppp",
    // Module32FirstW
    "p",
    // Module32NextW
    "p",
    // MoveFileWithProgressW
    "iuu",
    // OutputDebugStringA
    "s",
    // Process32FirstW
    "pui",
    // Process32NextW
    "pui",
    // ReadProcessMemory
    "ppB",
    // RemoveDirectoryA
    "u",
    // RemoveDirectoryW
    "u",
    // SearchPathW
    "uuuu",
    // SetEndOfFile
    "p",
    // SetErrorMode
    "i",
    // SetFileAttributesW
    "iu",
    // SetFileInformationByHandle
    "pi",
    // SetFilePointer
    "piq",
    // SetFilePointerEx
    "pQi",
    // SetUnhandledExceptionFilter
    "",
    // SizeofResource
    "ppi",
    // Thread32First
    "p",
    // Thread32Next
    "p",
    // WriteConsoleA
    "pS",
    // WriteConsoleW
    "pU",
    // WriteProcessMemory
    "pp!B",
    // CDocument_write
    "z",
    // CElement_put_innerHTML
    "u",
    // CHyperlink_SetUrlComponent
    "ui",
    // CIFrameElement_CreateElement
    "z",
    // CScriptElement_put_src
    "u",
    // CWindow_AddTimeoutCode
    "uiui",
    // system
    "s",
    // PRF
    "ssss",
    // Ssl3GenerateKeyMaterial
    "sss",
    // NetGetJoinInformation
    "uu",
    // NetShareEnum
    "ui",
    // NetUserGetInfo
    "uui",
    // NetUserGetLocalGroups
    "uuii",
    // LdrGetDllHandle
    "Pu",
    // LdrGetProcedureAddress
    "poiP",
    // LdrLoadDll
    "IPus",
    // LdrUnloadDll
    "p",
    // NtAllocateVirtualMemory
    "pPLii",
    // NtClose
    "ss",
    // NtCreateDirectoryObject
    "Pxu",
    // NtCreateFile
    "sssssss",
    // NtCreateKey
    "sssssss",
    // NtCreateMutant
    "ssss",
    // NtCreateProcess
    "ssss",
    // NtCreateProcessEx
    "ssss",
    // NtCreateSection
    "ssssss",
    // NtCreateThread
    "sssss",
    // NtCreateThreadEx
    "ssssssss",
    // NtCreateUserProcess
    "ssssssss",
    // NtDelayExecution
    "s",
    // NtDeleteFile
    "s",
    // NtDeleteKey
    "ss",
    // NtDeleteValueKey
    "ss",
    // NtDeviceIoControlFile
    "ssss",
    // NtDuplicateObject
    "pppPxiiii",
    // NtEnumerateKey
    "piibu",
    // NtEnumerateValueKey
    "piiuuiR",
    // NtFreeVirtualMemory
    "pPLi",
    // NtGetContextThread
    "p",
    // NtLoadDriver
    "s",
    // NtLoadKey
    "uu",
    // NtLoadKey2
    "iuu",
    // NtLoadKeyEx
    "ipuu",
    // NtMakePermanentObject
    "p",
    // NtMakeTemporaryObject
    "p",
    // NtMapViewOfSection
    "sssssssss",
    // NtOpenDirectoryObject
    "Pxu",
    // NtOpenFile
    "sssss",
    // NtOpenKey
    "sss",
    // NtOpenKeyEx
    "ssss",
    // NtOpenProcess
    "sss",
    // NtOpenSection
    "Pxu",
    // NtOpenThread
    "sss",
    // NtProtectVirtualMemory
    "pPLi",
    // NtQueryAttributesFile
    "s",
    // NtQueryDirectoryFile
    "pibu",
    // NtQueryFullAttributesFile
    "s",
    // NtQueryInformationFile
    "pib",
    // NtQueryKey
    "pibu",
    // NtQueryMultipleValueKey
    "pibu",
    // NtQuerySystemTime
    "",
    // NtQueryValueKey
    "sssss"
    //"piuuiR",
    // NtQueueApcThread
    "ssss",
    // NtReadFile
    "ssss",
    // NtReadVirtualMemory
    "sss",
    // NtRenameKey
    "puu",
    // NtReplaceKey
    "puuu",
    // NtResumeThread
    "ss",
    // NtSaveKey
    "ppuu",
    // NtSaveKeyEx
    "ppiuu",
    // NtSetContextThread
    "s",
    // NtSetInformationFile
    "ssss",
    // NtSetValueKey
    "ssssss",
    // NtSuspendThread
    "pI",
    // NtTerminateProcess
    "px",
    // NtTerminateThread
    "px",
    // NtUnloadDriver
    "u",
    // NtUnmapViewOfSection
    "ppl",
    // NtWriteFile
    "sss",
    // NtWriteVirtualMemory
    "sss",
    // RtlAddVectoredContinueHandler
    "i",
    // RtlAddVectoredExceptionHandler
    "i",
    // RtlCompressBuffer
    "!biiI!B",
    // RtlCreateUserProcess
    "iiu",
    // RtlCreateUserThread
    "pippP",
    // RtlDecompressBuffer
    "!biiI!B",
    // RtlDecompressFragment
    "!biiiI!B",
    // RtlDispatchException
    "",
    // RtlRemoveVectoredContinueHandler
    "",
    // RtlRemoveVectoredExceptionHandler
    "",
    // CoCreateInstance
    "cic",
    // CoInitializeEx
    "i",
    // CoInitializeSecurity
    "",
    // OleInitialize
    "",
    // UuidCreate
    "s",
    // GetUserNameExA
    "iS",
    // GetUserNameExW
    "iU",
    // ReadCabinetState
    "",
    // SHGetFolderPathW
    "pipiu",
    // SHGetSpecialFolderLocation
    "pi",
    // ShellExecuteExW
    "uul",
    // NetShareEnum
    "ui",
    // ObtainUserAgentString
    "iS",
    // URLDownloadToFileW
    "uu",
    // DrawTextExA
    "S",
    // DrawTextExW
    "U",
    // EnumWindows
    "",
    // ExitWindowsEx
    "ii",
    // FindWindowA
    "ss",
    // FindWindowExA
    "ppss",
    // FindWindowExW
    "ppuu",
    // FindWindowW
    "uu",
    // GetAsyncKeyState
    "i",
    // GetCursorPos
    "ll",
    // GetForegroundWindow
    "",
    // GetKeyState
    "i",
    // GetKeyboardState
    "",
    // GetSystemMetrics
    "i",
    // LoadStringA
    "pis",
    // LoadStringW
    "piu",
    // MessageBoxTimeoutA
    "pssii",
    // MessageBoxTimeoutW
    "puuii",
    // SendNotifyMessageA
    "pil",
    // SendNotifyMessageW
    "pil",
    // SetWindowsHookExA
    "ippi",
    // SetWindowsHookExW
    "ippi",
    // UnhookWindowsHookEx
    "p",
    // DeleteUrlCacheEntryA
    "s",
    // DeleteUrlCacheEntryW
    "u",
    // HttpOpenRequestA
    "pssssi",
    // HttpOpenRequestW
    "puuuui",
    // HttpQueryInfoA
    "piIb",
    // HttpSendRequestA
    "pSb",
    // HttpSendRequestW
    "pUb",
    // InternetCloseHandle
    "p",
    // InternetConnectA
    "psissii",
    // InternetConnectW
    "puiuuii",
    // InternetCrackUrlA
    "iS",
    // InternetCrackUrlW
    "iU",
    // InternetGetConnectedState
    "I",
    // InternetGetConnectedStateExA
    "Is",
    // InternetGetConnectedStateExW
    "Iu",
    // InternetOpenA
    "sissi",
    // InternetOpenUrlA
    "psib",
    // InternetOpenUrlW
    "puib",
    // InternetOpenW
    "uiuui",
    // InternetQueryOptionA
    "pi",
    // InternetReadFile
    "pb",
    // InternetSetOptionA
    "pi",
    // InternetSetStatusCallback
    "pp",
    // InternetWriteFile
    "pb",
    // timeGetTime
    "",
    // ConnectEx
    "isib",
    // GetAddrInfoW
    "uu",
    // TransmitFile
    "ipii",
    // WSAAccept
    "isi",
    // WSAConnect
    "isi",
    // WSARecv
    "ib",
    // WSARecvFrom
    "isib",
    // WSASend
    "ib",
    // WSASendTo
    "isib",
    // WSASocketA
    "iiiii",
    // WSASocketW
    "iiiii",
    // WSAStartup
    "i",
    // accept
    "isi",
    // bind
    "isi",
    // closesocket
    "i",
    // connect
    "isi",
    // getaddrinfo
    "ss",
    // gethostbyname
    "s",
    // getsockname
    "isi",
    // ioctlsocket
    "iiI",
    // listen
    "ii",
    // recv
    "ib",
    // recvfrom
    "iisib",
    // select
    "i",
    // send
    "iib",
    // sendto
    "iisiib",
    // setsockopt
    "iiib",
    // shutdown
    "ii",
    // socket
    "iiii",
    // NtSystemDebugControl
    "s",
    // NtDebugActiveProcess
    "ss",
};

const char *sig_flag_name(uint32_t sigidx, uint32_t flagidx)
{
    return g_api_flagnames[sigidx][flagidx];
}

uint32_t sig_flag_value(uint32_t sigidx, uint32_t flagidx)
{
    return g_api_flags[sigidx][flagidx];
}

const char *sig_apiname(uint32_t sigidx)
{
    return g_explain_apinames[sigidx];
}

const char *sig_category(uint32_t sigidx)
{
    return g_explain_categories[sigidx];
}

const char *sig_paramtypes(uint32_t sigidx)
{
    return g_explain_paramtypes[sigidx];
}

const char *sig_param_name(uint32_t sigidx, uint32_t argidx)
{
    return g_explain_paramnames[sigidx][argidx];
}

uint32_t sig_count()
{
    return MONITOR_HOOKCNT;
}

uint32_t sig_index_process()
{
    return SIG____process__;
}

uint32_t sig_index_anomaly()
{
    return SIG____anomaly__;
}

uint32_t sig_index_exception()
{
    return SIG____exception__;
}

uint32_t sig_index_missing()
{
    return SIG____missing__;
}

uint32_t sig_hook_count()
{
    return MONITOR_HOOKCNT;
}
