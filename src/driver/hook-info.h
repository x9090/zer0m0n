/*
Cuckoo Sandbox - Automated Malware Analysis.
Copyright (C) 2010-2015 Cuckoo Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef MONITOR_HOOK_INFO_H
#define MONITOR_HOOK_INFO_H

#define MONITOR_FIRSTHOOKIDX 5
#define MONITOR_HOOKCNT 432

typedef enum _signature_index_t {
    SIG____process__,
    SIG____anomaly__,
    SIG____exception__,
    SIG____missing__,
    SIG____exploit__,
    SIG___wmi___IWbemServices_ExecMethod,
    SIG___wmi___IWbemServices_ExecMethodAsync,
    SIG___wmi___IWbemServices_ExecQuery,
    SIG___wmi___IWbemServices_ExecQueryAsync,
    SIG_advapi32_ControlService,
    SIG_advapi32_CreateServiceA,
    SIG_advapi32_CreateServiceW,
    SIG_advapi32_CryptAcquireContextA,
    SIG_advapi32_CryptAcquireContextW,
    SIG_advapi32_CryptCreateHash,
    SIG_advapi32_CryptDecrypt,
    SIG_advapi32_CryptEncrypt,
    SIG_advapi32_CryptExportKey,
    SIG_advapi32_CryptGenKey,
    SIG_advapi32_CryptHashData,
    SIG_advapi32_DeleteService,
    SIG_advapi32_EnumServicesStatusA,
    SIG_advapi32_EnumServicesStatusW,
    SIG_advapi32_GetUserNameA,
    SIG_advapi32_GetUserNameW,
    SIG_advapi32_LookupAccountSidW,
    SIG_advapi32_LookupPrivilegeValueW,
    SIG_advapi32_NotifyBootConfigStatus,
    SIG_advapi32_OpenSCManagerA,
    SIG_advapi32_OpenSCManagerW,
    SIG_advapi32_OpenServiceA,
    SIG_advapi32_OpenServiceW,
    SIG_advapi32_RegCloseKey,
    SIG_advapi32_RegCreateKeyExA,
    SIG_advapi32_RegCreateKeyExW,
    SIG_advapi32_RegDeleteKeyA,
    SIG_advapi32_RegDeleteKeyW,
    SIG_advapi32_RegDeleteValueA,
    SIG_advapi32_RegDeleteValueW,
    SIG_advapi32_RegEnumKeyExA,
    SIG_advapi32_RegEnumKeyExW,
    SIG_advapi32_RegEnumKeyW,
    SIG_advapi32_RegEnumValueA,
    SIG_advapi32_RegEnumValueW,
    SIG_advapi32_RegOpenKeyExA,
    SIG_advapi32_RegOpenKeyExW,
    SIG_advapi32_RegQueryInfoKeyA,
    SIG_advapi32_RegQueryInfoKeyW,
    SIG_advapi32_RegQueryValueExA,
    SIG_advapi32_RegQueryValueExW,
    SIG_advapi32_RegSetValueExA,
    SIG_advapi32_RegSetValueExW,
    SIG_advapi32_StartServiceA,
    SIG_advapi32_StartServiceCtrlDispatcherW,
    SIG_advapi32_StartServiceW,
    SIG_comctl32_TaskDialog,
    SIG_crypt32_CertControlStore,
    SIG_crypt32_CertCreateCertificateContext,
    SIG_crypt32_CertOpenStore,
    SIG_crypt32_CertOpenSystemStoreA,
    SIG_crypt32_CertOpenSystemStoreW,
    SIG_crypt32_CryptDecodeMessage,
    SIG_crypt32_CryptDecodeObjectEx,
    SIG_crypt32_CryptDecryptMessage,
    SIG_crypt32_CryptEncryptMessage,
    SIG_crypt32_CryptHashMessage,
    SIG_crypt32_CryptProtectData,
    SIG_crypt32_CryptProtectMemory,
    SIG_crypt32_CryptUnprotectData,
    SIG_crypt32_CryptUnprotectMemory,
    SIG_dnsapi_DnsQuery_A,
    SIG_dnsapi_DnsQuery_UTF8,
    SIG_dnsapi_DnsQuery_W,
    SIG_iphlpapi_GetAdaptersAddresses,
    SIG_iphlpapi_GetAdaptersInfo,
    SIG_iphlpapi_GetBestInterfaceEx,
    SIG_iphlpapi_GetInterfaceInfo,
    SIG_jscript_ActiveXObjectFncObj_Construct,
    SIG_jscript_COleScript_Compile,
    SIG_kernel32_AssignProcessToJobObject,
    SIG_kernel32_CopyFileA,
    SIG_kernel32_CopyFileExW,
    SIG_kernel32_CopyFileW,
    SIG_kernel32_CreateActCtxW,
    SIG_kernel32_CreateDirectoryExW,
    SIG_kernel32_CreateDirectoryW,
    SIG_kernel32_CreateJobObjectW,
    SIG_kernel32_CreateProcessInternalW,
    SIG_kernel32_CreateRemoteThread,
    SIG_kernel32_CreateRemoteThreadEx,
    SIG_kernel32_CreateThread,
    SIG_kernel32_CreateToolhelp32Snapshot,
    SIG_kernel32_DeleteFileW,
    SIG_kernel32_DeviceIoControl,
    SIG_kernel32_FindFirstFileExA,
    SIG_kernel32_FindFirstFileExW,
    SIG_kernel32_FindResourceA,
    SIG_kernel32_FindResourceExA,
    SIG_kernel32_FindResourceExW,
    SIG_kernel32_FindResourceW,
    SIG_kernel32_GetComputerNameA,
    SIG_kernel32_GetComputerNameW,
    SIG_kernel32_GetDiskFreeSpaceExW,
    SIG_kernel32_GetDiskFreeSpaceW,
    SIG_kernel32_GetFileAttributesExW,
    SIG_kernel32_GetFileAttributesW,
    SIG_kernel32_GetFileInformationByHandle,
    SIG_kernel32_GetFileInformationByHandleEx,
    SIG_kernel32_GetFileSize,
    SIG_kernel32_GetFileSizeEx,
    SIG_kernel32_GetFileType,
    SIG_kernel32_GetLocalTime,
    SIG_kernel32_GetNativeSystemInfo,
    SIG_kernel32_GetShortPathNameW,
    SIG_kernel32_GetSystemDirectoryA,
    SIG_kernel32_GetSystemDirectoryW,
    SIG_kernel32_GetSystemInfo,
    SIG_kernel32_GetSystemTime,
    SIG_kernel32_GetSystemTimeAsFileTime,
    SIG_kernel32_GetSystemWindowsDirectoryA,
    SIG_kernel32_GetSystemWindowsDirectoryW,
    SIG_kernel32_GetTempPathW,
    SIG_kernel32_GetTickCount,
    SIG_kernel32_GetTimeZoneInformation,
    SIG_kernel32_GetVolumeNameForVolumeMountPointW,
    SIG_kernel32_GetVolumePathNameW,
    SIG_kernel32_GetVolumePathNamesForVolumeNameW,
    SIG_kernel32_GlobalMemoryStatus,
    SIG_kernel32_GlobalMemoryStatusEx,
    SIG_kernel32_IsDebuggerPresent,
    SIG_kernel32_LoadResource,
    SIG_kernel32_Module32FirstW,
    SIG_kernel32_Module32NextW,
    SIG_kernel32_MoveFileWithProgressW,
    SIG_kernel32_OutputDebugStringA,
    SIG_kernel32_Process32FirstW,
    SIG_kernel32_Process32NextW,
    SIG_kernel32_ReadProcessMemory,
    SIG_kernel32_RemoveDirectoryA,
    SIG_kernel32_RemoveDirectoryW,
    SIG_kernel32_SearchPathW,
    SIG_kernel32_SetEndOfFile,
    SIG_kernel32_SetErrorMode,
    SIG_kernel32_SetFileAttributesW,
    SIG_kernel32_SetFileInformationByHandle,
    SIG_kernel32_SetFilePointer,
    SIG_kernel32_SetFilePointerEx,
    SIG_kernel32_SetFileTime,
    SIG_kernel32_SetInformationJobObject,
    SIG_kernel32_SetUnhandledExceptionFilter,
    SIG_kernel32_SizeofResource,
    SIG_kernel32_Thread32First,
    SIG_kernel32_Thread32Next,
    SIG_kernel32_WriteConsoleA,
    SIG_kernel32_WriteConsoleW,
    SIG_kernel32_WriteProcessMemory,
    SIG_mpr_WNetGetProviderNameW,
    SIG_mshtml_CDocument_write,
    SIG_mshtml_CElement_put_innerHTML,
    SIG_mshtml_CHyperlink_SetUrlComponent,
    SIG_mshtml_CIFrameElement_CreateElement,
    SIG_mshtml_CImgElement_put_src,
    SIG_mshtml_CScriptElement_put_src,
    SIG_mshtml_CWindow_AddTimeoutCode,
    SIG_msvcrt_system,
    SIG_ncrypt_PRF,
    SIG_ncrypt_Ssl3GenerateKeyMaterial,
    SIG_netapi32_NetGetJoinInformation,
    SIG_netapi32_NetShareEnum,
    SIG_netapi32_NetUserGetInfo,
    SIG_netapi32_NetUserGetLocalGroups,
    SIG_ntdll_LdrGetDllHandle,
    SIG_ntdll_LdrGetProcedureAddress,
    SIG_ntdll_LdrLoadDll,
    SIG_ntdll_LdrUnloadDll,
    SIG_ntdll_NtAllocateVirtualMemory,
    SIG_ntdll_NtClose,
    SIG_ntdll_NtCreateDirectoryObject,
    SIG_ntdll_NtCreateFile,
    SIG_ntdll_NtCreateKey,
    SIG_ntdll_NtCreateMutant,
    SIG_ntdll_NtCreateProcess,
    SIG_ntdll_NtCreateProcessEx,
    SIG_ntdll_NtCreateSection,
    SIG_ntdll_NtCreateThread,
    SIG_ntdll_NtCreateThreadEx,
    SIG_ntdll_NtCreateUserProcess,
    SIG_ntdll_NtDelayExecution,
    SIG_ntdll_NtDeleteFile,
    SIG_ntdll_NtDeleteKey,
    SIG_ntdll_NtDeleteValueKey,
    SIG_ntdll_NtDeviceIoControlFile,
    SIG_ntdll_NtDuplicateObject,
    SIG_ntdll_NtEnumerateKey,
    SIG_ntdll_NtEnumerateValueKey,
    SIG_ntdll_NtFreeVirtualMemory,
    SIG_ntdll_NtGetContextThread,
    SIG_ntdll_NtLoadDriver,
    SIG_ntdll_NtLoadKey,
    SIG_ntdll_NtLoadKey2,
    SIG_ntdll_NtLoadKeyEx,
    SIG_ntdll_NtMakePermanentObject,
    SIG_ntdll_NtMakeTemporaryObject,
    SIG_ntdll_NtMapViewOfSection,
    SIG_ntdll_NtOpenDirectoryObject,
    SIG_ntdll_NtOpenFile,
    SIG_ntdll_NtOpenKey,
    SIG_ntdll_NtOpenKeyEx,
    SIG_ntdll_NtOpenMutant,
    SIG_ntdll_NtOpenProcess,
    SIG_ntdll_NtOpenSection,
    SIG_ntdll_NtOpenThread,
    SIG_ntdll_NtProtectVirtualMemory,
    SIG_ntdll_NtQueryAttributesFile,
    SIG_ntdll_NtQueryDirectoryFile,
    SIG_ntdll_NtQueryFullAttributesFile,
    SIG_ntdll_NtQueryInformationFile,
    SIG_ntdll_NtQueryKey,
    SIG_ntdll_NtQueryMultipleValueKey,
    SIG_ntdll_NtQuerySystemInformation,
    SIG_ntdll_NtQuerySystemTime,
    SIG_ntdll_NtQueryValueKey,
    SIG_ntdll_NtQueueApcThread,
    SIG_ntdll_NtReadFile,
    SIG_ntdll_NtReadVirtualMemory,
    SIG_ntdll_NtRenameKey,
    SIG_ntdll_NtReplaceKey,
    SIG_ntdll_NtResumeThread,
    SIG_ntdll_NtSaveKey,
    SIG_ntdll_NtSaveKeyEx,
    SIG_ntdll_NtSetContextThread,
    SIG_ntdll_NtSetInformationFile,
    SIG_ntdll_NtSetValueKey,
    SIG_ntdll_NtShutdownSystem,
    SIG_ntdll_NtSuspendThread,
    SIG_ntdll_NtTerminateProcess,
    SIG_ntdll_NtTerminateThread,
    SIG_ntdll_NtUnloadDriver,
    SIG_ntdll_NtUnmapViewOfSection,
    SIG_ntdll_NtWriteFile,
    SIG_ntdll_NtWriteVirtualMemory,
    SIG_ntdll_RtlAddVectoredContinueHandler,
    SIG_ntdll_RtlAddVectoredExceptionHandler,
    SIG_ntdll_RtlCompressBuffer,
    SIG_ntdll_RtlCreateUserProcess,
    SIG_ntdll_RtlCreateUserThread,
    SIG_ntdll_RtlDecompressBuffer,
    SIG_ntdll_RtlDecompressFragment,
    SIG_ntdll_RtlDispatchException,
    SIG_ntdll_RtlRemoveVectoredContinueHandler,
    SIG_ntdll_RtlRemoveVectoredExceptionHandler,
    SIG_ntoskrnl_NtAllocateVirtualMemory,
    SIG_ntoskrnl_NtClose,
    SIG_ntoskrnl_NtCreateDirectoryObject,
    SIG_ntoskrnl_NtCreateFile,
    SIG_ntoskrnl_NtCreateKey,
    SIG_ntoskrnl_NtCreateMutant,
    SIG_ntoskrnl_NtCreateProcess,
    SIG_ntoskrnl_NtCreateProcessEx,
    SIG_ntoskrnl_NtCreateSection,
    SIG_ntoskrnl_NtCreateThread,
    SIG_ntoskrnl_NtCreateThreadEx,
    SIG_ntoskrnl_NtCreateUserProcess,
    SIG_ntoskrnl_NtDeleteFile,
    SIG_ntoskrnl_NtDeleteKey,
    SIG_ntoskrnl_NtDeleteValueKey,
    SIG_ntoskrnl_NtDeviceIoControlFile,
    SIG_ntoskrnl_NtDuplicateObject,
    SIG_ntoskrnl_NtEnumerateKey,
    SIG_ntoskrnl_NtEnumerateValueKey,
    SIG_ntoskrnl_NtFreeVirtualMemory,
    SIG_ntoskrnl_NtGetContextThread,
    SIG_ntoskrnl_NtLoadDriver,
    SIG_ntoskrnl_NtLoadKey,
    SIG_ntoskrnl_NtLoadKey2,
    SIG_ntoskrnl_NtLoadKeyEx,
    SIG_ntoskrnl_NtMakePermanentObject,
    SIG_ntoskrnl_NtMakeTemporaryObject,
    SIG_ntoskrnl_NtMapViewOfSection,
    SIG_ntoskrnl_NtOpenDirectoryObject,
    SIG_ntoskrnl_NtOpenFile,
    SIG_ntoskrnl_NtOpenKey,
    SIG_ntoskrnl_NtOpenKeyEx,
    SIG_ntoskrnl_NtOpenMutant,
    SIG_ntoskrnl_NtOpenProcess,
    SIG_ntoskrnl_NtOpenSection,
    SIG_ntoskrnl_NtOpenThread,
    SIG_ntoskrnl_NtProtectVirtualMemory,
    SIG_ntoskrnl_NtQueryAttributesFile,
    SIG_ntoskrnl_NtQueryDirectoryFile,
    SIG_ntoskrnl_NtQueryFullAttributesFile,
    SIG_ntoskrnl_NtQueryInformationFile,
    SIG_ntoskrnl_NtQueryKey,
    SIG_ntoskrnl_NtQueryMultipleValueKey,
    SIG_ntoskrnl_NtQuerySystemInformation,
    SIG_ntoskrnl_NtQueryValueKey,
    SIG_ntoskrnl_NtQueueApcThread,
    SIG_ntoskrnl_NtReadFile,
    SIG_ntoskrnl_NtReadVirtualMemory,
    SIG_ntoskrnl_NtRenameKey,
    SIG_ntoskrnl_NtReplaceKey,
    SIG_ntoskrnl_NtResumeThread,
    SIG_ntoskrnl_NtSaveKey,
    SIG_ntoskrnl_NtSaveKeyEx,
    SIG_ntoskrnl_NtSetContextThread,
    SIG_ntoskrnl_NtSetInformationFile,
    SIG_ntoskrnl_NtSetValueKey,
    SIG_ntoskrnl_NtShutdownSystem,
    SIG_ntoskrnl_NtSuspendThread,
    SIG_ntoskrnl_NtTerminateProcess,
    SIG_ntoskrnl_NtTerminateThread,
    SIG_ntoskrnl_NtUnloadDriver,
    SIG_ntoskrnl_NtUnmapViewOfSection,
    SIG_ntoskrnl_NtWriteFile,
    SIG_ntoskrnl_NtWriteVirtualMemory,
    SIG_ntoskrnl_RtlCreateUserProcess,
    SIG_ntoskrnl_RtlCreateUserThread,
    SIG_ole32_CoCreateInstance,
    SIG_ole32_CoCreateInstanceEx,
    SIG_ole32_CoGetClassObject,
    SIG_ole32_CoInitializeEx,
    SIG_ole32_CoInitializeSecurity,
    SIG_ole32_CoUninitialize,
    SIG_ole32_OleConvertOLESTREAMToIStorage,
    SIG_ole32_OleInitialize,
    SIG_rpcrt4_UuidCreate,
    SIG_secur32_DecryptMessage,
    SIG_secur32_EncryptMessage,
    SIG_secur32_GetUserNameExA,
    SIG_secur32_GetUserNameExW,
    SIG_shell32_ReadCabinetState,
    SIG_shell32_SHGetFolderPathW,
    SIG_shell32_SHGetSpecialFolderLocation,
    SIG_shell32_ShellExecuteExW,
    SIG_srvcli_NetShareEnum,
    SIG_urlmon_ObtainUserAgentString,
    SIG_urlmon_URLDownloadToFileW,
    SIG_user32_DrawTextExA,
    SIG_user32_DrawTextExW,
    SIG_user32_EnumWindows,
    SIG_user32_ExitWindowsEx,
    SIG_user32_FindWindowA,
    SIG_user32_FindWindowExA,
    SIG_user32_FindWindowExW,
    SIG_user32_FindWindowW,
    SIG_user32_GetAsyncKeyState,
    SIG_user32_GetCursorPos,
    SIG_user32_GetForegroundWindow,
    SIG_user32_GetKeyState,
    SIG_user32_GetKeyboardState,
    SIG_user32_GetSystemMetrics,
    SIG_user32_LoadStringA,
    SIG_user32_LoadStringW,
    SIG_user32_MessageBoxTimeoutA,
    SIG_user32_MessageBoxTimeoutW,
    SIG_user32_RegisterHotKey,
    SIG_user32_SendNotifyMessageA,
    SIG_user32_SendNotifyMessageW,
    SIG_user32_SetWindowsHookExA,
    SIG_user32_SetWindowsHookExW,
    SIG_user32_UnhookWindowsHookEx,
    SIG_vbe6_vbe6_CallByName,
    SIG_vbe6_vbe6_Close,
    SIG_vbe6_vbe6_CreateObject,
    SIG_vbe6_vbe6_GetIDFromName,
    SIG_vbe6_vbe6_GetObject,
    SIG_vbe6_vbe6_Import,
    SIG_vbe6_vbe6_Invoke,
    SIG_vbe6_vbe6_Open,
    SIG_vbe6_vbe6_Print,
    SIG_vbe6_vbe6_Shell,
    SIG_vbe6_vbe6_StringConcat,
    SIG_version_GetFileVersionInfoExW,
    SIG_version_GetFileVersionInfoSizeExW,
    SIG_version_GetFileVersionInfoSizeW,
    SIG_version_GetFileVersionInfoW,
    SIG_wininet_DeleteUrlCacheEntryA,
    SIG_wininet_DeleteUrlCacheEntryW,
    SIG_wininet_HttpOpenRequestA,
    SIG_wininet_HttpOpenRequestW,
    SIG_wininet_HttpQueryInfoA,
    SIG_wininet_HttpSendRequestA,
    SIG_wininet_HttpSendRequestW,
    SIG_wininet_InternetCloseHandle,
    SIG_wininet_InternetConnectA,
    SIG_wininet_InternetConnectW,
    SIG_wininet_InternetCrackUrlA,
    SIG_wininet_InternetCrackUrlW,
    SIG_wininet_InternetGetConnectedState,
    SIG_wininet_InternetGetConnectedStateExA,
    SIG_wininet_InternetGetConnectedStateExW,
    SIG_wininet_InternetOpenA,
    SIG_wininet_InternetOpenUrlA,
    SIG_wininet_InternetOpenUrlW,
    SIG_wininet_InternetOpenW,
    SIG_wininet_InternetQueryOptionA,
    SIG_wininet_InternetReadFile,
    SIG_wininet_InternetSetOptionA,
    SIG_wininet_InternetSetStatusCallback,
    SIG_wininet_InternetWriteFile,
    SIG_winmm_timeGetTime,
    SIG_ws2_32_ConnectEx,
    SIG_ws2_32_GetAddrInfoW,
    SIG_ws2_32_TransmitFile,
    SIG_ws2_32_WSAAccept,
    SIG_ws2_32_WSAConnect,
    SIG_ws2_32_WSARecv,
    SIG_ws2_32_WSARecvFrom,
    SIG_ws2_32_WSASend,
    SIG_ws2_32_WSASendTo,
    SIG_ws2_32_WSASocketA,
    SIG_ws2_32_WSASocketW,
    SIG_ws2_32_WSAStartup,
    SIG_ws2_32_accept,
    SIG_ws2_32_bind,
    SIG_ws2_32_closesocket,
    SIG_ws2_32_connect,
    SIG_ws2_32_getaddrinfo,
    SIG_ws2_32_gethostbyname,
    SIG_ws2_32_getsockname,
    SIG_ws2_32_ioctlsocket,
    SIG_ws2_32_listen,
    SIG_ws2_32_recv,
    SIG_ws2_32_recvfrom,
    SIG_ws2_32_select,
    SIG_ws2_32_send,
    SIG_ws2_32_sendto,
    SIG_ws2_32_setsockopt,
    SIG_ws2_32_shutdown,
    SIG_ws2_32_socket,
    SIG_escript_api_pdf_unescape,
    SIG_escript_api_pdf_eval,
} signature_index_t;

#endif