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

#include <stdio.h>
#include <stdint.h>
#include "hooks.h"
#include "diffing.h"
#include "flags.h"
#include "hooking.h"
#include "hook-info.h"
#include "ignore.h"
#include "memory.h"
#include "monitor.h"
#include "native.h"
#include "ntapi.h"
#include "log.h"
#include "misc.h"
#include "misc2.h"
#include "pipe.h"
#include "sleep.h"
#include "unhook.h"






static HRESULT (WINAPI *Old___wmi___IWbemServices_ExecMethod)(
    IWbemServices *This,
    const wchar_t *strObjectPath,
    const wchar_t *strMethodName,
    long lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemClassObject **ppOutParams,
    IWbemCallResult **ppCallResult
);




static HRESULT (WINAPI *Old___wmi___IWbemServices_ExecMethodAsync)(
    IWbemServices *This,
    const BSTR strObjectPath,
    const BSTR strMethodName,
    long lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemObjectSink *pResponseHandler
);




static HRESULT (WINAPI *Old___wmi___IWbemServices_ExecQuery)(
    IWbemServices *This,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    ULONG lFlags,
    IWbemContext *pCtx,
    IEnumWbemClassObject **ppEnum
);




static HRESULT (WINAPI *Old___wmi___IWbemServices_ExecQueryAsync)(
    IWbemServices *This,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    long lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler
);




static BOOL (WINAPI *Old_advapi32_ControlService)(
    SC_HANDLE hService,
    DWORD dwControl,
    LPSERVICE_STATUS lpServiceStatus
);




static SC_HANDLE (WINAPI *Old_advapi32_CreateServiceA)(
    SC_HANDLE hSCManager,
    LPCTSTR lpServiceName,
    LPCTSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCTSTR lpBinaryPathName,
    LPCTSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCTSTR lpDependencies,
    LPCTSTR lpServiceStartName,
    LPCTSTR lpPassword
);




static SC_HANDLE (WINAPI *Old_advapi32_CreateServiceW)(
    SC_HANDLE hSCManager,
    LPWSTR lpServiceName,
    LPWSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPWSTR lpBinaryPathName,
    LPWSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPWSTR lpDependencies,
    LPWSTR lpServiceStartName,
    LPWSTR lpPassword
);




static BOOL (WINAPI *Old_advapi32_CryptAcquireContextA)(
    HCRYPTPROV *phProv,
    LPCSTR szContainer,
    LPCSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags
);




static BOOL (WINAPI *Old_advapi32_CryptAcquireContextW)(
    HCRYPTPROV *phProv,
    LPCWSTR szContainer,
    LPCWSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags
);




static BOOL (WINAPI *Old_advapi32_CryptCreateHash)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTKEY hKey,
    DWORD dwFlags,
    HCRYPTHASH *phHash
);




static BOOL (WINAPI *Old_advapi32_CryptDecrypt)(
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL Final,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen
);




static BOOL (WINAPI *Old_advapi32_CryptEncrypt)(
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL Final,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwBufLen
);




static BOOL (WINAPI *Old_advapi32_CryptExportKey)(
    HCRYPTKEY hKey,
    HCRYPTKEY hExpKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen
);




static BOOL (WINAPI *Old_advapi32_CryptGenKey)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    DWORD dwFlags,
    HCRYPTKEY *phKey
);




static BOOL (WINAPI *Old_advapi32_CryptHashData)(
    HCRYPTHASH hHash,
    BYTE *pbData,
    DWORD dwDataLen,
    DWORD dwFlags
);




static BOOL (WINAPI *Old_advapi32_DeleteService)(
    SC_HANDLE hService
);




static BOOL (WINAPI *Old_advapi32_EnumServicesStatusA)(
    SC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPENUM_SERVICE_STATUS lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle
);




static BOOL (WINAPI *Old_advapi32_EnumServicesStatusW)(
    SC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPENUM_SERVICE_STATUS lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle
);




static BOOL (WINAPI *Old_advapi32_GetUserNameA)(
    LPCSTR lpBuffer,
    LPDWORD lpnSize
);




static BOOL (WINAPI *Old_advapi32_GetUserNameW)(
    LPWSTR lpBuffer,
    LPDWORD lpnSize
);




static BOOL (WINAPI *Old_advapi32_LookupAccountSidW)(
    LPCWSTR lpSystemName,
    PSID lpSid,
    LPWSTR lpName,
    LPDWORD cchName,
    LPWSTR lpReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
);




static BOOL (WINAPI *Old_advapi32_LookupPrivilegeValueW)(
    LPWSTR lpSystemName,
    LPWSTR lpName,
    PLUID lpLuid
);




static BOOL (WINAPI *Old_advapi32_NotifyBootConfigStatus)(
    BOOL BootAcceptable
);




static SC_HANDLE (WINAPI *Old_advapi32_OpenSCManagerA)(
    LPCTSTR lpMachineName,
    LPCTSTR lpDatabaseName,
    DWORD dwDesiredAccess
);




static SC_HANDLE (WINAPI *Old_advapi32_OpenSCManagerW)(
    LPWSTR lpMachineName,
    LPWSTR lpDatabaseName,
    DWORD dwDesiredAccess
);




static SC_HANDLE (WINAPI *Old_advapi32_OpenServiceA)(
    SC_HANDLE hSCManager,
    LPCTSTR lpServiceName,
    DWORD dwDesiredAccess
);




static SC_HANDLE (WINAPI *Old_advapi32_OpenServiceW)(
    SC_HANDLE hSCManager,
    LPWSTR lpServiceName,
    DWORD dwDesiredAccess
);




static LONG (WINAPI *Old_advapi32_RegCloseKey)(
    HKEY hKey
);




static LONG (WINAPI *Old_advapi32_RegCreateKeyExA)(
    HKEY hKey,
    LPCTSTR lpSubKey,
    DWORD Reserved,
    LPTSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
);




static LONG (WINAPI *Old_advapi32_RegCreateKeyExW)(
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
);




static LONG (WINAPI *Old_advapi32_RegDeleteKeyA)(
    HKEY hKey,
    LPCTSTR lpSubKey
);




static LONG (WINAPI *Old_advapi32_RegDeleteKeyW)(
    HKEY hKey,
    LPWSTR lpSubKey
);




static LONG (WINAPI *Old_advapi32_RegDeleteValueA)(
    HKEY hKey,
    LPCTSTR lpValueName
);




static LONG (WINAPI *Old_advapi32_RegDeleteValueW)(
    HKEY hKey,
    LPWSTR lpValueName
);




static LONG (WINAPI *Old_advapi32_RegEnumKeyExA)(
    HKEY hKey,
    DWORD dwIndex,
    LPTSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPTSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
);




static LONG (WINAPI *Old_advapi32_RegEnumKeyExW)(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPWSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
);




static LONG (WINAPI *Old_advapi32_RegEnumKeyW)(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpName,
    DWORD cchName
);




static LONG (WINAPI *Old_advapi32_RegEnumValueA)(
    HKEY hKey,
    DWORD dwIndex,
    LPTSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);




static LONG (WINAPI *Old_advapi32_RegEnumValueW)(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);




static LONG (WINAPI *Old_advapi32_RegOpenKeyExA)(
    HKEY hKey,
    LPCTSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);




static LONG (WINAPI *Old_advapi32_RegOpenKeyExW)(
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);




static LONG (WINAPI *Old_advapi32_RegQueryInfoKeyA)(
    HKEY hKey,
    LPTSTR lpClass,
    LPDWORD lpcClass,
    LPDWORD lpReserved,
    LPDWORD lpcSubKeys,
    LPDWORD lpcMaxSubKeyLen,
    LPDWORD lpcMaxClassLen,
    LPDWORD lpcValues,
    LPDWORD lpcMaxValueNameLen,
    LPDWORD lpcMaxValueLen,
    LPDWORD lpcbSecurityDescriptor,
    PFILETIME lpftLastWriteTime
);




static LONG (WINAPI *Old_advapi32_RegQueryInfoKeyW)(
    HKEY hKey,
    LPWSTR lpClass,
    LPDWORD lpcClass,
    LPDWORD lpReserved,
    LPDWORD lpcSubKeys,
    LPDWORD lpcMaxSubKeyLen,
    LPDWORD lpcMaxClassLen,
    LPDWORD lpcValues,
    LPDWORD lpcMaxValueNameLen,
    LPDWORD lpcMaxValueLen,
    LPDWORD lpcbSecurityDescriptor,
    PFILETIME lpftLastWriteTime
);




static LONG (WINAPI *Old_advapi32_RegQueryValueExA)(
    HKEY hKey,
    LPCTSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);




static LONG (WINAPI *Old_advapi32_RegQueryValueExW)(
    HKEY hKey,
    LPWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);




static LONG (WINAPI *Old_advapi32_RegSetValueExA)(
    HKEY hKey,
    LPCTSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
);




static LONG (WINAPI *Old_advapi32_RegSetValueExW)(
    HKEY hKey,
    LPWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
);




static BOOL (WINAPI *Old_advapi32_StartServiceA)(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCTSTR *lpServiceArgVectors
);




static BOOL (WINAPI *Old_advapi32_StartServiceCtrlDispatcherW)(
    const SERVICE_TABLE_ENTRYW *lpServiceTable
);




static BOOL (WINAPI *Old_advapi32_StartServiceW)(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPWSTR *lpServiceArgVectors
);




static HRESULT (WINAPI *Old_comctl32_TaskDialog)(
    HWND hWndParent,
    HINSTANCE hInstance,
    PCWSTR pszWindowTitle,
    PCWSTR pszMainInstruction,
    PCWSTR pszContent,
    TASKDIALOG_COMMON_BUTTON_FLAGS dwCommonButtons,
    PCWSTR pszIcon,
    int *pnButton
);




static BOOL (WINAPI *Old_crypt32_CertControlStore)(
    HCERTSTORE hCertStore,
    DWORD dwFlags,
    DWORD dwCtrlType,
    const void *pvCtrlPara
);




static PCCERT_CONTEXT (WINAPI *Old_crypt32_CertCreateCertificateContext)(
    DWORD dwCertEncodingType,
    const BYTE *pbCertEncoded,
    DWORD cbCertEncoded
);




static HCERTSTORE (WINAPI *Old_crypt32_CertOpenStore)(
    LPCSTR lpszStoreProvider,
    DWORD dwMsgAndCertEncodingType,
    HCRYPTPROV hCryptProv,
    DWORD dwFlags,
    const void *pvPara
);




static HCERTSTORE (WINAPI *Old_crypt32_CertOpenSystemStoreA)(
    HCRYPTPROV hProv,
    LPCTSTR szSubsystemProtocol
);




static HCERTSTORE (WINAPI *Old_crypt32_CertOpenSystemStoreW)(
    HCRYPTPROV hProv,
    LPCWSTR szSubsystemProtocol
);




static BOOL (WINAPI *Old_crypt32_CryptDecodeMessage)(
    DWORD dwMsgTypeFlags,
    PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
    DWORD dwSignerIndex,
    const BYTE *pbEncodedBlob,
    DWORD cbEncodedBlob,
    DWORD dwPrevInnerContentType,
    DWORD *pdwMsgType,
    DWORD *pdwInnerContentType,
    BYTE *pbDecoded,
    DWORD *pcbDecoded,
    PCCERT_CONTEXT *ppXchgCert,
    PCCERT_CONTEXT *ppSignerCert
);




static BOOL (WINAPI *Old_crypt32_CryptDecodeObjectEx)(
    DWORD dwCertEncodingType,
    LPCSTR lpszStructType,
    const BYTE *pbEncoded,
    DWORD cbEncoded,
    DWORD dwFlags,
    PCRYPT_DECODE_PARA pDecodePara,
    void *pvStructInfo,
    DWORD *pcbStructInfo
);




static BOOL (WINAPI *Old_crypt32_CryptDecryptMessage)(
    PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    const BYTE *pbEncryptedBlob,
    DWORD cbEncryptedBlob,
    BYTE *pbDecrypted,
    DWORD *pcbDecrypted,
    PCCERT_CONTEXT *ppXchgCert
);




static BOOL (WINAPI *Old_crypt32_CryptEncryptMessage)(
    PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
    DWORD cRecipientCert,
    PCCERT_CONTEXT *rgpRecipientCert,
    const BYTE *pbToBeEncrypted,
    DWORD cbToBeEncrypted,
    BYTE *pbEncryptedBlob,
    DWORD *pcbEncryptedBlob
);




static BOOL (WINAPI *Old_crypt32_CryptHashMessage)(
    PCRYPT_HASH_MESSAGE_PARA pHashPara,
    BOOL fDetachedHash,
    DWORD cToBeHashed,
    const BYTE **rgpbToBeHashed,
    DWORD *rgcbToBeHashed,
    BYTE *pbHashedBlob,
    DWORD *pcbHashedBlob,
    BYTE *pbComputedHash,
    DWORD *pcbComputedHash
);




static BOOL (WINAPI *Old_crypt32_CryptProtectData)(
    DATA_BLOB *pDataIn,
    LPCWSTR szDataDescr,
    DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags,
    DATA_BLOB *pDataOut
);




static BOOL (WINAPI *Old_crypt32_CryptProtectMemory)(
    LPVOID pData,
    DWORD cbData,
    DWORD dwFlags
);




static BOOL (WINAPI *Old_crypt32_CryptUnprotectData)(
    DATA_BLOB *pDataIn,
    LPWSTR *ppszDataDescr,
    DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags,
    DATA_BLOB *pDataOut
);




static BOOL (WINAPI *Old_crypt32_CryptUnprotectMemory)(
    LPVOID pData,
    DWORD cbData,
    DWORD dwFlags
);




static DNS_STATUS (WINAPI *Old_dnsapi_DnsQuery_A)(
    PCSTR lpstrName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD *ppQueryResultsSet,
    PVOID *pReserved
);




static DNS_STATUS (WINAPI *Old_dnsapi_DnsQuery_UTF8)(
    LPBYTE lpstrName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD *ppQueryResultsSet,
    PVOID *pReserved
);




static DNS_STATUS (WINAPI *Old_dnsapi_DnsQuery_W)(
    PWSTR lpstrName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD *ppQueryResultsSet,
    PVOID *pReserved
);




static ULONG (WINAPI *Old_iphlpapi_GetAdaptersAddresses)(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses,
    PULONG SizePointer
);




static DWORD (WINAPI *Old_iphlpapi_GetAdaptersInfo)(
    PIP_ADAPTER_INFO pAdapterInfo,
    PULONG pOutBufLen
);




static DWORD (WINAPI *Old_iphlpapi_GetBestInterfaceEx)(
    struct sockaddr *pDestAddr,
    PDWORD pdwBestIfIndex
);




static DWORD (WINAPI *Old_iphlpapi_GetInterfaceInfo)(
    PIP_INTERFACE_INFO pIfTable,
    PULONG dwOutBufLen
);




static HRESULT (WINAPI *Old_jscript_ActiveXObjectFncObj_Construct)(
    void *this,
    VAR *unk1,
    int unk2,
    VAR *args
);




static int (WINAPI *Old_jscript_COleScript_Compile)(
    void *this,
    void *script_body,
    const wchar_t *script,
    uintptr_t unk1,
    uintptr_t unk2,
    uintptr_t unk3,
    const wchar_t *type,
    void *exception
);




static BOOL (WINAPI *Old_kernel32_AssignProcessToJobObject)(
    HANDLE hJob,
    HANDLE hProcess
);




static BOOL (WINAPI *Old_kernel32_CopyFileA)(
    LPCTSTR lpExistingFileName,
    LPCTSTR lpNewFileName,
    BOOL bFailIfExists
);




static BOOL (WINAPI *Old_kernel32_CopyFileExW)(
    LPWSTR lpExistingFileName,
    LPWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    LPBOOL pbCancel,
    DWORD dwCopyFlags
);




static BOOL (WINAPI *Old_kernel32_CopyFileW)(
    LPWSTR lpExistingFileName,
    LPWSTR lpNewFileName,
    BOOL bFailIfExists
);




static HANDLE (WINAPI *Old_kernel32_CreateActCtxW)(
    PACTCTX pActCtx
);




static BOOL (WINAPI *Old_kernel32_CreateDirectoryExW)(
    LPWSTR lpTemplateDirectory,
    LPWSTR lpNewDirectory,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
);




static BOOL (WINAPI *Old_kernel32_CreateDirectoryW)(
    LPWSTR lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
);




static HANDLE (WINAPI *Old_kernel32_CreateJobObjectW)(
    LPSECURITY_ATTRIBUTES lpJobAttributes,
    LPCTSTR lpName
);




static BOOL (WINAPI *Old_kernel32_CreateProcessInternalW)(
    LPVOID lpUnknown1,
    LPWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPWSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    LPVOID lpUnknown2
);




static HANDLE (WINAPI *Old_kernel32_CreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);




static HANDLE (WINAPI *Old_kernel32_CreateRemoteThreadEx)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId
);




static HANDLE (WINAPI *Old_kernel32_CreateThread)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);




static HANDLE (WINAPI *Old_kernel32_CreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID
);




static BOOL (WINAPI *Old_kernel32_DeleteFileW)(
    LPWSTR lpFileName
);




static BOOL (WINAPI *Old_kernel32_DeviceIoControl)(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
);




static HANDLE (WINAPI *Old_kernel32_FindFirstFileExA)(
    LPCTSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
);




static HANDLE (WINAPI *Old_kernel32_FindFirstFileExW)(
    LPWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
);




static HRSRC (WINAPI *Old_kernel32_FindResourceA)(
    HMODULE hModule,
    LPCSTR lpName,
    LPCSTR lpType
);




static HRSRC (WINAPI *Old_kernel32_FindResourceExA)(
    HMODULE hModule,
    LPCSTR lpName,
    LPCSTR lpType,
    WORD wLanguage
);




static HRSRC (WINAPI *Old_kernel32_FindResourceExW)(
    HMODULE hModule,
    LPWSTR lpName,
    LPWSTR lpType,
    WORD wLanguage
);




static HRSRC (WINAPI *Old_kernel32_FindResourceW)(
    HMODULE hModule,
    LPWSTR lpName,
    LPWSTR lpType
);




static BOOL (WINAPI *Old_kernel32_GetComputerNameA)(
    LPCSTR lpBuffer,
    LPDWORD lpnSize
);




static BOOL (WINAPI *Old_kernel32_GetComputerNameW)(
    LPWSTR lpBuffer,
    LPDWORD lpnSize
);




static BOOL (WINAPI *Old_kernel32_GetDiskFreeSpaceExW)(
    LPWSTR lpDirectoryName,
    PULARGE_INTEGER lpFreeBytesAvailable,
    PULARGE_INTEGER lpTotalNumberOfBytes,
    PULARGE_INTEGER lpTotalNumberOfFreeBytes
);




static BOOL (WINAPI *Old_kernel32_GetDiskFreeSpaceW)(
    LPWSTR lpRootPathName,
    LPDWORD lpSectorsPerCluster,
    LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters,
    LPDWORD lpTotalNumberOfClusters
);




static BOOL (WINAPI *Old_kernel32_GetFileAttributesExW)(
    LPCWSTR lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation
);




static DWORD (WINAPI *Old_kernel32_GetFileAttributesW)(
    LPCWSTR lpFileName
);




static BOOL (WINAPI *Old_kernel32_GetFileInformationByHandle)(
    HANDLE hFile,
    LPBY_HANDLE_FILE_INFORMATION lpFIleInformation
);




static BOOL (WINAPI *Old_kernel32_GetFileInformationByHandleEx)(
    HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFIleInformation,
    DWORD dwBufferSize
);




static DWORD (WINAPI *Old_kernel32_GetFileSize)(
    HANDLE hFile,
    LPDWORD lpFileSizeHigh
);




static BOOL (WINAPI *Old_kernel32_GetFileSizeEx)(
    HANDLE hFile,
    PLARGE_INTEGER lpFileSize
);




static DWORD (WINAPI *Old_kernel32_GetFileType)(
    HANDLE hFile
);




static void (WINAPI *Old_kernel32_GetLocalTime)(
    LPSYSTEMTIME lpSystemTime
);




static void (WINAPI *Old_kernel32_GetNativeSystemInfo)(
    LPSYSTEM_INFO lpSystemInfo
);




static DWORD (WINAPI *Old_kernel32_GetShortPathNameW)(
    LPCWSTR lpszLongPath,
    LPWSTR lpszShortPath,
    DWORD cchBuffer
);




static UINT (WINAPI *Old_kernel32_GetSystemDirectoryA)(
    LPTSTR lpBuffer,
    UINT uSize
);




static UINT (WINAPI *Old_kernel32_GetSystemDirectoryW)(
    LPWSTR lpBuffer,
    UINT uSize
);




static void (WINAPI *Old_kernel32_GetSystemInfo)(
    LPSYSTEM_INFO lpSystemInfo
);




static void (WINAPI *Old_kernel32_GetSystemTime)(
    LPSYSTEMTIME lpSystemTime
);




static void (WINAPI *Old_kernel32_GetSystemTimeAsFileTime)(
    LPFILETIME lpSystemTimeAsFileTime
);




static UINT (WINAPI *Old_kernel32_GetSystemWindowsDirectoryA)(
    LPTSTR lpBuffer,
    UINT uSize
);




static UINT (WINAPI *Old_kernel32_GetSystemWindowsDirectoryW)(
    LPWSTR lpBuffer,
    UINT uSize
);




static DWORD (WINAPI *Old_kernel32_GetTempPathW)(
    DWORD nBufferLength,
    LPWSTR lpBuffer
);




static DWORD (WINAPI *Old_kernel32_GetTickCount)(
);




static DWORD (WINAPI *Old_kernel32_GetTimeZoneInformation)(
    LPTIME_ZONE_INFORMATION lpTimeZoneInformation
);




static BOOL (WINAPI *Old_kernel32_GetVolumeNameForVolumeMountPointW)(
    LPCWSTR lpszVolumeMountPoint,
    LPWSTR lpszVolumeName,
    DWORD cchBufferLength
);




static BOOL (WINAPI *Old_kernel32_GetVolumePathNameW)(
    LPCWSTR lpszFileName,
    LPWSTR lpszVolumePathName,
    DWORD cchBufferLength
);




static BOOL (WINAPI *Old_kernel32_GetVolumePathNamesForVolumeNameW)(
    LPCWSTR lpszVolumeName,
    LPWSTR lpszVolumePathNames,
    DWORD cchBufferLength,
    PDWORD lpcchReturnLength
);




static BOOL (WINAPI *Old_kernel32_GlobalMemoryStatus)(
    LPMEMORYSTATUS lpBuffer
);




static BOOL (WINAPI *Old_kernel32_GlobalMemoryStatusEx)(
    LPMEMORYSTATUSEX lpBuffer
);




static BOOL (WINAPI *Old_kernel32_IsDebuggerPresent)(
);




static HGLOBAL (WINAPI *Old_kernel32_LoadResource)(
    HMODULE hModule,
    HRSRC hResInfo
);




static BOOL (WINAPI *Old_kernel32_Module32FirstW)(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
);




static BOOL (WINAPI *Old_kernel32_Module32NextW)(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
);




static BOOL (WINAPI *Old_kernel32_MoveFileWithProgressW)(
    LPWSTR lpExistingFileName,
    LPWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    DWORD dwFlags
);




static void (WINAPI *Old_kernel32_OutputDebugStringA)(
    LPSTR lpOutputString
);




static BOOL (WINAPI *Old_kernel32_Process32FirstW)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
);




static BOOL (WINAPI *Old_kernel32_Process32NextW)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
);




static BOOL (WINAPI *Old_kernel32_ReadProcessMemory)(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesRead
);




static BOOL (WINAPI *Old_kernel32_RemoveDirectoryA)(
    LPCTSTR lpPathName
);




static BOOL (WINAPI *Old_kernel32_RemoveDirectoryW)(
    LPWSTR lpPathName
);




static DWORD (WINAPI *Old_kernel32_SearchPathW)(
    LPCWSTR lpPath,
    LPCWSTR lpFileName,
    LPCWSTR lpExtension,
    DWORD nBufferLength,
    LPWSTR lpBuffer,
    LPWSTR *lpFilePart
);




static BOOL (WINAPI *Old_kernel32_SetEndOfFile)(
    HANDLE hFile
);




static UINT (WINAPI *Old_kernel32_SetErrorMode)(
    UINT uMode
);




static BOOL (WINAPI *Old_kernel32_SetFileAttributesW)(
    LPCWSTR lpFileName,
    DWORD dwFileAttributes
);




static BOOL (WINAPI *Old_kernel32_SetFileInformationByHandle)(
    HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFileInformation,
    DWORD dwBufferSize
);




static DWORD (WINAPI *Old_kernel32_SetFilePointer)(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod
);




static BOOL (WINAPI *Old_kernel32_SetFilePointerEx)(
    HANDLE hFile,
    LARGE_INTEGER liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer,
    DWORD dwMoveMethod
);




static BOOL (WINAPI *Old_kernel32_SetFileTime)(
    HANDLE hFile,
    FILETIME *lpCreationTime,
    FILETIME *lpLastAccessTime,
    FILETIME *lpLastWriteTime
);




static BOOL (WINAPI *Old_kernel32_SetInformationJobObject)(
    HANDLE hJob,
    JOBOBJECTINFOCLASS JobObjectInfoClass,
    LPVOID lpJobObjectInfo,
    DWORD cbJobObjectInfoLength
);




static LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *Old_kernel32_SetUnhandledExceptionFilter)(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
);




static DWORD (WINAPI *Old_kernel32_SizeofResource)(
    HMODULE hModule,
    HRSRC hResInfo
);




static BOOL (WINAPI *Old_kernel32_Thread32First)(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
);




static BOOL (WINAPI *Old_kernel32_Thread32Next)(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
);




static BOOL (WINAPI *Old_kernel32_WriteConsoleA)(
    HANDLE hConsoleOutput,
    const VOID *lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReseverd
);




static BOOL (WINAPI *Old_kernel32_WriteConsoleW)(
    HANDLE hConsoleOutput,
    const VOID *lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReseverd
);




static BOOL (WINAPI *Old_kernel32_WriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
);




static DWORD (WINAPI *Old_mpr_WNetGetProviderNameW)(
    DWORD dwNetType,
    LPTSTR lpProviderName,
    LPDWORD lpBufferSize
);




static int (WINAPI *Old_mshtml_CDocument_write)(
    void *cdocument,
    SAFEARRAY *arr
);




static HRESULT (WINAPI *Old_mshtml_CElement_put_innerHTML)(
    void *celement,
    const wchar_t *html
);




static int (WINAPI *Old_mshtml_CHyperlink_SetUrlComponent)(
    void *chyperlink,
    const wchar_t *component,
    int index
);




static HRESULT (WINAPI *Old_mshtml_CIFrameElement_CreateElement)(
    void *chtmtag,
    void *cdoc,
    void **celement
);




static HRESULT (WINAPI *Old_mshtml_CImgElement_put_src)(
    void *celement,
    const wchar_t *src
);




static HRESULT (WINAPI *Old_mshtml_CScriptElement_put_src)(
    void *cscriptelement,
    const wchar_t *url
);




static HRESULT (WINAPI *Old_mshtml_CWindow_AddTimeoutCode)(
    void *cwindow,
    VARIANT *data,
    const wchar_t *argument,
    int milliseconds,
    int repeat,
    void *unk2
);




static int (WINAPI *Old_msvcrt_system)(
    const char *command
);




static NTSTATUS (WINAPI *Old_ncrypt_PRF)(
    void *unk1,
    uintptr_t unk2,
    uint8_t *buf1,
    uintptr_t buf1_length,
    const char *type,
    uint32_t type_length,
    uint8_t *buf2,
    uint32_t buf2_length,
    uint8_t *buf3,
    uint32_t buf3_length
);




static NTSTATUS (WINAPI *Old_ncrypt_Ssl3GenerateKeyMaterial)(
    uintptr_t unk1,
    uint8_t *secret,
    uintptr_t secret_length,
    uint8_t *seed,
    uintptr_t seed_length,
    void *unk2,
    uintptr_t unk3
);




static NET_API_STATUS (WINAPI *Old_netapi32_NetGetJoinInformation)(
    LPCWSTR lpServer,
    LPWSTR *lpNameBuffer,
    PNETSETUP_JOIN_STATUS BufferType
);




static NET_API_STATUS (WINAPI *Old_netapi32_NetShareEnum)(
    LPWSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
);




static int (WINAPI *Old_netapi32_NetUserGetInfo)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE *bufptr
);




static NET_API_STATUS (WINAPI *Old_netapi32_NetUserGetLocalGroups)(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    DWORD flags,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries
);




static NTSTATUS (WINAPI *Old_ntdll_LdrGetDllHandle)(
    PWORD pwPath,
    PVOID Unused,
    PUNICODE_STRING ModuleFileName,
    PHANDLE pHModule
);




static NTSTATUS (WINAPI *Old_ntdll_LdrGetProcedureAddress)(
    HMODULE ModuleHandle,
    PANSI_STRING FunctionName,
    WORD Ordinal,
    PVOID *FunctionAddress
);




static NTSTATUS (WINAPI *Old_ntdll_LdrLoadDll)(
    PWCHAR PathToFile,
    PULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
);




static NTSTATUS (WINAPI *Old_ntdll_LdrUnloadDll)(
    HANDLE ModuleHandle
);




static NTSTATUS (WINAPI *Old_ntdll_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);




static NTSTATUS (WINAPI *Old_ntdll_NtClose)(
    HANDLE Handle
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateMutant)(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN InitialOwner
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateThreadEx)(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    PVOID lpParameter,
    BOOL CreateSuspended,
    LONG StackZeroBits,
    LONG SizeOfStackCommit,
    LONG SizeOfStackReserve,
    PVOID lpBytesBuffer
);




static NTSTATUS (WINAPI *Old_ntdll_NtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
);




static NTSTATUS (WINAPI *Old_ntdll_NtDelayExecution)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);




static NTSTATUS (WINAPI *Old_ntdll_NtDeleteFile)(
    POBJECT_ATTRIBUTES ObjectAttributes
);




static NTSTATUS (WINAPI *Old_ntdll_NtDeleteKey)(
    HANDLE KeyHandle
);




static NTSTATUS (WINAPI *Old_ntdll_NtDeleteValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
);




static NTSTATUS (WINAPI *Old_ntdll_NtDeviceIoControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    HANDLE *TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);




static NTSTATUS (WINAPI *Old_ntdll_NtEnumerateKey)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtEnumerateValueKey)(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);




static NTSTATUS (WINAPI *Old_ntdll_NtGetContextThread)(
    HANDLE ThreadHandle,
    LPCONTEXT Context
);




static NTSTATUS (WINAPI *Old_ntdll_NtLoadDriver)(
    PUNICODE_STRING DriverServiceName
);




static NTSTATUS (WINAPI *Old_ntdll_NtLoadKey)(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile
);




static NTSTATUS (WINAPI *Old_ntdll_NtLoadKey2)(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags
);




static NTSTATUS (WINAPI *Old_ntdll_NtLoadKeyEx)(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey
);




static NTSTATUS (WINAPI *Old_ntdll_NtMakePermanentObject)(
    HANDLE ObjectHandle
);




static NTSTATUS (WINAPI *Old_ntdll_NtMakeTemporaryObject)(
    HANDLE ObjectHandle
);




static NTSTATUS (WINAPI *Old_ntdll_NtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    UINT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenKeyEx)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenMutant)(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);




static NTSTATUS (WINAPI *Old_ntdll_NtOpenThread)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);




static NTSTATUS (WINAPI *Old_ntdll_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryAttributesFile)(
    POBJECT_ATTRIBUTES ObjectAttributes,
    void *FileInformation
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryFullAttributesFile)(
    POBJECT_ATTRIBUTES ObjectAttributes,
    void *FileInformation
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryKey)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryMultipleValueKey)(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtQuerySystemTime)(
    PLARGE_INTEGER SystemTime
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
);




static NTSTATUS (WINAPI *Old_ntdll_NtQueueApcThread)(
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved
);




static NTSTATUS (WINAPI *Old_ntdll_NtReadFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);




static NTSTATUS (WINAPI *Old_ntdll_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    LPCVOID BaseAddress,
    LPVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded
);




static NTSTATUS (WINAPI *Old_ntdll_NtRenameKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING NewName
);




static NTSTATUS (WINAPI *Old_ntdll_NtReplaceKey)(
    POBJECT_ATTRIBUTES NewHiveFileName,
    HANDLE KeyHandle,
    POBJECT_ATTRIBUTES BackupHiveFileName
);




static NTSTATUS (WINAPI *Old_ntdll_NtResumeThread)(
    HANDLE ThreadHandle,
    ULONG *SuspendCount
);




static NTSTATUS (WINAPI *Old_ntdll_NtSaveKey)(
    HANDLE KeyHandle,
    HANDLE FileHandle
);




static NTSTATUS (WINAPI *Old_ntdll_NtSaveKeyEx)(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format
);




static NTSTATUS (WINAPI *Old_ntdll_NtSetContextThread)(
    HANDLE ThreadHandle,
    const CONTEXT *Context
);




static NTSTATUS (WINAPI *Old_ntdll_NtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
);




static NTSTATUS (WINAPI *Old_ntdll_NtSetValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);




static NTSTATUS (WINAPI *Old_ntdll_NtShutdownSystem)(
    SHUTDOWN_ACTION Action
);




static NTSTATUS (WINAPI *Old_ntdll_NtSuspendThread)(
    HANDLE ThreadHandle,
    ULONG *PreviousSuspendCount
);




static NTSTATUS (WINAPI *Old_ntdll_NtTerminateProcess)(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
);




static NTSTATUS (WINAPI *Old_ntdll_NtTerminateThread)(
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus
);




static NTSTATUS (WINAPI *Old_ntdll_NtUnloadDriver)(
    PUNICODE_STRING DriverServiceName
);




static NTSTATUS (WINAPI *Old_ntdll_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);




static NTSTATUS (WINAPI *Old_ntdll_NtWriteFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);




static NTSTATUS (WINAPI *Old_ntdll_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    LPVOID BaseAddress,
    LPCVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);




static PVOID (WINAPI *Old_ntdll_RtlAddVectoredContinueHandler)(
    ULONG FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
);




static PVOID (WINAPI *Old_ntdll_RtlAddVectoredExceptionHandler)(
    ULONG FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
);




static NTSTATUS (WINAPI *Old_ntdll_RtlCompressBuffer)(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID WorkSpace
);




static NTSTATUS (WINAPI *Old_ntdll_RtlCreateUserProcess)(
    PUNICODE_STRING ImagePath,
    ULONG ObjectAttributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);




static NTSTATUS (WINAPI *Old_ntdll_RtlCreateUserThread)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    PCLIENT_ID ClientId
);




static NTSTATUS (WINAPI *Old_ntdll_RtlDecompressBuffer)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize
);




static NTSTATUS (WINAPI *Old_ntdll_RtlDecompressFragment)(
    USHORT CompressionFormat,
    PUCHAR UncompressedFragment,
    ULONG UncompressedFragmentSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG FragmentOffset,
    PULONG FinalUncompressedSize,
    PVOID WorkSpace
);




static void * (WINAPI *Old_ntdll_RtlDispatchException)(
    EXCEPTION_RECORD *ExceptionRecord,
    CONTEXT *Context
);




static ULONG (WINAPI *Old_ntdll_RtlRemoveVectoredContinueHandler)(
    PVOID VectoredHandlerHandle
);




static ULONG (WINAPI *Old_ntdll_RtlRemoveVectoredExceptionHandler)(
    PVOID VectoredHandlerHandle
);




static HRESULT (WINAPI *Old_ole32_CoCreateInstance)(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID *ppv
);




static HRESULT (WINAPI *Old_ole32_CoCreateInstanceEx)(
    REFCLSID rclsid,
    IUnknown *punkOuter,
    DWORD dwClsCtx,
    COSERVERINFO *pServerInfo,
    DWORD dwCount,
    MULTI_QI *pResults
);




static HRESULT (WINAPI *Old_ole32_CoGetClassObject)(
    REFCLSID rclsid,
    DWORD dwClsContext,
    COSERVERINFO *pServerInfo,
    REFIID riid,
    LPVOID *ppv
);




static HRESULT (WINAPI *Old_ole32_CoInitializeEx)(
    LPVOID pvReserved,
    DWORD dwCoInit
);




static HRESULT (WINAPI *Old_ole32_CoInitializeSecurity)(
    PSECURITY_DESCRIPTOR pSecDesc,
    LONG cAuthSvc,
    SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
    void *pReserved1,
    DWORD dwAuthnLevel,
    DWORD dwImpLevel,
    void *pAuthList,
    DWORD dwCapabilities,
    void *pReserved3
);




static HRESULT (WINAPI *Old_ole32_CoUninitialize)(
);




static HRESULT (WINAPI *Old_ole32_OleConvertOLESTREAMToIStorage)(
    LPOLESTREAM lpolestream,
    IStorage *pstg,
    const DVTARGETDEVICE *ptd
);




static HRESULT (WINAPI *Old_ole32_OleInitialize)(
    LPVOID pvReserved
);




static RPC_STATUS (WINAPI *Old_rpcrt4_UuidCreate)(
    UUID *Uuid
);




static SECURITY_STATUS (WINAPI *Old_secur32_DecryptMessage)(
    PCtxtHandle phContext,
    PSecBufferDesc pMessage,
    ULONG MessageSeqNo,
    PULONG pfQOP
);




static SECURITY_STATUS (WINAPI *Old_secur32_EncryptMessage)(
    PCtxtHandle phContext,
    ULONG fQOP,
    PSecBufferDesc pMessage,
    ULONG MessageSeqNo
);




static BOOL (WINAPI *Old_secur32_GetUserNameExA)(
    EXTENDED_NAME_FORMAT NameFormat,
    LPCSTR lpNameBuffer,
    PULONG lpnSize
);




static BOOL (WINAPI *Old_secur32_GetUserNameExW)(
    EXTENDED_NAME_FORMAT NameFormat,
    LPWSTR lpNameBuffer,
    PULONG lpnSize
);




static BOOL (WINAPI *Old_shell32_ReadCabinetState)(
    CABINETSTATE *pcs,
    int cLength
);




static HRESULT (WINAPI *Old_shell32_SHGetFolderPathW)(
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPWSTR pszPath
);




static HRESULT (WINAPI *Old_shell32_SHGetSpecialFolderLocation)(
    HWND hwndOwner,
    int nFolder,
    void *ppidl
);




static BOOL (WINAPI *Old_shell32_ShellExecuteExW)(
    SHELLEXECUTEINFOW *pExecInfo
);




static NET_API_STATUS (WINAPI *Old_srvcli_NetShareEnum)(
    LPWSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
);




static HRESULT (WINAPI *Old_urlmon_ObtainUserAgentString)(
    DWORD dwOption,
    LPSTR pcszUAOut,
    DWORD *cbSize
);




static HRESULT (WINAPI *Old_urlmon_URLDownloadToFileW)(
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
);




static int (WINAPI *Old_user32_DrawTextExA)(
    HDC hdc,
    LPSTR lpchText,
    int cchText,
    LPRECT lprc,
    UINT dwDTFormat,
    LPDRAWTEXTPARAMS lpDTParams
);




static int (WINAPI *Old_user32_DrawTextExW)(
    HDC hdc,
    LPWSTR lpchText,
    int cchText,
    LPRECT lprc,
    UINT dwDTFormat,
    LPDRAWTEXTPARAMS lpDTParams
);




static BOOL (WINAPI *Old_user32_EnumWindows)(
    WNDENUMPROC lpEnumProc,
    LPARAM lParam
);




static BOOL (WINAPI *Old_user32_ExitWindowsEx)(
    UINT uFlags,
    DWORD dwReason
);




static HWND (WINAPI *Old_user32_FindWindowA)(
    LPCSTR lpClassName,
    LPCTSTR lpWindowName
);




static HWND (WINAPI *Old_user32_FindWindowExA)(
    HWND hwndParent,
    HWND hwndChildAfter,
    LPCTSTR lpszClass,
    LPCTSTR lpszWindow
);




static HWND (WINAPI *Old_user32_FindWindowExW)(
    HWND hwndParent,
    HWND hwndChildAfter,
    LPWSTR lpszClass,
    LPWSTR lpszWindow
);




static HWND (WINAPI *Old_user32_FindWindowW)(
    LPWSTR lpClassName,
    LPWSTR lpWindowName
);




static SHORT (WINAPI *Old_user32_GetAsyncKeyState)(
    int vKey
);




static BOOL (WINAPI *Old_user32_GetCursorPos)(
    LPPOINT lpPoint
);




static HWND (WINAPI *Old_user32_GetForegroundWindow)(
);




static SHORT (WINAPI *Old_user32_GetKeyState)(
    int nVirtKey
);




static BOOL (WINAPI *Old_user32_GetKeyboardState)(
    PBYTE lpKeyState
);




static int (WINAPI *Old_user32_GetSystemMetrics)(
    int nIndex
);




static int (WINAPI *Old_user32_LoadStringA)(
    HINSTANCE hInstance,
    UINT uID,
    LPSTR lpBuffer,
    int nBufferMax
);




static int (WINAPI *Old_user32_LoadStringW)(
    HINSTANCE hInstance,
    UINT uID,
    LPWSTR lpBuffer,
    int nBufferMax
);




static int (WINAPI *Old_user32_MessageBoxTimeoutA)(
    HWND hWnd,
    LPCTSTR lpText,
    LPCTSTR lpCaption,
    UINT uType,
    WORD wLanguageId,
    INT Unknown
);




static int (WINAPI *Old_user32_MessageBoxTimeoutW)(
    HWND hWnd,
    LPWSTR lpText,
    LPWSTR lpCaption,
    UINT uType,
    WORD wLanguageId,
    INT Unknown
);




static BOOL (WINAPI *Old_user32_RegisterHotKey)(
    HWND hWnd,
    int id,
    UINT fsModifiers,
    UINT vk
);




static BOOL (WINAPI *Old_user32_SendNotifyMessageA)(
    HWND hWnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
);




static BOOL (WINAPI *Old_user32_SendNotifyMessageW)(
    HWND hWnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
);




static HHOOK (WINAPI *Old_user32_SetWindowsHookExA)(
    int idHook,
    HOOKPROC lpfn,
    HINSTANCE hMod,
    DWORD dwThreadId
);




static HHOOK (WINAPI *Old_user32_SetWindowsHookExW)(
    int idHook,
    HOOKPROC lpfn,
    HINSTANCE hMod,
    DWORD dwThreadId
);




static BOOL (WINAPI *Old_user32_UnhookWindowsHookEx)(
    HHOOK hhk
);




static void * (WINAPI *Old_vbe6_vbe6_CallByName)(
    void *result,
    void *this,
    const wchar_t *funcname,
    void *unk1,
    SAFEARRAY **args,
    void *unk3
);




static void * (__thiscall *Old_vbe6_vbe6_Close)(
    void *this,
    int fd
);




static void * (WINAPI *Old_vbe6_vbe6_CreateObject)(
    void **this,
    const BSTR object_name,
    void *unk1
);




static void * (WINAPI *Old_vbe6_vbe6_GetIDFromName)(
    const wchar_t *funcname,
    void *this
);




static void * (WINAPI *Old_vbe6_vbe6_GetObject)(
    void **this,
    const VARIANT *object_name,
    void *unk1
);




static void * (WINAPI *Old_vbe6_vbe6_Import)(
    void **args,
    void *unk1,
    void *unk2,
    void *unk3,
    void *unk4
);




static void * (WINAPI *Old_vbe6_vbe6_Invoke)(
    void *this,
    int funcidx,
    void *unk1,
    void *unk2,
    void *unk3,
    uint8_t *args,
    VARIANT *result,
    void *unk8,
    void *unk9
);




static void * (WINAPI *Old_vbe6_vbe6_Open)(
    int mode,
    void *unk1,
    int fd,
    const wchar_t *filename
);




static void * (WINAPI *Old_vbe6_vbe6_Print)(
    void *unk1,
    void *unk2,
    const VARIANT *buf,
    void *unk4
);




static void * (WINAPI *Old_vbe6_vbe6_Shell)(
    const VARIANT *command_line,
    int show_type
);




static void * (__thiscall *Old_vbe6_vbe6_StringConcat)(
    void *this,
    VARIANT *dst,
    VARIANT *src2,
    VARIANT *src1
);




static BOOL (WINAPI *Old_version_GetFileVersionInfoExW)(
    DWORD dwFlags,
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
);




static DWORD (WINAPI *Old_version_GetFileVersionInfoSizeExW)(
    DWORD dwFlags,
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle
);




static DWORD (WINAPI *Old_version_GetFileVersionInfoSizeW)(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle
);




static BOOL (WINAPI *Old_version_GetFileVersionInfoW)(
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
);




static BOOL (WINAPI *Old_wininet_DeleteUrlCacheEntryA)(
    LPCSTR lpszUrlName
);




static BOOL (WINAPI *Old_wininet_DeleteUrlCacheEntryW)(
    LPWSTR lpszUrlName
);




static HINTERNET (WINAPI *Old_wininet_HttpOpenRequestA)(
    HINTERNET hConnect,
    LPCTSTR lpszVerb,
    LPCTSTR lpszObjectName,
    LPCTSTR lpszVersion,
    LPCTSTR lpszReferer,
    LPCTSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
);




static HINTERNET (WINAPI *Old_wininet_HttpOpenRequestW)(
    HINTERNET hConnect,
    LPWSTR lpszVerb,
    LPWSTR lpszObjectName,
    LPWSTR lpszVersion,
    LPWSTR lpszReferer,
    LPWSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
);




static BOOL (WINAPI *Old_wininet_HttpQueryInfoA)(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPVOID lpvBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
);




static BOOL (WINAPI *Old_wininet_HttpSendRequestA)(
    HINTERNET hRequest,
    LPCTSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
);




static BOOL (WINAPI *Old_wininet_HttpSendRequestW)(
    HINTERNET hRequest,
    LPWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
);




static BOOL (WINAPI *Old_wininet_InternetCloseHandle)(
    HINTERNET hInternet
);




static HINTERNET (WINAPI *Old_wininet_InternetConnectA)(
    HINTERNET hInternet,
    LPCTSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCTSTR lpszUsername,
    LPCTSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
);




static HINTERNET (WINAPI *Old_wininet_InternetConnectW)(
    HINTERNET hInternet,
    LPWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPWSTR lpszUsername,
    LPWSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
);




static BOOL (WINAPI *Old_wininet_InternetCrackUrlA)(
    LPCSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSA lpUrlComponents
);




static BOOL (WINAPI *Old_wininet_InternetCrackUrlW)(
    LPCWSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSW lpUrlComponents
);




static BOOL (WINAPI *Old_wininet_InternetGetConnectedState)(
    LPDWORD lpdwFlags,
    DWORD dwReserved
);




static BOOL (WINAPI *Old_wininet_InternetGetConnectedStateExA)(
    LPDWORD lpdwFlags,
    LPCSTR lpszConnectionName,
    DWORD dwNameLen,
    DWORD dwReserved
);




static BOOL (WINAPI *Old_wininet_InternetGetConnectedStateExW)(
    LPDWORD lpdwFlags,
    LPWSTR lpszConnectionName,
    DWORD dwNameLen,
    DWORD dwReserved
);




static HINTERNET (WINAPI *Old_wininet_InternetOpenA)(
    LPCTSTR lpszAgent,
    DWORD dwAccessType,
    LPCTSTR lpszProxyName,
    LPCTSTR lpszProxyBypass,
    DWORD dwFlags
);




static HINTERNET (WINAPI *Old_wininet_InternetOpenUrlA)(
    HINTERNET hInternet,
    LPCTSTR lpszUrl,
    LPCTSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
);




static HINTERNET (WINAPI *Old_wininet_InternetOpenUrlW)(
    HINTERNET hInternet,
    LPWSTR lpszUrl,
    LPWSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
);




static HINTERNET (WINAPI *Old_wininet_InternetOpenW)(
    LPWSTR lpszAgent,
    DWORD dwAccessType,
    LPWSTR lpszProxyName,
    LPWSTR lpszProxyBypass,
    DWORD dwFlags
);




static BOOL (WINAPI *Old_wininet_InternetQueryOptionA)(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength
);




static BOOL (WINAPI *Old_wininet_InternetReadFile)(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
);




static BOOL (WINAPI *Old_wininet_InternetSetOptionA)(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
);




static INTERNET_STATUS_CALLBACK (WINAPI *Old_wininet_InternetSetStatusCallback)(
    HINTERNET hInternet,
    INTERNET_STATUS_CALLBACK lpfnInternetCallback
);




static BOOL (WINAPI *Old_wininet_InternetWriteFile)(
    HINTERNET hFile,
    LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite,
    LPDWORD lpdwNumberOfBytesWritten
);




static DWORD (WINAPI *Old_winmm_timeGetTime)(
);




static BOOL (WINAPI *Old_ws2_32_ConnectEx)(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
);




static int (WINAPI *Old_ws2_32_GetAddrInfoW)(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW *pHints,
    PADDRINFOW *ppResult
);




static BOOL (WINAPI *Old_ws2_32_TransmitFile)(
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags
);




static SOCKET (WINAPI *Old_ws2_32_WSAAccept)(
    SOCKET s,
    struct sockaddr *addr,
    LPINT addrlen,
    LPCONDITIONPROC lpfnCondition,
    DWORD_PTR dwCallbackData
);




static int (WINAPI *Old_ws2_32_WSAConnect)(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
);




static int (WINAPI *Old_ws2_32_WSARecv)(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);




static int (WINAPI *Old_ws2_32_WSARecvFrom)(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    struct sockaddr *lpFrom,
    LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);




static int (WINAPI *Old_ws2_32_WSASend)(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);




static int (WINAPI *Old_ws2_32_WSASendTo)(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr *lpTo,
    int iToLen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);




static SOCKET (WINAPI *Old_ws2_32_WSASocketA)(
    int af,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFO lpProtocolInfo,
    GROUP g,
    DWORD dwFlags
);




static SOCKET (WINAPI *Old_ws2_32_WSASocketW)(
    int af,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFO lpProtocolInfo,
    GROUP g,
    DWORD dwFlags
);




static int (WINAPI *Old_ws2_32_WSAStartup)(
    WORD wVersionRequested,
    LPWSADATA lpWSAData
);




static SOCKET (WINAPI *Old_ws2_32_accept)(
    SOCKET s,
    struct sockaddr *addr,
    int *addrlen
);




static int (WINAPI *Old_ws2_32_bind)(
    SOCKET s,
    const struct sockaddr *name,
    int namelen
);




static int (WINAPI *Old_ws2_32_closesocket)(
    SOCKET s
);




static int (WINAPI *Old_ws2_32_connect)(
    SOCKET s,
    const struct sockaddr *name,
    int namelen
);




static int (WINAPI *Old_ws2_32_getaddrinfo)(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA *ppResult
);




static struct hostent * (WINAPI *Old_ws2_32_gethostbyname)(
    const char *name
);




static int (WINAPI *Old_ws2_32_getsockname)(
    SOCKET s,
    struct sockaddr *name,
    int *namelen
);




static int (WINAPI *Old_ws2_32_ioctlsocket)(
    SOCKET s,
    long cmd,
    u_long *argp
);




static int (WINAPI *Old_ws2_32_listen)(
    SOCKET s,
    int backlog
);




static int (WINAPI *Old_ws2_32_recv)(
    SOCKET s,
    char *buf,
    int len,
    int flags
);




static int (WINAPI *Old_ws2_32_recvfrom)(
    SOCKET s,
    char *buf,
    int len,
    int flags,
    struct sockaddr *from,
    int *fromlen
);




static int (WINAPI *Old_ws2_32_select)(
    SOCKET s,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const struct timeval *timeout
);




static int (WINAPI *Old_ws2_32_send)(
    SOCKET s,
    const char *buf,
    int len,
    int flags
);




static int (WINAPI *Old_ws2_32_sendto)(
    SOCKET s,
    const char *buf,
    int len,
    int flags,
    const struct sockaddr *to,
    int tolen
);




static int (WINAPI *Old_ws2_32_setsockopt)(
    SOCKET s,
    int level,
    int optname,
    const char *optval,
    int optlen
);




static int (WINAPI *Old_ws2_32_shutdown)(
    SOCKET s,
    int how
);




static SOCKET (WINAPI *Old_ws2_32_socket)(
    int af,
    int type,
    int protocol
);



HRESULT WINAPI New___wmi___IWbemServices_ExecMethod(
    IWbemServices *This,
    const wchar_t *strObjectPath,
    const wchar_t *strMethodName,
    long lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemClassObject **ppOutParams,
    IWbemCallResult **ppCallResult
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "IWbemServices_ExecMethod");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "IWbemServices_ExecMethod");

        set_last_error(&lasterror);
        HRESULT ret = Old___wmi___IWbemServices_ExecMethod(
            This,
            strObjectPath,
            strMethodName,
            lFlags,
            pCtx,
            pInParams,
            ppOutParams,
            ppCallResult
        );
        return ret;
    }
    
    int adjusted = -1; uint32_t creation_flags = 0;
    
    // We adjust some parameters for Win32_Process::Create so we can follow
    // the newly created process cleanly.
    if(wcscmp(strObjectPath, L"Win32_Process") == 0 &&
            wcscmp(strMethodName, L"Create") == 0) {
        adjusted = wmi_win32_process_create_pre(
            This, pInParams, &creation_flags
        );
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old___wmi___IWbemServices_ExecMethod(
        This,
        strObjectPath,
        strMethodName,
        lFlags,
        pCtx,
        pInParams,
        ppOutParams,
        ppCallResult
    );
    get_last_error(&lasterror);

    log_api(SIG___wmi___IWbemServices_ExecMethod,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        strObjectPath,
        strMethodName,
        lFlags
    );
    
    HRESULT hr; VARIANT vt; uint32_t pid = 0, tid = 0;
    
    if(adjusted == 0 && SUCCEEDED(ret) != FALSE) {
        vt.vt = VT_EMPTY;
        hr = (*ppOutParams)->lpVtbl->Get(
            *ppOutParams, L"ProcessId", 0, &vt, NULL, NULL
        );
        if(SUCCEEDED(hr) != FALSE && vt.vt == VT_I4) {
            pid = vt.uintVal; tid = first_tid_from_pid(pid);
            pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);
        }
    
        if((creation_flags & CREATE_SUSPENDED) == 0 && tid != 0) {
            resume_thread_identifier(tid);
        }
    
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "IWbemServices_ExecMethod");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New___wmi___IWbemServices_ExecMethodAsync(
    IWbemServices *This,
    const BSTR strObjectPath,
    const BSTR strMethodName,
    long lFlags,
    IWbemContext *pCtx,
    IWbemClassObject *pInParams,
    IWbemObjectSink *pResponseHandler
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "IWbemServices_ExecMethodAsync");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "IWbemServices_ExecMethodAsync");

        set_last_error(&lasterror);
        HRESULT ret = Old___wmi___IWbemServices_ExecMethodAsync(
            This,
            strObjectPath,
            strMethodName,
            lFlags,
            pCtx,
            pInParams,
            pResponseHandler
        );
        return ret;
    }
    
    // TODO Implement process following functionality.

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old___wmi___IWbemServices_ExecMethodAsync(
        This,
        strObjectPath,
        strMethodName,
        lFlags,
        pCtx,
        pInParams,
        pResponseHandler
    );
    get_last_error(&lasterror);

    log_api(SIG___wmi___IWbemServices_ExecMethodAsync,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        strObjectPath,
        strMethodName,
        lFlags
    );

    log_debug("Leaving %s\n", "IWbemServices_ExecMethodAsync");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New___wmi___IWbemServices_ExecQuery(
    IWbemServices *This,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    ULONG lFlags,
    IWbemContext *pCtx,
    IEnumWbemClassObject **ppEnum
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "IWbemServices_ExecQuery");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "IWbemServices_ExecQuery");

        set_last_error(&lasterror);
        HRESULT ret = Old___wmi___IWbemServices_ExecQuery(
            This,
            strQueryLanguage,
            strQuery,
            lFlags,
            pCtx,
            ppEnum
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old___wmi___IWbemServices_ExecQuery(
        This,
        strQueryLanguage,
        strQuery,
        lFlags,
        pCtx,
        ppEnum
    );
    get_last_error(&lasterror);

    log_api(SIG___wmi___IWbemServices_ExecQuery,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        strQueryLanguage,
        strQuery,
        lFlags
    );

    log_debug("Leaving %s\n", "IWbemServices_ExecQuery");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New___wmi___IWbemServices_ExecQueryAsync(
    IWbemServices *This,
    const BSTR strQueryLanguage,
    const BSTR strQuery,
    long lFlags,
    IWbemContext *pCtx,
    IWbemObjectSink *pResponseHandler
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "IWbemServices_ExecQueryAsync");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "IWbemServices_ExecQueryAsync");

        set_last_error(&lasterror);
        HRESULT ret = Old___wmi___IWbemServices_ExecQueryAsync(
            This,
            strQueryLanguage,
            strQuery,
            lFlags,
            pCtx,
            pResponseHandler
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old___wmi___IWbemServices_ExecQueryAsync(
        This,
        strQueryLanguage,
        strQuery,
        lFlags,
        pCtx,
        pResponseHandler
    );
    get_last_error(&lasterror);

    log_api(SIG___wmi___IWbemServices_ExecQueryAsync,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        strQueryLanguage,
        strQuery,
        lFlags
    );

    log_debug("Leaving %s\n", "IWbemServices_ExecQueryAsync");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_ControlService(
    SC_HANDLE hService,
    DWORD dwControl,
    LPSERVICE_STATUS lpServiceStatus
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ControlService");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ControlService");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_ControlService(
            hService,
            dwControl,
            lpServiceStatus
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_ControlService(
        hService,
        dwControl,
        lpServiceStatus
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_ControlService,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hService,
        dwControl
    );

    log_debug("Leaving %s\n", "ControlService");

    set_last_error(&lasterror);
    return ret;
}

SC_HANDLE WINAPI New_advapi32_CreateServiceA(
    SC_HANDLE hSCManager,
    LPCTSTR lpServiceName,
    LPCTSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPCTSTR lpBinaryPathName,
    LPCTSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPCTSTR lpDependencies,
    LPCTSTR lpServiceStartName,
    LPCTSTR lpPassword
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateServiceA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateServiceA");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_CreateServiceA(
            hSCManager,
            lpServiceName,
            lpDisplayName,
            dwDesiredAccess,
            dwServiceType,
            dwStartType,
            dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathA(lpBinaryPathName, filepath);

    uint64_t hash = call_hash(
        "ssiiiiuss", 
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        filepath,
        lpServiceStartName,
        lpPassword
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CreateServiceA");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_CreateServiceA(
            hSCManager,
            lpServiceName,
            lpDisplayName,
            dwDesiredAccess,
            dwServiceType,
            dwStartType,
            dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword
        );
        return ret;
    }

    set_last_error(&lasterror);
    SC_HANDLE ret = Old_advapi32_CreateServiceA(
        hSCManager,
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        lpBinaryPathName,
        lpLoadOrderGroup,
        lpdwTagId,
        lpDependencies,
        lpServiceStartName,
        lpPassword
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CreateServiceA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSCManager,
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        lpServiceStartName,
        lpPassword,
        ret,
        filepath,
        lpBinaryPathName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "CreateServiceA");

    set_last_error(&lasterror);
    return ret;
}

SC_HANDLE WINAPI New_advapi32_CreateServiceW(
    SC_HANDLE hSCManager,
    LPWSTR lpServiceName,
    LPWSTR lpDisplayName,
    DWORD dwDesiredAccess,
    DWORD dwServiceType,
    DWORD dwStartType,
    DWORD dwErrorControl,
    LPWSTR lpBinaryPathName,
    LPWSTR lpLoadOrderGroup,
    LPDWORD lpdwTagId,
    LPWSTR lpDependencies,
    LPWSTR lpServiceStartName,
    LPWSTR lpPassword
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateServiceW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateServiceW");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_CreateServiceW(
            hSCManager,
            lpServiceName,
            lpDisplayName,
            dwDesiredAccess,
            dwServiceType,
            dwStartType,
            dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpBinaryPathName, filepath);

    uint64_t hash = call_hash(
        "uuiiiiuuu", 
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        filepath,
        lpServiceStartName,
        lpPassword
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CreateServiceW");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_CreateServiceW(
            hSCManager,
            lpServiceName,
            lpDisplayName,
            dwDesiredAccess,
            dwServiceType,
            dwStartType,
            dwErrorControl,
            lpBinaryPathName,
            lpLoadOrderGroup,
            lpdwTagId,
            lpDependencies,
            lpServiceStartName,
            lpPassword
        );
        return ret;
    }

    set_last_error(&lasterror);
    SC_HANDLE ret = Old_advapi32_CreateServiceW(
        hSCManager,
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        lpBinaryPathName,
        lpLoadOrderGroup,
        lpdwTagId,
        lpDependencies,
        lpServiceStartName,
        lpPassword
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CreateServiceW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSCManager,
        lpServiceName,
        lpDisplayName,
        dwDesiredAccess,
        dwServiceType,
        dwStartType,
        dwErrorControl,
        lpServiceStartName,
        lpPassword,
        ret,
        filepath,
        lpBinaryPathName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "CreateServiceW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptAcquireContextA(
    HCRYPTPROV *phProv,
    LPCSTR szContainer,
    LPCSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptAcquireContextA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptAcquireContextA");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptAcquireContextA(
            phProv,
            szContainer,
            szProvider,
            dwProvType,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptAcquireContextA(
        phProv,
        szContainer,
        szProvider,
        dwProvType,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptAcquireContextA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        phProv,
        szContainer,
        szProvider,
        dwProvType,
        dwFlags
    );

    log_debug("Leaving %s\n", "CryptAcquireContextA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptAcquireContextW(
    HCRYPTPROV *phProv,
    LPCWSTR szContainer,
    LPCWSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptAcquireContextW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptAcquireContextW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptAcquireContextW(
            phProv,
            szContainer,
            szProvider,
            dwProvType,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptAcquireContextW(
        phProv,
        szContainer,
        szProvider,
        dwProvType,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptAcquireContextW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        phProv,
        szContainer,
        szProvider,
        dwProvType,
        dwFlags
    );

    log_debug("Leaving %s\n", "CryptAcquireContextW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptCreateHash(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTKEY hKey,
    DWORD dwFlags,
    HCRYPTHASH *phHash
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptCreateHash");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptCreateHash");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptCreateHash(
            hProv,
            Algid,
            hKey,
            dwFlags,
            phHash
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptCreateHash(
        hProv,
        Algid,
        hKey,
        dwFlags,
        phHash
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptCreateHash,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hProv,
        Algid,
        hKey,
        dwFlags,
        phHash
    );

    log_debug("Leaving %s\n", "CryptCreateHash");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptDecrypt(
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL Final,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptDecrypt");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptDecrypt");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptDecrypt(
            hKey,
            hHash,
            Final,
            dwFlags,
            pbData,
            pdwDataLen
        );
        return ret;
    }

    DWORD _pdwDataLen;
    if(pdwDataLen == NULL) {
        pdwDataLen = &_pdwDataLen;
        memset(&_pdwDataLen, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptDecrypt(
        hKey,
        hHash,
        Final,
        dwFlags,
        pbData,
        pdwDataLen
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptDecrypt,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        hHash,
        Final,
        dwFlags,
        (uintptr_t) copy_uint32(pdwDataLen), pbData
    );

    log_debug("Leaving %s\n", "CryptDecrypt");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptEncrypt(
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL Final,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwBufLen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptEncrypt");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptEncrypt");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptEncrypt(
            hKey,
            hHash,
            Final,
            dwFlags,
            pbData,
            pdwDataLen,
            dwBufLen
        );
        return ret;
    }

    uint64_t hash = 0;

    uintptr_t prelen = (uintptr_t) dwBufLen;
    uint8_t *prebuf = memdup(pbData, prelen);

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptEncrypt(
        hKey,
        hHash,
        Final,
        dwFlags,
        pbData,
        pdwDataLen,
        dwBufLen
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptEncrypt,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf,
        hKey,
        hHash,
        Final,
        dwFlags
    );

    log_debug("Leaving %s\n", "CryptEncrypt");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

BOOL WINAPI New_advapi32_CryptExportKey(
    HCRYPTKEY hKey,
    HCRYPTKEY hExpKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE *pbData,
    DWORD *pdwDataLen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptExportKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptExportKey");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptExportKey(
            hKey,
            hExpKey,
            dwBlobType,
            dwFlags,
            pbData,
            pdwDataLen
        );
        return ret;
    }

    DWORD _pdwDataLen;
    if(pdwDataLen == NULL) {
        pdwDataLen = &_pdwDataLen;
        memset(&_pdwDataLen, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptExportKey(
        hKey,
        hExpKey,
        dwBlobType,
        dwFlags,
        pbData,
        pdwDataLen
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptExportKey,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        hExpKey,
        dwBlobType,
        dwFlags,
        (uintptr_t) copy_uint32(pdwDataLen), pbData
    );

    log_debug("Leaving %s\n", "CryptExportKey");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptGenKey(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    DWORD dwFlags,
    HCRYPTKEY *phKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptGenKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptGenKey");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptGenKey(
            hProv,
            Algid,
            dwFlags,
            phKey
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptGenKey(
        hProv,
        Algid,
        dwFlags,
        phKey
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptGenKey,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hProv,
        Algid,
        dwFlags,
        phKey
    );

    log_debug("Leaving %s\n", "CryptGenKey");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_CryptHashData(
    HCRYPTHASH hHash,
    BYTE *pbData,
    DWORD dwDataLen,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptHashData");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptHashData");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_CryptHashData(
            hHash,
            pbData,
            dwDataLen,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_CryptHashData(
        hHash,
        pbData,
        dwDataLen,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_CryptHashData,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hHash,
        dwFlags,
        (uintptr_t) dwDataLen, pbData
    );

    log_debug("Leaving %s\n", "CryptHashData");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_DeleteService(
    SC_HANDLE hService
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DeleteService");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DeleteService");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_DeleteService(
            hService
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_DeleteService(
        hService
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_DeleteService,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hService
    );

    log_debug("Leaving %s\n", "DeleteService");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_EnumServicesStatusA(
    SC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPENUM_SERVICE_STATUS lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "EnumServicesStatusA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "EnumServicesStatusA");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_EnumServicesStatusA(
            hSCManager,
            dwServiceType,
            dwServiceState,
            lpServices,
            cbBufSize,
            pcbBytesNeeded,
            lpServicesReturned,
            lpResumeHandle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_EnumServicesStatusA(
        hSCManager,
        dwServiceType,
        dwServiceState,
        lpServices,
        cbBufSize,
        pcbBytesNeeded,
        lpServicesReturned,
        lpResumeHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_EnumServicesStatusA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSCManager,
        dwServiceType,
        dwServiceState
    );

    log_debug("Leaving %s\n", "EnumServicesStatusA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_EnumServicesStatusW(
    SC_HANDLE hSCManager,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPENUM_SERVICE_STATUS lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "EnumServicesStatusW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "EnumServicesStatusW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_EnumServicesStatusW(
            hSCManager,
            dwServiceType,
            dwServiceState,
            lpServices,
            cbBufSize,
            pcbBytesNeeded,
            lpServicesReturned,
            lpResumeHandle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_EnumServicesStatusW(
        hSCManager,
        dwServiceType,
        dwServiceState,
        lpServices,
        cbBufSize,
        pcbBytesNeeded,
        lpServicesReturned,
        lpResumeHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_EnumServicesStatusW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSCManager,
        dwServiceType,
        dwServiceState
    );

    log_debug("Leaving %s\n", "EnumServicesStatusW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_GetUserNameA(
    LPCSTR lpBuffer,
    LPDWORD lpnSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetUserNameA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetUserNameA");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_GetUserNameA(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    DWORD _lpnSize;
    if(lpnSize == NULL) {
        lpnSize = &_lpnSize;
        memset(&_lpnSize, 0, sizeof(DWORD));
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetUserNameA");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_GetUserNameA(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_GetUserNameA(
        lpBuffer,
        lpnSize
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_GetUserNameA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        copy_uint32(lpnSize)-1, lpBuffer
    );

    log_debug("Leaving %s\n", "GetUserNameA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_GetUserNameW(
    LPWSTR lpBuffer,
    LPDWORD lpnSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetUserNameW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetUserNameW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_GetUserNameW(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    DWORD _lpnSize;
    if(lpnSize == NULL) {
        lpnSize = &_lpnSize;
        memset(&_lpnSize, 0, sizeof(DWORD));
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetUserNameW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_GetUserNameW(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_GetUserNameW(
        lpBuffer,
        lpnSize
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_GetUserNameW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        copy_uint32(lpnSize)-1, lpBuffer
    );

    log_debug("Leaving %s\n", "GetUserNameW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_LookupAccountSidW(
    LPCWSTR lpSystemName,
    PSID lpSid,
    LPWSTR lpName,
    LPDWORD cchName,
    LPWSTR lpReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LookupAccountSidW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LookupAccountSidW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_LookupAccountSidW(
            lpSystemName,
            lpSid,
            lpName,
            cchName,
            lpReferencedDomainName,
            cchReferencedDomainName,
            peUse
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_LookupAccountSidW(
        lpSystemName,
        lpSid,
        lpName,
        cchName,
        lpReferencedDomainName,
        cchReferencedDomainName,
        peUse
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_LookupAccountSidW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpSystemName,
        lpName,
        lpReferencedDomainName
    );

    log_debug("Leaving %s\n", "LookupAccountSidW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_LookupPrivilegeValueW(
    LPWSTR lpSystemName,
    LPWSTR lpName,
    PLUID lpLuid
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LookupPrivilegeValueW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LookupPrivilegeValueW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_LookupPrivilegeValueW(
            lpSystemName,
            lpName,
            lpLuid
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_LookupPrivilegeValueW(
        lpSystemName,
        lpName,
        lpLuid
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_LookupPrivilegeValueW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpSystemName,
        lpName
    );

    log_debug("Leaving %s\n", "LookupPrivilegeValueW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_NotifyBootConfigStatus(
    BOOL BootAcceptable
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NotifyBootConfigStatus");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NotifyBootConfigStatus");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_NotifyBootConfigStatus(
            BootAcceptable
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_NotifyBootConfigStatus(
        BootAcceptable
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_NotifyBootConfigStatus,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        BootAcceptable
    );

    log_debug("Leaving %s\n", "NotifyBootConfigStatus");

    set_last_error(&lasterror);
    return ret;
}

SC_HANDLE WINAPI New_advapi32_OpenSCManagerA(
    LPCTSTR lpMachineName,
    LPCTSTR lpDatabaseName,
    DWORD dwDesiredAccess
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OpenSCManagerA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OpenSCManagerA");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenSCManagerA(
            lpMachineName,
            lpDatabaseName,
            dwDesiredAccess
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ssi", 
        lpMachineName,
        lpDatabaseName,
        dwDesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "OpenSCManagerA");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenSCManagerA(
            lpMachineName,
            lpDatabaseName,
            dwDesiredAccess
        );
        return ret;
    }

    set_last_error(&lasterror);
    SC_HANDLE ret = Old_advapi32_OpenSCManagerA(
        lpMachineName,
        lpDatabaseName,
        dwDesiredAccess
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_OpenSCManagerA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpMachineName,
        lpDatabaseName,
        dwDesiredAccess
    );

    log_debug("Leaving %s\n", "OpenSCManagerA");

    set_last_error(&lasterror);
    return ret;
}

SC_HANDLE WINAPI New_advapi32_OpenSCManagerW(
    LPWSTR lpMachineName,
    LPWSTR lpDatabaseName,
    DWORD dwDesiredAccess
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OpenSCManagerW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OpenSCManagerW");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenSCManagerW(
            lpMachineName,
            lpDatabaseName,
            dwDesiredAccess
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uui", 
        lpMachineName,
        lpDatabaseName,
        dwDesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "OpenSCManagerW");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenSCManagerW(
            lpMachineName,
            lpDatabaseName,
            dwDesiredAccess
        );
        return ret;
    }

    set_last_error(&lasterror);
    SC_HANDLE ret = Old_advapi32_OpenSCManagerW(
        lpMachineName,
        lpDatabaseName,
        dwDesiredAccess
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_OpenSCManagerW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpMachineName,
        lpDatabaseName,
        dwDesiredAccess
    );

    log_debug("Leaving %s\n", "OpenSCManagerW");

    set_last_error(&lasterror);
    return ret;
}

SC_HANDLE WINAPI New_advapi32_OpenServiceA(
    SC_HANDLE hSCManager,
    LPCTSTR lpServiceName,
    DWORD dwDesiredAccess
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OpenServiceA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OpenServiceA");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenServiceA(
            hSCManager,
            lpServiceName,
            dwDesiredAccess
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "si", 
        lpServiceName,
        dwDesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "OpenServiceA");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenServiceA(
            hSCManager,
            lpServiceName,
            dwDesiredAccess
        );
        return ret;
    }

    set_last_error(&lasterror);
    SC_HANDLE ret = Old_advapi32_OpenServiceA(
        hSCManager,
        lpServiceName,
        dwDesiredAccess
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_OpenServiceA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSCManager,
        lpServiceName,
        dwDesiredAccess,
        ret
    );

    log_debug("Leaving %s\n", "OpenServiceA");

    set_last_error(&lasterror);
    return ret;
}

SC_HANDLE WINAPI New_advapi32_OpenServiceW(
    SC_HANDLE hSCManager,
    LPWSTR lpServiceName,
    DWORD dwDesiredAccess
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OpenServiceW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OpenServiceW");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenServiceW(
            hSCManager,
            lpServiceName,
            dwDesiredAccess
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ui", 
        lpServiceName,
        dwDesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "OpenServiceW");

        set_last_error(&lasterror);
        SC_HANDLE ret = Old_advapi32_OpenServiceW(
            hSCManager,
            lpServiceName,
            dwDesiredAccess
        );
        return ret;
    }

    set_last_error(&lasterror);
    SC_HANDLE ret = Old_advapi32_OpenServiceW(
        hSCManager,
        lpServiceName,
        dwDesiredAccess
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_OpenServiceW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSCManager,
        lpServiceName,
        dwDesiredAccess,
        ret
    );

    log_debug("Leaving %s\n", "OpenServiceW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegCloseKey(
    HKEY hKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegCloseKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegCloseKey");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegCloseKey(
            hKey
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegCloseKey(
        hKey
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegCloseKey,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey
    );

    log_debug("Leaving %s\n", "RegCloseKey");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegCreateKeyExA(
    HKEY hKey,
    LPCTSTR lpSubKey,
    DWORD Reserved,
    LPTSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegCreateKeyExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegCreateKeyExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegCreateKeyExA(
            hKey,
            lpSubKey,
            Reserved,
            lpClass,
            dwOptions,
            samDesired,
            lpSecurityAttributes,
            phkResult,
            lpdwDisposition
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

    uint64_t hash = call_hash(
        "usiiI", 
        regkey,
        lpClass,
        dwOptions,
        samDesired,
        lpdwDisposition
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegCreateKeyExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegCreateKeyExA(
            hKey,
            lpSubKey,
            Reserved,
            lpClass,
            dwOptions,
            samDesired,
            lpSecurityAttributes,
            phkResult,
            lpdwDisposition
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegCreateKeyExA(
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegCreateKeyExA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpSubKey,
        lpClass,
        dwOptions,
        samDesired,
        phkResult,
        lpdwDisposition,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegCreateKeyExA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegCreateKeyExW(
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult,
    LPDWORD lpdwDisposition
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegCreateKeyExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegCreateKeyExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegCreateKeyExW(
            hKey,
            lpSubKey,
            Reserved,
            lpClass,
            dwOptions,
            samDesired,
            lpSecurityAttributes,
            phkResult,
            lpdwDisposition
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpSubKey, regkey);

    uint64_t hash = call_hash(
        "uuiiI", 
        regkey,
        lpClass,
        dwOptions,
        samDesired,
        lpdwDisposition
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegCreateKeyExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegCreateKeyExW(
            hKey,
            lpSubKey,
            Reserved,
            lpClass,
            dwOptions,
            samDesired,
            lpSecurityAttributes,
            phkResult,
            lpdwDisposition
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegCreateKeyExW(
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegCreateKeyExW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpSubKey,
        lpClass,
        dwOptions,
        samDesired,
        phkResult,
        lpdwDisposition,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegCreateKeyExW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegDeleteKeyA(
    HKEY hKey,
    LPCTSTR lpSubKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegDeleteKeyA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegDeleteKeyA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteKeyA(
            hKey,
            lpSubKey
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegDeleteKeyA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteKeyA(
            hKey,
            lpSubKey
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegDeleteKeyA(
        hKey,
        lpSubKey
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegDeleteKeyA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpSubKey,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegDeleteKeyA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegDeleteKeyW(
    HKEY hKey,
    LPWSTR lpSubKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegDeleteKeyW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegDeleteKeyW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteKeyW(
            hKey,
            lpSubKey
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpSubKey, regkey);

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegDeleteKeyW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteKeyW(
            hKey,
            lpSubKey
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegDeleteKeyW(
        hKey,
        lpSubKey
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegDeleteKeyW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpSubKey,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegDeleteKeyW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegDeleteValueA(
    HKEY hKey,
    LPCTSTR lpValueName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegDeleteValueA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegDeleteValueA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteValueA(
            hKey,
            lpValueName
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegDeleteValueA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteValueA(
            hKey,
            lpValueName
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegDeleteValueA(
        hKey,
        lpValueName
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegDeleteValueA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpValueName,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegDeleteValueA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegDeleteValueW(
    HKEY hKey,
    LPWSTR lpValueName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegDeleteValueW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegDeleteValueW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteValueW(
            hKey,
            lpValueName
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegDeleteValueW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegDeleteValueW(
            hKey,
            lpValueName
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegDeleteValueW(
        hKey,
        lpValueName
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegDeleteValueW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpValueName,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegDeleteValueW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegEnumKeyExA(
    HKEY hKey,
    DWORD dwIndex,
    LPTSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPTSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegEnumKeyExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegEnumKeyExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumKeyExA(
            hKey,
            dwIndex,
            lpName,
            lpcName,
            lpReserved,
            lpClass,
            lpcClass,
            lpftLastWriteTime
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        dwIndex
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegEnumKeyExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumKeyExA(
            hKey,
            dwIndex,
            lpName,
            lpcName,
            lpReserved,
            lpClass,
            lpcClass,
            lpftLastWriteTime
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegEnumKeyExA(
        hKey,
        dwIndex,
        lpName,
        lpcName,
        lpReserved,
        lpClass,
        lpcClass,
        lpftLastWriteTime
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegEnumKeyExA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        dwIndex,
        lpName,
        lpClass,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegEnumKeyExA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegEnumKeyExW(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpName,
    LPDWORD lpcName,
    LPDWORD lpReserved,
    LPWSTR lpClass,
    LPDWORD lpcClass,
    PFILETIME lpftLastWriteTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegEnumKeyExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegEnumKeyExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumKeyExW(
            hKey,
            dwIndex,
            lpName,
            lpcName,
            lpReserved,
            lpClass,
            lpcClass,
            lpftLastWriteTime
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        dwIndex
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegEnumKeyExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumKeyExW(
            hKey,
            dwIndex,
            lpName,
            lpcName,
            lpReserved,
            lpClass,
            lpcClass,
            lpftLastWriteTime
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegEnumKeyExW(
        hKey,
        dwIndex,
        lpName,
        lpcName,
        lpReserved,
        lpClass,
        lpcClass,
        lpftLastWriteTime
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegEnumKeyExW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        dwIndex,
        lpName,
        lpClass,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegEnumKeyExW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegEnumKeyW(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpName,
    DWORD cchName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegEnumKeyW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegEnumKeyW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumKeyW(
            hKey,
            dwIndex,
            lpName,
            cchName
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        dwIndex
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegEnumKeyW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumKeyW(
            hKey,
            dwIndex,
            lpName,
            cchName
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegEnumKeyW(
        hKey,
        dwIndex,
        lpName,
        cchName
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegEnumKeyW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        dwIndex,
        lpName,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegEnumKeyW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegEnumValueA(
    HKEY hKey,
    DWORD dwIndex,
    LPTSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegEnumValueA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegEnumValueA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumValueA(
            hKey,
            dwIndex,
            lpValueName,
            lpcchValueName,
            lpReserved,
            lpType,
            lpData,
            lpcbData
        );
        return ret;
    }

    DWORD _lpType;
    if(lpType == NULL) {
        lpType = &_lpType;
        memset(&_lpType, 0, sizeof(DWORD));
    }

    DWORD _lpcbData;
    if(lpcbData == NULL) {
        lpcbData = &_lpcbData;
        memset(&_lpcbData, 0, sizeof(DWORD));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);
    
    *lpType = REG_NONE;

    uint64_t hash = 0;

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegEnumValueA(
        hKey,
        dwIndex,
        lpValueName,
        lpcchValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegEnumValueA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        dwIndex,
        lpValueName,
        lpType,
        regkey,
        lpType, lpcbData, lpData
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegEnumValueA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegEnumValueW(
    HKEY hKey,
    DWORD dwIndex,
    LPWSTR lpValueName,
    LPDWORD lpcchValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegEnumValueW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegEnumValueW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegEnumValueW(
            hKey,
            dwIndex,
            lpValueName,
            lpcchValueName,
            lpReserved,
            lpType,
            lpData,
            lpcbData
        );
        return ret;
    }

    DWORD _lpType;
    if(lpType == NULL) {
        lpType = &_lpType;
        memset(&_lpType, 0, sizeof(DWORD));
    }

    DWORD _lpcbData;
    if(lpcbData == NULL) {
        lpcbData = &_lpcbData;
        memset(&_lpcbData, 0, sizeof(DWORD));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);
    
    *lpType = REG_NONE;

    uint64_t hash = 0;

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegEnumValueW(
        hKey,
        dwIndex,
        lpValueName,
        lpcchValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegEnumValueW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        dwIndex,
        lpValueName,
        lpType,
        regkey,
        lpType, lpcbData, lpData
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegEnumValueW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegOpenKeyExA(
    HKEY hKey,
    LPCTSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegOpenKeyExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegOpenKeyExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegOpenKeyExA(
            hKey,
            lpSubKey,
            ulOptions,
            samDesired,
            phkResult
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpSubKey, regkey);

    uint64_t hash = call_hash(
        "uii", 
        regkey,
        ulOptions,
        samDesired
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegOpenKeyExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegOpenKeyExA(
            hKey,
            lpSubKey,
            ulOptions,
            samDesired,
            phkResult
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegOpenKeyExA(
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegOpenKeyExA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegOpenKeyExA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegOpenKeyExW(
    HKEY hKey,
    LPWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegOpenKeyExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegOpenKeyExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegOpenKeyExW(
            hKey,
            lpSubKey,
            ulOptions,
            samDesired,
            phkResult
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpSubKey, regkey);

    uint64_t hash = call_hash(
        "uii", 
        regkey,
        ulOptions,
        samDesired
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegOpenKeyExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegOpenKeyExW(
            hKey,
            lpSubKey,
            ulOptions,
            samDesired,
            phkResult
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegOpenKeyExW(
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegOpenKeyExW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpSubKey,
        ulOptions,
        samDesired,
        phkResult,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegOpenKeyExW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegQueryInfoKeyA(
    HKEY hKey,
    LPTSTR lpClass,
    LPDWORD lpcClass,
    LPDWORD lpReserved,
    LPDWORD lpcSubKeys,
    LPDWORD lpcMaxSubKeyLen,
    LPDWORD lpcMaxClassLen,
    LPDWORD lpcValues,
    LPDWORD lpcMaxValueNameLen,
    LPDWORD lpcMaxValueLen,
    LPDWORD lpcbSecurityDescriptor,
    PFILETIME lpftLastWriteTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegQueryInfoKeyA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegQueryInfoKeyA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegQueryInfoKeyA(
            hKey,
            lpClass,
            lpcClass,
            lpReserved,
            lpcSubKeys,
            lpcMaxSubKeyLen,
            lpcMaxClassLen,
            lpcValues,
            lpcMaxValueNameLen,
            lpcMaxValueLen,
            lpcbSecurityDescriptor,
            lpftLastWriteTime
        );
        return ret;
    }

    DWORD _lpcMaxValueLen;
    if(lpcMaxValueLen == NULL) {
        lpcMaxValueLen = &_lpcMaxValueLen;
        memset(&_lpcMaxValueLen, 0, sizeof(DWORD));
    }

    DWORD _lpcMaxSubKeyLen;
    if(lpcMaxSubKeyLen == NULL) {
        lpcMaxSubKeyLen = &_lpcMaxSubKeyLen;
        memset(&_lpcMaxSubKeyLen, 0, sizeof(DWORD));
    }

    DWORD _lpcMaxValueNameLen;
    if(lpcMaxValueNameLen == NULL) {
        lpcMaxValueNameLen = &_lpcMaxValueNameLen;
        memset(&_lpcMaxValueNameLen, 0, sizeof(DWORD));
    }

    DWORD _lpcMaxClassLen;
    if(lpcMaxClassLen == NULL) {
        lpcMaxClassLen = &_lpcMaxClassLen;
        memset(&_lpcMaxClassLen, 0, sizeof(DWORD));
    }

    DWORD _lpcValues;
    if(lpcValues == NULL) {
        lpcValues = &_lpcValues;
        memset(&_lpcValues, 0, sizeof(DWORD));
    }

    DWORD _lpcSubKeys;
    if(lpcSubKeys == NULL) {
        lpcSubKeys = &_lpcSubKeys;
        memset(&_lpcSubKeys, 0, sizeof(DWORD));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegQueryInfoKeyA(
        hKey,
        lpClass,
        lpcClass,
        lpReserved,
        lpcSubKeys,
        lpcMaxSubKeyLen,
        lpcMaxClassLen,
        lpcValues,
        lpcMaxValueNameLen,
        lpcMaxValueLen,
        lpcbSecurityDescriptor,
        lpftLastWriteTime
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegQueryInfoKeyA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpClass,
        lpcSubKeys,
        lpcMaxSubKeyLen,
        lpcMaxClassLen,
        lpcValues,
        lpcMaxValueNameLen,
        lpcMaxValueLen,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegQueryInfoKeyA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegQueryInfoKeyW(
    HKEY hKey,
    LPWSTR lpClass,
    LPDWORD lpcClass,
    LPDWORD lpReserved,
    LPDWORD lpcSubKeys,
    LPDWORD lpcMaxSubKeyLen,
    LPDWORD lpcMaxClassLen,
    LPDWORD lpcValues,
    LPDWORD lpcMaxValueNameLen,
    LPDWORD lpcMaxValueLen,
    LPDWORD lpcbSecurityDescriptor,
    PFILETIME lpftLastWriteTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegQueryInfoKeyW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegQueryInfoKeyW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegQueryInfoKeyW(
            hKey,
            lpClass,
            lpcClass,
            lpReserved,
            lpcSubKeys,
            lpcMaxSubKeyLen,
            lpcMaxClassLen,
            lpcValues,
            lpcMaxValueNameLen,
            lpcMaxValueLen,
            lpcbSecurityDescriptor,
            lpftLastWriteTime
        );
        return ret;
    }

    DWORD _lpcMaxValueLen;
    if(lpcMaxValueLen == NULL) {
        lpcMaxValueLen = &_lpcMaxValueLen;
        memset(&_lpcMaxValueLen, 0, sizeof(DWORD));
    }

    DWORD _lpcMaxSubKeyLen;
    if(lpcMaxSubKeyLen == NULL) {
        lpcMaxSubKeyLen = &_lpcMaxSubKeyLen;
        memset(&_lpcMaxSubKeyLen, 0, sizeof(DWORD));
    }

    DWORD _lpcMaxValueNameLen;
    if(lpcMaxValueNameLen == NULL) {
        lpcMaxValueNameLen = &_lpcMaxValueNameLen;
        memset(&_lpcMaxValueNameLen, 0, sizeof(DWORD));
    }

    DWORD _lpcMaxClassLen;
    if(lpcMaxClassLen == NULL) {
        lpcMaxClassLen = &_lpcMaxClassLen;
        memset(&_lpcMaxClassLen, 0, sizeof(DWORD));
    }

    DWORD _lpcValues;
    if(lpcValues == NULL) {
        lpcValues = &_lpcValues;
        memset(&_lpcValues, 0, sizeof(DWORD));
    }

    DWORD _lpcSubKeys;
    if(lpcSubKeys == NULL) {
        lpcSubKeys = &_lpcSubKeys;
        memset(&_lpcSubKeys, 0, sizeof(DWORD));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(hKey, regkey);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegQueryInfoKeyW(
        hKey,
        lpClass,
        lpcClass,
        lpReserved,
        lpcSubKeys,
        lpcMaxSubKeyLen,
        lpcMaxClassLen,
        lpcValues,
        lpcMaxValueNameLen,
        lpcMaxValueLen,
        lpcbSecurityDescriptor,
        lpftLastWriteTime
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegQueryInfoKeyW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpClass,
        lpcSubKeys,
        lpcMaxSubKeyLen,
        lpcMaxClassLen,
        lpcValues,
        lpcMaxValueNameLen,
        lpcMaxValueLen,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegQueryInfoKeyW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegQueryValueExA(
    HKEY hKey,
    LPCTSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegQueryValueExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegQueryValueExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegQueryValueExA(
            hKey,
            lpValueName,
            lpReserved,
            lpType,
            lpData,
            lpcbData
        );
        return ret;
    }

    DWORD _lpType;
    if(lpType == NULL) {
        lpType = &_lpType;
        memset(&_lpType, 0, sizeof(DWORD));
    }

    DWORD _lpcbData;
    if(lpcbData == NULL) {
        lpcbData = &_lpcbData;
        memset(&_lpcbData, 0, sizeof(DWORD));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);
    
    *lpType = REG_NONE;

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegQueryValueExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegQueryValueExA(
            hKey,
            lpValueName,
            lpReserved,
            lpType,
            lpData,
            lpcbData
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegQueryValueExA(
        hKey,
        lpValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegQueryValueExA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpValueName,
        lpType,
        regkey,
        lpType, lpcbData, lpData
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegQueryValueExA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegQueryValueExW(
    HKEY hKey,
    LPWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegQueryValueExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegQueryValueExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegQueryValueExW(
            hKey,
            lpValueName,
            lpReserved,
            lpType,
            lpData,
            lpcbData
        );
        return ret;
    }

    DWORD _lpType;
    if(lpType == NULL) {
        lpType = &_lpType;
        memset(&_lpType, 0, sizeof(DWORD));
    }

    DWORD _lpcbData;
    if(lpcbData == NULL) {
        lpcbData = &_lpcbData;
        memset(&_lpcbData, 0, sizeof(DWORD));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);
    
    *lpType = REG_NONE;

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegQueryValueExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegQueryValueExW(
            hKey,
            lpValueName,
            lpReserved,
            lpType,
            lpData,
            lpcbData
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegQueryValueExW(
        hKey,
        lpValueName,
        lpReserved,
        lpType,
        lpData,
        lpcbData
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegQueryValueExW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpValueName,
        lpType,
        regkey,
        lpType, lpcbData, lpData
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegQueryValueExW");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegSetValueExA(
    HKEY hKey,
    LPCTSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegSetValueExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegSetValueExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegSetValueExA(
            hKey,
            lpValueName,
            Reserved,
            dwType,
            lpData,
            cbData
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_asciiz(hKey, lpValueName, regkey);

    uint64_t hash = call_hash(
        "uib", 
        regkey,
        dwType,
        cbData, lpData
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegSetValueExA");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegSetValueExA(
            hKey,
            lpValueName,
            Reserved,
            dwType,
            lpData,
            cbData
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegSetValueExA(
        hKey,
        lpValueName,
        Reserved,
        dwType,
        lpData,
        cbData
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegSetValueExA,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpValueName,
        dwType,
        regkey,
        &dwType, &cbData, lpData
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegSetValueExA");

    set_last_error(&lasterror);
    return ret;
}

LONG WINAPI New_advapi32_RegSetValueExW(
    HKEY hKey,
    LPWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegSetValueExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegSetValueExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegSetValueExW(
            hKey,
            lpValueName,
            Reserved,
            dwType,
            lpData,
            cbData
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_uniz(hKey, lpValueName, regkey);

    uint64_t hash = call_hash(
        "uib", 
        regkey,
        dwType,
        cbData, lpData
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RegSetValueExW");

        set_last_error(&lasterror);
        LONG ret = Old_advapi32_RegSetValueExW(
            hKey,
            lpValueName,
            Reserved,
            dwType,
            lpData,
            cbData
        );
        return ret;
    }

    set_last_error(&lasterror);
    LONG ret = Old_advapi32_RegSetValueExW(
        hKey,
        lpValueName,
        Reserved,
        dwType,
        lpData,
        cbData
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_RegSetValueExW,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hKey,
        lpValueName,
        dwType,
        regkey,
        &dwType, &cbData, lpData
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "RegSetValueExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_StartServiceA(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCTSTR *lpServiceArgVectors
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "StartServiceA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "StartServiceA");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_StartServiceA(
            hService,
            dwNumServiceArgs,
            lpServiceArgVectors
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_StartServiceA(
        hService,
        dwNumServiceArgs,
        lpServiceArgVectors
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_StartServiceA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hService,
        dwNumServiceArgs, lpServiceArgVectors
    );

    log_debug("Leaving %s\n", "StartServiceA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_StartServiceCtrlDispatcherW(
    const SERVICE_TABLE_ENTRYW *lpServiceTable
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "StartServiceCtrlDispatcherW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "StartServiceCtrlDispatcherW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_StartServiceCtrlDispatcherW(
            lpServiceTable
        );
        return ret;
    }
    
    bson b, a; char index[10]; int idx = 0; SERVICE_TABLE_ENTRYW entry;
    bson_init(&b);
    bson_init(&a);
    
    bson_append_start_array(&b, "services");
    bson_append_start_array(&a, "addresses");
    
    const SERVICE_TABLE_ENTRYW *ptr = lpServiceTable;
    while (
        copy_bytes(&entry, ptr, sizeof(SERVICE_TABLE_ENTRYW)) == 0 &&
        entry.lpServiceProc != NULL
    ) {
        our_snprintf(index, sizeof(index), "%d", idx++);
        log_wstring(&b, index, entry.lpServiceName,
            copy_strlenW(entry.lpServiceName));
    
        log_intptr(&a, index, (intptr_t)(uintptr_t) entry.lpServiceProc);
    }
    
    bson_append_finish_array(&a);
    bson_append_finish_array(&b);
    bson_finish(&a);
    bson_finish(&b);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_StartServiceCtrlDispatcherW(
        lpServiceTable
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_StartServiceCtrlDispatcherW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        &a,
        &b
    );
    
    bson_destroy(&a);
    bson_destroy(&b);

    log_debug("Leaving %s\n", "StartServiceCtrlDispatcherW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_advapi32_StartServiceW(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPWSTR *lpServiceArgVectors
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "StartServiceW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "StartServiceW");

        set_last_error(&lasterror);
        BOOL ret = Old_advapi32_StartServiceW(
            hService,
            dwNumServiceArgs,
            lpServiceArgVectors
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_advapi32_StartServiceW(
        hService,
        dwNumServiceArgs,
        lpServiceArgVectors
    );
    get_last_error(&lasterror);

    log_api(SIG_advapi32_StartServiceW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hService,
        dwNumServiceArgs, lpServiceArgVectors
    );

    log_debug("Leaving %s\n", "StartServiceW");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_comctl32_TaskDialog(
    HWND hWndParent,
    HINSTANCE hInstance,
    PCWSTR pszWindowTitle,
    PCWSTR pszMainInstruction,
    PCWSTR pszContent,
    TASKDIALOG_COMMON_BUTTON_FLAGS dwCommonButtons,
    PCWSTR pszIcon,
    int *pnButton
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "TaskDialog");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "TaskDialog");

        set_last_error(&lasterror);
        HRESULT ret = Old_comctl32_TaskDialog(
            hWndParent,
            hInstance,
            pszWindowTitle,
            pszMainInstruction,
            pszContent,
            dwCommonButtons,
            pszIcon,
            pnButton
        );
        return ret;
    }
    
    wchar_t title_buf[10], description_buf[10], content_buf[10], icon_buf[10];
    wchar_t *title, *description, *content, *icon;
    
    int_or_strW(&title, pszWindowTitle, title_buf);
    int_or_strW(&description, pszMainInstruction, description_buf);
    int_or_strW(&content, pszContent, content_buf);
    int_or_strW(&icon, pszIcon, icon_buf);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_comctl32_TaskDialog(
        hWndParent,
        hInstance,
        pszWindowTitle,
        pszMainInstruction,
        pszContent,
        dwCommonButtons,
        pszIcon,
        pnButton
    );
    get_last_error(&lasterror);

    log_api(SIG_comctl32_TaskDialog,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hWndParent,
        hInstance,
        dwCommonButtons,
        pnButton,
        title,
        description,
        content,
        icon
    );

    log_debug("Leaving %s\n", "TaskDialog");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CertControlStore(
    HCERTSTORE hCertStore,
    DWORD dwFlags,
    DWORD dwCtrlType,
    const void *pvCtrlPara
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CertControlStore");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CertControlStore");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CertControlStore(
            hCertStore,
            dwFlags,
            dwCtrlType,
            pvCtrlPara
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CertControlStore(
        hCertStore,
        dwFlags,
        dwCtrlType,
        pvCtrlPara
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CertControlStore,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hCertStore,
        dwFlags,
        dwCtrlType
    );

    log_debug("Leaving %s\n", "CertControlStore");

    set_last_error(&lasterror);
    return ret;
}

PCCERT_CONTEXT WINAPI New_crypt32_CertCreateCertificateContext(
    DWORD dwCertEncodingType,
    const BYTE *pbCertEncoded,
    DWORD cbCertEncoded
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CertCreateCertificateContext");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CertCreateCertificateContext");

        set_last_error(&lasterror);
        PCCERT_CONTEXT ret = Old_crypt32_CertCreateCertificateContext(
            dwCertEncodingType,
            pbCertEncoded,
            cbCertEncoded
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    PCCERT_CONTEXT ret = Old_crypt32_CertCreateCertificateContext(
        dwCertEncodingType,
        pbCertEncoded,
        cbCertEncoded
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CertCreateCertificateContext,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwCertEncodingType,
        cbCertEncoded, pbCertEncoded
    );

    log_debug("Leaving %s\n", "CertCreateCertificateContext");

    set_last_error(&lasterror);
    return ret;
}

HCERTSTORE WINAPI New_crypt32_CertOpenStore(
    LPCSTR lpszStoreProvider,
    DWORD dwMsgAndCertEncodingType,
    HCRYPTPROV hCryptProv,
    DWORD dwFlags,
    const void *pvPara
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CertOpenStore");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CertOpenStore");

        set_last_error(&lasterror);
        HCERTSTORE ret = Old_crypt32_CertOpenStore(
            lpszStoreProvider,
            dwMsgAndCertEncodingType,
            hCryptProv,
            dwFlags,
            pvPara
        );
        return ret;
    }
    
    char number[10], *store_provider;
    
    int_or_strA(&store_provider, lpszStoreProvider, number);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HCERTSTORE ret = Old_crypt32_CertOpenStore(
        lpszStoreProvider,
        dwMsgAndCertEncodingType,
        hCryptProv,
        dwFlags,
        pvPara
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CertOpenStore,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwMsgAndCertEncodingType,
        dwFlags,
        store_provider
    );

    log_debug("Leaving %s\n", "CertOpenStore");

    set_last_error(&lasterror);
    return ret;
}

HCERTSTORE WINAPI New_crypt32_CertOpenSystemStoreA(
    HCRYPTPROV hProv,
    LPCTSTR szSubsystemProtocol
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CertOpenSystemStoreA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CertOpenSystemStoreA");

        set_last_error(&lasterror);
        HCERTSTORE ret = Old_crypt32_CertOpenSystemStoreA(
            hProv,
            szSubsystemProtocol
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HCERTSTORE ret = Old_crypt32_CertOpenSystemStoreA(
        hProv,
        szSubsystemProtocol
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CertOpenSystemStoreA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        szSubsystemProtocol
    );

    log_debug("Leaving %s\n", "CertOpenSystemStoreA");

    set_last_error(&lasterror);
    return ret;
}

HCERTSTORE WINAPI New_crypt32_CertOpenSystemStoreW(
    HCRYPTPROV hProv,
    LPCWSTR szSubsystemProtocol
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CertOpenSystemStoreW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CertOpenSystemStoreW");

        set_last_error(&lasterror);
        HCERTSTORE ret = Old_crypt32_CertOpenSystemStoreW(
            hProv,
            szSubsystemProtocol
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HCERTSTORE ret = Old_crypt32_CertOpenSystemStoreW(
        hProv,
        szSubsystemProtocol
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CertOpenSystemStoreW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        szSubsystemProtocol
    );

    log_debug("Leaving %s\n", "CertOpenSystemStoreW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CryptDecodeMessage(
    DWORD dwMsgTypeFlags,
    PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
    DWORD dwSignerIndex,
    const BYTE *pbEncodedBlob,
    DWORD cbEncodedBlob,
    DWORD dwPrevInnerContentType,
    DWORD *pdwMsgType,
    DWORD *pdwInnerContentType,
    BYTE *pbDecoded,
    DWORD *pcbDecoded,
    PCCERT_CONTEXT *ppXchgCert,
    PCCERT_CONTEXT *ppSignerCert
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptDecodeMessage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptDecodeMessage");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptDecodeMessage(
            dwMsgTypeFlags,
            pDecryptPara,
            pVerifyPara,
            dwSignerIndex,
            pbEncodedBlob,
            cbEncodedBlob,
            dwPrevInnerContentType,
            pdwMsgType,
            pdwInnerContentType,
            pbDecoded,
            pcbDecoded,
            ppXchgCert,
            ppSignerCert
        );
        return ret;
    }

    DWORD _pcbDecoded;
    if(pcbDecoded == NULL) {
        pcbDecoded = &_pcbDecoded;
        memset(&_pcbDecoded, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptDecodeMessage(
        dwMsgTypeFlags,
        pDecryptPara,
        pVerifyPara,
        dwSignerIndex,
        pbEncodedBlob,
        cbEncodedBlob,
        dwPrevInnerContentType,
        pdwMsgType,
        pdwInnerContentType,
        pbDecoded,
        pcbDecoded,
        ppXchgCert,
        ppSignerCert
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptDecodeMessage,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        (uintptr_t) copy_uint32(pcbDecoded), pbDecoded
    );

    log_debug("Leaving %s\n", "CryptDecodeMessage");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CryptDecodeObjectEx(
    DWORD dwCertEncodingType,
    LPCSTR lpszStructType,
    const BYTE *pbEncoded,
    DWORD cbEncoded,
    DWORD dwFlags,
    PCRYPT_DECODE_PARA pDecodePara,
    void *pvStructInfo,
    DWORD *pcbStructInfo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptDecodeObjectEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptDecodeObjectEx");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptDecodeObjectEx(
            dwCertEncodingType,
            lpszStructType,
            pbEncoded,
            cbEncoded,
            dwFlags,
            pDecodePara,
            pvStructInfo,
            pcbStructInfo
        );
        return ret;
    }

    DWORD _pcbStructInfo;
    if(pcbStructInfo == NULL) {
        pcbStructInfo = &_pcbStructInfo;
        memset(&_pcbStructInfo, 0, sizeof(DWORD));
    }
    
    char number[10], *struct_type;
    
    int_or_strA(&struct_type, lpszStructType, number);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptDecodeObjectEx(
        dwCertEncodingType,
        lpszStructType,
        pbEncoded,
        cbEncoded,
        dwFlags,
        pDecodePara,
        pvStructInfo,
        pcbStructInfo
    );
    get_last_error(&lasterror);
    
    void *buf = pvStructInfo;
    
    if((dwFlags & CRYPT_ENCODE_ALLOC_FLAG) != 0) {
        buf = copy_ptr(pvStructInfo);
    }

    log_api(SIG_crypt32_CryptDecodeObjectEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwCertEncodingType,
        dwFlags,
        struct_type,
        (uintptr_t) copy_uint32(pcbStructInfo), buf
    );

    log_debug("Leaving %s\n", "CryptDecodeObjectEx");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CryptDecryptMessage(
    PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    const BYTE *pbEncryptedBlob,
    DWORD cbEncryptedBlob,
    BYTE *pbDecrypted,
    DWORD *pcbDecrypted,
    PCCERT_CONTEXT *ppXchgCert
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptDecryptMessage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptDecryptMessage");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptDecryptMessage(
            pDecryptPara,
            pbEncryptedBlob,
            cbEncryptedBlob,
            pbDecrypted,
            pcbDecrypted,
            ppXchgCert
        );
        return ret;
    }

    DWORD _pcbDecrypted;
    if(pcbDecrypted == NULL) {
        pcbDecrypted = &_pcbDecrypted;
        memset(&_pcbDecrypted, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptDecryptMessage(
        pDecryptPara,
        pbEncryptedBlob,
        cbEncryptedBlob,
        pbDecrypted,
        pcbDecrypted,
        ppXchgCert
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptDecryptMessage,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        (uintptr_t) copy_uint32(pcbDecrypted), pbDecrypted
    );

    log_debug("Leaving %s\n", "CryptDecryptMessage");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CryptEncryptMessage(
    PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
    DWORD cRecipientCert,
    PCCERT_CONTEXT *rgpRecipientCert,
    const BYTE *pbToBeEncrypted,
    DWORD cbToBeEncrypted,
    BYTE *pbEncryptedBlob,
    DWORD *pcbEncryptedBlob
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptEncryptMessage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptEncryptMessage");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptEncryptMessage(
            pEncryptPara,
            cRecipientCert,
            rgpRecipientCert,
            pbToBeEncrypted,
            cbToBeEncrypted,
            pbEncryptedBlob,
            pcbEncryptedBlob
        );
        return ret;
    }

    uint64_t hash = 0;

    uintptr_t prelen = (uintptr_t) cbToBeEncrypted;
    uint8_t *prebuf = memdup(pbToBeEncrypted, prelen);

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptEncryptMessage(
        pEncryptPara,
        cRecipientCert,
        rgpRecipientCert,
        pbToBeEncrypted,
        cbToBeEncrypted,
        pbEncryptedBlob,
        pcbEncryptedBlob
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptEncryptMessage,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf
    );

    log_debug("Leaving %s\n", "CryptEncryptMessage");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

BOOL WINAPI New_crypt32_CryptHashMessage(
    PCRYPT_HASH_MESSAGE_PARA pHashPara,
    BOOL fDetachedHash,
    DWORD cToBeHashed,
    const BYTE **rgpbToBeHashed,
    DWORD *rgcbToBeHashed,
    BYTE *pbHashedBlob,
    DWORD *pcbHashedBlob,
    BYTE *pbComputedHash,
    DWORD *pcbComputedHash
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptHashMessage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptHashMessage");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptHashMessage(
            pHashPara,
            fDetachedHash,
            cToBeHashed,
            rgpbToBeHashed,
            rgcbToBeHashed,
            pbHashedBlob,
            pcbHashedBlob,
            pbComputedHash,
            pcbComputedHash
        );
        return ret;
    }
    
    uintptr_t length = 0;
    for (uint32_t idx = 0; idx < cToBeHashed; idx++) {
        length += copy_uint32(&rgcbToBeHashed[idx]);
    }
    
    uint8_t *buf = mem_alloc(length);
    if(buf != NULL) {
        for (uint32_t idx = 0, offset = 0; idx < cToBeHashed; idx++) {
            copy_bytes(
                &buf[offset], copy_ptr(&rgpbToBeHashed[idx]),
                copy_uint32(&rgcbToBeHashed[idx])
            );
            offset += copy_uint32(&rgcbToBeHashed[idx]);
        }
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptHashMessage(
        pHashPara,
        fDetachedHash,
        cToBeHashed,
        rgpbToBeHashed,
        rgcbToBeHashed,
        pbHashedBlob,
        pcbHashedBlob,
        pbComputedHash,
        pcbComputedHash
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptHashMessage,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        length, buf
    );
    
    mem_free(buf);

    log_debug("Leaving %s\n", "CryptHashMessage");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CryptProtectData(
    DATA_BLOB *pDataIn,
    LPCWSTR szDataDescr,
    DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags,
    DATA_BLOB *pDataOut
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptProtectData");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptProtectData");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptProtectData(
            pDataIn,
            szDataDescr,
            pOptionalEntropy,
            pvReserved,
            pPromptStruct,
            dwFlags,
            pDataOut
        );
        return ret;
    }

    DATA_BLOB _pDataIn;
    if(pDataIn == NULL) {
        pDataIn = &_pDataIn;
        memset(&_pDataIn, 0, sizeof(DATA_BLOB));
    }

    uint64_t hash = 0;

    uintptr_t prelen = (uintptr_t) copy_uint32(&pDataIn->cbData);
    uint8_t *prebuf = memdup(copy_ptr(&pDataIn->pbData), prelen);

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptProtectData(
        pDataIn,
        szDataDescr,
        pOptionalEntropy,
        pvReserved,
        pPromptStruct,
        dwFlags,
        pDataOut
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptProtectData,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf,
        szDataDescr,
        dwFlags
    );

    log_debug("Leaving %s\n", "CryptProtectData");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

BOOL WINAPI New_crypt32_CryptProtectMemory(
    LPVOID pData,
    DWORD cbData,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptProtectMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptProtectMemory");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptProtectMemory(
            pData,
            cbData,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = 0;

    uintptr_t prelen = (uintptr_t) cbData;
    uint8_t *prebuf = memdup(pData, prelen);

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptProtectMemory(
        pData,
        cbData,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptProtectMemory,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf,
        dwFlags
    );

    log_debug("Leaving %s\n", "CryptProtectMemory");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

BOOL WINAPI New_crypt32_CryptUnprotectData(
    DATA_BLOB *pDataIn,
    LPWSTR *ppszDataDescr,
    DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved,
    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    DWORD dwFlags,
    DATA_BLOB *pDataOut
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptUnprotectData");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptUnprotectData");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptUnprotectData(
            pDataIn,
            ppszDataDescr,
            pOptionalEntropy,
            pvReserved,
            pPromptStruct,
            dwFlags,
            pDataOut
        );
        return ret;
    }

    DATA_BLOB _pDataOut;
    if(pDataOut == NULL) {
        pDataOut = &_pDataOut;
        memset(&_pDataOut, 0, sizeof(DATA_BLOB));
    }

    DATA_BLOB _pOptionalEntropy;
    if(pOptionalEntropy == NULL) {
        pOptionalEntropy = &_pOptionalEntropy;
        memset(&_pOptionalEntropy, 0, sizeof(DATA_BLOB));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptUnprotectData(
        pDataIn,
        ppszDataDescr,
        pOptionalEntropy,
        pvReserved,
        pPromptStruct,
        dwFlags,
        pDataOut
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptUnprotectData,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        ppszDataDescr != NULL ? copy_ptr(ppszDataDescr) : NULL,
        (uintptr_t) copy_uint32(&pOptionalEntropy->cbData), copy_ptr(&pOptionalEntropy->pbData),
        (uintptr_t) copy_uint32(&pDataOut->cbData), copy_ptr(&pDataOut->pbData)
    );

    log_debug("Leaving %s\n", "CryptUnprotectData");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_crypt32_CryptUnprotectMemory(
    LPVOID pData,
    DWORD cbData,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CryptUnprotectMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CryptUnprotectMemory");

        set_last_error(&lasterror);
        BOOL ret = Old_crypt32_CryptUnprotectMemory(
            pData,
            cbData,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_crypt32_CryptUnprotectMemory(
        pData,
        cbData,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_crypt32_CryptUnprotectMemory,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        (uintptr_t) cbData, pData
    );

    log_debug("Leaving %s\n", "CryptUnprotectMemory");

    set_last_error(&lasterror);
    return ret;
}

DNS_STATUS WINAPI New_dnsapi_DnsQuery_A(
    PCSTR lpstrName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD *ppQueryResultsSet,
    PVOID *pReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DnsQuery_A");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DnsQuery_A");

        set_last_error(&lasterror);
        DNS_STATUS ret = Old_dnsapi_DnsQuery_A(
            lpstrName,
            wType,
            Options,
            pExtra,
            ppQueryResultsSet,
            pReserved
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "sii", 
        lpstrName,
        wType,
        Options
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "DnsQuery_A");

        set_last_error(&lasterror);
        DNS_STATUS ret = Old_dnsapi_DnsQuery_A(
            lpstrName,
            wType,
            Options,
            pExtra,
            ppQueryResultsSet,
            pReserved
        );
        return ret;
    }

    set_last_error(&lasterror);
    DNS_STATUS ret = Old_dnsapi_DnsQuery_A(
        lpstrName,
        wType,
        Options,
        pExtra,
        ppQueryResultsSet,
        pReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_dnsapi_DnsQuery_A,
        ret == DNS_RCODE_NOERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpstrName,
        wType,
        Options
    );

    log_debug("Leaving %s\n", "DnsQuery_A");

    set_last_error(&lasterror);
    return ret;
}

DNS_STATUS WINAPI New_dnsapi_DnsQuery_UTF8(
    LPBYTE lpstrName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD *ppQueryResultsSet,
    PVOID *pReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DnsQuery_UTF8");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DnsQuery_UTF8");

        set_last_error(&lasterror);
        DNS_STATUS ret = Old_dnsapi_DnsQuery_UTF8(
            lpstrName,
            wType,
            Options,
            pExtra,
            ppQueryResultsSet,
            pReserved
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "sii", 
        lpstrName,
        wType,
        Options
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "DnsQuery_UTF8");

        set_last_error(&lasterror);
        DNS_STATUS ret = Old_dnsapi_DnsQuery_UTF8(
            lpstrName,
            wType,
            Options,
            pExtra,
            ppQueryResultsSet,
            pReserved
        );
        return ret;
    }

    set_last_error(&lasterror);
    DNS_STATUS ret = Old_dnsapi_DnsQuery_UTF8(
        lpstrName,
        wType,
        Options,
        pExtra,
        ppQueryResultsSet,
        pReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_dnsapi_DnsQuery_UTF8,
        ret == DNS_RCODE_NOERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        wType,
        Options,
        lpstrName
    );

    log_debug("Leaving %s\n", "DnsQuery_UTF8");

    set_last_error(&lasterror);
    return ret;
}

DNS_STATUS WINAPI New_dnsapi_DnsQuery_W(
    PWSTR lpstrName,
    WORD wType,
    DWORD Options,
    PVOID pExtra,
    PDNS_RECORD *ppQueryResultsSet,
    PVOID *pReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DnsQuery_W");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DnsQuery_W");

        set_last_error(&lasterror);
        DNS_STATUS ret = Old_dnsapi_DnsQuery_W(
            lpstrName,
            wType,
            Options,
            pExtra,
            ppQueryResultsSet,
            pReserved
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uii", 
        lpstrName,
        wType,
        Options
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "DnsQuery_W");

        set_last_error(&lasterror);
        DNS_STATUS ret = Old_dnsapi_DnsQuery_W(
            lpstrName,
            wType,
            Options,
            pExtra,
            ppQueryResultsSet,
            pReserved
        );
        return ret;
    }

    set_last_error(&lasterror);
    DNS_STATUS ret = Old_dnsapi_DnsQuery_W(
        lpstrName,
        wType,
        Options,
        pExtra,
        ppQueryResultsSet,
        pReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_dnsapi_DnsQuery_W,
        ret == DNS_RCODE_NOERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpstrName,
        wType,
        Options
    );

    log_debug("Leaving %s\n", "DnsQuery_W");

    set_last_error(&lasterror);
    return ret;
}

ULONG WINAPI New_iphlpapi_GetAdaptersAddresses(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses,
    PULONG SizePointer
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetAdaptersAddresses");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetAdaptersAddresses");

        set_last_error(&lasterror);
        ULONG ret = Old_iphlpapi_GetAdaptersAddresses(
            Family,
            Flags,
            Reserved,
            AdapterAddresses,
            SizePointer
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    ULONG ret = Old_iphlpapi_GetAdaptersAddresses(
        Family,
        Flags,
        Reserved,
        AdapterAddresses,
        SizePointer
    );
    get_last_error(&lasterror);

    log_api(SIG_iphlpapi_GetAdaptersAddresses,
        ret == ERROR_SUCCESS,
        (uintptr_t) ret,
        hash,
        &lasterror,
        Family,
        Flags
    );

    log_debug("Leaving %s\n", "GetAdaptersAddresses");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_iphlpapi_GetAdaptersInfo(
    PIP_ADAPTER_INFO pAdapterInfo,
    PULONG pOutBufLen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetAdaptersInfo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetAdaptersInfo");

        set_last_error(&lasterror);
        DWORD ret = Old_iphlpapi_GetAdaptersInfo(
            pAdapterInfo,
            pOutBufLen
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_iphlpapi_GetAdaptersInfo(
        pAdapterInfo,
        pOutBufLen
    );
    get_last_error(&lasterror);

    log_api(SIG_iphlpapi_GetAdaptersInfo,
        ret == NO_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GetAdaptersInfo");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_iphlpapi_GetBestInterfaceEx(
    struct sockaddr *pDestAddr,
    PDWORD pdwBestIfIndex
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetBestInterfaceEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetBestInterfaceEx");

        set_last_error(&lasterror);
        DWORD ret = Old_iphlpapi_GetBestInterfaceEx(
            pDestAddr,
            pdwBestIfIndex
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_iphlpapi_GetBestInterfaceEx(
        pDestAddr,
        pdwBestIfIndex
    );
    get_last_error(&lasterror);

    log_api(SIG_iphlpapi_GetBestInterfaceEx,
        ret == NO_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GetBestInterfaceEx");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_iphlpapi_GetInterfaceInfo(
    PIP_INTERFACE_INFO pIfTable,
    PULONG dwOutBufLen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetInterfaceInfo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetInterfaceInfo");

        set_last_error(&lasterror);
        DWORD ret = Old_iphlpapi_GetInterfaceInfo(
            pIfTable,
            dwOutBufLen
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_iphlpapi_GetInterfaceInfo(
        pIfTable,
        dwOutBufLen
    );
    get_last_error(&lasterror);

    log_api(SIG_iphlpapi_GetInterfaceInfo,
        ret == NO_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GetInterfaceInfo");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_jscript_ActiveXObjectFncObj_Construct(
    void *this,
    VAR *unk1,
    int unk2,
    VAR *args
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ActiveXObjectFncObj_Construct");
    
    wchar_t *objname = NULL; void *session = ((void **) this)[3];
    
    VAR *value = iexplore_var_getvalue(args, session);
    if(value != NULL) {
        objname = *((wchar_t **) value + 1);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_jscript_ActiveXObjectFncObj_Construct(
        this,
        unk1,
        unk2,
        args
    );
    get_last_error(&lasterror);
        
    log_api(SIG_jscript_ActiveXObjectFncObj_Construct,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        objname
    );
        

    log_debug("Leaving %s\n", "ActiveXObjectFncObj_Construct");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_jscript_COleScript_Compile(
    void *this,
    void *script_body,
    const wchar_t *script,
    uintptr_t unk1,
    uintptr_t unk2,
    uintptr_t unk3,
    const wchar_t *type,
    void *exception
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "COleScript_Compile");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_jscript_COleScript_Compile(
        this,
        script_body,
        script,
        unk1,
        unk2,
        unk3,
        type,
        exception
    );
    get_last_error(&lasterror);
        
    log_api(SIG_jscript_COleScript_Compile,
        ret >= 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        script,
        type
    );
        

    log_debug("Leaving %s\n", "COleScript_Compile");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_AssignProcessToJobObject(
    HANDLE hJob,
    HANDLE hProcess
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "AssignProcessToJobObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "AssignProcessToJobObject");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_AssignProcessToJobObject(
            hJob,
            hProcess
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_AssignProcessToJobObject(
        hJob,
        hProcess
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_AssignProcessToJobObject,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hJob,
        hProcess,
        pid_from_process_handle(hProcess)
    );

    log_debug("Leaving %s\n", "AssignProcessToJobObject");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_CopyFileA(
    LPCTSTR lpExistingFileName,
    LPCTSTR lpNewFileName,
    BOOL bFailIfExists
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CopyFileA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CopyFileA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CopyFileA(
            lpExistingFileName,
            lpNewFileName,
            bFailIfExists
        );
        return ret;
    }
    
    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathA(lpExistingFileName, oldfilepath);
    
    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_pathA(lpNewFileName, newfilepath);

    uint64_t hash = call_hash(
        "uu", 
        oldfilepath,
        newfilepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CopyFileA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CopyFileA(
            lpExistingFileName,
            lpNewFileName,
            bFailIfExists
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_CopyFileA(
        lpExistingFileName,
        lpNewFileName,
        bFailIfExists
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CopyFileA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        bFailIfExists,
        oldfilepath,
        lpExistingFileName,
        newfilepath,
        lpNewFileName
    );
    
    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);

    log_debug("Leaving %s\n", "CopyFileA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_CopyFileExW(
    LPWSTR lpExistingFileName,
    LPWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    LPBOOL pbCancel,
    DWORD dwCopyFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CopyFileExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CopyFileExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CopyFileExW(
            lpExistingFileName,
            lpNewFileName,
            lpProgressRoutine,
            lpData,
            pbCancel,
            dwCopyFlags
        );
        return ret;
    }
    
    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);
    
    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_pathW(lpNewFileName, newfilepath);

    uint64_t hash = call_hash(
        "uu", 
        oldfilepath,
        newfilepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CopyFileExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CopyFileExW(
            lpExistingFileName,
            lpNewFileName,
            lpProgressRoutine,
            lpData,
            pbCancel,
            dwCopyFlags
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_CopyFileExW(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CopyFileExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwCopyFlags,
        oldfilepath,
        lpExistingFileName,
        newfilepath,
        lpNewFileName
    );
    
    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);

    log_debug("Leaving %s\n", "CopyFileExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_CopyFileW(
    LPWSTR lpExistingFileName,
    LPWSTR lpNewFileName,
    BOOL bFailIfExists
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CopyFileW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CopyFileW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CopyFileW(
            lpExistingFileName,
            lpNewFileName,
            bFailIfExists
        );
        return ret;
    }
    
    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);
    
    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_pathW(lpNewFileName, newfilepath);

    uint64_t hash = call_hash(
        "uu", 
        oldfilepath,
        newfilepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CopyFileW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CopyFileW(
            lpExistingFileName,
            lpNewFileName,
            bFailIfExists
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_CopyFileW(
        lpExistingFileName,
        lpNewFileName,
        bFailIfExists
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CopyFileW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        bFailIfExists,
        oldfilepath,
        lpExistingFileName,
        newfilepath,
        lpNewFileName
    );
    
    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);

    log_debug("Leaving %s\n", "CopyFileW");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_CreateActCtxW(
    PACTCTX pActCtx
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateActCtxW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateActCtxW");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateActCtxW(
            pActCtx
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_CreateActCtxW(
        pActCtx
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateActCtxW,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        pActCtx != NULL ? copy_ptr(&pActCtx->lpResourceName) : NULL,
        pActCtx != NULL ? copy_ptr(&pActCtx->lpApplicationName) : NULL,
        pActCtx != NULL ? copy_ptr(&pActCtx->hModule) : NULL
    );

    log_debug("Leaving %s\n", "CreateActCtxW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_CreateDirectoryExW(
    LPWSTR lpTemplateDirectory,
    LPWSTR lpNewDirectory,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateDirectoryExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateDirectoryExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CreateDirectoryExW(
            lpTemplateDirectory,
            lpNewDirectory,
            lpSecurityAttributes
        );
        return ret;
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(lpNewDirectory, dirpath);

    uint64_t hash = call_hash(
        "u", 
        dirpath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CreateDirectoryExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CreateDirectoryExW(
            lpTemplateDirectory,
            lpNewDirectory,
            lpSecurityAttributes
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_CreateDirectoryExW(
        lpTemplateDirectory,
        lpNewDirectory,
        lpSecurityAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateDirectoryExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dirpath,
        lpNewDirectory
    );
    
    free_unicode_buffer(dirpath);

    log_debug("Leaving %s\n", "CreateDirectoryExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_CreateDirectoryW(
    LPWSTR lpPathName,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateDirectoryW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateDirectoryW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CreateDirectoryW(
            lpPathName,
            lpSecurityAttributes
        );
        return ret;
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(lpPathName, dirpath);

    uint64_t hash = call_hash(
        "u", 
        dirpath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CreateDirectoryW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CreateDirectoryW(
            lpPathName,
            lpSecurityAttributes
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_CreateDirectoryW(
        lpPathName,
        lpSecurityAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateDirectoryW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dirpath,
        lpPathName
    );
    
    free_unicode_buffer(dirpath);

    log_debug("Leaving %s\n", "CreateDirectoryW");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_CreateJobObjectW(
    LPSECURITY_ATTRIBUTES lpJobAttributes,
    LPCTSTR lpName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateJobObjectW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateJobObjectW");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateJobObjectW(
            lpJobAttributes,
            lpName
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_CreateJobObjectW(
        lpJobAttributes,
        lpName
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateJobObjectW,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpName,
        ret
    );

    log_debug("Leaving %s\n", "CreateJobObjectW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_CreateProcessInternalW(
    LPVOID lpUnknown1,
    LPWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPWSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    LPVOID lpUnknown2
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateProcessInternalW");

    PROCESS_INFORMATION _lpProcessInformation;
    if(lpProcessInformation == NULL) {
        lpProcessInformation = &_lpProcessInformation;
        memset(&_lpProcessInformation, 0, sizeof(PROCESS_INFORMATION));
    }
    
    // Ensure the CREATE_SUSPENDED flag is set when calling
    // the original function.
    DWORD creation_flags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpApplicationName, filepath);

    uint64_t hash = call_hash(
        "uuiiu", 
        filepath,
        lpCommandLine,
        bInheritHandles,
        creation_flags,
        lpCurrentDirectory
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CreateProcessInternalW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_CreateProcessInternalW(
            lpUnknown1,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation,
            lpUnknown2
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_CreateProcessInternalW(
        lpUnknown1,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        lpUnknown2
    );
    get_last_error(&lasterror);
    
    int track = 0;
    
    if(ret != FALSE) {
        uint32_t mode = HOOK_MODE_ALL;
    
        const wchar_t *command_line = lpCommandLine;
        if(command_line == NULL) {
            command_line = lpApplicationName;
        }
    
        // Let's ask nicely whether we want to propagate execution into this
        // new process and if so, in what monitoring mode.
        if(monitor_mode_should_propagate(command_line, &mode) == 0) {
            pipe("PROCESS2:%d,%d,%d",
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId,
                mode);
            track = 1;
        }
    }
        
    log_api(SIG_kernel32_CreateProcessInternalW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpCommandLine,
        bInheritHandles,
        lpCurrentDirectory,
        filepath,
        lpApplicationName,
        creation_flags,
        lpProcessInformation->dwProcessId,
        lpProcessInformation->dwThreadId,
        lpProcessInformation->hProcess,
        lpProcessInformation->hThread,
        track
    );
        
    
    if(ret != FALSE) {
        // If the CREATE_SUSPENDED flag was not set then we have to resume
        // the main thread ourselves.
        if((creation_flags & CREATE_SUSPENDED) == 0) {
            ResumeThread(lpProcessInformation->hThread);
        }
    
        sleep_skip_disable();
    }
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "CreateProcessInternalW");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_CreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateRemoteThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateRemoteThread");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateRemoteThread(
            hProcess,
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags,
            lpThreadId
        );
        return ret;
    }
    
    uint32_t pid = pid_from_process_handle(hProcess);
    pipe("PROCESS:%d", pid);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_CreateRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateRemoteThread,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hProcess,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId,
        pid
    );
    
    if(ret != NULL) {
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "CreateRemoteThread");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_CreateRemoteThreadEx(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateRemoteThreadEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateRemoteThreadEx");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateRemoteThreadEx(
            hProcess,
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags,
            lpAttributeList,
            lpThreadId
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_CreateRemoteThreadEx(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpAttributeList,
        lpThreadId
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateRemoteThreadEx,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hProcess,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    );

    log_debug("Leaving %s\n", "CreateRemoteThreadEx");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_CreateThread(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateThread");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateThread(
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags,
            lpThreadId
        );
        return ret;
    }

    DWORD _lpThreadId;
    if(lpThreadId == NULL) {
        lpThreadId = &_lpThreadId;
        memset(&_lpThreadId, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_CreateThread(
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateThread,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId
    );
    
    if(ret != NULL) {
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "CreateThread");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CreateToolhelp32Snapshot");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CreateToolhelp32Snapshot");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateToolhelp32Snapshot(
            dwFlags,
            th32ProcessID
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ii", 
        dwFlags,
        th32ProcessID
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CreateToolhelp32Snapshot");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_CreateToolhelp32Snapshot(
            dwFlags,
            th32ProcessID
        );
        return ret;
    }

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_CreateToolhelp32Snapshot(
        dwFlags,
        th32ProcessID
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_CreateToolhelp32Snapshot,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        th32ProcessID
    );

    log_debug("Leaving %s\n", "CreateToolhelp32Snapshot");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_DeleteFileW(
    LPWSTR lpFileName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DeleteFileW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DeleteFileW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_DeleteFileW(
            lpFileName
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);
    pipe("FILE_DEL:%Z", filepath);

    uint64_t hash = call_hash(
        "u", 
        filepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "DeleteFileW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_DeleteFileW(
            lpFileName
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_DeleteFileW(
        lpFileName
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_DeleteFileW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        lpFileName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "DeleteFileW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_DeviceIoControl(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DeviceIoControl");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DeviceIoControl");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_DeviceIoControl(
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped
        );
        return ret;
    }

    DWORD _lpBytesReturned;
    if(lpBytesReturned == NULL) {
        lpBytesReturned = &_lpBytesReturned;
        memset(&_lpBytesReturned, 0, sizeof(DWORD));
    }

    uint64_t hash = call_hash(
        "h", 
        hDevice
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "DeviceIoControl");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_DeviceIoControl(
            hDevice,
            dwIoControlCode,
            lpInBuffer,
            nInBufferSize,
            lpOutBuffer,
            nOutBufferSize,
            lpBytesReturned,
            lpOverlapped
        );
        return ret;
    }

    uintptr_t prelen = nInBufferSize;
    uint8_t *prebuf = memdup(lpInBuffer, prelen);

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_DeviceIoControl(
        hDevice,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize,
        lpBytesReturned,
        lpOverlapped
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_DeviceIoControl,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf,
        hDevice,
        dwIoControlCode,
        (uintptr_t) copy_uint32(lpBytesReturned), lpOutBuffer
    );

    log_debug("Leaving %s\n", "DeviceIoControl");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

HANDLE WINAPI New_kernel32_FindFirstFileExA(
    LPCTSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindFirstFileExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindFirstFileExA");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_FindFirstFileExA(
            lpFileName,
            fInfoLevelId,
            lpFindFileData,
            fSearchOp,
            lpSearchFilter,
            dwAdditionalFlags
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathA(lpFileName, filepath);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_FindFirstFileExA(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_FindFirstFileExA,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        lpFileName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "FindFirstFileExA");

    set_last_error(&lasterror);
    return ret;
}

HANDLE WINAPI New_kernel32_FindFirstFileExW(
    LPWSTR lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp,
    LPVOID lpSearchFilter,
    DWORD dwAdditionalFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindFirstFileExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindFirstFileExW");

        set_last_error(&lasterror);
        HANDLE ret = Old_kernel32_FindFirstFileExW(
            lpFileName,
            fInfoLevelId,
            lpFindFileData,
            fSearchOp,
            lpSearchFilter,
            dwAdditionalFlags
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HANDLE ret = Old_kernel32_FindFirstFileExW(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_FindFirstFileExW,
        ret != NULL && ret != INVALID_HANDLE_VALUE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        lpFileName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "FindFirstFileExW");

    set_last_error(&lasterror);
    return ret;
}

HRSRC WINAPI New_kernel32_FindResourceA(
    HMODULE hModule,
    LPCSTR lpName,
    LPCSTR lpType
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindResourceA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindResourceA");

        set_last_error(&lasterror);
        HRSRC ret = Old_kernel32_FindResourceA(
            hModule,
            lpName,
            lpType
        );
        return ret;
    }
    
    char value[10], value2[10], *name, *type;
    
    int_or_strA(&name, lpName, value);
    int_or_strA(&type, lpType, value2);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRSRC ret = Old_kernel32_FindResourceA(
        hModule,
        lpName,
        lpType
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_FindResourceA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hModule,
        name,
        type
    );

    log_debug("Leaving %s\n", "FindResourceA");

    set_last_error(&lasterror);
    return ret;
}

HRSRC WINAPI New_kernel32_FindResourceExA(
    HMODULE hModule,
    LPCSTR lpName,
    LPCSTR lpType,
    WORD wLanguage
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindResourceExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindResourceExA");

        set_last_error(&lasterror);
        HRSRC ret = Old_kernel32_FindResourceExA(
            hModule,
            lpName,
            lpType,
            wLanguage
        );
        return ret;
    }
    
    char value[10], value2[10], *name, *type;
    
    int_or_strA(&name, lpName, value);
    int_or_strA(&type, lpType, value2);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRSRC ret = Old_kernel32_FindResourceExA(
        hModule,
        lpName,
        lpType,
        wLanguage
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_FindResourceExA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hModule,
        wLanguage,
        name,
        type
    );

    log_debug("Leaving %s\n", "FindResourceExA");

    set_last_error(&lasterror);
    return ret;
}

HRSRC WINAPI New_kernel32_FindResourceExW(
    HMODULE hModule,
    LPWSTR lpName,
    LPWSTR lpType,
    WORD wLanguage
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindResourceExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindResourceExW");

        set_last_error(&lasterror);
        HRSRC ret = Old_kernel32_FindResourceExW(
            hModule,
            lpName,
            lpType,
            wLanguage
        );
        return ret;
    }
    
    wchar_t value[10], value2[10], *name, *type;
    
    int_or_strW(&name, lpName, value);
    int_or_strW(&type, lpType, value2);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRSRC ret = Old_kernel32_FindResourceExW(
        hModule,
        lpName,
        lpType,
        wLanguage
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_FindResourceExW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hModule,
        wLanguage,
        name,
        type
    );

    log_debug("Leaving %s\n", "FindResourceExW");

    set_last_error(&lasterror);
    return ret;
}

HRSRC WINAPI New_kernel32_FindResourceW(
    HMODULE hModule,
    LPWSTR lpName,
    LPWSTR lpType
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindResourceW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindResourceW");

        set_last_error(&lasterror);
        HRSRC ret = Old_kernel32_FindResourceW(
            hModule,
            lpName,
            lpType
        );
        return ret;
    }
    
    wchar_t value[10], value2[10], *name, *type;
    
    int_or_strW(&name, lpName, value);
    int_or_strW(&type, lpType, value2);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRSRC ret = Old_kernel32_FindResourceW(
        hModule,
        lpName,
        lpType
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_FindResourceW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hModule,
        name,
        type
    );

    log_debug("Leaving %s\n", "FindResourceW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetComputerNameA(
    LPCSTR lpBuffer,
    LPDWORD lpnSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetComputerNameA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetComputerNameA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetComputerNameA(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    DWORD _lpnSize;
    if(lpnSize == NULL) {
        lpnSize = &_lpnSize;
        memset(&_lpnSize, 0, sizeof(DWORD));
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetComputerNameA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetComputerNameA(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetComputerNameA(
        lpBuffer,
        lpnSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetComputerNameA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        copy_uint32(lpnSize), lpBuffer
    );

    log_debug("Leaving %s\n", "GetComputerNameA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetComputerNameW(
    LPWSTR lpBuffer,
    LPDWORD lpnSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetComputerNameW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetComputerNameW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetComputerNameW(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    DWORD _lpnSize;
    if(lpnSize == NULL) {
        lpnSize = &_lpnSize;
        memset(&_lpnSize, 0, sizeof(DWORD));
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetComputerNameW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetComputerNameW(
            lpBuffer,
            lpnSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetComputerNameW(
        lpBuffer,
        lpnSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetComputerNameW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        copy_uint32(lpnSize), lpBuffer
    );

    log_debug("Leaving %s\n", "GetComputerNameW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetDiskFreeSpaceExW(
    LPWSTR lpDirectoryName,
    PULARGE_INTEGER lpFreeBytesAvailable,
    PULARGE_INTEGER lpTotalNumberOfBytes,
    PULARGE_INTEGER lpTotalNumberOfFreeBytes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetDiskFreeSpaceExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetDiskFreeSpaceExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetDiskFreeSpaceExW(
            lpDirectoryName,
            lpFreeBytesAvailable,
            lpTotalNumberOfBytes,
            lpTotalNumberOfFreeBytes
        );
        return ret;
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetDiskFreeSpaceExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetDiskFreeSpaceExW(
            lpDirectoryName,
            lpFreeBytesAvailable,
            lpTotalNumberOfBytes,
            lpTotalNumberOfFreeBytes
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetDiskFreeSpaceExW(
        lpDirectoryName,
        lpFreeBytesAvailable,
        lpTotalNumberOfBytes,
        lpTotalNumberOfFreeBytes
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetDiskFreeSpaceExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpDirectoryName,
        lpFreeBytesAvailable,
        lpTotalNumberOfBytes,
        lpTotalNumberOfFreeBytes
    );

    log_debug("Leaving %s\n", "GetDiskFreeSpaceExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetDiskFreeSpaceW(
    LPWSTR lpRootPathName,
    LPDWORD lpSectorsPerCluster,
    LPDWORD lpBytesPerSector,
    LPDWORD lpNumberOfFreeClusters,
    LPDWORD lpTotalNumberOfClusters
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetDiskFreeSpaceW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetDiskFreeSpaceW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetDiskFreeSpaceW(
            lpRootPathName,
            lpSectorsPerCluster,
            lpBytesPerSector,
            lpNumberOfFreeClusters,
            lpTotalNumberOfClusters
        );
        return ret;
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetDiskFreeSpaceW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetDiskFreeSpaceW(
            lpRootPathName,
            lpSectorsPerCluster,
            lpBytesPerSector,
            lpNumberOfFreeClusters,
            lpTotalNumberOfClusters
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetDiskFreeSpaceW(
        lpRootPathName,
        lpSectorsPerCluster,
        lpBytesPerSector,
        lpNumberOfFreeClusters,
        lpTotalNumberOfClusters
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetDiskFreeSpaceW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpRootPathName,
        lpSectorsPerCluster,
        lpBytesPerSector,
        lpNumberOfFreeClusters,
        lpTotalNumberOfClusters
    );

    log_debug("Leaving %s\n", "GetDiskFreeSpaceW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetFileAttributesExW(
    LPCWSTR lpFileName,
    GET_FILEEX_INFO_LEVELS fInfoLevelId,
    LPVOID lpFileInformation
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileAttributesExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileAttributesExW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetFileAttributesExW(
            lpFileName,
            fInfoLevelId,
            lpFileInformation
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetFileAttributesExW(
        lpFileName,
        fInfoLevelId,
        lpFileInformation
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileAttributesExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        fInfoLevelId,
        filepath,
        lpFileName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "GetFileAttributesExW");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_GetFileAttributesW(
    LPCWSTR lpFileName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileAttributesW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileAttributesW");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetFileAttributesW(
            lpFileName
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetFileAttributesW(
        lpFileName
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileAttributesW,
        ret != INVALID_FILE_ATTRIBUTES,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        lpFileName,
        ret
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "GetFileAttributesW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetFileInformationByHandle(
    HANDLE hFile,
    LPBY_HANDLE_FILE_INFORMATION lpFIleInformation
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileInformationByHandle");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileInformationByHandle");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetFileInformationByHandle(
            hFile,
            lpFIleInformation
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetFileInformationByHandle(
        hFile,
        lpFIleInformation
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileInformationByHandle,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile
    );

    log_debug("Leaving %s\n", "GetFileInformationByHandle");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetFileInformationByHandleEx(
    HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFIleInformation,
    DWORD dwBufferSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileInformationByHandleEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileInformationByHandleEx");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetFileInformationByHandleEx(
            hFile,
            FileInformationClass,
            lpFIleInformation,
            dwBufferSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetFileInformationByHandleEx(
        hFile,
        FileInformationClass,
        lpFIleInformation,
        dwBufferSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileInformationByHandleEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        FileInformationClass
    );

    log_debug("Leaving %s\n", "GetFileInformationByHandleEx");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_GetFileSize(
    HANDLE hFile,
    LPDWORD lpFileSizeHigh
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileSize");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileSize");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetFileSize(
            hFile,
            lpFileSizeHigh
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetFileSize(
        hFile,
        lpFileSizeHigh
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileSize,
        ret != INVALID_FILE_SIZE && lpFileSizeHigh != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        ret
    );

    log_debug("Leaving %s\n", "GetFileSize");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetFileSizeEx(
    HANDLE hFile,
    PLARGE_INTEGER lpFileSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileSizeEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileSizeEx");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetFileSizeEx(
            hFile,
            lpFileSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetFileSizeEx(
        hFile,
        lpFileSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileSizeEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        lpFileSize
    );

    log_debug("Leaving %s\n", "GetFileSizeEx");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_GetFileType(
    HANDLE hFile
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileType");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileType");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetFileType(
            hFile
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetFileType(
        hFile
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetFileType,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile
    );

    log_debug("Leaving %s\n", "GetFileType");

    set_last_error(&lasterror);
    return ret;
}

void WINAPI New_kernel32_GetLocalTime(
    LPSYSTEMTIME lpSystemTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetLocalTime");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetLocalTime");

        set_last_error(&lasterror);
        Old_kernel32_GetLocalTime(
            lpSystemTime
        );
        return;
    }

    set_last_error(&lasterror);
    Old_kernel32_GetLocalTime(
        lpSystemTime
    );
    get_last_error(&lasterror);
    
    sleep_apply_systemtime(lpSystemTime);

    log_debug("Leaving %s\n", "GetLocalTime");

    set_last_error(&lasterror);
}

void WINAPI New_kernel32_GetNativeSystemInfo(
    LPSYSTEM_INFO lpSystemInfo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetNativeSystemInfo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetNativeSystemInfo");

        set_last_error(&lasterror);
        Old_kernel32_GetNativeSystemInfo(
            lpSystemInfo
        );
        return;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    Old_kernel32_GetNativeSystemInfo(
        lpSystemInfo
    );
    get_last_error(&lasterror);
    
    uint32_t processor_count = lpSystemInfo->dwNumberOfProcessors;
    
    // The PEB either contains the real number of processors or the number
    // of processors that we spoofed into it.
    lpSystemInfo->dwNumberOfProcessors = get_peb()->NumberOfProcessors;

    log_api(SIG_kernel32_GetNativeSystemInfo,
        1,
        0,
        hash,
        &lasterror,
        processor_count
    );

    log_debug("Leaving %s\n", "GetNativeSystemInfo");

    set_last_error(&lasterror);
}

DWORD WINAPI New_kernel32_GetShortPathNameW(
    LPCWSTR lpszLongPath,
    LPWSTR lpszShortPath,
    DWORD cchBuffer
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetShortPathNameW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetShortPathNameW");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetShortPathNameW(
            lpszLongPath,
            lpszShortPath,
            cchBuffer
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetShortPathNameW(
        lpszLongPath,
        lpszShortPath,
        cchBuffer
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetShortPathNameW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszLongPath,
        lpszShortPath
    );

    log_debug("Leaving %s\n", "GetShortPathNameW");

    set_last_error(&lasterror);
    return ret;
}

UINT WINAPI New_kernel32_GetSystemDirectoryA(
    LPTSTR lpBuffer,
    UINT uSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemDirectoryA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemDirectoryA");

        set_last_error(&lasterror);
        UINT ret = Old_kernel32_GetSystemDirectoryA(
            lpBuffer,
            uSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    UINT ret = Old_kernel32_GetSystemDirectoryA(
        lpBuffer,
        uSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetSystemDirectoryA,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ret, lpBuffer
    );

    log_debug("Leaving %s\n", "GetSystemDirectoryA");

    set_last_error(&lasterror);
    return ret;
}

UINT WINAPI New_kernel32_GetSystemDirectoryW(
    LPWSTR lpBuffer,
    UINT uSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemDirectoryW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemDirectoryW");

        set_last_error(&lasterror);
        UINT ret = Old_kernel32_GetSystemDirectoryW(
            lpBuffer,
            uSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    UINT ret = Old_kernel32_GetSystemDirectoryW(
        lpBuffer,
        uSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetSystemDirectoryW,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ret, lpBuffer
    );

    log_debug("Leaving %s\n", "GetSystemDirectoryW");

    set_last_error(&lasterror);
    return ret;
}

void WINAPI New_kernel32_GetSystemInfo(
    LPSYSTEM_INFO lpSystemInfo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemInfo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemInfo");

        set_last_error(&lasterror);
        Old_kernel32_GetSystemInfo(
            lpSystemInfo
        );
        return;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    Old_kernel32_GetSystemInfo(
        lpSystemInfo
    );
    get_last_error(&lasterror);
    
    uint32_t processor_count = lpSystemInfo->dwNumberOfProcessors;
    
    // The PEB either contains the real number of processors or the number
    // of processors that we spoofed into it.
    lpSystemInfo->dwNumberOfProcessors = get_peb()->NumberOfProcessors;

    log_api(SIG_kernel32_GetSystemInfo,
        1,
        0,
        hash,
        &lasterror,
        processor_count
    );

    log_debug("Leaving %s\n", "GetSystemInfo");

    set_last_error(&lasterror);
}

void WINAPI New_kernel32_GetSystemTime(
    LPSYSTEMTIME lpSystemTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemTime");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemTime");

        set_last_error(&lasterror);
        Old_kernel32_GetSystemTime(
            lpSystemTime
        );
        return;
    }

    set_last_error(&lasterror);
    Old_kernel32_GetSystemTime(
        lpSystemTime
    );
    get_last_error(&lasterror);
    
    sleep_apply_systemtime(lpSystemTime);

    log_debug("Leaving %s\n", "GetSystemTime");

    set_last_error(&lasterror);
}

void WINAPI New_kernel32_GetSystemTimeAsFileTime(
    LPFILETIME lpSystemTimeAsFileTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemTimeAsFileTime");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemTimeAsFileTime");

        set_last_error(&lasterror);
        Old_kernel32_GetSystemTimeAsFileTime(
            lpSystemTimeAsFileTime
        );
        return;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    Old_kernel32_GetSystemTimeAsFileTime(
        lpSystemTimeAsFileTime
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetSystemTimeAsFileTime,
        1,
        0,
        hash,
        &lasterror
    );
    
    sleep_apply_filetime(lpSystemTimeAsFileTime);

    log_debug("Leaving %s\n", "GetSystemTimeAsFileTime");

    set_last_error(&lasterror);
}

UINT WINAPI New_kernel32_GetSystemWindowsDirectoryA(
    LPTSTR lpBuffer,
    UINT uSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemWindowsDirectoryA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemWindowsDirectoryA");

        set_last_error(&lasterror);
        UINT ret = Old_kernel32_GetSystemWindowsDirectoryA(
            lpBuffer,
            uSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    UINT ret = Old_kernel32_GetSystemWindowsDirectoryA(
        lpBuffer,
        uSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetSystemWindowsDirectoryA,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ret, lpBuffer
    );

    log_debug("Leaving %s\n", "GetSystemWindowsDirectoryA");

    set_last_error(&lasterror);
    return ret;
}

UINT WINAPI New_kernel32_GetSystemWindowsDirectoryW(
    LPWSTR lpBuffer,
    UINT uSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemWindowsDirectoryW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemWindowsDirectoryW");

        set_last_error(&lasterror);
        UINT ret = Old_kernel32_GetSystemWindowsDirectoryW(
            lpBuffer,
            uSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    UINT ret = Old_kernel32_GetSystemWindowsDirectoryW(
        lpBuffer,
        uSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetSystemWindowsDirectoryW,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ret, lpBuffer
    );

    log_debug("Leaving %s\n", "GetSystemWindowsDirectoryW");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_GetTempPathW(
    DWORD nBufferLength,
    LPWSTR lpBuffer
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetTempPathW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetTempPathW");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetTempPathW(
            nBufferLength,
            lpBuffer
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetTempPathW(
        nBufferLength,
        lpBuffer
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetTempPathW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ret, lpBuffer
    );

    log_debug("Leaving %s\n", "GetTempPathW");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_GetTickCount(
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetTickCount");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetTickCount");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetTickCount(
        );
        return ret;
    }

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetTickCount(
    );
    get_last_error(&lasterror);
    
    ret += sleep_skipped() / 10000;

    log_debug("Leaving %s\n", "GetTickCount");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_GetTimeZoneInformation(
    LPTIME_ZONE_INFORMATION lpTimeZoneInformation
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetTimeZoneInformation");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetTimeZoneInformation");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_GetTimeZoneInformation(
            lpTimeZoneInformation
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_GetTimeZoneInformation(
        lpTimeZoneInformation
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetTimeZoneInformation,
        ret != TIME_ZONE_ID_INVALID,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GetTimeZoneInformation");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetVolumeNameForVolumeMountPointW(
    LPCWSTR lpszVolumeMountPoint,
    LPWSTR lpszVolumeName,
    DWORD cchBufferLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetVolumeNameForVolumeMountPointW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetVolumeNameForVolumeMountPointW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetVolumeNameForVolumeMountPointW(
            lpszVolumeMountPoint,
            lpszVolumeName,
            cchBufferLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetVolumeNameForVolumeMountPointW(
        lpszVolumeMountPoint,
        lpszVolumeName,
        cchBufferLength
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetVolumeNameForVolumeMountPointW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszVolumeMountPoint,
        lpszVolumeName
    );

    log_debug("Leaving %s\n", "GetVolumeNameForVolumeMountPointW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetVolumePathNameW(
    LPCWSTR lpszFileName,
    LPWSTR lpszVolumePathName,
    DWORD cchBufferLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetVolumePathNameW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetVolumePathNameW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetVolumePathNameW(
            lpszFileName,
            lpszVolumePathName,
            cchBufferLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetVolumePathNameW(
        lpszFileName,
        lpszVolumePathName,
        cchBufferLength
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetVolumePathNameW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszFileName,
        lpszVolumePathName
    );

    log_debug("Leaving %s\n", "GetVolumePathNameW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GetVolumePathNamesForVolumeNameW(
    LPCWSTR lpszVolumeName,
    LPWSTR lpszVolumePathNames,
    DWORD cchBufferLength,
    PDWORD lpcchReturnLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetVolumePathNamesForVolumeNameW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetVolumePathNamesForVolumeNameW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GetVolumePathNamesForVolumeNameW(
            lpszVolumeName,
            lpszVolumePathNames,
            cchBufferLength,
            lpcchReturnLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GetVolumePathNamesForVolumeNameW(
        lpszVolumeName,
        lpszVolumePathNames,
        cchBufferLength,
        lpcchReturnLength
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_GetVolumePathNamesForVolumeNameW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszVolumeName,
        lpszVolumePathNames
    );

    log_debug("Leaving %s\n", "GetVolumePathNamesForVolumeNameW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GlobalMemoryStatus(
    LPMEMORYSTATUS lpBuffer
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GlobalMemoryStatus");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GlobalMemoryStatus");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GlobalMemoryStatus(
            lpBuffer
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GlobalMemoryStatus(
        lpBuffer
    );
    get_last_error(&lasterror);
    
    lpBuffer->dwTotalPhys += g_extra_virtual_memory;
    lpBuffer->dwTotalVirtual += g_extra_virtual_memory;

    log_api(SIG_kernel32_GlobalMemoryStatus,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GlobalMemoryStatus");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_GlobalMemoryStatusEx(
    LPMEMORYSTATUSEX lpBuffer
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GlobalMemoryStatusEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GlobalMemoryStatusEx");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_GlobalMemoryStatusEx(
            lpBuffer
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_GlobalMemoryStatusEx(
        lpBuffer
    );
    get_last_error(&lasterror);
    
    lpBuffer->ullTotalPhys += g_extra_virtual_memory;
    lpBuffer->ullTotalVirtual += g_extra_virtual_memory;

    log_api(SIG_kernel32_GlobalMemoryStatusEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GlobalMemoryStatusEx");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_IsDebuggerPresent(
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "IsDebuggerPresent");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "IsDebuggerPresent");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_IsDebuggerPresent(
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_IsDebuggerPresent(
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_IsDebuggerPresent,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "IsDebuggerPresent");

    set_last_error(&lasterror);
    return ret;
}

HGLOBAL WINAPI New_kernel32_LoadResource(
    HMODULE hModule,
    HRSRC hResInfo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LoadResource");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LoadResource");

        set_last_error(&lasterror);
        HGLOBAL ret = Old_kernel32_LoadResource(
            hModule,
            hResInfo
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HGLOBAL ret = Old_kernel32_LoadResource(
        hModule,
        hResInfo
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_LoadResource,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hModule,
        hResInfo,
        ret
    );

    log_debug("Leaving %s\n", "LoadResource");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_Module32FirstW(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Module32FirstW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Module32FirstW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_Module32FirstW(
            hSnapshot,
            lpme
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_Module32FirstW(
        hSnapshot,
        lpme
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_Module32FirstW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSnapshot
    );

    log_debug("Leaving %s\n", "Module32FirstW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_Module32NextW(
    HANDLE hSnapshot,
    LPMODULEENTRY32W lpme
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Module32NextW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Module32NextW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_Module32NextW(
            hSnapshot,
            lpme
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_Module32NextW(
        hSnapshot,
        lpme
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_Module32NextW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSnapshot
    );

    log_debug("Leaving %s\n", "Module32NextW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_MoveFileWithProgressW(
    LPWSTR lpExistingFileName,
    LPWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "MoveFileWithProgressW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "MoveFileWithProgressW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_MoveFileWithProgressW(
            lpExistingFileName,
            lpNewFileName,
            lpProgressRoutine,
            lpData,
            dwFlags
        );
        return ret;
    }
    
    wchar_t *oldfilepath = get_unicode_buffer();
    path_get_full_pathW(lpExistingFileName, oldfilepath);
    
    wchar_t *newfilepath = get_unicode_buffer();
    if(lpNewFileName != NULL) {
        path_get_full_pathW(lpNewFileName, newfilepath);
    }

    uint64_t hash = call_hash(
        "uu", 
        oldfilepath,
        newfilepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "MoveFileWithProgressW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_MoveFileWithProgressW(
            lpExistingFileName,
            lpNewFileName,
            lpProgressRoutine,
            lpData,
            dwFlags
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_MoveFileWithProgressW(
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_MoveFileWithProgressW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        oldfilepath,
        lpExistingFileName,
        newfilepath,
        lpNewFileName
    );
    
    if(ret != FALSE) {
        if(lpNewFileName == NULL) {
            pipe("FILE_DEL:%Z", oldfilepath);
        }
        else {
            pipe("FILE_MOVE:%Z::%Z", oldfilepath, newfilepath);
        }
    }
    
    free_unicode_buffer(oldfilepath);
    free_unicode_buffer(newfilepath);

    log_debug("Leaving %s\n", "MoveFileWithProgressW");

    set_last_error(&lasterror);
    return ret;
}

void WINAPI New_kernel32_OutputDebugStringA(
    LPSTR lpOutputString
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OutputDebugStringA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OutputDebugStringA");

        set_last_error(&lasterror);
        Old_kernel32_OutputDebugStringA(
            lpOutputString
        );
        return;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    Old_kernel32_OutputDebugStringA(
        lpOutputString
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_OutputDebugStringA,
        1,
        0,
        hash,
        &lasterror,
        lpOutputString
    );

    log_debug("Leaving %s\n", "OutputDebugStringA");

    set_last_error(&lasterror);
}

BOOL WINAPI New_kernel32_Process32FirstW(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Process32FirstW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Process32FirstW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_Process32FirstW(
            hSnapshot,
            lppe
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_Process32FirstW(
        hSnapshot,
        lppe
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_Process32FirstW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSnapshot,
        lppe->szExeFile,
        copy_uint32(&lppe->th32ProcessID)
    );

    log_debug("Leaving %s\n", "Process32FirstW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_Process32NextW(
    HANDLE hSnapshot,
    LPPROCESSENTRY32W lppe
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Process32NextW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Process32NextW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_Process32NextW(
            hSnapshot,
            lppe
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_Process32NextW(
        hSnapshot,
        lppe
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_Process32NextW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSnapshot,
        lppe->szExeFile,
        copy_uint32(&lppe->th32ProcessID)
    );

    log_debug("Leaving %s\n", "Process32NextW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesRead
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ReadProcessMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ReadProcessMemory");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_ReadProcessMemory(
            hProcess,
            lpBaseAddress,
            lpBuffer,
            nSize,
            lpNumberOfBytesRead
        );
        return ret;
    }

    SIZE_T _lpNumberOfBytesRead;
    if(lpNumberOfBytesRead == NULL) {
        lpNumberOfBytesRead = &_lpNumberOfBytesRead;
        memset(&_lpNumberOfBytesRead, 0, sizeof(SIZE_T));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_ReadProcessMemory(
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesRead
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_ReadProcessMemory,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hProcess,
        lpBaseAddress,
        lpNumberOfBytesRead, lpBuffer
    );

    log_debug("Leaving %s\n", "ReadProcessMemory");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_RemoveDirectoryA(
    LPCTSTR lpPathName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RemoveDirectoryA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RemoveDirectoryA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_RemoveDirectoryA(
            lpPathName
        );
        return ret;
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathA(lpPathName, dirpath);

    uint64_t hash = call_hash(
        "u", 
        dirpath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RemoveDirectoryA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_RemoveDirectoryA(
            lpPathName
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_RemoveDirectoryA(
        lpPathName
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_RemoveDirectoryA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dirpath,
        lpPathName
    );
    
    free_unicode_buffer(dirpath);

    log_debug("Leaving %s\n", "RemoveDirectoryA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_RemoveDirectoryW(
    LPWSTR lpPathName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RemoveDirectoryW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RemoveDirectoryW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_RemoveDirectoryW(
            lpPathName
        );
        return ret;
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(lpPathName, dirpath);

    uint64_t hash = call_hash(
        "u", 
        dirpath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RemoveDirectoryW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_RemoveDirectoryW(
            lpPathName
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_RemoveDirectoryW(
        lpPathName
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_RemoveDirectoryW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dirpath,
        lpPathName
    );
    
    free_unicode_buffer(dirpath);

    log_debug("Leaving %s\n", "RemoveDirectoryW");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_SearchPathW(
    LPCWSTR lpPath,
    LPCWSTR lpFileName,
    LPCWSTR lpExtension,
    DWORD nBufferLength,
    LPWSTR lpBuffer,
    LPWSTR *lpFilePart
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SearchPathW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SearchPathW");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_SearchPathW(
            lpPath,
            lpFileName,
            lpExtension,
            nBufferLength,
            lpBuffer,
            lpFilePart
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_SearchPathW(
        lpPath,
        lpFileName,
        lpExtension,
        nBufferLength,
        lpBuffer,
        lpFilePart
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SearchPathW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpPath,
        lpFileName,
        lpExtension,
        lpBuffer
    );

    log_debug("Leaving %s\n", "SearchPathW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_SetEndOfFile(
    HANDLE hFile
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetEndOfFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetEndOfFile");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_SetEndOfFile(
            hFile
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_SetEndOfFile(
        hFile
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetEndOfFile,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile
    );

    log_debug("Leaving %s\n", "SetEndOfFile");

    set_last_error(&lasterror);
    return ret;
}

UINT WINAPI New_kernel32_SetErrorMode(
    UINT uMode
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetErrorMode");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetErrorMode");

        set_last_error(&lasterror);
        UINT ret = Old_kernel32_SetErrorMode(
            uMode
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    UINT ret = Old_kernel32_SetErrorMode(
        uMode
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetErrorMode,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        uMode
    );

    log_debug("Leaving %s\n", "SetErrorMode");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_SetFileAttributesW(
    LPCWSTR lpFileName,
    DWORD dwFileAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetFileAttributesW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetFileAttributesW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_SetFileAttributesW(
            lpFileName,
            dwFileAttributes
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(lpFileName, filepath);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_SetFileAttributesW(
        lpFileName,
        dwFileAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetFileAttributesW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFileAttributes,
        filepath,
        lpFileName
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "SetFileAttributesW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_SetFileInformationByHandle(
    HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    LPVOID lpFileInformation,
    DWORD dwBufferSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetFileInformationByHandle");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetFileInformationByHandle");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_SetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_SetFileInformationByHandle(
        hFile,
        FileInformationClass,
        lpFileInformation,
        dwBufferSize
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetFileInformationByHandle,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        FileInformationClass
    );

    log_debug("Leaving %s\n", "SetFileInformationByHandle");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_SetFilePointer(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetFilePointer");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetFilePointer");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_SetFilePointer(
            hFile,
            lDistanceToMove,
            lpDistanceToMoveHigh,
            dwMoveMethod
        );
        return ret;
    }
    
    uint64_t offset = lDistanceToMove;
    if(lpDistanceToMoveHigh != NULL) {
        offset += (uint64_t) copy_uint32(lpDistanceToMoveHigh) << 32;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_SetFilePointer(
        hFile,
        lDistanceToMove,
        lpDistanceToMoveHigh,
        dwMoveMethod
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetFilePointer,
        ret != INVALID_SET_FILE_POINTER,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        dwMoveMethod,
        offset
    );

    log_debug("Leaving %s\n", "SetFilePointer");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_SetFilePointerEx(
    HANDLE hFile,
    LARGE_INTEGER liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer,
    DWORD dwMoveMethod
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetFilePointerEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetFilePointerEx");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_SetFilePointerEx(
            hFile,
            liDistanceToMove,
            lpNewFilePointer,
            dwMoveMethod
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_SetFilePointerEx(
        hFile,
        liDistanceToMove,
        lpNewFilePointer,
        dwMoveMethod
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetFilePointerEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        lpNewFilePointer,
        dwMoveMethod
    );

    log_debug("Leaving %s\n", "SetFilePointerEx");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_SetFileTime(
    HANDLE hFile,
    FILETIME *lpCreationTime,
    FILETIME *lpLastAccessTime,
    FILETIME *lpLastWriteTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetFileTime");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetFileTime");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_SetFileTime(
            hFile,
            lpCreationTime,
            lpLastAccessTime,
            lpLastWriteTime
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_SetFileTime(
        hFile,
        lpCreationTime,
        lpLastAccessTime,
        lpLastWriteTime
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetFileTime,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile
    );

    log_debug("Leaving %s\n", "SetFileTime");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_SetInformationJobObject(
    HANDLE hJob,
    JOBOBJECTINFOCLASS JobObjectInfoClass,
    LPVOID lpJobObjectInfo,
    DWORD cbJobObjectInfoLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetInformationJobObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetInformationJobObject");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_SetInformationJobObject(
            hJob,
            JobObjectInfoClass,
            lpJobObjectInfo,
            cbJobObjectInfoLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_SetInformationJobObject(
        hJob,
        JobObjectInfoClass,
        lpJobObjectInfo,
        cbJobObjectInfoLength
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetInformationJobObject,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hJob,
        JobObjectInfoClass,
        (uintptr_t) cbJobObjectInfoLength, lpJobObjectInfo
    );

    log_debug("Leaving %s\n", "SetInformationJobObject");

    set_last_error(&lasterror);
    return ret;
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI New_kernel32_SetUnhandledExceptionFilter(
    LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetUnhandledExceptionFilter");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetUnhandledExceptionFilter");

        set_last_error(&lasterror);
        LPTOP_LEVEL_EXCEPTION_FILTER ret = Old_kernel32_SetUnhandledExceptionFilter(
            lpTopLevelExceptionFilter
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "p", 
        lpTopLevelExceptionFilter
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "SetUnhandledExceptionFilter");

        set_last_error(&lasterror);
        LPTOP_LEVEL_EXCEPTION_FILTER ret = Old_kernel32_SetUnhandledExceptionFilter(
            lpTopLevelExceptionFilter
        );
        return ret;
    }

    set_last_error(&lasterror);
    LPTOP_LEVEL_EXCEPTION_FILTER ret = Old_kernel32_SetUnhandledExceptionFilter(
        lpTopLevelExceptionFilter
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SetUnhandledExceptionFilter,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "SetUnhandledExceptionFilter");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_kernel32_SizeofResource(
    HMODULE hModule,
    HRSRC hResInfo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SizeofResource");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SizeofResource");

        set_last_error(&lasterror);
        DWORD ret = Old_kernel32_SizeofResource(
            hModule,
            hResInfo
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_kernel32_SizeofResource(
        hModule,
        hResInfo
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_SizeofResource,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hModule,
        hResInfo,
        ret
    );

    log_debug("Leaving %s\n", "SizeofResource");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_Thread32First(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Thread32First");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Thread32First");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_Thread32First(
            hSnapshot,
            lpte
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_Thread32First(
        hSnapshot,
        lpte
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_Thread32First,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSnapshot
    );

    log_debug("Leaving %s\n", "Thread32First");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_Thread32Next(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Thread32Next");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Thread32Next");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_Thread32Next(
            hSnapshot,
            lpte
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_Thread32Next(
        hSnapshot,
        lpte
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_Thread32Next,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSnapshot
    );

    log_debug("Leaving %s\n", "Thread32Next");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_WriteConsoleA(
    HANDLE hConsoleOutput,
    const VOID *lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReseverd
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WriteConsoleA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WriteConsoleA");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_WriteConsoleA(
            hConsoleOutput,
            lpBuffer,
            nNumberOfCharsToWrite,
            lpNumberOfCharsWritten,
            lpReseverd
        );
        return ret;
    }

    DWORD _lpNumberOfCharsWritten;
    if(lpNumberOfCharsWritten == NULL) {
        lpNumberOfCharsWritten = &_lpNumberOfCharsWritten;
        memset(&_lpNumberOfCharsWritten, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_WriteConsoleA(
        hConsoleOutput,
        lpBuffer,
        nNumberOfCharsToWrite,
        lpNumberOfCharsWritten,
        lpReseverd
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_WriteConsoleA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hConsoleOutput,
        copy_uint32(lpNumberOfCharsWritten), lpBuffer
    );

    log_debug("Leaving %s\n", "WriteConsoleA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_WriteConsoleW(
    HANDLE hConsoleOutput,
    const VOID *lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReseverd
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WriteConsoleW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WriteConsoleW");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_WriteConsoleW(
            hConsoleOutput,
            lpBuffer,
            nNumberOfCharsToWrite,
            lpNumberOfCharsWritten,
            lpReseverd
        );
        return ret;
    }

    DWORD _lpNumberOfCharsWritten;
    if(lpNumberOfCharsWritten == NULL) {
        lpNumberOfCharsWritten = &_lpNumberOfCharsWritten;
        memset(&_lpNumberOfCharsWritten, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_WriteConsoleW(
        hConsoleOutput,
        lpBuffer,
        nNumberOfCharsToWrite,
        lpNumberOfCharsWritten,
        lpReseverd
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_WriteConsoleW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hConsoleOutput,
        copy_uint32(lpNumberOfCharsWritten), lpBuffer
    );

    log_debug("Leaving %s\n", "WriteConsoleW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_kernel32_WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WriteProcessMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WriteProcessMemory");

        set_last_error(&lasterror);
        BOOL ret = Old_kernel32_WriteProcessMemory(
            hProcess,
            lpBaseAddress,
            lpBuffer,
            nSize,
            lpNumberOfBytesWritten
        );
        return ret;
    }

    SIZE_T _lpNumberOfBytesWritten;
    if(lpNumberOfBytesWritten == NULL) {
        lpNumberOfBytesWritten = &_lpNumberOfBytesWritten;
        memset(&_lpNumberOfBytesWritten, 0, sizeof(SIZE_T));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_kernel32_WriteProcessMemory(
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten
    );
    get_last_error(&lasterror);

    log_api(SIG_kernel32_WriteProcessMemory,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hProcess,
        lpBaseAddress,
        pid_from_process_handle(hProcess),
        lpNumberOfBytesWritten, lpBuffer
    );

    log_debug("Leaving %s\n", "WriteProcessMemory");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_mpr_WNetGetProviderNameW(
    DWORD dwNetType,
    LPTSTR lpProviderName,
    LPDWORD lpBufferSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WNetGetProviderNameW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WNetGetProviderNameW");

        set_last_error(&lasterror);
        DWORD ret = Old_mpr_WNetGetProviderNameW(
            dwNetType,
            lpProviderName,
            lpBufferSize
        );
        return ret;
    }

    DWORD _lpBufferSize;
    if(lpBufferSize == NULL) {
        lpBufferSize = &_lpBufferSize;
        memset(&_lpBufferSize, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_mpr_WNetGetProviderNameW(
        dwNetType,
        lpProviderName,
        lpBufferSize
    );
    get_last_error(&lasterror);

    log_api(SIG_mpr_WNetGetProviderNameW,
        ret == NO_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwNetType
    );

    log_debug("Leaving %s\n", "WNetGetProviderNameW");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_mshtml_CDocument_write(
    void *cdocument,
    SAFEARRAY *arr
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CDocument_write");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_mshtml_CDocument_write(
        cdocument,
        arr
    );
    get_last_error(&lasterror);
    
    bson b; char index[8];
    bson_init_size(&b, mem_suggested_size(4096));
    bson_append_start_array(&b, "lines");
    
    VARIANT *elements = (VARIANT *) arr->pvData;
    for (uint32_t idx = 0, jdx = 0; idx < arr->rgsabound[0].cElements;
            idx++, elements++) {
        if(elements->vt == VT_BSTR && elements->bstrVal != NULL) {
            our_snprintf(index, sizeof(index), "%d", jdx++);
            log_wstring(&b, index, elements->bstrVal,
                sys_string_length(elements->bstrVal));
        }
    }
    
    bson_append_finish_array(&b);
    bson_finish(&b);
        
    log_api(SIG_mshtml_CDocument_write,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        &b
    );
        
    
    bson_destroy(&b);

    log_debug("Leaving %s\n", "CDocument_write");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_mshtml_CElement_put_innerHTML(
    void *celement,
    const wchar_t *html
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CElement_put_innerHTML");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_mshtml_CElement_put_innerHTML(
        celement,
        html
    );
    get_last_error(&lasterror);
        
    log_api(SIG_mshtml_CElement_put_innerHTML,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        html
    );
        

    log_debug("Leaving %s\n", "CElement_put_innerHTML");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_mshtml_CHyperlink_SetUrlComponent(
    void *chyperlink,
    const wchar_t *component,
    int index
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CHyperlink_SetUrlComponent");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_mshtml_CHyperlink_SetUrlComponent(
        chyperlink,
        component,
        index
    );
    get_last_error(&lasterror);
        
    log_api(SIG_mshtml_CHyperlink_SetUrlComponent,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        component,
        index
    );
        

    log_debug("Leaving %s\n", "CHyperlink_SetUrlComponent");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_mshtml_CIFrameElement_CreateElement(
    void *chtmtag,
    void *cdoc,
    void **celement
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CIFrameElement_CreateElement");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_mshtml_CIFrameElement_CreateElement(
        chtmtag,
        cdoc,
        celement
    );
    get_last_error(&lasterror);
    
    bson b;
    bson_init_size(&b, mem_suggested_size(1024));
    bson_append_start_object(&b, "attributes");
    
    chtmtag_attrs(chtmtag, &b);
    
    bson_append_finish_object(&b);
    bson_finish(&b);
        
    log_api(SIG_mshtml_CIFrameElement_CreateElement,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        &b
    );
        
    
    bson_destroy(&b);

    log_debug("Leaving %s\n", "CIFrameElement_CreateElement");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_mshtml_CImgElement_put_src(
    void *celement,
    const wchar_t *src
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CImgElement_put_src");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_mshtml_CImgElement_put_src(
        celement,
        src
    );
    get_last_error(&lasterror);
        
    log_api(SIG_mshtml_CImgElement_put_src,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        src
    );
        

    log_debug("Leaving %s\n", "CImgElement_put_src");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_mshtml_CScriptElement_put_src(
    void *cscriptelement,
    const wchar_t *url
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CScriptElement_put_src");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_mshtml_CScriptElement_put_src(
        cscriptelement,
        url
    );
    get_last_error(&lasterror);
        
    log_api(SIG_mshtml_CScriptElement_put_src,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        url
    );
        

    log_debug("Leaving %s\n", "CScriptElement_put_src");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_mshtml_CWindow_AddTimeoutCode(
    void *cwindow,
    VARIANT *data,
    const wchar_t *argument,
    int milliseconds,
    int repeat,
    void *unk2
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CWindow_AddTimeoutCode");
    
    wchar_t *code = NULL;
    if(data != NULL && data->vt == VT_BSTR) {
        code = data->bstrVal;
    }
    
    VARIANT v; v.vt = VT_EMPTY;
    if(data != NULL && data->vt == VT_DISPATCH) {
        if(SUCCEEDED(variant_change_type(&v, data, 0, VT_BSTR)) != FALSE) {
            code = v.bstrVal;
        }
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_mshtml_CWindow_AddTimeoutCode(
        cwindow,
        data,
        argument,
        milliseconds,
        repeat,
        unk2
    );
    get_last_error(&lasterror);
        
    log_api(SIG_mshtml_CWindow_AddTimeoutCode,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        argument,
        milliseconds,
        code,
        repeat != 0
    );
        
    
    if(v.vt != VT_EMPTY) {
        variant_clear(&v);
    }

    log_debug("Leaving %s\n", "CWindow_AddTimeoutCode");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_msvcrt_system(
    const char *command
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "system");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "system");

        set_last_error(&lasterror);
        int ret = Old_msvcrt_system(
            command
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "s", 
        command
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "system");

        set_last_error(&lasterror);
        int ret = Old_msvcrt_system(
            command
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_msvcrt_system(
        command
    );
    get_last_error(&lasterror);

    log_api(SIG_msvcrt_system,
        ret == 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        command
    );

    log_debug("Leaving %s\n", "system");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ncrypt_PRF(
    void *unk1,
    uintptr_t unk2,
    uint8_t *buf1,
    uintptr_t buf1_length,
    const char *type,
    uint32_t type_length,
    uint8_t *buf2,
    uint32_t buf2_length,
    uint8_t *buf3,
    uint32_t buf3_length
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "PRF");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "PRF");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ncrypt_PRF(
            unk1,
            unk2,
            buf1,
            buf1_length,
            type,
            type_length,
            buf2,
            buf2_length,
            buf3,
            buf3_length
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ncrypt_PRF(
        unk1,
        unk2,
        buf1,
        buf1_length,
        type,
        type_length,
        buf2,
        buf2_length,
        buf3,
        buf3_length
    );
    get_last_error(&lasterror);
    
    uintptr_t master_secret_length = 0, random_length = 0;
    uint8_t *master_secret = NULL, *client_random = NULL;
    uint8_t *server_random = NULL;
    
    char client_random_repr[32*2+1] = {};
    char server_random_repr[32*2+1] = {};
    char master_secret_repr[48*2+1] = {};
    
    if(type_length == 13 && strcmp(type, "key expansion") == 0 &&
            buf2_length == 64) {
        master_secret_length = buf1_length;
        master_secret = buf1;
    
        random_length = 32;
        server_random = buf2;
        client_random = buf2 + random_length;
    
        hexencode(client_random_repr, client_random, random_length);
        hexencode(server_random_repr, server_random, random_length);
        hexencode(master_secret_repr, master_secret, master_secret_length);
    }

    log_api(SIG_ncrypt_PRF,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        type,
        client_random_repr,
        server_random_repr,
        master_secret_repr
    );

    log_debug("Leaving %s\n", "PRF");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ncrypt_Ssl3GenerateKeyMaterial(
    uintptr_t unk1,
    uint8_t *secret,
    uintptr_t secret_length,
    uint8_t *seed,
    uintptr_t seed_length,
    void *unk2,
    uintptr_t unk3
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "Ssl3GenerateKeyMaterial");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "Ssl3GenerateKeyMaterial");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ncrypt_Ssl3GenerateKeyMaterial(
            unk1,
            secret,
            secret_length,
            seed,
            seed_length,
            unk2,
            unk3
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ncrypt_Ssl3GenerateKeyMaterial(
        unk1,
        secret,
        secret_length,
        seed,
        seed_length,
        unk2,
        unk3
    );
    get_last_error(&lasterror);
    
    uintptr_t random_length = 32;
    uint8_t *client_random = seed;
    uint8_t *server_random = seed + random_length;
    
    char client_random_repr[32*2+1] = {};
    char server_random_repr[32*2+1] = {};
    char master_secret_repr[48*2+1] = {};
    
    if(seed_length == 64 && secret_length == 48) {
        hexencode(client_random_repr, client_random, random_length);
        hexencode(server_random_repr, server_random, random_length);
        hexencode(master_secret_repr, secret, secret_length);
    }

    log_api(SIG_ncrypt_Ssl3GenerateKeyMaterial,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        client_random_repr,
        server_random_repr,
        master_secret_repr
    );

    log_debug("Leaving %s\n", "Ssl3GenerateKeyMaterial");

    set_last_error(&lasterror);
    return ret;
}

NET_API_STATUS WINAPI New_netapi32_NetGetJoinInformation(
    LPCWSTR lpServer,
    LPWSTR *lpNameBuffer,
    PNETSETUP_JOIN_STATUS BufferType
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NetGetJoinInformation");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NetGetJoinInformation");

        set_last_error(&lasterror);
        NET_API_STATUS ret = Old_netapi32_NetGetJoinInformation(
            lpServer,
            lpNameBuffer,
            BufferType
        );
        return ret;
    }

    LPWSTR _lpNameBuffer;
    if(lpNameBuffer == NULL) {
        lpNameBuffer = &_lpNameBuffer;
        memset(&_lpNameBuffer, 0, sizeof(LPWSTR));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NET_API_STATUS ret = Old_netapi32_NetGetJoinInformation(
        lpServer,
        lpNameBuffer,
        BufferType
    );
    get_last_error(&lasterror);

    log_api(SIG_netapi32_NetGetJoinInformation,
        ret == NERR_Success,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpServer,
        *lpNameBuffer
    );

    log_debug("Leaving %s\n", "NetGetJoinInformation");

    set_last_error(&lasterror);
    return ret;
}

NET_API_STATUS WINAPI New_netapi32_NetShareEnum(
    LPWSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NetShareEnum");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NetShareEnum");

        set_last_error(&lasterror);
        NET_API_STATUS ret = Old_netapi32_NetShareEnum(
            servername,
            level,
            bufptr,
            prefmaxlen,
            entriesread,
            totalentries,
            resume_handle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NET_API_STATUS ret = Old_netapi32_NetShareEnum(
        servername,
        level,
        bufptr,
        prefmaxlen,
        entriesread,
        totalentries,
        resume_handle
    );
    get_last_error(&lasterror);

    log_api(SIG_netapi32_NetShareEnum,
        ret == NERR_Success,
        (uintptr_t) ret,
        hash,
        &lasterror,
        servername,
        level
    );

    log_debug("Leaving %s\n", "NetShareEnum");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_netapi32_NetUserGetInfo(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    LPBYTE *bufptr
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NetUserGetInfo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NetUserGetInfo");

        set_last_error(&lasterror);
        int ret = Old_netapi32_NetUserGetInfo(
            servername,
            username,
            level,
            bufptr
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_netapi32_NetUserGetInfo(
        servername,
        username,
        level,
        bufptr
    );
    get_last_error(&lasterror);

    log_api(SIG_netapi32_NetUserGetInfo,
        ret == 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        servername,
        username,
        level
    );

    log_debug("Leaving %s\n", "NetUserGetInfo");

    set_last_error(&lasterror);
    return ret;
}

NET_API_STATUS WINAPI New_netapi32_NetUserGetLocalGroups(
    LPCWSTR servername,
    LPCWSTR username,
    DWORD level,
    DWORD flags,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NetUserGetLocalGroups");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NetUserGetLocalGroups");

        set_last_error(&lasterror);
        NET_API_STATUS ret = Old_netapi32_NetUserGetLocalGroups(
            servername,
            username,
            level,
            flags,
            bufptr,
            prefmaxlen,
            entriesread,
            totalentries
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NET_API_STATUS ret = Old_netapi32_NetUserGetLocalGroups(
        servername,
        username,
        level,
        flags,
        bufptr,
        prefmaxlen,
        entriesread,
        totalentries
    );
    get_last_error(&lasterror);

    log_api(SIG_netapi32_NetUserGetLocalGroups,
        ret == NERR_Success,
        (uintptr_t) ret,
        hash,
        &lasterror,
        servername,
        username,
        level,
        flags
    );

    log_debug("Leaving %s\n", "NetUserGetLocalGroups");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_LdrGetDllHandle(
    PWORD pwPath,
    PVOID Unused,
    PUNICODE_STRING ModuleFileName,
    PHANDLE pHModule
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LdrGetDllHandle");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LdrGetDllHandle");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_LdrGetDllHandle(
            pwPath,
            Unused,
            ModuleFileName,
            pHModule
        );
        return ret;
    }
    
    wchar_t *module_name = extract_unicode_string_unistr(ModuleFileName);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_LdrGetDllHandle(
        pwPath,
        Unused,
        ModuleFileName,
        pHModule
    );
    get_last_error(&lasterror);
    
    if(NT_SUCCESS(ret) == FALSE && pHModule != NULL) {
        *pHModule = NULL;
    }

    log_api(SIG_ntdll_LdrGetDllHandle,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        pHModule,
        module_name
    );
    
    free_unicode_buffer(module_name);

    log_debug("Leaving %s\n", "LdrGetDllHandle");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_LdrGetProcedureAddress(
    HMODULE ModuleHandle,
    PANSI_STRING FunctionName,
    WORD Ordinal,
    PVOID *FunctionAddress
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LdrGetProcedureAddress");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LdrGetProcedureAddress");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_LdrGetProcedureAddress(
            ModuleHandle,
            FunctionName,
            Ordinal,
            FunctionAddress
        );
        return ret;
    }
    
    char library[MAX_PATH+1];
    
    library_from_unicodez(get_module_file_name(ModuleHandle),
        library, sizeof(library));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_LdrGetProcedureAddress(
        ModuleHandle,
        FunctionName,
        Ordinal,
        FunctionAddress
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_LdrGetProcedureAddress,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ModuleHandle,
        FunctionName,
        Ordinal,
        FunctionAddress,
        library
    );

    log_debug("Leaving %s\n", "LdrGetProcedureAddress");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_LdrLoadDll(
    PWCHAR PathToFile,
    PULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LdrLoadDll");
    
    char library[MAX_PATH];
    wchar_t *module_name = extract_unicode_string_unistr(ModuleFileName);
    library_from_unicode_string(ModuleFileName, library, sizeof(library));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_LdrLoadDll(
        PathToFile,
        Flags,
        ModuleFileName,
        ModuleHandle
    );
    get_last_error(&lasterror);
        
    if(hook_in_monitor() == 0) {
        log_api(SIG_ntdll_LdrLoadDll,
            NT_SUCCESS(ret) != FALSE,
            (uintptr_t) ret,
            hash,
            &lasterror,
            Flags,
            ModuleHandle,
            module_name,
            library
        );
    }
        
    
    if(NT_SUCCESS(ret) != FALSE) {
        hook_library(library, NULL);
    }
    
    free_unicode_buffer(module_name);

    log_debug("Leaving %s\n", "LdrLoadDll");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_LdrUnloadDll(
    HANDLE ModuleHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LdrUnloadDll");
    
    MEMORY_BASIC_INFORMATION_CROSS mbi;
    
    memset(&mbi, 0, sizeof(mbi));
    virtual_query(ModuleHandle, &mbi);
    
    unhook_detect_disable();
    
    char library[MAX_PATH+1];
    library_from_unicodez(get_module_file_name(ModuleHandle),
        library, sizeof(library));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_LdrUnloadDll(
        ModuleHandle
    );
    get_last_error(&lasterror);
    
    // If the module address is not readable anymore then the module got
    // unhooked and thus we have to notify the unhook detection monitoring.
    if(NT_SUCCESS(ret) != FALSE &&
            page_is_readable((const uint8_t *) mbi.AllocationBase) == 0) {
        unhook_detect_remove_dead_regions();
    }
    
    unhook_detect_enable();
        
    if(hook_in_monitor() == 0) {
        log_api(SIG_ntdll_LdrUnloadDll,
            NT_SUCCESS(ret) != FALSE,
            (uintptr_t) ret,
            hash,
            &lasterror,
            ModuleHandle,
            library
        );
    }
        
    
    if(range_is_readable(ModuleHandle, 0x1000) == 0) {
        unhook_library(library, ModuleHandle);
    }

    log_debug("Leaving %s\n", "LdrUnloadDll");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtAllocateVirtualMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtAllocateVirtualMemory");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtAllocateVirtualMemory(
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            RegionSize,
            AllocationType,
            Protect
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtAllocateVirtualMemory(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtAllocateVirtualMemory,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        BaseAddress,
        RegionSize,
        AllocationType,
        Protect,
        pid_from_process_handle(ProcessHandle)
    );

    log_debug("Leaving %s\n", "NtAllocateVirtualMemory");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtClose(
    HANDLE Handle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtClose");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtClose(
        Handle
    );
    get_last_error(&lasterror);
        
    if(hook_in_monitor() == 0) {
        log_api(SIG_ntdll_NtClose,
            NT_SUCCESS(ret) != FALSE,
            (uintptr_t) ret,
            hash,
            &lasterror,
            Handle
        );
    }
        
    
    if(NT_SUCCESS(ret) != FALSE) {
        ignored_object_remove(Handle);
    }

    log_debug("Leaving %s\n", "NtClose");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateDirectoryObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateDirectoryObject");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateDirectoryObject(
            DirectoryHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, dirpath);
    
    wchar_t *dirpath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = call_hash(
        "ui", 
        dirpath,
        DesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtCreateDirectoryObject");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateDirectoryObject(
            DirectoryHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateDirectoryObject(
        DirectoryHandle,
        DesiredAccess,
        ObjectAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtCreateDirectoryObject,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        DirectoryHandle,
        DesiredAccess,
        dirpath,
        dirpath_r
    );
    
    free_unicode_buffer(dirpath);
    free_unicode_buffer(dirpath_r);

    log_debug("Leaving %s\n", "NtCreateDirectoryObject");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength
        );
        return ret;
    }

    HANDLE _FileHandle;
    if(FileHandle == NULL) {
        FileHandle = &_FileHandle;
        memset(&_FileHandle, 0, sizeof(HANDLE));
    }

    IO_STATUS_BLOCK _IoStatusBlock;
    if(IoStatusBlock == NULL) {
        IoStatusBlock = &_IoStatusBlock;
        memset(&_IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
    }
    
    // Not sure what other value we could be handing out here (in any case
    // this value should always be overwritten by the kernel anyway).
    IoStatusBlock->Information = 0xffffffff;
    uint32_t share_access = ShareAccess;
    ShareAccess |= FILE_SHARE_READ;

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
    get_last_error(&lasterror);
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    log_api(SIG_ntdll_NtCreateFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        DesiredAccess,
        FileAttributes,
        CreateDisposition,
        CreateOptions,
        share_access,
        filepath,
        filepath_r,
        IoStatusBlock->Information
    );
    
    if(NT_SUCCESS(ret) != FALSE && hook_in_monitor() != 0) {
        ignored_object_add(*FileHandle);
    }
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtCreateFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateKey(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes,
            TitleIndex,
            Class,
            CreateOptions,
            Disposition
        );
        return ret;
    }
    
    wchar_t *class = extract_unicode_string_unistr(Class);
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

    uint64_t hash = call_hash(
        "uiiii", 
        regkey,
        DesiredAccess,
        TitleIndex,
        CreateOptions,
        Disposition
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtCreateKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateKey(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes,
            TitleIndex,
            Class,
            CreateOptions,
            Disposition
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateKey(
        KeyHandle,
        DesiredAccess,
        ObjectAttributes,
        TitleIndex,
        Class,
        CreateOptions,
        Disposition
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtCreateKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        DesiredAccess,
        TitleIndex,
        CreateOptions,
        Disposition,
        regkey,
        class
    );
    
    free_unicode_buffer(class);
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtCreateKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    BOOLEAN InitialOwner
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateMutant");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateMutant");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateMutant(
            MutantHandle,
            DesiredAccess,
            ObjectAttributes,
            InitialOwner
        );
        return ret;
    }
    
    wchar_t *mutant_name = NULL;
    if(ObjectAttributes != NULL) {
        mutant_name = extract_unicode_string_unistr(ObjectAttributes->ObjectName);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateMutant(
        MutantHandle,
        DesiredAccess,
        ObjectAttributes,
        InitialOwner
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtCreateMutant,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        MutantHandle,
        DesiredAccess,
        InitialOwner,
        mutant_name
    );
    
    free_unicode_buffer(mutant_name);

    log_debug("Leaving %s\n", "NtCreateMutant");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateProcess");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateProcess(
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ParentProcess,
            InheritObjectTable,
            SectionHandle,
            DebugPort,
            ExceptionPort
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = call_hash(
        "uii", 
        filepath,
        DesiredAccess,
        InheritObjectTable
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtCreateProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateProcess(
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ParentProcess,
            InheritObjectTable,
            SectionHandle,
            DebugPort,
            ExceptionPort
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ParentProcess,
        InheritObjectTable,
        SectionHandle,
        DebugPort,
        ExceptionPort
    );
    get_last_error(&lasterror);
    
    uint32_t pid = pid_from_process_handle(copy_ptr(ProcessHandle));

    log_api(SIG_ntdll_NtCreateProcess,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        DesiredAccess,
        ParentProcess,
        InheritObjectTable,
        pid,
        filepath,
        filepath_r
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtCreateProcess");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateProcessEx(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateProcessEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateProcessEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateProcessEx(
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ParentProcess,
            Flags,
            SectionHandle,
            DebugPort,
            ExceptionPort,
            InJob
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = call_hash(
        "uii", 
        filepath,
        DesiredAccess,
        Flags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtCreateProcessEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateProcessEx(
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ParentProcess,
            Flags,
            SectionHandle,
            DebugPort,
            ExceptionPort,
            InJob
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateProcessEx(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ParentProcess,
        Flags,
        SectionHandle,
        DebugPort,
        ExceptionPort,
        InJob
    );
    get_last_error(&lasterror);
    
    uint32_t pid = pid_from_process_handle(copy_ptr(ProcessHandle));

    log_api(SIG_ntdll_NtCreateProcessEx,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        DesiredAccess,
        ParentProcess,
        Flags,
        pid,
        filepath,
        filepath_r
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtCreateProcessEx");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateSection");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateSection");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateSection(
            SectionHandle,
            DesiredAccess,
            ObjectAttributes,
            MaximumSize,
            SectionPageProtection,
            AllocationAttributes,
            FileHandle
        );
        return ret;
    }
    
    wchar_t *section_name = extract_unicode_string_objattr(ObjectAttributes);
    
    HANDLE object_handle = NULL; OBJECT_ATTRIBUTES objattr;
    
    if(ObjectAttributes != NULL && copy_bytes(
            &objattr, ObjectAttributes, sizeof(OBJECT_ATTRIBUTES)) == 0) {
        object_handle = objattr.RootDirectory;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateSection(
        SectionHandle,
        DesiredAccess,
        ObjectAttributes,
        MaximumSize,
        SectionPageProtection,
        AllocationAttributes,
        FileHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtCreateSection,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        SectionHandle,
        DesiredAccess,
        SectionPageProtection,
        FileHandle,
        object_handle,
        section_name
    );
    
    free_unicode_buffer(section_name);

    log_debug("Leaving %s\n", "NtCreateSection");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PCLIENT_ID ClientId,
    PCONTEXT ThreadContext,
    PINITIAL_TEB InitialTeb,
    BOOLEAN CreateSuspended
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateThread(
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle,
            ClientId,
            ThreadContext,
            InitialTeb,
            CreateSuspended
        );
        return ret;
    }
    
    wchar_t *thread_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, thread_name);
    
    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateThread(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        ClientId,
        ThreadContext,
        InitialTeb,
        CreateSuspended
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtCreateThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        DesiredAccess,
        ProcessHandle,
        CreateSuspended,
        thread_name
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }
    
    free_unicode_buffer(thread_name);

    log_debug("Leaving %s\n", "NtCreateThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateThreadEx(
    PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    PVOID lpParameter,
    BOOL CreateSuspended,
    LONG StackZeroBits,
    LONG SizeOfStackCommit,
    LONG SizeOfStackReserve,
    PVOID lpBytesBuffer
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateThreadEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateThreadEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateThreadEx(
            hThread,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle,
            lpStartAddress,
            lpParameter,
            CreateSuspended,
            StackZeroBits,
            SizeOfStackCommit,
            SizeOfStackReserve,
            lpBytesBuffer
        );
        return ret;
    }
    
    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateThreadEx(
        hThread,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        lpStartAddress,
        lpParameter,
        CreateSuspended,
        StackZeroBits,
        SizeOfStackCommit,
        SizeOfStackReserve,
        lpBytesBuffer
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtCreateThreadEx,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hThread,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        lpStartAddress,
        lpParameter,
        CreateSuspended,
        StackZeroBits
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "NtCreateThreadEx");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PPS_CREATE_INFO CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtCreateUserProcess");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtCreateUserProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtCreateUserProcess(
            ProcessHandle,
            ThreadHandle,
            ProcessDesiredAccess,
            ThreadDesiredAccess,
            ProcessObjectAttributes,
            ThreadObjectAttributes,
            ProcessFlags,
            ThreadFlags,
            ProcessParameters,
            CreateInfo,
            AttributeList
        );
        return ret;
    }
    
    wchar_t *process_name = get_unicode_buffer();
    path_get_full_path_objattr(ProcessObjectAttributes, process_name);
    
    wchar_t *process_name_r =
        extract_unicode_string_objattr(ProcessObjectAttributes);
    
    wchar_t *thread_name = get_unicode_buffer();
    path_get_full_path_objattr(ThreadObjectAttributes, thread_name);
    
    wchar_t *thread_name_r =
        extract_unicode_string_objattr(ThreadObjectAttributes);
    
    wchar_t *filepath =
        extract_unicode_string_unistr(&ProcessParameters->ImagePathName);
    wchar_t *command_line =
        extract_unicode_string_unistr(&ProcessParameters->CommandLine);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtCreateUserProcess(
        ProcessHandle,
        ThreadHandle,
        ProcessDesiredAccess,
        ThreadDesiredAccess,
        ProcessObjectAttributes,
        ThreadObjectAttributes,
        ProcessFlags,
        ThreadFlags,
        ProcessParameters,
        CreateInfo,
        AttributeList
    );
    get_last_error(&lasterror);
    
    uint32_t pid = pid_from_process_handle(copy_ptr(ProcessHandle));
    uint32_t tid = tid_from_thread_handle(copy_ptr(ThreadHandle));

    log_api(SIG_ntdll_NtCreateUserProcess,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        ThreadHandle,
        ProcessDesiredAccess,
        ThreadDesiredAccess,
        ProcessFlags,
        ThreadFlags,
        pid,
        tid,
        process_name,
        process_name_r,
        thread_name,
        thread_name_r,
        filepath,
        command_line
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);
        sleep_skip_disable();
    }
    
    free_unicode_buffer(process_name);
    free_unicode_buffer(process_name_r);
    free_unicode_buffer(thread_name);
    free_unicode_buffer(thread_name_r);
    free_unicode_buffer(filepath);
    free_unicode_buffer(command_line);

    log_debug("Leaving %s\n", "NtCreateUserProcess");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtDelayExecution");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtDelayExecution");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDelayExecution(
            Alertable,
            DelayInterval
        );
        return ret;
    }

    LARGE_INTEGER _DelayInterval;
    if(DelayInterval == NULL) {
        DelayInterval = &_DelayInterval;
        memset(&_DelayInterval, 0, sizeof(LARGE_INTEGER));
    }
    
    int64_t milliseconds = -DelayInterval->QuadPart / 10000;
    int skipped = sleep_skip(DelayInterval);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtDelayExecution(
        Alertable,
        DelayInterval
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtDelayExecution,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        milliseconds,
        skipped
    );

    log_debug("Leaving %s\n", "NtDelayExecution");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtDeleteFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtDeleteFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeleteFile(
            ObjectAttributes
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    pipe("FILE_DEL:%Z", filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = call_hash(
        "u", 
        filepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtDeleteFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeleteFile(
            ObjectAttributes
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtDeleteFile(
        ObjectAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtDeleteFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        filepath_r
    );
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtDeleteFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtDeleteKey(
    HANDLE KeyHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtDeleteKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtDeleteKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeleteKey(
            KeyHandle
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtDeleteKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeleteKey(
            KeyHandle
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtDeleteKey(
        KeyHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtDeleteKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtDeleteKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtDeleteValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtDeleteValueKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtDeleteValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeleteValueKey(
            KeyHandle,
            ValueName
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

    uint64_t hash = call_hash(
        "u", 
        regkey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtDeleteValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeleteValueKey(
            KeyHandle,
            ValueName
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtDeleteValueKey(
        KeyHandle,
        ValueName
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtDeleteValueKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtDeleteValueKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtDeviceIoControlFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtDeviceIoControlFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeviceIoControlFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength
        );
        return ret;
    }

    IO_STATUS_BLOCK _IoStatusBlock;
    if(IoStatusBlock == NULL) {
        IoStatusBlock = &_IoStatusBlock;
        memset(&_IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
    }

    uint64_t hash = call_hash(
        "h", 
        FileHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtDeviceIoControlFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtDeviceIoControlFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            IoControlCode,
            InputBuffer,
            InputBufferLength,
            OutputBuffer,
            OutputBufferLength
        );
        return ret;
    }

    uintptr_t prelen = (uintptr_t) InputBufferLength;
    uint8_t *prebuf = memdup(InputBuffer, prelen);

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtDeviceIoControlFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtDeviceIoControlFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf,
        FileHandle,
        IoControlCode,
        (uintptr_t) copy_uint32(&IoStatusBlock->Information), OutputBuffer
    );

    log_debug("Leaving %s\n", "NtDeviceIoControlFile");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtDuplicateObject(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    HANDLE *TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtDuplicateObject");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtDuplicateObject(
        SourceProcessHandle,
        SourceHandle,
        TargetProcessHandle,
        TargetHandle,
        DesiredAccess,
        HandleAttributes,
        Options
    );
    get_last_error(&lasterror);
        
    if(hook_in_monitor() == 0) {
        log_api(SIG_ntdll_NtDuplicateObject,
            NT_SUCCESS(ret) != FALSE,
            (uintptr_t) ret,
            hash,
            &lasterror,
            SourceProcessHandle,
            SourceHandle,
            TargetProcessHandle,
            TargetHandle,
            DesiredAccess,
            HandleAttributes,
            Options,
            pid_from_process_handle(SourceProcessHandle),
            pid_from_process_handle(TargetProcessHandle)
        );
    }
        
    
    uintptr_t source_pid = pid_from_process_handle(SourceProcessHandle);
    uintptr_t target_pid = pid_from_process_handle(TargetProcessHandle);
    if(NT_SUCCESS(ret) != FALSE &&
            source_pid == get_current_process_id() &&
            target_pid == get_current_process_id()) {
        if(is_ignored_object_handle(SourceHandle) != 0) {
            ignored_object_add(*TargetHandle);
        }
    }

    log_debug("Leaving %s\n", "NtDuplicateObject");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtEnumerateKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtEnumerateKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtEnumerateKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtEnumerateKey(
            KeyHandle,
            Index,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    ULONG _ResultLength;
    if(ResultLength == NULL) {
        ResultLength = &_ResultLength;
        memset(&_ResultLength, 0, sizeof(ULONG));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        Index
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtEnumerateKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtEnumerateKey(
            KeyHandle,
            Index,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtEnumerateKey(
        KeyHandle,
        Index,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtEnumerateKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        Index,
        KeyInformationClass,
        (uintptr_t) *ResultLength, KeyInformation,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtEnumerateKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtEnumerateValueKey(
    HANDLE KeyHandle,
    ULONG Index,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtEnumerateValueKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtEnumerateValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtEnumerateValueKey(
            KeyHandle,
            Index,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    ULONG _ResultLength;
    if(ResultLength == NULL) {
        ResultLength = &_ResultLength;
        memset(&_ResultLength, 0, sizeof(ULONG));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        Index
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtEnumerateValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtEnumerateValueKey(
            KeyHandle,
            Index,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtEnumerateValueKey(
        KeyHandle,
        Index,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
    );
    get_last_error(&lasterror);
    
    wchar_t *key_name = NULL; uint8_t *data = NULL;
    uint32_t reg_type = REG_NONE, data_length = 0;
    
    if(NT_SUCCESS(ret) != FALSE) {
        reg_get_info_from_keyvalue(KeyValueInformation, *ResultLength,
            KeyValueInformationClass, &key_name, &reg_type,
            &data_length, &data
        );
    }

    log_api(SIG_ntdll_NtEnumerateValueKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        Index,
        KeyValueInformationClass,
        regkey,
        key_name,
        reg_type,
        &reg_type, &data_length, data
    );
    
    free_unicode_buffer(regkey);
    free_unicode_buffer(key_name);

    log_debug("Leaving %s\n", "NtEnumerateValueKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtFreeVirtualMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtFreeVirtualMemory");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtFreeVirtualMemory(
            ProcessHandle,
            BaseAddress,
            RegionSize,
            FreeType
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtFreeVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtFreeVirtualMemory,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        BaseAddress,
        RegionSize,
        FreeType,
        pid_from_process_handle(ProcessHandle)
    );

    log_debug("Leaving %s\n", "NtFreeVirtualMemory");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtGetContextThread(
    HANDLE ThreadHandle,
    LPCONTEXT Context
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtGetContextThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtGetContextThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtGetContextThread(
            ThreadHandle,
            Context
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtGetContextThread(
        ThreadHandle,
        Context
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtGetContextThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle
    );

    log_debug("Leaving %s\n", "NtGetContextThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtLoadDriver(
    PUNICODE_STRING DriverServiceName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtLoadDriver");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtLoadDriver");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadDriver(
            DriverServiceName
        );
        return ret;
    }
    
    wchar_t *driver_service_name =
        extract_unicode_string_unistr(DriverServiceName);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtLoadDriver(
        DriverServiceName
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtLoadDriver,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        driver_service_name
    );
    
    free_unicode_buffer(driver_service_name);

    log_debug("Leaving %s\n", "NtLoadDriver");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtLoadKey(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtLoadKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtLoadKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadKey(
            TargetKey,
            SourceFile
        );
        return ret;
    }
    
    wchar_t *source_file = get_unicode_buffer();
    path_get_full_path_objattr(SourceFile, source_file);
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

    uint64_t hash = call_hash(
        "uu", 
        regkey,
        source_file
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtLoadKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadKey(
            TargetKey,
            SourceFile
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtLoadKey(
        TargetKey,
        SourceFile
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtLoadKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        source_file,
        regkey
    );
    
    free_unicode_buffer(source_file);
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtLoadKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtLoadKey2(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtLoadKey2");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtLoadKey2");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadKey2(
            TargetKey,
            SourceFile,
            Flags
        );
        return ret;
    }
    
    wchar_t *source_file = get_unicode_buffer();
    path_get_full_path_objattr(SourceFile, source_file);
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

    uint64_t hash = call_hash(
        "uui", 
        regkey,
        source_file,
        Flags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtLoadKey2");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadKey2(
            TargetKey,
            SourceFile,
            Flags
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtLoadKey2(
        TargetKey,
        SourceFile,
        Flags
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtLoadKey2,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        Flags,
        source_file,
        regkey
    );
    
    free_unicode_buffer(regkey);
    free_unicode_buffer(source_file);

    log_debug("Leaving %s\n", "NtLoadKey2");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtLoadKeyEx(
    POBJECT_ATTRIBUTES TargetKey,
    POBJECT_ATTRIBUTES SourceFile,
    ULONG Flags,
    HANDLE TrustClassKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtLoadKeyEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtLoadKeyEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadKeyEx(
            TargetKey,
            SourceFile,
            Flags,
            TrustClassKey
        );
        return ret;
    }
    
    wchar_t *source_file = get_unicode_buffer();
    path_get_full_path_objattr(SourceFile, source_file);
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(TargetKey, regkey);

    uint64_t hash = call_hash(
        "uui", 
        regkey,
        source_file,
        Flags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtLoadKeyEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtLoadKeyEx(
            TargetKey,
            SourceFile,
            Flags,
            TrustClassKey
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtLoadKeyEx(
        TargetKey,
        SourceFile,
        Flags,
        TrustClassKey
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtLoadKeyEx,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        Flags,
        TrustClassKey,
        source_file,
        regkey
    );
    
    free_unicode_buffer(regkey);
    free_unicode_buffer(source_file);

    log_debug("Leaving %s\n", "NtLoadKeyEx");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtMakePermanentObject(
    HANDLE ObjectHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtMakePermanentObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtMakePermanentObject");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtMakePermanentObject(
            ObjectHandle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtMakePermanentObject(
        ObjectHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtMakePermanentObject,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ObjectHandle
    );

    log_debug("Leaving %s\n", "NtMakePermanentObject");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtMakeTemporaryObject(
    HANDLE ObjectHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtMakeTemporaryObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtMakeTemporaryObject");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtMakeTemporaryObject(
            ObjectHandle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtMakeTemporaryObject(
        ObjectHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtMakeTemporaryObject,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ObjectHandle
    );

    log_debug("Leaving %s\n", "NtMakeTemporaryObject");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    UINT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtMapViewOfSection");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtMapViewOfSection");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtMapViewOfSection(
            SectionHandle,
            ProcessHandle,
            BaseAddress,
            ZeroBits,
            CommitSize,
            SectionOffset,
            ViewSize,
            InheritDisposition,
            AllocationType,
            Win32Protect
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtMapViewOfSection(
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        CommitSize,
        SectionOffset,
        ViewSize,
        InheritDisposition,
        AllocationType,
        Win32Protect
    );
    get_last_error(&lasterror);
    
    uintptr_t buflen = 0; uint8_t *buffer = NULL;
    
    uint32_t pid = pid_from_process_handle(ProcessHandle);
    
    if(NT_SUCCESS(ret) != FALSE && pid != get_current_process_id()) {
    
        // The actual size of the mapped view.
        buflen = *ViewSize;
    
        // As it is non-trivial to extract the base address of the original
        // mapped section, we'll just go ahead and read the memory from the
        // remote process.
        buffer = mem_alloc(buflen);
        if(buffer != NULL) {
            virtual_read_ex(ProcessHandle, *BaseAddress, buffer, &buflen);
        }
    }

    log_api(SIG_ntdll_NtMapViewOfSection,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        SectionHandle,
        ProcessHandle,
        BaseAddress,
        CommitSize,
        SectionOffset,
        ViewSize,
        AllocationType,
        Win32Protect,
        pid,
        buflen, buffer
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS:%d", pid);
        sleep_skip_disable();
    }
    
    mem_free(buffer);

    log_debug("Leaving %s\n", "NtMapViewOfSection");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenDirectoryObject(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenDirectoryObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenDirectoryObject");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenDirectoryObject(
            DirectoryHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, dirpath);
    
    wchar_t *dirpath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = call_hash(
        "ui", 
        dirpath,
        DesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtOpenDirectoryObject");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenDirectoryObject(
            DirectoryHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenDirectoryObject(
        DirectoryHandle,
        DesiredAccess,
        ObjectAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenDirectoryObject,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        DirectoryHandle,
        DesiredAccess,
        dirpath,
        dirpath_r
    );
    
    free_unicode_buffer(dirpath);
    free_unicode_buffer(dirpath_r);

    log_debug("Leaving %s\n", "NtOpenDirectoryObject");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            ShareAccess,
            OpenOptions
        );
        return ret;
    }

    HANDLE _FileHandle;
    if(FileHandle == NULL) {
        FileHandle = &_FileHandle;
        memset(&_FileHandle, 0, sizeof(HANDLE));
    }

    IO_STATUS_BLOCK _IoStatusBlock;
    if(IoStatusBlock == NULL) {
        IoStatusBlock = &_IoStatusBlock;
        memset(&_IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
    }
    
    // Not sure what other value we could be handing out here (in any case
    // this value should always be overwritten by the kernel anyway).
    IoStatusBlock->Information = 0xffffffff;
    uint32_t share_access = ShareAccess;
    ShareAccess |= FILE_SHARE_READ;

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        ShareAccess,
        OpenOptions
    );
    get_last_error(&lasterror);
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    log_api(SIG_ntdll_NtOpenFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        DesiredAccess,
        OpenOptions,
        share_access,
        filepath,
        filepath_r,
        IoStatusBlock->Information
    );
    
    if(NT_SUCCESS(ret) != FALSE && hook_in_monitor() != 0) {
        ignored_object_add(*FileHandle);
    }
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtOpenFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenKey(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenKey(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        DesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtOpenKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenKey(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenKey(
        KeyHandle,
        DesiredAccess,
        ObjectAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        DesiredAccess,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtOpenKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenKeyEx(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG OpenOptions
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenKeyEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenKeyEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenKeyEx(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes,
            OpenOptions
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_objattr(ObjectAttributes, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        DesiredAccess
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtOpenKeyEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenKeyEx(
            KeyHandle,
            DesiredAccess,
            ObjectAttributes,
            OpenOptions
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenKeyEx(
        KeyHandle,
        DesiredAccess,
        ObjectAttributes,
        OpenOptions
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenKeyEx,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        DesiredAccess,
        OpenOptions,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtOpenKeyEx");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenMutant(
    PHANDLE MutantHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenMutant");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenMutant");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenMutant(
            MutantHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }
    
    wchar_t *mutant_name = NULL;
    if(ObjectAttributes != NULL) {
        mutant_name = extract_unicode_string_unistr(ObjectAttributes->ObjectName);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenMutant(
        MutantHandle,
        DesiredAccess,
        ObjectAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenMutant,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        MutantHandle,
        DesiredAccess,
        mutant_name
    );
    
    free_unicode_buffer(mutant_name);

    log_debug("Leaving %s\n", "NtOpenMutant");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenProcess");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenProcess(
            ProcessHandle,
            DesiredAccess,
            ObjectAttributes,
            ClientId
        );
        return ret;
    }

    CLIENT_ID _ClientId;
    if(ClientId == NULL) {
        ClientId = &_ClientId;
        memset(&_ClientId, 0, sizeof(CLIENT_ID));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenProcess(
        ProcessHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenProcess,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        DesiredAccess,
        copy_uint32(&ClientId->UniqueProcess)
    );

    log_debug("Leaving %s\n", "NtOpenProcess");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenSection");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenSection");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenSection(
            SectionHandle,
            DesiredAccess,
            ObjectAttributes
        );
        return ret;
    }
    
    wchar_t *section_name = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenSection(
        SectionHandle,
        DesiredAccess,
        ObjectAttributes
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenSection,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        SectionHandle,
        DesiredAccess,
        section_name
    );
    
    free_unicode_buffer(section_name);

    log_debug("Leaving %s\n", "NtOpenSection");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtOpenThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtOpenThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtOpenThread(
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ClientId
        );
        return ret;
    }
    
    wchar_t *thread_name = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, thread_name);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtOpenThread(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ClientId
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtOpenThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        DesiredAccess,
        thread_name,
        pid_from_thread_handle(ThreadHandle)
    );
    
    free_unicode_buffer(thread_name);

    log_debug("Leaving %s\n", "NtOpenThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtProtectVirtualMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtProtectVirtualMemory");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtProtectVirtualMemory(
            ProcessHandle,
            BaseAddress,
            NumberOfBytesToProtect,
            NewAccessProtection,
            OldAccessProtection
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        NumberOfBytesToProtect,
        NewAccessProtection,
        OldAccessProtection
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtProtectVirtualMemory,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        BaseAddress,
        NumberOfBytesToProtect,
        NewAccessProtection,
        pid_from_process_handle(ProcessHandle)
    );

    log_debug("Leaving %s\n", "NtProtectVirtualMemory");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    void *FileInformation
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryAttributesFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryAttributesFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryAttributesFile(
            ObjectAttributes,
            FileInformation
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryAttributesFile(
        ObjectAttributes,
        FileInformation
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueryAttributesFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        filepath_r
    );
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtQueryAttributesFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryDirectoryFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryDirectoryFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryDirectoryFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass,
            ReturnSingleEntry,
            FileName,
            RestartScan
        );
        return ret;
    }

    IO_STATUS_BLOCK _IoStatusBlock;
    if(IoStatusBlock == NULL) {
        IoStatusBlock = &_IoStatusBlock;
        memset(&_IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
    }
    
    wchar_t *dirpath = get_unicode_buffer();
    
    OBJECT_ATTRIBUTES objattr;
    InitializeObjectAttributes(&objattr, FileName, 0, FileHandle, NULL);
    path_get_full_path_objattr(&objattr, dirpath);
    
    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

    uint64_t hash = call_hash(
        "h", 
        FileHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtQueryDirectoryFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryDirectoryFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass,
            ReturnSingleEntry,
            FileName,
            RestartScan
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueryDirectoryFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        FileInformationClass,
        dirpath
    );
    
    free_unicode_buffer(dirpath);

    log_debug("Leaving %s\n", "NtQueryDirectoryFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryFullAttributesFile(
    POBJECT_ATTRIBUTES ObjectAttributes,
    void *FileInformation
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryFullAttributesFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryFullAttributesFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryFullAttributesFile(
            ObjectAttributes,
            FileInformation
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_objattr(ObjectAttributes, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_objattr(ObjectAttributes);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryFullAttributesFile(
        ObjectAttributes,
        FileInformation
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueryFullAttributesFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        filepath_r
    );
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "NtQueryFullAttributesFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryInformationFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryInformationFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass
        );
        return ret;
    }

    IO_STATUS_BLOCK _IoStatusBlock;
    if(IoStatusBlock == NULL) {
        IoStatusBlock = &_IoStatusBlock;
        memset(&_IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
    }
    
    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

    uint64_t hash = call_hash(
        "h", 
        FileHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtQueryInformationFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueryInformationFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        FileInformationClass
    );

    log_debug("Leaving %s\n", "NtQueryInformationFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryKey(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryKey(
            KeyHandle,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    ULONG _ResultLength;
    if(ResultLength == NULL) {
        ResultLength = &_ResultLength;
        memset(&_ResultLength, 0, sizeof(ULONG));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        KeyInformationClass
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtQueryKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryKey(
            KeyHandle,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryKey(
        KeyHandle,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueryKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        KeyInformationClass,
        (uintptr_t) *ResultLength, KeyInformation,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtQueryKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryMultipleValueKey(
    HANDLE KeyHandle,
    PKEY_VALUE_ENTRY ValueEntries,
    ULONG EntryCount,
    PVOID ValueBuffer,
    PULONG BufferLength,
    PULONG RequiredBufferLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryMultipleValueKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryMultipleValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryMultipleValueKey(
            KeyHandle,
            ValueEntries,
            EntryCount,
            ValueBuffer,
            BufferLength,
            RequiredBufferLength
        );
        return ret;
    }

    ULONG _BufferLength;
    if(BufferLength == NULL) {
        BufferLength = &_BufferLength;
        memset(&_BufferLength, 0, sizeof(ULONG));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryMultipleValueKey(
        KeyHandle,
        ValueEntries,
        EntryCount,
        ValueBuffer,
        BufferLength,
        RequiredBufferLength
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueryMultipleValueKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        EntryCount,
        (uintptr_t) *BufferLength, ValueBuffer,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtQueryMultipleValueKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQuerySystemInformation");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQuerySystemInformation");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQuerySystemInformation(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQuerySystemInformation,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        SystemInformationClass
    );

    log_debug("Leaving %s\n", "NtQuerySystemInformation");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQuerySystemTime(
    PLARGE_INTEGER SystemTime
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQuerySystemTime");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQuerySystemTime");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQuerySystemTime(
            SystemTime
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQuerySystemTime(
        SystemTime
    );
    get_last_error(&lasterror);
    
    if(NT_SUCCESS(ret) != FALSE) {
        SystemTime->QuadPart += sleep_skipped();
    }

    log_debug("Leaving %s\n", "NtQuerySystemTime");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueryValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueryValueKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueryValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryValueKey(
            KeyHandle,
            ValueName,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    ULONG _ResultLength;
    if(ResultLength == NULL) {
        ResultLength = &_ResultLength;
        memset(&_ResultLength, 0, sizeof(ULONG));
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

    uint64_t hash = call_hash(
        "ui", 
        regkey,
        KeyValueInformationClass
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtQueryValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueryValueKey(
            KeyHandle,
            ValueName,
            KeyValueInformationClass,
            KeyValueInformation,
            Length,
            ResultLength
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueryValueKey(
        KeyHandle,
        ValueName,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength
    );
    get_last_error(&lasterror);
    
    wchar_t *key_name = NULL; uint8_t *data = NULL;
    uint32_t reg_type = REG_NONE, data_length = 0;
    
    if(NT_SUCCESS(ret) != FALSE) {
        reg_get_info_from_keyvalue(KeyValueInformation, *ResultLength,
            KeyValueInformationClass, &key_name, &reg_type,
            &data_length, &data
        );
    }

    log_api(SIG_ntdll_NtQueryValueKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        KeyValueInformationClass,
        regkey,
        key_name,
        reg_type,
        &reg_type, &data_length, data
    );
    
    free_unicode_buffer(regkey);
    free_unicode_buffer(key_name);

    log_debug("Leaving %s\n", "NtQueryValueKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtQueueApcThread(
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtQueueApcThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtQueueApcThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtQueueApcThread(
            ThreadHandle,
            ApcRoutine,
            ApcRoutineContext,
            ApcStatusBlock,
            ApcReserved
        );
        return ret;
    }
    
    pipe("PROCESS:%d", pid_from_thread_handle(ThreadHandle));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtQueueApcThread(
        ThreadHandle,
        ApcRoutine,
        ApcRoutineContext,
        ApcStatusBlock,
        ApcReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtQueueApcThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        ApcRoutineContext,
        ApcStatusBlock,
        pid_from_thread_handle(ThreadHandle)
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "NtQueueApcThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtReadFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtReadFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtReadFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
        );
        return ret;
    }

    IO_STATUS_BLOCK _IoStatusBlock;
    if(IoStatusBlock == NULL) {
        IoStatusBlock = &_IoStatusBlock;
        memset(&_IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));
    }
    
    memset(IoStatusBlock, 0, sizeof(IO_STATUS_BLOCK));

    uint64_t hash = call_hash(
        "h", 
        FileHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtReadFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtReadFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtReadFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtReadFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        Length,
        ByteOffset,
        IoStatusBlock->Information, Buffer
    );

    log_debug("Leaving %s\n", "NtReadFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    LPCVOID BaseAddress,
    LPVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesReaded
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtReadVirtualMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtReadVirtualMemory");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtReadVirtualMemory(
            ProcessHandle,
            BaseAddress,
            Buffer,
            NumberOfBytesToRead,
            NumberOfBytesReaded
        );
        return ret;
    }

    SIZE_T _NumberOfBytesReaded;
    if(NumberOfBytesReaded == NULL) {
        NumberOfBytesReaded = &_NumberOfBytesReaded;
        memset(&_NumberOfBytesReaded, 0, sizeof(SIZE_T));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtReadVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToRead,
        NumberOfBytesReaded
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtReadVirtualMemory,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        BaseAddress,
        NumberOfBytesReaded, Buffer
    );

    log_debug("Leaving %s\n", "NtReadVirtualMemory");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtRenameKey(
    HANDLE KeyHandle,
    PUNICODE_STRING NewName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtRenameKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtRenameKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtRenameKey(
            KeyHandle,
            NewName
        );
        return ret;
    }
    
    wchar_t *new_name = extract_unicode_string_unistr(NewName);
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtRenameKey(
        KeyHandle,
        NewName
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtRenameKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        new_name,
        regkey
    );
    
    free_unicode_buffer(new_name);
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtRenameKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtReplaceKey(
    POBJECT_ATTRIBUTES NewHiveFileName,
    HANDLE KeyHandle,
    POBJECT_ATTRIBUTES BackupHiveFileName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtReplaceKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtReplaceKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtReplaceKey(
            NewHiveFileName,
            KeyHandle,
            BackupHiveFileName
        );
        return ret;
    }
    
    wchar_t *newfilepath = get_unicode_buffer();
    path_get_full_path_objattr(NewHiveFileName, newfilepath);
    
    wchar_t *backupfilepath = get_unicode_buffer();
    path_get_full_path_objattr(BackupHiveFileName, backupfilepath);
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtReplaceKey(
        NewHiveFileName,
        KeyHandle,
        BackupHiveFileName
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtReplaceKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        newfilepath,
        backupfilepath,
        regkey
    );
    
    free_unicode_buffer(newfilepath);
    free_unicode_buffer(backupfilepath);
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtReplaceKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtResumeThread(
    HANDLE ThreadHandle,
    ULONG *SuspendCount
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtResumeThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtResumeThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtResumeThread(
            ThreadHandle,
            SuspendCount
        );
        return ret;
    }

    ULONG _SuspendCount;
    if(SuspendCount == NULL) {
        SuspendCount = &_SuspendCount;
        memset(&_SuspendCount, 0, sizeof(ULONG));
    }
    
    uint32_t pid = pid_from_thread_handle(ThreadHandle);
    if(pid != get_current_process_id()) {
        pipe("PROCESS:%d", pid);
        pipe("DUMPMEM:%d", pid);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtResumeThread(
        ThreadHandle,
        SuspendCount
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtResumeThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        SuspendCount,
        pid
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "NtResumeThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtSaveKey(
    HANDLE KeyHandle,
    HANDLE FileHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtSaveKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtSaveKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSaveKey(
            KeyHandle,
            FileHandle
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_handle(FileHandle, filepath);

    uint64_t hash = call_hash(
        "uu", 
        regkey,
        filepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtSaveKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSaveKey(
            KeyHandle,
            FileHandle
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtSaveKey(
        KeyHandle,
        FileHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtSaveKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        FileHandle,
        regkey,
        filepath
    );
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtSaveKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtSaveKeyEx(
    HANDLE KeyHandle,
    HANDLE FileHandle,
    ULONG Format
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtSaveKeyEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtSaveKeyEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSaveKeyEx(
            KeyHandle,
            FileHandle,
            Format
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key(KeyHandle, regkey);
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_handle(FileHandle, filepath);

    uint64_t hash = call_hash(
        "uu", 
        regkey,
        filepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtSaveKeyEx");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSaveKeyEx(
            KeyHandle,
            FileHandle,
            Format
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtSaveKeyEx(
        KeyHandle,
        FileHandle,
        Format
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtSaveKeyEx,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        FileHandle,
        Format,
        regkey,
        filepath
    );
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtSaveKeyEx");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtSetContextThread(
    HANDLE ThreadHandle,
    const CONTEXT *Context
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtSetContextThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtSetContextThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSetContextThread(
            ThreadHandle,
            Context
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtSetContextThread(
        ThreadHandle,
        Context
    );
    get_last_error(&lasterror);
    
    bson registers;
    bson_init(&registers);
    bson_append_start_object(&registers, "registers");
    
    // TODO What about WOW64 processes?
    if(Context != NULL) {
    #if __x86_64__
        bson_append_long(&registers, "rax", Context->Rax);
        bson_append_long(&registers, "rcx", Context->Rcx);
        bson_append_long(&registers, "rdx", Context->Rdx);
        bson_append_long(&registers, "rbx", Context->Rbx);
        bson_append_long(&registers, "rsp", Context->Rsp);
        bson_append_long(&registers, "rbp", Context->Rbp);
        bson_append_long(&registers, "rsi", Context->Rsi);
        bson_append_long(&registers, "rdi", Context->Rdi);
        bson_append_long(&registers, "r8",  Context->R8);
        bson_append_long(&registers, "r9",  Context->R9);
        bson_append_long(&registers, "r10", Context->R10);
        bson_append_long(&registers, "r11", Context->R11);
        bson_append_long(&registers, "r12", Context->R12);
        bson_append_long(&registers, "r13", Context->R13);
        bson_append_long(&registers, "r14", Context->R14);
        bson_append_long(&registers, "r15", Context->R15);
        bson_append_long(&registers, "rip", Context->Rip);
    #else
        bson_append_int(&registers, "eax", Context->Eax);
        bson_append_int(&registers, "ecx", Context->Ecx);
        bson_append_int(&registers, "edx", Context->Edx);
        bson_append_int(&registers, "ebx", Context->Ebx);
        bson_append_int(&registers, "esp", Context->Esp);
        bson_append_int(&registers, "ebp", Context->Ebp);
        bson_append_int(&registers, "esi", Context->Esi);
        bson_append_int(&registers, "edi", Context->Edi);
        bson_append_int(&registers, "eip", Context->Eip);
    #endif
    }
    
    bson_append_finish_object(&registers);
    bson_finish(&registers);
    
    uint32_t pid = pid_from_thread_handle(ThreadHandle);

    log_api(SIG_ntdll_NtSetContextThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        pid,
        &registers
    );
    
    pipe("PROCESS:%d", pid);
    sleep_skip_disable();
    bson_destroy(&registers);

    log_debug("Leaving %s\n", "NtSetContextThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtSetInformationFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtSetInformationFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass
        );
        return ret;
    }
    
    BOOLEAN value = FALSE;
    if(FileInformation != NULL && Length == sizeof(BOOLEAN) &&
            FileInformationClass == FileDispositionInformation &&
            copy_bytes(&value, FileInformation, sizeof(BOOLEAN)) == 0 &&
            value != FALSE) {
        wchar_t *filepath = get_unicode_buffer();
        path_get_full_path_handle(FileHandle, filepath);
        pipe("FILE_DEL:%Z", filepath);
        free_unicode_buffer(filepath);
    }

    uint64_t hash = call_hash(
        "h", 
        FileHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtSetInformationFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtSetInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtSetInformationFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        FileInformationClass
    );

    log_debug("Leaving %s\n", "NtSetInformationFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtSetValueKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtSetValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSetValueKey(
            KeyHandle,
            ValueName,
            TitleIndex,
            Type,
            Data,
            DataSize
        );
        return ret;
    }
    
    wchar_t *regkey = get_unicode_buffer();
    reg_get_key_unistr(KeyHandle, ValueName, regkey);

    uint64_t hash = call_hash(
        "uiib", 
        regkey,
        TitleIndex,
        Type,
        DataSize, Data
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtSetValueKey");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSetValueKey(
            KeyHandle,
            ValueName,
            TitleIndex,
            Type,
            Data,
            DataSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtSetValueKey(
        KeyHandle,
        ValueName,
        TitleIndex,
        Type,
        Data,
        DataSize
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtSetValueKey,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        KeyHandle,
        TitleIndex,
        Type,
        Type,
        &Type, &DataSize, Data,
        regkey
    );
    
    free_unicode_buffer(regkey);

    log_debug("Leaving %s\n", "NtSetValueKey");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtShutdownSystem(
    SHUTDOWN_ACTION Action
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtShutdownSystem");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtShutdownSystem");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtShutdownSystem(
            Action
        );
        return ret;
    }

    uint64_t hash = 0;
    log_api(SIG_ntdll_NtShutdownSystem,
        0,
        0,
        hash,
        &lasterror,
        Action
    );
    

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtShutdownSystem(
        Action
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtShutdownSystem,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        Action
    );

    log_debug("Leaving %s\n", "NtShutdownSystem");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtSuspendThread(
    HANDLE ThreadHandle,
    ULONG *PreviousSuspendCount
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtSuspendThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtSuspendThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtSuspendThread(
            ThreadHandle,
            PreviousSuspendCount
        );
        return ret;
    }

    ULONG _PreviousSuspendCount;
    if(PreviousSuspendCount == NULL) {
        PreviousSuspendCount = &_PreviousSuspendCount;
        memset(&_PreviousSuspendCount, 0, sizeof(ULONG));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtSuspendThread(
        ThreadHandle,
        PreviousSuspendCount
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtSuspendThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        PreviousSuspendCount
    );

    log_debug("Leaving %s\n", "NtSuspendThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtTerminateProcess");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtTerminateProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtTerminateProcess(
            ProcessHandle,
            ExitStatus
        );
        return ret;
    }
    
    uint32_t pid = pid_from_process_handle(ProcessHandle);
    
    // If the process handle is a nullptr then it will kill all threads in
    // the current process except for the current one. TODO Should we have
    // any special handling for that? Perhaps the unhook detection logic?
    if(ProcessHandle != NULL) {
        pipe("KILL:%d", pid);
    }

    uint64_t hash = 0;
    log_api(SIG_ntdll_NtTerminateProcess,
        0,
        0,
        hash,
        &lasterror,
        ProcessHandle,
        ExitStatus,
        pid
    );
    

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtTerminateProcess(
        ProcessHandle,
        ExitStatus
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtTerminateProcess,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        ExitStatus,
        pid
    );

    log_debug("Leaving %s\n", "NtTerminateProcess");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtTerminateThread(
    HANDLE ThreadHandle,
    NTSTATUS ExitStatus
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtTerminateThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtTerminateThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtTerminateThread(
            ThreadHandle,
            ExitStatus
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtTerminateThread(
        ThreadHandle,
        ExitStatus
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtTerminateThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ThreadHandle,
        ExitStatus
    );

    log_debug("Leaving %s\n", "NtTerminateThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtUnloadDriver(
    PUNICODE_STRING DriverServiceName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtUnloadDriver");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtUnloadDriver");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtUnloadDriver(
            DriverServiceName
        );
        return ret;
    }
    
    wchar_t *driver_service_name =
        extract_unicode_string_unistr(DriverServiceName);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtUnloadDriver(
        DriverServiceName
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtUnloadDriver,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        driver_service_name
    );
    
    free_unicode_buffer(driver_service_name);

    log_debug("Leaving %s\n", "NtUnloadDriver");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtUnmapViewOfSection");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtUnmapViewOfSection");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtUnmapViewOfSection(
            ProcessHandle,
            BaseAddress
        );
        return ret;
    }
    
    MEMORY_BASIC_INFORMATION_CROSS mbi; uintptr_t region_size = 0;
    if(virtual_query_ex(ProcessHandle, BaseAddress, &mbi) != FALSE) {
        region_size = mbi.RegionSize;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtUnmapViewOfSection(
        ProcessHandle,
        BaseAddress
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtUnmapViewOfSection,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        BaseAddress,
        pid_from_process_handle(ProcessHandle),
        region_size
    );

    log_debug("Leaving %s\n", "NtUnmapViewOfSection");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtWriteFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtWriteFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtWriteFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "h", 
        FileHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "NtWriteFile");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtWriteFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtWriteFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtWriteFile,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FileHandle,
        ByteOffset,
        (uintptr_t) Length, Buffer
    );
    
    wchar_t *filepath = get_unicode_buffer();
    
    if(NT_SUCCESS(ret) != FALSE &&
            path_get_full_path_handle(FileHandle, filepath) != 0) {
        pipe("FILE_NEW:%Z", filepath);
    }
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "NtWriteFile");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    LPVOID BaseAddress,
    LPCVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NtWriteVirtualMemory");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NtWriteVirtualMemory");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_NtWriteVirtualMemory(
            ProcessHandle,
            BaseAddress,
            Buffer,
            NumberOfBytesToWrite,
            NumberOfBytesWritten
        );
        return ret;
    }

    SIZE_T _NumberOfBytesWritten;
    if(NumberOfBytesWritten == NULL) {
        NumberOfBytesWritten = &_NumberOfBytesWritten;
        memset(&_NumberOfBytesWritten, 0, sizeof(SIZE_T));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_NtWriteVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_NtWriteVirtualMemory,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        BaseAddress,
        pid_from_process_handle(ProcessHandle),
        NumberOfBytesWritten, Buffer
    );

    log_debug("Leaving %s\n", "NtWriteVirtualMemory");

    set_last_error(&lasterror);
    return ret;
}

PVOID WINAPI New_ntdll_RtlAddVectoredContinueHandler(
    ULONG FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlAddVectoredContinueHandler");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlAddVectoredContinueHandler");

        set_last_error(&lasterror);
        PVOID ret = Old_ntdll_RtlAddVectoredContinueHandler(
            FirstHandler,
            VectoredHandler
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "p", 
        VectoredHandler
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RtlAddVectoredContinueHandler");

        set_last_error(&lasterror);
        PVOID ret = Old_ntdll_RtlAddVectoredContinueHandler(
            FirstHandler,
            VectoredHandler
        );
        return ret;
    }

    set_last_error(&lasterror);
    PVOID ret = Old_ntdll_RtlAddVectoredContinueHandler(
        FirstHandler,
        VectoredHandler
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlAddVectoredContinueHandler,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FirstHandler
    );

    log_debug("Leaving %s\n", "RtlAddVectoredContinueHandler");

    set_last_error(&lasterror);
    return ret;
}

PVOID WINAPI New_ntdll_RtlAddVectoredExceptionHandler(
    ULONG FirstHandler,
    PVECTORED_EXCEPTION_HANDLER VectoredHandler
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlAddVectoredExceptionHandler");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlAddVectoredExceptionHandler");

        set_last_error(&lasterror);
        PVOID ret = Old_ntdll_RtlAddVectoredExceptionHandler(
            FirstHandler,
            VectoredHandler
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "pi", 
        VectoredHandler,
        FirstHandler
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RtlAddVectoredExceptionHandler");

        set_last_error(&lasterror);
        PVOID ret = Old_ntdll_RtlAddVectoredExceptionHandler(
            FirstHandler,
            VectoredHandler
        );
        return ret;
    }

    set_last_error(&lasterror);
    PVOID ret = Old_ntdll_RtlAddVectoredExceptionHandler(
        FirstHandler,
        VectoredHandler
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlAddVectoredExceptionHandler,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        FirstHandler
    );

    log_debug("Leaving %s\n", "RtlAddVectoredExceptionHandler");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_RtlCompressBuffer(
    USHORT CompressionFormatAndEngine,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize,
    PVOID WorkSpace
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlCompressBuffer");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlCompressBuffer");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_RtlCompressBuffer(
            CompressionFormatAndEngine,
            UncompressedBuffer,
            UncompressedBufferSize,
            CompressedBuffer,
            CompressedBufferSize,
            UncompressedChunkSize,
            FinalCompressedSize,
            WorkSpace
        );
        return ret;
    }

    uint64_t hash = 0;

    uintptr_t prelen = UncompressedBufferSize;
    uint8_t *prebuf = memdup(UncompressedBuffer, prelen);

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_RtlCompressBuffer(
        CompressionFormatAndEngine,
        UncompressedBuffer,
        UncompressedBufferSize,
        CompressedBuffer,
        CompressedBufferSize,
        UncompressedChunkSize,
        FinalCompressedSize,
        WorkSpace
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlCompressBuffer,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        prelen, prebuf,
        CompressionFormatAndEngine,
        UncompressedBufferSize,
        FinalCompressedSize
    );

    log_debug("Leaving %s\n", "RtlCompressBuffer");

    set_last_error(&lasterror);
    mem_free(prebuf);
    return ret;
}

NTSTATUS WINAPI New_ntdll_RtlCreateUserProcess(
    PUNICODE_STRING ImagePath,
    ULONG ObjectAttributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlCreateUserProcess");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlCreateUserProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_RtlCreateUserProcess(
            ImagePath,
            ObjectAttributes,
            ProcessParameters,
            ProcessSecurityDescriptor,
            ThreadSecurityDescriptor,
            ParentProcess,
            InheritHandles,
            DebugPort,
            ExceptionPort,
            ProcessInformation
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_path_unistr(ImagePath, filepath);
    
    wchar_t *filepath_r = extract_unicode_string_unistr(ImagePath);

    uint64_t hash = call_hash(
        "uii", 
        filepath,
        ObjectAttributes,
        InheritHandles
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RtlCreateUserProcess");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_RtlCreateUserProcess(
            ImagePath,
            ObjectAttributes,
            ProcessParameters,
            ProcessSecurityDescriptor,
            ThreadSecurityDescriptor,
            ParentProcess,
            InheritHandles,
            DebugPort,
            ExceptionPort,
            ProcessInformation
        );
        return ret;
    }

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_RtlCreateUserProcess(
        ImagePath,
        ObjectAttributes,
        ProcessParameters,
        ProcessSecurityDescriptor,
        ThreadSecurityDescriptor,
        ParentProcess,
        InheritHandles,
        DebugPort,
        ExceptionPort,
        ProcessInformation
    );
    get_last_error(&lasterror);
    
    uint32_t pid = 0, tid = 0;
    if(ProcessInformation != NULL) {
        pid = pid_from_process_handle(copy_ptr(&ProcessInformation->ProcessHandle));
        tid = tid_from_thread_handle(copy_ptr(&ProcessInformation->ThreadHandle));
    }

    log_api(SIG_ntdll_RtlCreateUserProcess,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ObjectAttributes,
        ParentProcess,
        InheritHandles,
        pid,
        tid,
        filepath,
        filepath_r
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);
        sleep_skip_disable();
    }
    
    free_unicode_buffer(filepath);
    free_unicode_buffer(filepath_r);

    log_debug("Leaving %s\n", "RtlCreateUserProcess");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_RtlCreateUserThread(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    PCLIENT_ID ClientId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlCreateUserThread");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlCreateUserThread");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_RtlCreateUserThread(
            ProcessHandle,
            SecurityDescriptor,
            CreateSuspended,
            StackZeroBits,
            StackReserved,
            StackCommit,
            StartAddress,
            StartParameter,
            ThreadHandle,
            ClientId
        );
        return ret;
    }
    
    pipe("PROCESS:%d", pid_from_process_handle(ProcessHandle));

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_RtlCreateUserThread(
        ProcessHandle,
        SecurityDescriptor,
        CreateSuspended,
        StackZeroBits,
        StackReserved,
        StackCommit,
        StartAddress,
        StartParameter,
        ThreadHandle,
        ClientId
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlCreateUserThread,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        ProcessHandle,
        CreateSuspended,
        StartAddress,
        StartParameter,
        ThreadHandle
    );
    
    if(NT_SUCCESS(ret) != FALSE) {
        sleep_skip_disable();
    }

    log_debug("Leaving %s\n", "RtlCreateUserThread");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_RtlDecompressBuffer(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlDecompressBuffer");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlDecompressBuffer");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_RtlDecompressBuffer(
            CompressionFormat,
            UncompressedBuffer,
            UncompressedBufferSize,
            CompressedBuffer,
            CompressedBufferSize,
            FinalUncompressedSize
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_RtlDecompressBuffer(
        CompressionFormat,
        UncompressedBuffer,
        UncompressedBufferSize,
        CompressedBuffer,
        CompressedBufferSize,
        FinalUncompressedSize
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlDecompressBuffer,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        CompressionFormat,
        CompressedBufferSize,
        FinalUncompressedSize,
        FinalUncompressedSize, UncompressedBuffer
    );

    log_debug("Leaving %s\n", "RtlDecompressBuffer");

    set_last_error(&lasterror);
    return ret;
}

NTSTATUS WINAPI New_ntdll_RtlDecompressFragment(
    USHORT CompressionFormat,
    PUCHAR UncompressedFragment,
    ULONG UncompressedFragmentSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    ULONG FragmentOffset,
    PULONG FinalUncompressedSize,
    PVOID WorkSpace
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlDecompressFragment");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlDecompressFragment");

        set_last_error(&lasterror);
        NTSTATUS ret = Old_ntdll_RtlDecompressFragment(
            CompressionFormat,
            UncompressedFragment,
            UncompressedFragmentSize,
            CompressedBuffer,
            CompressedBufferSize,
            FragmentOffset,
            FinalUncompressedSize,
            WorkSpace
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NTSTATUS ret = Old_ntdll_RtlDecompressFragment(
        CompressionFormat,
        UncompressedFragment,
        UncompressedFragmentSize,
        CompressedBuffer,
        CompressedBufferSize,
        FragmentOffset,
        FinalUncompressedSize,
        WorkSpace
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlDecompressFragment,
        NT_SUCCESS(ret) != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        CompressionFormat,
        CompressedBufferSize,
        FragmentOffset,
        FinalUncompressedSize,
        FinalUncompressedSize, UncompressedFragment
    );

    log_debug("Leaving %s\n", "RtlDecompressFragment");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_ntdll_RtlDispatchException(
    EXCEPTION_RECORD *ExceptionRecord,
    CONTEXT *Context
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlDispatchException");
    
    uint32_t exception_code = 0;
    if(ExceptionRecord != NULL) {
        exception_code = ExceptionRecord->ExceptionCode;
    }
    
    uintptr_t pc = 0;
    #if __x86_64__
    pc = Context->Rip;
    #else
    pc = Context->Eip;
    #endif
    
    // Is this exception within our monitor?
    if(exception_code == STATUS_ACCESS_VIOLATION &&
            pc >= g_monitor_start && pc < g_monitor_end) {
        copy_return();
    }
    
    // Is this exception address whitelisted? This is the case for the
    // IsBadReadPtr function where access violations are expected.
    if(exception_code == STATUS_ACCESS_VIOLATION &&
            is_exception_address_whitelisted(pc) == 0) {
        // TODO Should we do something here?
        // For now we'll just ignore this code path.
    }
    // Ignore exceptions that are caused by calling OutputDebugString().
    else if(is_exception_code_whitelisted(exception_code) == 0) {
        uintptr_t addrs[RETADDRCNT]; uint32_t count = 0;
        count = stacktrace(Context, addrs, RETADDRCNT);
        log_exception(Context, ExceptionRecord, addrs, count);
    }

    set_last_error(&lasterror);
    void * ret = Old_ntdll_RtlDispatchException(
        ExceptionRecord,
        Context
    );
    get_last_error(&lasterror);
        

    log_debug("Leaving %s\n", "RtlDispatchException");

    set_last_error(&lasterror);
    return ret;
}

ULONG WINAPI New_ntdll_RtlRemoveVectoredContinueHandler(
    PVOID VectoredHandlerHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlRemoveVectoredContinueHandler");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlRemoveVectoredContinueHandler");

        set_last_error(&lasterror);
        ULONG ret = Old_ntdll_RtlRemoveVectoredContinueHandler(
            VectoredHandlerHandle
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "p", 
        VectoredHandlerHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RtlRemoveVectoredContinueHandler");

        set_last_error(&lasterror);
        ULONG ret = Old_ntdll_RtlRemoveVectoredContinueHandler(
            VectoredHandlerHandle
        );
        return ret;
    }

    set_last_error(&lasterror);
    ULONG ret = Old_ntdll_RtlRemoveVectoredContinueHandler(
        VectoredHandlerHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlRemoveVectoredContinueHandler,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "RtlRemoveVectoredContinueHandler");

    set_last_error(&lasterror);
    return ret;
}

ULONG WINAPI New_ntdll_RtlRemoveVectoredExceptionHandler(
    PVOID VectoredHandlerHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RtlRemoveVectoredExceptionHandler");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RtlRemoveVectoredExceptionHandler");

        set_last_error(&lasterror);
        ULONG ret = Old_ntdll_RtlRemoveVectoredExceptionHandler(
            VectoredHandlerHandle
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "p", 
        VectoredHandlerHandle
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "RtlRemoveVectoredExceptionHandler");

        set_last_error(&lasterror);
        ULONG ret = Old_ntdll_RtlRemoveVectoredExceptionHandler(
            VectoredHandlerHandle
        );
        return ret;
    }

    set_last_error(&lasterror);
    ULONG ret = Old_ntdll_RtlRemoveVectoredExceptionHandler(
        VectoredHandlerHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_ntdll_RtlRemoveVectoredExceptionHandler,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "RtlRemoveVectoredExceptionHandler");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_CoCreateInstance(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID *ppv
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CoCreateInstance");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CoCreateInstance");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoCreateInstance(
            rclsid,
            pUnkOuter,
            dwClsContext,
            riid,
            ppv
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "bib", 
        sizeof(CLSID), rclsid,
        dwClsContext,
        sizeof(IID), riid
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "CoCreateInstance");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoCreateInstance(
            rclsid,
            pUnkOuter,
            dwClsContext,
            riid,
            ppv
        );
        return ret;
    }

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_CoCreateInstance(
        rclsid,
        pUnkOuter,
        dwClsContext,
        riid,
        ppv
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_CoCreateInstance,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        rclsid,
        dwClsContext,
        riid
    );
    
    ole_enable_hooks(rclsid);

    log_debug("Leaving %s\n", "CoCreateInstance");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_CoCreateInstanceEx(
    REFCLSID rclsid,
    IUnknown *punkOuter,
    DWORD dwClsCtx,
    COSERVERINFO *pServerInfo,
    DWORD dwCount,
    MULTI_QI *pResults
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CoCreateInstanceEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CoCreateInstanceEx");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoCreateInstanceEx(
            rclsid,
            punkOuter,
            dwClsCtx,
            pServerInfo,
            dwCount,
            pResults
        );
        return ret;
    }
    
    bson b; char index[8], clsid[64];
    bson_init(&b);
    
    bson_append_start_array(&b, "iid");
    
    MULTI_QI *multi_qi = pResults;
    for (uint32_t idx = 0; idx < dwCount; idx++, multi_qi++) {
        our_snprintf(index, sizeof(index), "%d", idx++);
        clsid_to_string(copy_ptr(&multi_qi->pIID), clsid);
        log_string(&b, index, clsid, our_strlen(clsid));
    }
    
    bson_append_finish_array(&b);
    bson_finish(&b);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_CoCreateInstanceEx(
        rclsid,
        punkOuter,
        dwClsCtx,
        pServerInfo,
        dwCount,
        pResults
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_CoCreateInstanceEx,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        rclsid,
        dwClsCtx,
        &b
    );
    
    ole_enable_hooks(rclsid);
    bson_destroy(&b);

    log_debug("Leaving %s\n", "CoCreateInstanceEx");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_CoGetClassObject(
    REFCLSID rclsid,
    DWORD dwClsContext,
    COSERVERINFO *pServerInfo,
    REFIID riid,
    LPVOID *ppv
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CoGetClassObject");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CoGetClassObject");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoGetClassObject(
            rclsid,
            dwClsContext,
            pServerInfo,
            riid,
            ppv
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_CoGetClassObject(
        rclsid,
        dwClsContext,
        pServerInfo,
        riid,
        ppv
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_CoGetClassObject,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        rclsid,
        dwClsContext,
        riid
    );
    
    ole_enable_hooks(rclsid);

    log_debug("Leaving %s\n", "CoGetClassObject");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_CoInitializeEx(
    LPVOID pvReserved,
    DWORD dwCoInit
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CoInitializeEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CoInitializeEx");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoInitializeEx(
            pvReserved,
            dwCoInit
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_CoInitializeEx(
        pvReserved,
        dwCoInit
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_CoInitializeEx,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwCoInit
    );

    log_debug("Leaving %s\n", "CoInitializeEx");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_CoInitializeSecurity(
    PSECURITY_DESCRIPTOR pSecDesc,
    LONG cAuthSvc,
    SOLE_AUTHENTICATION_SERVICE *asAuthSvc,
    void *pReserved1,
    DWORD dwAuthnLevel,
    DWORD dwImpLevel,
    void *pAuthList,
    DWORD dwCapabilities,
    void *pReserved3
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CoInitializeSecurity");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CoInitializeSecurity");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoInitializeSecurity(
            pSecDesc,
            cAuthSvc,
            asAuthSvc,
            pReserved1,
            dwAuthnLevel,
            dwImpLevel,
            pAuthList,
            dwCapabilities,
            pReserved3
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_CoInitializeSecurity(
        pSecDesc,
        cAuthSvc,
        asAuthSvc,
        pReserved1,
        dwAuthnLevel,
        dwImpLevel,
        pAuthList,
        dwCapabilities,
        pReserved3
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_CoInitializeSecurity,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "CoInitializeSecurity");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_CoUninitialize(
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "CoUninitialize");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "CoUninitialize");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_CoUninitialize(
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_CoUninitialize(
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_CoUninitialize,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "CoUninitialize");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_OleConvertOLESTREAMToIStorage(
    LPOLESTREAM lpolestream,
    IStorage *pstg,
    const DVTARGETDEVICE *ptd
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OleConvertOLESTREAMToIStorage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OleConvertOLESTREAMToIStorage");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_OleConvertOLESTREAMToIStorage(
            lpolestream,
            pstg,
            ptd
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_OleConvertOLESTREAMToIStorage(
        lpolestream,
        pstg,
        ptd
    );
    get_last_error(&lasterror);
    
    void *buf = NULL; uintptr_t len = 0;
    
    #if !__x86_64__
    if(lpolestream != NULL) {
        buf = copy_ptr(copy_ptr((uint8_t *) lpolestream + 8));
        len = copy_uint32((uint8_t *) lpolestream + 12);
    }
    #endif

    log_api(SIG_ole32_OleConvertOLESTREAMToIStorage,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        len, buf
    );

    log_debug("Leaving %s\n", "OleConvertOLESTREAMToIStorage");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_ole32_OleInitialize(
    LPVOID pvReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "OleInitialize");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "OleInitialize");

        set_last_error(&lasterror);
        HRESULT ret = Old_ole32_OleInitialize(
            pvReserved
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_ole32_OleInitialize(
        pvReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_ole32_OleInitialize,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "OleInitialize");

    set_last_error(&lasterror);
    return ret;
}

RPC_STATUS WINAPI New_rpcrt4_UuidCreate(
    UUID *Uuid
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "UuidCreate");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "UuidCreate");

        set_last_error(&lasterror);
        RPC_STATUS ret = Old_rpcrt4_UuidCreate(
            Uuid
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    RPC_STATUS ret = Old_rpcrt4_UuidCreate(
        Uuid
    );
    get_last_error(&lasterror);
    
    char uuid[128];
    clsid_to_string(Uuid, uuid);

    log_api(SIG_rpcrt4_UuidCreate,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        uuid
    );

    log_debug("Leaving %s\n", "UuidCreate");

    set_last_error(&lasterror);
    return ret;
}

SECURITY_STATUS WINAPI New_secur32_DecryptMessage(
    PCtxtHandle phContext,
    PSecBufferDesc pMessage,
    ULONG MessageSeqNo,
    PULONG pfQOP
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DecryptMessage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DecryptMessage");

        set_last_error(&lasterror);
        SECURITY_STATUS ret = Old_secur32_DecryptMessage(
            phContext,
            pMessage,
            MessageSeqNo,
            pfQOP
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    SECURITY_STATUS ret = Old_secur32_DecryptMessage(
        phContext,
        pMessage,
        MessageSeqNo,
        pfQOP
    );
    get_last_error(&lasterror);
    
    uint8_t *buf = NULL; uintptr_t length = 0;
    
    if(pMessage != NULL && pMessage->pBuffers != NULL) {
        secbuf_get_buffer(pMessage->cBuffers,
            pMessage->pBuffers, &buf, &length);
    }

    log_api(SIG_secur32_DecryptMessage,
        ret == SEC_E_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        phContext,
        MessageSeqNo,
        pfQOP,
        length, buf
    );

    log_debug("Leaving %s\n", "DecryptMessage");

    set_last_error(&lasterror);
    return ret;
}

SECURITY_STATUS WINAPI New_secur32_EncryptMessage(
    PCtxtHandle phContext,
    ULONG fQOP,
    PSecBufferDesc pMessage,
    ULONG MessageSeqNo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "EncryptMessage");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "EncryptMessage");

        set_last_error(&lasterror);
        SECURITY_STATUS ret = Old_secur32_EncryptMessage(
            phContext,
            fQOP,
            pMessage,
            MessageSeqNo
        );
        return ret;
    }
    
    uint8_t *buf = NULL; uintptr_t length = 0;
    
    if(pMessage != NULL && pMessage->pBuffers != NULL) {
        secbuf_get_buffer(pMessage->cBuffers,
            pMessage->pBuffers, &buf, &length);
        buf = memdup(buf, length);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    SECURITY_STATUS ret = Old_secur32_EncryptMessage(
        phContext,
        fQOP,
        pMessage,
        MessageSeqNo
    );
    get_last_error(&lasterror);

    log_api(SIG_secur32_EncryptMessage,
        ret == SEC_E_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        phContext,
        fQOP,
        MessageSeqNo,
        length, buf
    );
    
    mem_free(buf);

    log_debug("Leaving %s\n", "EncryptMessage");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_secur32_GetUserNameExA(
    EXTENDED_NAME_FORMAT NameFormat,
    LPCSTR lpNameBuffer,
    PULONG lpnSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetUserNameExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetUserNameExA");

        set_last_error(&lasterror);
        BOOL ret = Old_secur32_GetUserNameExA(
            NameFormat,
            lpNameBuffer,
            lpnSize
        );
        return ret;
    }

    ULONG _lpnSize;
    if(lpnSize == NULL) {
        lpnSize = &_lpnSize;
        memset(&_lpnSize, 0, sizeof(ULONG));
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetUserNameExA");

        set_last_error(&lasterror);
        BOOL ret = Old_secur32_GetUserNameExA(
            NameFormat,
            lpNameBuffer,
            lpnSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_secur32_GetUserNameExA(
        NameFormat,
        lpNameBuffer,
        lpnSize
    );
    get_last_error(&lasterror);

    log_api(SIG_secur32_GetUserNameExA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        NameFormat,
        copy_uint32(lpnSize)-1, lpNameBuffer
    );

    log_debug("Leaving %s\n", "GetUserNameExA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_secur32_GetUserNameExW(
    EXTENDED_NAME_FORMAT NameFormat,
    LPWSTR lpNameBuffer,
    PULONG lpnSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetUserNameExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetUserNameExW");

        set_last_error(&lasterror);
        BOOL ret = Old_secur32_GetUserNameExW(
            NameFormat,
            lpNameBuffer,
            lpnSize
        );
        return ret;
    }

    ULONG _lpnSize;
    if(lpnSize == NULL) {
        lpnSize = &_lpnSize;
        memset(&_lpnSize, 0, sizeof(ULONG));
    }

    uint64_t hash = call_hash("");
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetUserNameExW");

        set_last_error(&lasterror);
        BOOL ret = Old_secur32_GetUserNameExW(
            NameFormat,
            lpNameBuffer,
            lpnSize
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_secur32_GetUserNameExW(
        NameFormat,
        lpNameBuffer,
        lpnSize
    );
    get_last_error(&lasterror);

    log_api(SIG_secur32_GetUserNameExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        NameFormat,
        copy_uint32(lpnSize)-1, lpNameBuffer
    );

    log_debug("Leaving %s\n", "GetUserNameExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_shell32_ReadCabinetState(
    CABINETSTATE *pcs,
    int cLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ReadCabinetState");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ReadCabinetState");

        set_last_error(&lasterror);
        BOOL ret = Old_shell32_ReadCabinetState(
            pcs,
            cLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_shell32_ReadCabinetState(
        pcs,
        cLength
    );
    get_last_error(&lasterror);

    log_api(SIG_shell32_ReadCabinetState,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "ReadCabinetState");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_shell32_SHGetFolderPathW(
    HWND hwndOwner,
    int nFolder,
    HANDLE hToken,
    DWORD dwFlags,
    LPWSTR pszPath
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SHGetFolderPathW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SHGetFolderPathW");

        set_last_error(&lasterror);
        HRESULT ret = Old_shell32_SHGetFolderPathW(
            hwndOwner,
            nFolder,
            hToken,
            dwFlags,
            pszPath
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_shell32_SHGetFolderPathW(
        hwndOwner,
        nFolder,
        hToken,
        dwFlags,
        pszPath
    );
    get_last_error(&lasterror);
    
    wchar_t *dirpath = get_unicode_buffer();
    path_get_full_pathW(pszPath, dirpath);

    log_api(SIG_shell32_SHGetFolderPathW,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hwndOwner,
        nFolder,
        hToken,
        dwFlags,
        dirpath,
        pszPath
    );
    
    free_unicode_buffer(dirpath);

    log_debug("Leaving %s\n", "SHGetFolderPathW");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_shell32_SHGetSpecialFolderLocation(
    HWND hwndOwner,
    int nFolder,
    void *ppidl
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SHGetSpecialFolderLocation");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SHGetSpecialFolderLocation");

        set_last_error(&lasterror);
        HRESULT ret = Old_shell32_SHGetSpecialFolderLocation(
            hwndOwner,
            nFolder,
            ppidl
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_shell32_SHGetSpecialFolderLocation(
        hwndOwner,
        nFolder,
        ppidl
    );
    get_last_error(&lasterror);

    log_api(SIG_shell32_SHGetSpecialFolderLocation,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hwndOwner,
        nFolder
    );

    log_debug("Leaving %s\n", "SHGetSpecialFolderLocation");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_shell32_ShellExecuteExW(
    SHELLEXECUTEINFOW *pExecInfo
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ShellExecuteExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ShellExecuteExW");

        set_last_error(&lasterror);
        BOOL ret = Old_shell32_ShellExecuteExW(
            pExecInfo
        );
        return ret;
    }

    SHELLEXECUTEINFOW _pExecInfo;
    if(pExecInfo == NULL) {
        pExecInfo = &_pExecInfo;
        memset(&_pExecInfo, 0, sizeof(SHELLEXECUTEINFOW));
    }
    
    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof(SHELLEXECUTEINFOW));
    
    wchar_t *filepath = get_unicode_buffer();
    if(pExecInfo != NULL &&
            copy_bytes(&sei, pExecInfo, sizeof(SHELLEXECUTEINFOW)) == 0 &&
            sei.lpFile != NULL) {
        // In case it's a relative path we'll just stick to it.
        copy_unicodez(filepath, sei.lpFile);
    
        // If this is not a relative path then we resolve the full path.
        if(lstrlenW(filepath) > 2 && filepath[1] == ':' &&
                filepath[2] == '\\') {
            path_get_full_pathW(sei.lpFile, filepath);
        }
    }

    uint64_t hash = call_hash(
        "uiuuuuiui", 
        filepath,
        sei.fMask,
        sei.lpVerb,
        sei.lpFile,
        sei.lpParameters,
        sei.lpDirectory,
        sei.nShow,
        sei.lpClass,
        sei.dwHotKey
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "ShellExecuteExW");

        set_last_error(&lasterror);
        BOOL ret = Old_shell32_ShellExecuteExW(
            pExecInfo
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_shell32_ShellExecuteExW(
        pExecInfo
    );
    get_last_error(&lasterror);

    log_api(SIG_shell32_ShellExecuteExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        filepath,
        sei.lpFile,
        sei.lpParameters,
        sei.nShow
    );
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "ShellExecuteExW");

    set_last_error(&lasterror);
    return ret;
}

NET_API_STATUS WINAPI New_srvcli_NetShareEnum(
    LPWSTR servername,
    DWORD level,
    LPBYTE *bufptr,
    DWORD prefmaxlen,
    LPDWORD entriesread,
    LPDWORD totalentries,
    LPDWORD resume_handle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "NetShareEnum");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "NetShareEnum");

        set_last_error(&lasterror);
        NET_API_STATUS ret = Old_srvcli_NetShareEnum(
            servername,
            level,
            bufptr,
            prefmaxlen,
            entriesread,
            totalentries,
            resume_handle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    NET_API_STATUS ret = Old_srvcli_NetShareEnum(
        servername,
        level,
        bufptr,
        prefmaxlen,
        entriesread,
        totalentries,
        resume_handle
    );
    get_last_error(&lasterror);

    log_api(SIG_srvcli_NetShareEnum,
        ret == NERR_Success,
        (uintptr_t) ret,
        hash,
        &lasterror,
        servername,
        level
    );

    log_debug("Leaving %s\n", "NetShareEnum");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_urlmon_ObtainUserAgentString(
    DWORD dwOption,
    LPSTR pcszUAOut,
    DWORD *cbSize
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ObtainUserAgentString");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ObtainUserAgentString");

        set_last_error(&lasterror);
        HRESULT ret = Old_urlmon_ObtainUserAgentString(
            dwOption,
            pcszUAOut,
            cbSize
        );
        return ret;
    }

    DWORD _cbSize;
    if(cbSize == NULL) {
        cbSize = &_cbSize;
        memset(&_cbSize, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HRESULT ret = Old_urlmon_ObtainUserAgentString(
        dwOption,
        pcszUAOut,
        cbSize
    );
    get_last_error(&lasterror);
    
    uint32_t length = ret == S_OK ? copy_uint32(cbSize) : 0;

    log_api(SIG_urlmon_ObtainUserAgentString,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwOption,
        length, pcszUAOut
    );

    log_debug("Leaving %s\n", "ObtainUserAgentString");

    set_last_error(&lasterror);
    return ret;
}

HRESULT WINAPI New_urlmon_URLDownloadToFileW(
    LPUNKNOWN pCaller,
    LPWSTR szURL,
    LPWSTR szFileName,
    DWORD dwReserved,
    LPVOID lpfnCB
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "URLDownloadToFileW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "URLDownloadToFileW");

        set_last_error(&lasterror);
        HRESULT ret = Old_urlmon_URLDownloadToFileW(
            pCaller,
            szURL,
            szFileName,
            dwReserved,
            lpfnCB
        );
        return ret;
    }
    
    wchar_t *filepath = get_unicode_buffer();
    path_get_full_pathW(szFileName, filepath);

    uint64_t hash = call_hash(
        "uu", 
        szURL,
        filepath
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "URLDownloadToFileW");

        set_last_error(&lasterror);
        HRESULT ret = Old_urlmon_URLDownloadToFileW(
            pCaller,
            szURL,
            szFileName,
            dwReserved,
            lpfnCB
        );
        return ret;
    }

    set_last_error(&lasterror);
    HRESULT ret = Old_urlmon_URLDownloadToFileW(
        pCaller,
        szURL,
        szFileName,
        dwReserved,
        lpfnCB
    );
    get_last_error(&lasterror);

    log_api(SIG_urlmon_URLDownloadToFileW,
        ret == S_OK,
        (uintptr_t) ret,
        hash,
        &lasterror,
        szURL,
        filepath,
        szFileName
    );
    
    if(ret == S_OK) {
        pipe("FILE_NEW:%Z", filepath);
    }
    
    free_unicode_buffer(filepath);

    log_debug("Leaving %s\n", "URLDownloadToFileW");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_DrawTextExA(
    HDC hdc,
    LPSTR lpchText,
    int cchText,
    LPRECT lprc,
    UINT dwDTFormat,
    LPDRAWTEXTPARAMS lpDTParams
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DrawTextExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DrawTextExA");

        set_last_error(&lasterror);
        int ret = Old_user32_DrawTextExA(
            hdc,
            lpchText,
            cchText,
            lprc,
            dwDTFormat,
            lpDTParams
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_user32_DrawTextExA(
        hdc,
        lpchText,
        cchText,
        lprc,
        dwDTFormat,
        lpDTParams
    );
    get_last_error(&lasterror);
    
    if(cchText == -1) {
        cchText = copy_strlen(lpchText);
    }

    log_api(SIG_user32_DrawTextExA,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        cchText, lpchText
    );

    log_debug("Leaving %s\n", "DrawTextExA");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_DrawTextExW(
    HDC hdc,
    LPWSTR lpchText,
    int cchText,
    LPRECT lprc,
    UINT dwDTFormat,
    LPDRAWTEXTPARAMS lpDTParams
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DrawTextExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DrawTextExW");

        set_last_error(&lasterror);
        int ret = Old_user32_DrawTextExW(
            hdc,
            lpchText,
            cchText,
            lprc,
            dwDTFormat,
            lpDTParams
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_user32_DrawTextExW(
        hdc,
        lpchText,
        cchText,
        lprc,
        dwDTFormat,
        lpDTParams
    );
    get_last_error(&lasterror);
    
    if(cchText == -1) {
        cchText = copy_strlenW(lpchText);
    }

    log_api(SIG_user32_DrawTextExW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        cchText, lpchText
    );

    log_debug("Leaving %s\n", "DrawTextExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_EnumWindows(
    WNDENUMPROC lpEnumProc,
    LPARAM lParam
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "EnumWindows");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "EnumWindows");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_EnumWindows(
            lpEnumProc,
            lParam
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_EnumWindows(
        lpEnumProc,
        lParam
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_EnumWindows,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "EnumWindows");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_ExitWindowsEx(
    UINT uFlags,
    DWORD dwReason
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ExitWindowsEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ExitWindowsEx");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_ExitWindowsEx(
            uFlags,
            dwReason
        );
        return ret;
    }

    uint64_t hash = 0;
    log_api(SIG_user32_ExitWindowsEx,
        0,
        0,
        hash,
        &lasterror,
        uFlags,
        dwReason
    );
    

    set_last_error(&lasterror);
    BOOL ret = Old_user32_ExitWindowsEx(
        uFlags,
        dwReason
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_ExitWindowsEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        uFlags,
        dwReason
    );

    log_debug("Leaving %s\n", "ExitWindowsEx");

    set_last_error(&lasterror);
    return ret;
}

HWND WINAPI New_user32_FindWindowA(
    LPCSTR lpClassName,
    LPCTSTR lpWindowName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindWindowA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindWindowA");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowA(
            lpClassName,
            lpWindowName
        );
        return ret;
    }
    
    char value[10], *class_name;
    
    int_or_strA(&class_name, lpClassName, value);

    uint64_t hash = call_hash(
        "ss", 
        class_name,
        lpWindowName
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "FindWindowA");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowA(
            lpClassName,
            lpWindowName
        );
        return ret;
    }

    set_last_error(&lasterror);
    HWND ret = Old_user32_FindWindowA(
        lpClassName,
        lpWindowName
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_FindWindowA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpWindowName,
        class_name
    );

    log_debug("Leaving %s\n", "FindWindowA");

    set_last_error(&lasterror);
    return ret;
}

HWND WINAPI New_user32_FindWindowExA(
    HWND hwndParent,
    HWND hwndChildAfter,
    LPCTSTR lpszClass,
    LPCTSTR lpszWindow
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindWindowExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindWindowExA");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowExA(
            hwndParent,
            hwndChildAfter,
            lpszClass,
            lpszWindow
        );
        return ret;
    }
    
    char value[10], *class_name;
    
    int_or_strA(&class_name, lpszClass, value);

    uint64_t hash = call_hash(
        "ss", 
        class_name,
        lpszWindow
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "FindWindowExA");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowExA(
            hwndParent,
            hwndChildAfter,
            lpszClass,
            lpszWindow
        );
        return ret;
    }

    set_last_error(&lasterror);
    HWND ret = Old_user32_FindWindowExA(
        hwndParent,
        hwndChildAfter,
        lpszClass,
        lpszWindow
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_FindWindowExA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hwndParent,
        hwndChildAfter,
        lpszWindow,
        class_name
    );

    log_debug("Leaving %s\n", "FindWindowExA");

    set_last_error(&lasterror);
    return ret;
}

HWND WINAPI New_user32_FindWindowExW(
    HWND hwndParent,
    HWND hwndChildAfter,
    LPWSTR lpszClass,
    LPWSTR lpszWindow
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindWindowExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindWindowExW");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowExW(
            hwndParent,
            hwndChildAfter,
            lpszClass,
            lpszWindow
        );
        return ret;
    }
    
    wchar_t value[10], *class_name;
    
    int_or_strW(&class_name, lpszClass, value);

    uint64_t hash = call_hash(
        "uu", 
        class_name,
        lpszWindow
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "FindWindowExW");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowExW(
            hwndParent,
            hwndChildAfter,
            lpszClass,
            lpszWindow
        );
        return ret;
    }

    set_last_error(&lasterror);
    HWND ret = Old_user32_FindWindowExW(
        hwndParent,
        hwndChildAfter,
        lpszClass,
        lpszWindow
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_FindWindowExW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hwndParent,
        hwndChildAfter,
        lpszWindow,
        class_name
    );

    log_debug("Leaving %s\n", "FindWindowExW");

    set_last_error(&lasterror);
    return ret;
}

HWND WINAPI New_user32_FindWindowW(
    LPWSTR lpClassName,
    LPWSTR lpWindowName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "FindWindowW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "FindWindowW");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowW(
            lpClassName,
            lpWindowName
        );
        return ret;
    }
    
    wchar_t value[10], *class_name;
    
    int_or_strW(&class_name, lpClassName, value);

    uint64_t hash = call_hash(
        "uu", 
        class_name,
        lpWindowName
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "FindWindowW");

        set_last_error(&lasterror);
        HWND ret = Old_user32_FindWindowW(
            lpClassName,
            lpWindowName
        );
        return ret;
    }

    set_last_error(&lasterror);
    HWND ret = Old_user32_FindWindowW(
        lpClassName,
        lpWindowName
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_FindWindowW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpWindowName,
        class_name
    );

    log_debug("Leaving %s\n", "FindWindowW");

    set_last_error(&lasterror);
    return ret;
}

SHORT WINAPI New_user32_GetAsyncKeyState(
    int vKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetAsyncKeyState");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetAsyncKeyState");

        set_last_error(&lasterror);
        SHORT ret = Old_user32_GetAsyncKeyState(
            vKey
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    SHORT ret = Old_user32_GetAsyncKeyState(
        vKey
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_GetAsyncKeyState,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        vKey
    );

    log_debug("Leaving %s\n", "GetAsyncKeyState");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_GetCursorPos(
    LPPOINT lpPoint
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetCursorPos");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetCursorPos");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_GetCursorPos(
            lpPoint
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_GetCursorPos(
        lpPoint
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_GetCursorPos,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpPoint != NULL ? &lpPoint->x : 0,
        lpPoint != NULL ? &lpPoint->y : 0
    );

    log_debug("Leaving %s\n", "GetCursorPos");

    set_last_error(&lasterror);
    return ret;
}

HWND WINAPI New_user32_GetForegroundWindow(
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetForegroundWindow");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetForegroundWindow");

        set_last_error(&lasterror);
        HWND ret = Old_user32_GetForegroundWindow(
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    HWND ret = Old_user32_GetForegroundWindow(
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_GetForegroundWindow,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GetForegroundWindow");

    set_last_error(&lasterror);
    return ret;
}

SHORT WINAPI New_user32_GetKeyState(
    int nVirtKey
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetKeyState");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetKeyState");

        set_last_error(&lasterror);
        SHORT ret = Old_user32_GetKeyState(
            nVirtKey
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    SHORT ret = Old_user32_GetKeyState(
        nVirtKey
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_GetKeyState,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        nVirtKey
    );

    log_debug("Leaving %s\n", "GetKeyState");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_GetKeyboardState(
    PBYTE lpKeyState
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetKeyboardState");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetKeyboardState");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_GetKeyboardState(
            lpKeyState
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_GetKeyboardState(
        lpKeyState
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_GetKeyboardState,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror
    );

    log_debug("Leaving %s\n", "GetKeyboardState");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_GetSystemMetrics(
    int nIndex
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetSystemMetrics");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetSystemMetrics");

        set_last_error(&lasterror);
        int ret = Old_user32_GetSystemMetrics(
            nIndex
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "i", 
        nIndex
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetSystemMetrics");

        set_last_error(&lasterror);
        int ret = Old_user32_GetSystemMetrics(
            nIndex
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_user32_GetSystemMetrics(
        nIndex
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_GetSystemMetrics,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        nIndex
    );

    log_debug("Leaving %s\n", "GetSystemMetrics");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_LoadStringA(
    HINSTANCE hInstance,
    UINT uID,
    LPSTR lpBuffer,
    int nBufferMax
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LoadStringA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LoadStringA");

        set_last_error(&lasterror);
        int ret = Old_user32_LoadStringA(
            hInstance,
            uID,
            lpBuffer,
            nBufferMax
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_user32_LoadStringA(
        hInstance,
        uID,
        lpBuffer,
        nBufferMax
    );
    get_last_error(&lasterror);
    
    const char *buf = lpBuffer;
    if(nBufferMax == 0 && lpBuffer != NULL) {
        buf = *(const char **) lpBuffer;
    }

    log_api(SIG_user32_LoadStringA,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInstance,
        uID,
        buf
    );

    log_debug("Leaving %s\n", "LoadStringA");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_LoadStringW(
    HINSTANCE hInstance,
    UINT uID,
    LPWSTR lpBuffer,
    int nBufferMax
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "LoadStringW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "LoadStringW");

        set_last_error(&lasterror);
        int ret = Old_user32_LoadStringW(
            hInstance,
            uID,
            lpBuffer,
            nBufferMax
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_user32_LoadStringW(
        hInstance,
        uID,
        lpBuffer,
        nBufferMax
    );
    get_last_error(&lasterror);
    
    const wchar_t *buf = lpBuffer;
    if(nBufferMax == 0 && lpBuffer != NULL) {
        buf = *(const wchar_t **) lpBuffer;
    }

    log_api(SIG_user32_LoadStringW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInstance,
        uID,
        buf
    );

    log_debug("Leaving %s\n", "LoadStringW");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_MessageBoxTimeoutA(
    HWND hWnd,
    LPCTSTR lpText,
    LPCTSTR lpCaption,
    UINT uType,
    WORD wLanguageId,
    INT Unknown
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "MessageBoxTimeoutA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "MessageBoxTimeoutA");

        set_last_error(&lasterror);
        int ret = Old_user32_MessageBoxTimeoutA(
            hWnd,
            lpText,
            lpCaption,
            uType,
            wLanguageId,
            Unknown
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ssii", 
        lpText,
        lpCaption,
        uType,
        wLanguageId
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "MessageBoxTimeoutA");

        set_last_error(&lasterror);
        int ret = Old_user32_MessageBoxTimeoutA(
            hWnd,
            lpText,
            lpCaption,
            uType,
            wLanguageId,
            Unknown
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_user32_MessageBoxTimeoutA(
        hWnd,
        lpText,
        lpCaption,
        uType,
        wLanguageId,
        Unknown
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_MessageBoxTimeoutA,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hWnd,
        lpText,
        lpCaption,
        uType,
        wLanguageId
    );

    log_debug("Leaving %s\n", "MessageBoxTimeoutA");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_user32_MessageBoxTimeoutW(
    HWND hWnd,
    LPWSTR lpText,
    LPWSTR lpCaption,
    UINT uType,
    WORD wLanguageId,
    INT Unknown
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "MessageBoxTimeoutW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "MessageBoxTimeoutW");

        set_last_error(&lasterror);
        int ret = Old_user32_MessageBoxTimeoutW(
            hWnd,
            lpText,
            lpCaption,
            uType,
            wLanguageId,
            Unknown
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uuii", 
        lpText,
        lpCaption,
        uType,
        wLanguageId
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "MessageBoxTimeoutW");

        set_last_error(&lasterror);
        int ret = Old_user32_MessageBoxTimeoutW(
            hWnd,
            lpText,
            lpCaption,
            uType,
            wLanguageId,
            Unknown
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_user32_MessageBoxTimeoutW(
        hWnd,
        lpText,
        lpCaption,
        uType,
        wLanguageId,
        Unknown
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_MessageBoxTimeoutW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hWnd,
        lpText,
        lpCaption,
        uType,
        wLanguageId
    );

    log_debug("Leaving %s\n", "MessageBoxTimeoutW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_RegisterHotKey(
    HWND hWnd,
    int id,
    UINT fsModifiers,
    UINT vk
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "RegisterHotKey");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "RegisterHotKey");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_RegisterHotKey(
            hWnd,
            id,
            fsModifiers,
            vk
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_RegisterHotKey(
        hWnd,
        id,
        fsModifiers,
        vk
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_RegisterHotKey,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hWnd,
        id,
        fsModifiers,
        vk
    );

    log_debug("Leaving %s\n", "RegisterHotKey");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_SendNotifyMessageA(
    HWND hWnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SendNotifyMessageA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SendNotifyMessageA");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_SendNotifyMessageA(
            hWnd,
            uMsg,
            wParam,
            lParam
        );
        return ret;
    }
    
    uint32_t pid = 0, tid;
    
    // TODO Will this still happen before the notify message is executed?
    tid = get_window_thread_process_id(hWnd, &pid);
    pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_SendNotifyMessageA(
        hWnd,
        uMsg,
        wParam,
        lParam
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_SendNotifyMessageA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hWnd,
        uMsg,
        pid
    );

    log_debug("Leaving %s\n", "SendNotifyMessageA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_SendNotifyMessageW(
    HWND hWnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SendNotifyMessageW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SendNotifyMessageW");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_SendNotifyMessageW(
            hWnd,
            uMsg,
            wParam,
            lParam
        );
        return ret;
    }
    
    uint32_t pid = 0, tid;
    
    // TODO Will this still happen before the notify message is executed?
    tid = get_window_thread_process_id(hWnd, &pid);
    pipe("PROCESS2:%d,%d,%d", pid, tid, HOOK_MODE_ALL);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_SendNotifyMessageW(
        hWnd,
        uMsg,
        wParam,
        lParam
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_SendNotifyMessageW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hWnd,
        uMsg,
        pid
    );

    log_debug("Leaving %s\n", "SendNotifyMessageW");

    set_last_error(&lasterror);
    return ret;
}

HHOOK WINAPI New_user32_SetWindowsHookExA(
    int idHook,
    HOOKPROC lpfn,
    HINSTANCE hMod,
    DWORD dwThreadId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetWindowsHookExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetWindowsHookExA");

        set_last_error(&lasterror);
        HHOOK ret = Old_user32_SetWindowsHookExA(
            idHook,
            lpfn,
            hMod,
            dwThreadId
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ii", 
        idHook,
        dwThreadId
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "SetWindowsHookExA");

        set_last_error(&lasterror);
        HHOOK ret = Old_user32_SetWindowsHookExA(
            idHook,
            lpfn,
            hMod,
            dwThreadId
        );
        return ret;
    }

    set_last_error(&lasterror);
    HHOOK ret = Old_user32_SetWindowsHookExA(
        idHook,
        lpfn,
        hMod,
        dwThreadId
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_SetWindowsHookExA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        idHook,
        lpfn,
        hMod,
        dwThreadId
    );

    log_debug("Leaving %s\n", "SetWindowsHookExA");

    set_last_error(&lasterror);
    return ret;
}

HHOOK WINAPI New_user32_SetWindowsHookExW(
    int idHook,
    HOOKPROC lpfn,
    HINSTANCE hMod,
    DWORD dwThreadId
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "SetWindowsHookExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "SetWindowsHookExW");

        set_last_error(&lasterror);
        HHOOK ret = Old_user32_SetWindowsHookExW(
            idHook,
            lpfn,
            hMod,
            dwThreadId
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ii", 
        idHook,
        dwThreadId
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "SetWindowsHookExW");

        set_last_error(&lasterror);
        HHOOK ret = Old_user32_SetWindowsHookExW(
            idHook,
            lpfn,
            hMod,
            dwThreadId
        );
        return ret;
    }

    set_last_error(&lasterror);
    HHOOK ret = Old_user32_SetWindowsHookExW(
        idHook,
        lpfn,
        hMod,
        dwThreadId
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_SetWindowsHookExW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        idHook,
        lpfn,
        hMod,
        dwThreadId
    );

    log_debug("Leaving %s\n", "SetWindowsHookExW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_user32_UnhookWindowsHookEx(
    HHOOK hhk
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "UnhookWindowsHookEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "UnhookWindowsHookEx");

        set_last_error(&lasterror);
        BOOL ret = Old_user32_UnhookWindowsHookEx(
            hhk
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_user32_UnhookWindowsHookEx(
        hhk
    );
    get_last_error(&lasterror);

    log_api(SIG_user32_UnhookWindowsHookEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hhk
    );

    log_debug("Leaving %s\n", "UnhookWindowsHookEx");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_CallByName(
    void *result,
    void *this,
    const wchar_t *funcname,
    void *unk1,
    SAFEARRAY **args,
    void *unk3
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_CallByName");
    
    vbe6_set_funcname(funcname);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_CallByName(
        result,
        this,
        funcname,
        unk1,
        args,
        unk3
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_CallByName,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror
    );
        

    log_debug("Leaving %s\n", "vbe6_CallByName");

    set_last_error(&lasterror);
    return ret;
}

void * __thiscall New_vbe6_vbe6_Close(
    void *this,
    int fd
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_Close");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_Close(
        this,
        fd
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_Close,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        fd
    );
        

    log_debug("Leaving %s\n", "vbe6_Close");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_CreateObject(
    void **this,
    const BSTR object_name,
    void *unk1
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_CreateObject");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_CreateObject(
        this,
        object_name,
        unk1
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_CreateObject,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        this,
        object_name,
        this[2]
    );
        

    log_debug("Leaving %s\n", "vbe6_CreateObject");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_GetIDFromName(
    const wchar_t *funcname,
    void *this
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_GetIDFromName");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_GetIDFromName(
        funcname,
        this
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_GetIDFromName,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        funcname,
        this,
        ret
    );
        

    log_debug("Leaving %s\n", "vbe6_GetIDFromName");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_GetObject(
    void **this,
    const VARIANT *object_name,
    void *unk1
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_GetObject");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_GetObject(
        this,
        object_name,
        unk1
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_GetObject,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        object_name,
        this[2]
    );
        

    log_debug("Leaving %s\n", "vbe6_GetObject");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_Import(
    void **args,
    void *unk1,
    void *unk2,
    void *unk3,
    void *unk4
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_Import");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_Import(
        args,
        unk1,
        unk2,
        unk3,
        unk4
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_Import,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        args[0],
        args[1]
    );
        

    log_debug("Leaving %s\n", "vbe6_Import");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_Invoke(
    void *this,
    int funcidx,
    void *unk1,
    void *unk2,
    void *unk3,
    uint8_t *args,
    VARIANT *result,
    void *unk8,
    void *unk9
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_Invoke");
    
    bson b;
    
    bson_init_size(&b, mem_suggested_size(4096));
    bson_append_start_array(&b, "bson");
    
    if(args != NULL) {
        vbe6_invoke_extract_args(args, &b);
    }
    
    bson_append_finish_array(&b);
    bson_finish(&b);
    
    wchar_t *funcname = vbe6_get_funcname();

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_Invoke(
        this,
        funcidx,
        unk1,
        unk2,
        unk3,
        args,
        result,
        unk8,
        unk9
    );
    get_last_error(&lasterror);
    
    bson b2;
    
    bson_init_size(&b2, mem_suggested_size(4096));
    
    if(result != NULL) {
        variant_to_bson(&b2, "0", result);
    }
    else {
        bson_append_null(&b2, "0");
    }
    
    bson_finish(&b2);
        
    log_api(SIG_vbe6_vbe6_Invoke,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        this,
        funcidx,
        funcname,
        &b,
        &b2
    );
        
    
    bson_destroy(&b);
    bson_destroy(&b2);
    mem_free(funcname);

    log_debug("Leaving %s\n", "vbe6_Invoke");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_Open(
    int mode,
    void *unk1,
    int fd,
    const wchar_t *filename
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_Open");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_Open(
        mode,
        unk1,
        fd,
        filename
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_Open,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        mode,
        fd,
        filename
    );
        

    log_debug("Leaving %s\n", "vbe6_Open");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_Print(
    void *unk1,
    void *unk2,
    const VARIANT *buf,
    void *unk4
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_Print");
    
    // TODO Figure out where to locate the fd.

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_Print(
        unk1,
        unk2,
        buf,
        unk4
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_Print,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        buf
    );
        

    log_debug("Leaving %s\n", "vbe6_Print");

    set_last_error(&lasterror);
    return ret;
}

void * WINAPI New_vbe6_vbe6_Shell(
    const VARIANT *command_line,
    int show_type
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_Shell");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_Shell(
        command_line,
        show_type
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_Shell,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        command_line,
        show_type
    );
        

    log_debug("Leaving %s\n", "vbe6_Shell");

    set_last_error(&lasterror);
    return ret;
}

void * __thiscall New_vbe6_vbe6_StringConcat(
    void *this,
    VARIANT *dst,
    VARIANT *src2,
    VARIANT *src1
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "vbe6_StringConcat");

    uint64_t hash = 0;

    set_last_error(&lasterror);
    void * ret = Old_vbe6_vbe6_StringConcat(
        this,
        dst,
        src2,
        src1
    );
    get_last_error(&lasterror);
        
    log_api(SIG_vbe6_vbe6_StringConcat,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dst,
        src1,
        src2
    );
        

    log_debug("Leaving %s\n", "vbe6_StringConcat");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_version_GetFileVersionInfoExW(
    DWORD dwFlags,
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileVersionInfoExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileVersionInfoExW");

        set_last_error(&lasterror);
        BOOL ret = Old_version_GetFileVersionInfoExW(
            dwFlags,
            lptstrFilename,
            dwHandle,
            dwLen,
            lpData
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_version_GetFileVersionInfoExW(
        dwFlags,
        lptstrFilename,
        dwHandle,
        dwLen,
        lpData
    );
    get_last_error(&lasterror);

    log_api(SIG_version_GetFileVersionInfoExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        lptstrFilename,
        dwLen, lpData
    );

    log_debug("Leaving %s\n", "GetFileVersionInfoExW");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_version_GetFileVersionInfoSizeExW(
    DWORD dwFlags,
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileVersionInfoSizeExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileVersionInfoSizeExW");

        set_last_error(&lasterror);
        DWORD ret = Old_version_GetFileVersionInfoSizeExW(
            dwFlags,
            lptstrFilename,
            lpdwHandle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_version_GetFileVersionInfoSizeExW(
        dwFlags,
        lptstrFilename,
        lpdwHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_version_GetFileVersionInfoSizeExW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        lptstrFilename
    );

    log_debug("Leaving %s\n", "GetFileVersionInfoSizeExW");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_version_GetFileVersionInfoSizeW(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileVersionInfoSizeW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileVersionInfoSizeW");

        set_last_error(&lasterror);
        DWORD ret = Old_version_GetFileVersionInfoSizeW(
            lptstrFilename,
            lpdwHandle
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_version_GetFileVersionInfoSizeW(
        lptstrFilename,
        lpdwHandle
    );
    get_last_error(&lasterror);

    log_api(SIG_version_GetFileVersionInfoSizeW,
        ret != 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lptstrFilename
    );

    log_debug("Leaving %s\n", "GetFileVersionInfoSizeW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_version_GetFileVersionInfoW(
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetFileVersionInfoW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetFileVersionInfoW");

        set_last_error(&lasterror);
        BOOL ret = Old_version_GetFileVersionInfoW(
            lptstrFilename,
            dwHandle,
            dwLen,
            lpData
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_version_GetFileVersionInfoW(
        lptstrFilename,
        dwHandle,
        dwLen,
        lpData
    );
    get_last_error(&lasterror);

    log_api(SIG_version_GetFileVersionInfoW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lptstrFilename,
        dwLen, lpData
    );

    log_debug("Leaving %s\n", "GetFileVersionInfoW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_DeleteUrlCacheEntryA(
    LPCSTR lpszUrlName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DeleteUrlCacheEntryA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DeleteUrlCacheEntryA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_DeleteUrlCacheEntryA(
            lpszUrlName
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_DeleteUrlCacheEntryA(
        lpszUrlName
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_DeleteUrlCacheEntryA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszUrlName
    );

    log_debug("Leaving %s\n", "DeleteUrlCacheEntryA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_DeleteUrlCacheEntryW(
    LPWSTR lpszUrlName
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "DeleteUrlCacheEntryW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "DeleteUrlCacheEntryW");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_DeleteUrlCacheEntryW(
            lpszUrlName
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_DeleteUrlCacheEntryW(
        lpszUrlName
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_DeleteUrlCacheEntryW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszUrlName
    );

    log_debug("Leaving %s\n", "DeleteUrlCacheEntryW");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_HttpOpenRequestA(
    HINTERNET hConnect,
    LPCTSTR lpszVerb,
    LPCTSTR lpszObjectName,
    LPCTSTR lpszVersion,
    LPCTSTR lpszReferer,
    LPCTSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "HttpOpenRequestA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "HttpOpenRequestA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_HttpOpenRequestA(
            hConnect,
            lpszVerb,
            lpszObjectName,
            lpszVersion,
            lpszReferer,
            lplpszAcceptTypes,
            dwFlags,
            dwContext
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ssssi", 
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferer,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "HttpOpenRequestA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_HttpOpenRequestA(
            hConnect,
            lpszVerb,
            lpszObjectName,
            lpszVersion,
            lpszReferer,
            lplpszAcceptTypes,
            dwFlags,
            dwContext
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_HttpOpenRequestA(
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferer,
        lplpszAcceptTypes,
        dwFlags,
        dwContext
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_HttpOpenRequestA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferer,
        dwFlags
    );

    log_debug("Leaving %s\n", "HttpOpenRequestA");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_HttpOpenRequestW(
    HINTERNET hConnect,
    LPWSTR lpszVerb,
    LPWSTR lpszObjectName,
    LPWSTR lpszVersion,
    LPWSTR lpszReferer,
    LPWSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "HttpOpenRequestW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "HttpOpenRequestW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_HttpOpenRequestW(
            hConnect,
            lpszVerb,
            lpszObjectName,
            lpszVersion,
            lpszReferer,
            lplpszAcceptTypes,
            dwFlags,
            dwContext
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uuuui", 
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferer,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "HttpOpenRequestW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_HttpOpenRequestW(
            hConnect,
            lpszVerb,
            lpszObjectName,
            lpszVersion,
            lpszReferer,
            lplpszAcceptTypes,
            dwFlags,
            dwContext
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_HttpOpenRequestW(
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferer,
        lplpszAcceptTypes,
        dwFlags,
        dwContext
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_HttpOpenRequestW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hConnect,
        lpszVerb,
        lpszObjectName,
        lpszVersion,
        lpszReferer,
        dwFlags
    );

    log_debug("Leaving %s\n", "HttpOpenRequestW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_HttpQueryInfoA(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPVOID lpvBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "HttpQueryInfoA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "HttpQueryInfoA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_HttpQueryInfoA(
            hRequest,
            dwInfoLevel,
            lpvBuffer,
            lpdwBufferLength,
            lpdwIndex
        );
        return ret;
    }

    DWORD _lpdwBufferLength;
    if(lpdwBufferLength == NULL) {
        lpdwBufferLength = &_lpdwBufferLength;
        memset(&_lpdwBufferLength, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_HttpQueryInfoA(
        hRequest,
        dwInfoLevel,
        lpvBuffer,
        lpdwBufferLength,
        lpdwIndex
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_HttpQueryInfoA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hRequest,
        dwInfoLevel,
        lpdwIndex,
        (uintptr_t) copy_uint32(lpdwBufferLength), lpvBuffer
    );

    log_debug("Leaving %s\n", "HttpQueryInfoA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_HttpSendRequestA(
    HINTERNET hRequest,
    LPCTSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "HttpSendRequestA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "HttpSendRequestA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_HttpSendRequestA(
            hRequest,
            lpszHeaders,
            dwHeadersLength,
            lpOptional,
            dwOptionalLength
        );
        return ret;
    }
    
    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlen(lpszHeaders);
    }

    uint64_t hash = call_hash(
        "Sb", 
        dwHeadersLength, lpszHeaders,
        dwOptionalLength, lpOptional
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "HttpSendRequestA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_HttpSendRequestA(
            hRequest,
            lpszHeaders,
            dwHeadersLength,
            lpOptional,
            dwOptionalLength
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_HttpSendRequestA(
        hRequest,
        lpszHeaders,
        dwHeadersLength,
        lpOptional,
        dwOptionalLength
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_HttpSendRequestA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hRequest,
        headers_length, lpszHeaders,
        (uintptr_t) dwOptionalLength, lpOptional
    );

    log_debug("Leaving %s\n", "HttpSendRequestA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_HttpSendRequestW(
    HINTERNET hRequest,
    LPWSTR lpszHeaders,
    DWORD dwHeadersLength,
    LPVOID lpOptional,
    DWORD dwOptionalLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "HttpSendRequestW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "HttpSendRequestW");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_HttpSendRequestW(
            hRequest,
            lpszHeaders,
            dwHeadersLength,
            lpOptional,
            dwOptionalLength
        );
        return ret;
    }
    
    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlenW(lpszHeaders);
    }

    uint64_t hash = call_hash(
        "Ub", 
        dwHeadersLength, lpszHeaders,
        dwOptionalLength, lpOptional
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "HttpSendRequestW");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_HttpSendRequestW(
            hRequest,
            lpszHeaders,
            dwHeadersLength,
            lpOptional,
            dwOptionalLength
        );
        return ret;
    }

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_HttpSendRequestW(
        hRequest,
        lpszHeaders,
        dwHeadersLength,
        lpOptional,
        dwOptionalLength
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_HttpSendRequestW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hRequest,
        headers_length, lpszHeaders,
        (uintptr_t) dwOptionalLength, lpOptional
    );

    log_debug("Leaving %s\n", "HttpSendRequestW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetCloseHandle(
    HINTERNET hInternet
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetCloseHandle");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetCloseHandle");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetCloseHandle(
            hInternet
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetCloseHandle(
        hInternet
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetCloseHandle,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet
    );

    log_debug("Leaving %s\n", "InternetCloseHandle");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_InternetConnectA(
    HINTERNET hInternet,
    LPCTSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCTSTR lpszUsername,
    LPCTSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetConnectA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetConnectA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetConnectA(
            hInternet,
            lpszServerName,
            nServerPort,
            lpszUsername,
            lpszPassword,
            dwService,
            dwFlags,
            dwContext
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "sissii", 
        lpszServerName,
        nServerPort,
        lpszUsername,
        lpszPassword,
        dwService,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "InternetConnectA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetConnectA(
            hInternet,
            lpszServerName,
            nServerPort,
            lpszUsername,
            lpszPassword,
            dwService,
            dwFlags,
            dwContext
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_InternetConnectA(
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUsername,
        lpszPassword,
        dwService,
        dwFlags,
        dwContext
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetConnectA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUsername,
        lpszPassword,
        dwService,
        dwFlags
    );

    log_debug("Leaving %s\n", "InternetConnectA");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_InternetConnectW(
    HINTERNET hInternet,
    LPWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPWSTR lpszUsername,
    LPWSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetConnectW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetConnectW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetConnectW(
            hInternet,
            lpszServerName,
            nServerPort,
            lpszUsername,
            lpszPassword,
            dwService,
            dwFlags,
            dwContext
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uiuuii", 
        lpszServerName,
        nServerPort,
        lpszUsername,
        lpszPassword,
        dwService,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "InternetConnectW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetConnectW(
            hInternet,
            lpszServerName,
            nServerPort,
            lpszUsername,
            lpszPassword,
            dwService,
            dwFlags,
            dwContext
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_InternetConnectW(
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUsername,
        lpszPassword,
        dwService,
        dwFlags,
        dwContext
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetConnectW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        lpszServerName,
        nServerPort,
        lpszUsername,
        lpszPassword,
        dwService,
        dwFlags
    );

    log_debug("Leaving %s\n", "InternetConnectW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetCrackUrlA(
    LPCSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSA lpUrlComponents
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetCrackUrlA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetCrackUrlA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetCrackUrlA(
            lpszUrl,
            dwUrlLength,
            dwFlags,
            lpUrlComponents
        );
        return ret;
    }
    
    uint32_t length = dwUrlLength;
    if(length == 0 && lpszUrl != NULL) {
        length = copy_strlen(lpszUrl);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetCrackUrlA(
        lpszUrl,
        dwUrlLength,
        dwFlags,
        lpUrlComponents
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetCrackUrlA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        length, lpszUrl
    );

    log_debug("Leaving %s\n", "InternetCrackUrlA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetCrackUrlW(
    LPCWSTR lpszUrl,
    DWORD dwUrlLength,
    DWORD dwFlags,
    LPURL_COMPONENTSW lpUrlComponents
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetCrackUrlW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetCrackUrlW");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetCrackUrlW(
            lpszUrl,
            dwUrlLength,
            dwFlags,
            lpUrlComponents
        );
        return ret;
    }
    
    uint32_t length = dwUrlLength;
    if(length == 0 && lpszUrl != NULL) {
        length = copy_strlenW(lpszUrl);
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetCrackUrlW(
        lpszUrl,
        dwUrlLength,
        dwFlags,
        lpUrlComponents
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetCrackUrlW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        dwFlags,
        length, lpszUrl
    );

    log_debug("Leaving %s\n", "InternetCrackUrlW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetGetConnectedState(
    LPDWORD lpdwFlags,
    DWORD dwReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetGetConnectedState");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetGetConnectedState");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetGetConnectedState(
            lpdwFlags,
            dwReserved
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetGetConnectedState(
        lpdwFlags,
        dwReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetGetConnectedState,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpdwFlags
    );

    log_debug("Leaving %s\n", "InternetGetConnectedState");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetGetConnectedStateExA(
    LPDWORD lpdwFlags,
    LPCSTR lpszConnectionName,
    DWORD dwNameLen,
    DWORD dwReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetGetConnectedStateExA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetGetConnectedStateExA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetGetConnectedStateExA(
            lpdwFlags,
            lpszConnectionName,
            dwNameLen,
            dwReserved
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetGetConnectedStateExA(
        lpdwFlags,
        lpszConnectionName,
        dwNameLen,
        dwReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetGetConnectedStateExA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpdwFlags,
        lpszConnectionName
    );

    log_debug("Leaving %s\n", "InternetGetConnectedStateExA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetGetConnectedStateExW(
    LPDWORD lpdwFlags,
    LPWSTR lpszConnectionName,
    DWORD dwNameLen,
    DWORD dwReserved
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetGetConnectedStateExW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetGetConnectedStateExW");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetGetConnectedStateExW(
            lpdwFlags,
            lpszConnectionName,
            dwNameLen,
            dwReserved
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetGetConnectedStateExW(
        lpdwFlags,
        lpszConnectionName,
        dwNameLen,
        dwReserved
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetGetConnectedStateExW,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpdwFlags,
        lpszConnectionName
    );

    log_debug("Leaving %s\n", "InternetGetConnectedStateExW");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_InternetOpenA(
    LPCTSTR lpszAgent,
    DWORD dwAccessType,
    LPCTSTR lpszProxyName,
    LPCTSTR lpszProxyBypass,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetOpenA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetOpenA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenA(
            lpszAgent,
            dwAccessType,
            lpszProxyName,
            lpszProxyBypass,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "sissi", 
        lpszAgent,
        dwAccessType,
        lpszProxyName,
        lpszProxyBypass,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "InternetOpenA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenA(
            lpszAgent,
            dwAccessType,
            lpszProxyName,
            lpszProxyBypass,
            dwFlags
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_InternetOpenA(
        lpszAgent,
        dwAccessType,
        lpszProxyName,
        lpszProxyBypass,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetOpenA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszAgent,
        dwAccessType,
        lpszProxyName,
        lpszProxyBypass,
        dwFlags
    );

    log_debug("Leaving %s\n", "InternetOpenA");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_InternetOpenUrlA(
    HINTERNET hInternet,
    LPCTSTR lpszUrl,
    LPCTSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetOpenUrlA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetOpenUrlA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenUrlA(
            hInternet,
            lpszUrl,
            lpszHeaders,
            dwHeadersLength,
            dwFlags,
            dwContext
        );
        return ret;
    }
    
    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlen(lpszHeaders);
    }

    uint64_t hash = call_hash(
        "sSi", 
        lpszUrl,
        headers_length, lpszHeaders,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "InternetOpenUrlA");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenUrlA(
            hInternet,
            lpszUrl,
            lpszHeaders,
            dwHeadersLength,
            dwFlags,
            dwContext
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_InternetOpenUrlA(
        hInternet,
        lpszUrl,
        lpszHeaders,
        dwHeadersLength,
        dwFlags,
        dwContext
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetOpenUrlA,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        lpszUrl,
        dwFlags,
        (uintptr_t) headers_length, lpszHeaders
    );

    log_debug("Leaving %s\n", "InternetOpenUrlA");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_InternetOpenUrlW(
    HINTERNET hInternet,
    LPWSTR lpszUrl,
    LPWSTR lpszHeaders,
    DWORD dwHeadersLength,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetOpenUrlW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetOpenUrlW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenUrlW(
            hInternet,
            lpszUrl,
            lpszHeaders,
            dwHeadersLength,
            dwFlags,
            dwContext
        );
        return ret;
    }
    
    int headers_length = dwHeadersLength;
    if(lpszHeaders != NULL && headers_length == -1) {
        headers_length = copy_strlenW(lpszHeaders);
    }

    uint64_t hash = call_hash(
        "uUi", 
        lpszUrl,
        headers_length, lpszHeaders,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "InternetOpenUrlW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenUrlW(
            hInternet,
            lpszUrl,
            lpszHeaders,
            dwHeadersLength,
            dwFlags,
            dwContext
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_InternetOpenUrlW(
        hInternet,
        lpszUrl,
        lpszHeaders,
        dwHeadersLength,
        dwFlags,
        dwContext
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetOpenUrlW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        lpszUrl,
        dwFlags,
        (uintptr_t) headers_length, lpszHeaders
    );

    log_debug("Leaving %s\n", "InternetOpenUrlW");

    set_last_error(&lasterror);
    return ret;
}

HINTERNET WINAPI New_wininet_InternetOpenW(
    LPWSTR lpszAgent,
    DWORD dwAccessType,
    LPWSTR lpszProxyName,
    LPWSTR lpszProxyBypass,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetOpenW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetOpenW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenW(
            lpszAgent,
            dwAccessType,
            lpszProxyName,
            lpszProxyBypass,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uiuui", 
        lpszAgent,
        dwAccessType,
        lpszProxyName,
        lpszProxyBypass,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "InternetOpenW");

        set_last_error(&lasterror);
        HINTERNET ret = Old_wininet_InternetOpenW(
            lpszAgent,
            dwAccessType,
            lpszProxyName,
            lpszProxyBypass,
            dwFlags
        );
        return ret;
    }

    set_last_error(&lasterror);
    HINTERNET ret = Old_wininet_InternetOpenW(
        lpszAgent,
        dwAccessType,
        lpszProxyName,
        lpszProxyBypass,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetOpenW,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        lpszAgent,
        dwAccessType,
        lpszProxyName,
        lpszProxyBypass,
        dwFlags
    );

    log_debug("Leaving %s\n", "InternetOpenW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetQueryOptionA(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetQueryOptionA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetQueryOptionA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetQueryOptionA(
            hInternet,
            dwOption,
            lpBuffer,
            lpdwBufferLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetQueryOptionA(
        hInternet,
        dwOption,
        lpBuffer,
        lpdwBufferLength
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetQueryOptionA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        dwOption
    );

    log_debug("Leaving %s\n", "InternetQueryOptionA");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetReadFile(
    HINTERNET hFile,
    LPVOID lpBuffer,
    DWORD dwNumberOfBytesToRead,
    LPDWORD lpdwNumberOfBytesRead
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetReadFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetReadFile");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetReadFile(
            hFile,
            lpBuffer,
            dwNumberOfBytesToRead,
            lpdwNumberOfBytesRead
        );
        return ret;
    }

    DWORD _lpdwNumberOfBytesRead;
    if(lpdwNumberOfBytesRead == NULL) {
        lpdwNumberOfBytesRead = &_lpdwNumberOfBytesRead;
        memset(&_lpdwNumberOfBytesRead, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetReadFile(
        hFile,
        lpBuffer,
        dwNumberOfBytesToRead,
        lpdwNumberOfBytesRead
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetReadFile,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        (uintptr_t) copy_uint32(lpdwNumberOfBytesRead), lpBuffer
    );

    log_debug("Leaving %s\n", "InternetReadFile");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetSetOptionA(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetSetOptionA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetSetOptionA");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetSetOptionA(
            hInternet,
            dwOption,
            lpBuffer,
            dwBufferLength
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetSetOptionA(
        hInternet,
        dwOption,
        lpBuffer,
        dwBufferLength
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetSetOptionA,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        dwOption
    );

    log_debug("Leaving %s\n", "InternetSetOptionA");

    set_last_error(&lasterror);
    return ret;
}

INTERNET_STATUS_CALLBACK WINAPI New_wininet_InternetSetStatusCallback(
    HINTERNET hInternet,
    INTERNET_STATUS_CALLBACK lpfnInternetCallback
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetSetStatusCallback");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetSetStatusCallback");

        set_last_error(&lasterror);
        INTERNET_STATUS_CALLBACK ret = Old_wininet_InternetSetStatusCallback(
            hInternet,
            lpfnInternetCallback
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    INTERNET_STATUS_CALLBACK ret = Old_wininet_InternetSetStatusCallback(
        hInternet,
        lpfnInternetCallback
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetSetStatusCallback,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hInternet,
        lpfnInternetCallback
    );

    log_debug("Leaving %s\n", "InternetSetStatusCallback");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_wininet_InternetWriteFile(
    HINTERNET hFile,
    LPCVOID lpBuffer,
    DWORD dwNumberOfBytesToWrite,
    LPDWORD lpdwNumberOfBytesWritten
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "InternetWriteFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "InternetWriteFile");

        set_last_error(&lasterror);
        BOOL ret = Old_wininet_InternetWriteFile(
            hFile,
            lpBuffer,
            dwNumberOfBytesToWrite,
            lpdwNumberOfBytesWritten
        );
        return ret;
    }

    DWORD _lpdwNumberOfBytesWritten;
    if(lpdwNumberOfBytesWritten == NULL) {
        lpdwNumberOfBytesWritten = &_lpdwNumberOfBytesWritten;
        memset(&_lpdwNumberOfBytesWritten, 0, sizeof(DWORD));
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_wininet_InternetWriteFile(
        hFile,
        lpBuffer,
        dwNumberOfBytesToWrite,
        lpdwNumberOfBytesWritten
    );
    get_last_error(&lasterror);

    log_api(SIG_wininet_InternetWriteFile,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hFile,
        (uintptr_t) copy_uint32(lpdwNumberOfBytesWritten), lpBuffer
    );

    log_debug("Leaving %s\n", "InternetWriteFile");

    set_last_error(&lasterror);
    return ret;
}

DWORD WINAPI New_winmm_timeGetTime(
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "timeGetTime");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "timeGetTime");

        set_last_error(&lasterror);
        DWORD ret = Old_winmm_timeGetTime(
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    DWORD ret = Old_winmm_timeGetTime(
    );
    get_last_error(&lasterror);

    log_api(SIG_winmm_timeGetTime,
        1,
        (uintptr_t) ret,
        hash,
        &lasterror
    );
    
    ret += sleep_skipped() / 10000;

    log_debug("Leaving %s\n", "timeGetTime");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_ws2_32_ConnectEx(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ConnectEx");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ConnectEx");

        set_last_error(&lasterror);
        BOOL ret = Old_ws2_32_ConnectEx(
            s,
            name,
            namelen,
            lpSendBuffer,
            dwSendDataLength,
            lpdwBytesSent,
            lpOverlapped
        );
        return ret;
    }

    DWORD _lpdwBytesSent;
    if(lpdwBytesSent == NULL) {
        lpdwBytesSent = &_lpdwBytesSent;
        memset(&_lpdwBytesSent, 0, sizeof(DWORD));
    }
    
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_ws2_32_ConnectEx(
        s,
        name,
        namelen,
        lpSendBuffer,
        dwSendDataLength,
        lpdwBytesSent,
        lpOverlapped
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_ConnectEx,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port,
        (uintptr_t) *lpdwBytesSent, lpSendBuffer
    );

    log_debug("Leaving %s\n", "ConnectEx");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_GetAddrInfoW(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW *pHints,
    PADDRINFOW *ppResult
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "GetAddrInfoW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "GetAddrInfoW");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_GetAddrInfoW(
            pNodeName,
            pServiceName,
            pHints,
            ppResult
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "uu", 
        pNodeName,
        pServiceName
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "GetAddrInfoW");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_GetAddrInfoW(
            pNodeName,
            pServiceName,
            pHints,
            ppResult
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_ws2_32_GetAddrInfoW(
        pNodeName,
        pServiceName,
        pHints,
        ppResult
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_GetAddrInfoW,
        ret == 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        pNodeName,
        pServiceName
    );

    log_debug("Leaving %s\n", "GetAddrInfoW");

    set_last_error(&lasterror);
    return ret;
}

BOOL WINAPI New_ws2_32_TransmitFile(
    SOCKET hSocket,
    HANDLE hFile,
    DWORD nNumberOfBytesToWrite,
    DWORD nNumberOfBytesPerSend,
    LPOVERLAPPED lpOverlapped,
    LPTRANSMIT_FILE_BUFFERS lpTransmitBuffers,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "TransmitFile");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "TransmitFile");

        set_last_error(&lasterror);
        BOOL ret = Old_ws2_32_TransmitFile(
            hSocket,
            hFile,
            nNumberOfBytesToWrite,
            nNumberOfBytesPerSend,
            lpOverlapped,
            lpTransmitBuffers,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    BOOL ret = Old_ws2_32_TransmitFile(
        hSocket,
        hFile,
        nNumberOfBytesToWrite,
        nNumberOfBytesPerSend,
        lpOverlapped,
        lpTransmitBuffers,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_TransmitFile,
        ret != FALSE,
        (uintptr_t) ret,
        hash,
        &lasterror,
        hSocket,
        hFile,
        nNumberOfBytesToWrite,
        nNumberOfBytesPerSend
    );

    log_debug("Leaving %s\n", "TransmitFile");

    set_last_error(&lasterror);
    return ret;
}

SOCKET WINAPI New_ws2_32_WSAAccept(
    SOCKET s,
    struct sockaddr *addr,
    LPINT addrlen,
    LPCONDITIONPROC lpfnCondition,
    DWORD_PTR dwCallbackData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSAAccept");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSAAccept");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_WSAAccept(
            s,
            addr,
            addrlen,
            lpfnCondition,
            dwCallbackData
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    SOCKET ret = Old_ws2_32_WSAAccept(
        s,
        addr,
        addrlen,
        lpfnCondition,
        dwCallbackData
    );
    get_last_error(&lasterror);
    
    const char *ip = NULL; int port = 0;
    get_ip_port(addr, &ip, &port);

    log_api(SIG_ws2_32_WSAAccept,
        ret != INVALID_SOCKET,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port
    );

    log_debug("Leaving %s\n", "WSAAccept");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_WSAConnect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSAConnect");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSAConnect");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSAConnect(
            s,
            name,
            namelen,
            lpCallerData,
            lpCalleeData,
            lpSQOS,
            lpGQOS
        );
        return ret;
    }
    
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);
    
    // TODO Dump lpCallerData and lpCalleeData.

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_WSAConnect(
        s,
        name,
        namelen,
        lpCallerData,
        lpCalleeData,
        lpSQOS,
        lpGQOS
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_WSAConnect,
        ret == 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port
    );

    log_debug("Leaving %s\n", "WSAConnect");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_WSARecv(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSARecv");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSARecv");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSARecv(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesRecvd,
            lpFlags,
            lpOverlapped,
            lpCompletionRoutine
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_WSARecv(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesRecvd,
        lpFlags,
        lpOverlapped,
        lpCompletionRoutine
    );
    get_last_error(&lasterror);
    
    uint8_t *buf = NULL; uintptr_t length = 0;
    wsabuf_get_buffer(dwBufferCount, lpBuffers, &buf, &length);
    
    if(lpNumberOfBytesRecvd != NULL && *lpNumberOfBytesRecvd < length) {
        length = *lpNumberOfBytesRecvd;
    }

    log_api(SIG_ws2_32_WSARecv,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        length, buf
    );
    
    mem_free(buf);

    log_debug("Leaving %s\n", "WSARecv");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_WSARecvFrom(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    struct sockaddr *lpFrom,
    LPINT lpFromlen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSARecvFrom");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSARecvFrom");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSARecvFrom(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesRecvd,
            lpFlags,
            lpFrom,
            lpFromlen,
            lpOverlapped,
            lpCompletionRoutine
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_WSARecvFrom(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesRecvd,
        lpFlags,
        lpFrom,
        lpFromlen,
        lpOverlapped,
        lpCompletionRoutine
    );
    get_last_error(&lasterror);
    
    const char *ip = NULL; int port = 0;
    get_ip_port(lpFrom, &ip, &port);
    
    uint8_t *buf = NULL; uintptr_t length = 0;
    wsabuf_get_buffer(dwBufferCount, lpBuffers, &buf, &length);
    
    if(lpNumberOfBytesRecvd != NULL && *lpNumberOfBytesRecvd < length) {
        length = *lpNumberOfBytesRecvd;
    }

    log_api(SIG_ws2_32_WSARecvFrom,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port,
        length, buf
    );
    
    mem_free(buf);

    log_debug("Leaving %s\n", "WSARecvFrom");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_WSASend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSASend");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSASend");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_WSASend(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesSent,
        dwFlags,
        lpOverlapped,
        lpCompletionRoutine
    );
    get_last_error(&lasterror);
    
    uint8_t *buf = NULL; uintptr_t length = 0;
    wsabuf_get_buffer(dwBufferCount, lpBuffers, &buf, &length);
    
    if(lpNumberOfBytesSent != NULL && *lpNumberOfBytesSent < length) {
        length = *lpNumberOfBytesSent;
    }

    log_api(SIG_ws2_32_WSASend,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        length, buf
    );
    
    mem_free(buf);

    log_debug("Leaving %s\n", "WSASend");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_WSASendTo(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr *lpTo,
    int iToLen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSASendTo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSASendTo");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSASendTo(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpTo,
            iToLen,
            lpOverlapped,
            lpCompletionRoutine
        );
        return ret;
    }
    
    const char *ip = NULL; int port = 0;
    get_ip_port(lpTo, &ip, &port);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_WSASendTo(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesSent,
        dwFlags,
        lpTo,
        iToLen,
        lpOverlapped,
        lpCompletionRoutine
    );
    get_last_error(&lasterror);
    
    uint8_t *buf = NULL; uintptr_t length = 0;
    wsabuf_get_buffer(dwBufferCount, lpBuffers, &buf, &length);
    
    if(lpNumberOfBytesSent != NULL && *lpNumberOfBytesSent < length) {
        length = *lpNumberOfBytesSent;
    }

    log_api(SIG_ws2_32_WSASendTo,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port,
        length, buf
    );
    
    mem_free(buf);

    log_debug("Leaving %s\n", "WSASendTo");

    set_last_error(&lasterror);
    return ret;
}

SOCKET WINAPI New_ws2_32_WSASocketA(
    int af,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFO lpProtocolInfo,
    GROUP g,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSASocketA");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSASocketA");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_WSASocketA(
            af,
            type,
            protocol,
            lpProtocolInfo,
            g,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "iiii", 
        af,
        type,
        protocol,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "WSASocketA");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_WSASocketA(
            af,
            type,
            protocol,
            lpProtocolInfo,
            g,
            dwFlags
        );
        return ret;
    }

    set_last_error(&lasterror);
    SOCKET ret = Old_ws2_32_WSASocketA(
        af,
        type,
        protocol,
        lpProtocolInfo,
        g,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_WSASocketA,
        ret != INVALID_SOCKET,
        (uintptr_t) ret,
        hash,
        &lasterror,
        af,
        type,
        protocol,
        dwFlags,
        ret
    );

    log_debug("Leaving %s\n", "WSASocketA");

    set_last_error(&lasterror);
    return ret;
}

SOCKET WINAPI New_ws2_32_WSASocketW(
    int af,
    int type,
    int protocol,
    LPWSAPROTOCOL_INFO lpProtocolInfo,
    GROUP g,
    DWORD dwFlags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSASocketW");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSASocketW");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_WSASocketW(
            af,
            type,
            protocol,
            lpProtocolInfo,
            g,
            dwFlags
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "iiii", 
        af,
        type,
        protocol,
        dwFlags
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "WSASocketW");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_WSASocketW(
            af,
            type,
            protocol,
            lpProtocolInfo,
            g,
            dwFlags
        );
        return ret;
    }

    set_last_error(&lasterror);
    SOCKET ret = Old_ws2_32_WSASocketW(
        af,
        type,
        protocol,
        lpProtocolInfo,
        g,
        dwFlags
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_WSASocketW,
        ret != INVALID_SOCKET,
        (uintptr_t) ret,
        hash,
        &lasterror,
        af,
        type,
        protocol,
        dwFlags,
        ret
    );

    log_debug("Leaving %s\n", "WSASocketW");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_WSAStartup(
    WORD wVersionRequested,
    LPWSADATA lpWSAData
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "WSAStartup");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "WSAStartup");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSAStartup(
            wVersionRequested,
            lpWSAData
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "i", 
        wVersionRequested
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "WSAStartup");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_WSAStartup(
            wVersionRequested,
            lpWSAData
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_ws2_32_WSAStartup(
        wVersionRequested,
        lpWSAData
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_WSAStartup,
        ret == 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        wVersionRequested
    );

    log_debug("Leaving %s\n", "WSAStartup");

    set_last_error(&lasterror);
    return ret;
}

SOCKET WINAPI New_ws2_32_accept(
    SOCKET s,
    struct sockaddr *addr,
    int *addrlen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "accept");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "accept");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_accept(
            s,
            addr,
            addrlen
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    SOCKET ret = Old_ws2_32_accept(
        s,
        addr,
        addrlen
    );
    get_last_error(&lasterror);
    
    const char *ip = NULL; int port = 0;
    get_ip_port(addr, &ip, &port);

    log_api(SIG_ws2_32_accept,
        ret != INVALID_SOCKET,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port
    );

    log_debug("Leaving %s\n", "accept");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_bind(
    SOCKET s,
    const struct sockaddr *name,
    int namelen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "bind");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "bind");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_bind(
            s,
            name,
            namelen
        );
        return ret;
    }
    
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_bind(
        s,
        name,
        namelen
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_bind,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port
    );

    log_debug("Leaving %s\n", "bind");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_closesocket(
    SOCKET s
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "closesocket");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "closesocket");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_closesocket(
            s
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_closesocket(
        s
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_closesocket,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s
    );

    log_debug("Leaving %s\n", "closesocket");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_connect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "connect");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "connect");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_connect(
            s,
            name,
            namelen
        );
        return ret;
    }
    
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);

    uint64_t hash = call_hash(
        "si", 
        ip,
        port
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "connect");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_connect(
            s,
            name,
            namelen
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_ws2_32_connect(
        s,
        name,
        namelen
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_connect,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port
    );

    log_debug("Leaving %s\n", "connect");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_getaddrinfo(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA *pHints,
    PADDRINFOA *ppResult
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "getaddrinfo");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "getaddrinfo");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_getaddrinfo(
            pNodeName,
            pServiceName,
            pHints,
            ppResult
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "ss", 
        pNodeName,
        pServiceName
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "getaddrinfo");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_getaddrinfo(
            pNodeName,
            pServiceName,
            pHints,
            ppResult
        );
        return ret;
    }

    set_last_error(&lasterror);
    int ret = Old_ws2_32_getaddrinfo(
        pNodeName,
        pServiceName,
        pHints,
        ppResult
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_getaddrinfo,
        ret == 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        pNodeName,
        pServiceName
    );

    log_debug("Leaving %s\n", "getaddrinfo");

    set_last_error(&lasterror);
    return ret;
}

struct hostent * WINAPI New_ws2_32_gethostbyname(
    const char *name
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "gethostbyname");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "gethostbyname");

        set_last_error(&lasterror);
        struct hostent * ret = Old_ws2_32_gethostbyname(
            name
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "s", 
        name
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "gethostbyname");

        set_last_error(&lasterror);
        struct hostent * ret = Old_ws2_32_gethostbyname(
            name
        );
        return ret;
    }

    set_last_error(&lasterror);
    struct hostent * ret = Old_ws2_32_gethostbyname(
        name
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_gethostbyname,
        ret != NULL,
        (uintptr_t) ret,
        hash,
        &lasterror,
        name
    );

    log_debug("Leaving %s\n", "gethostbyname");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_getsockname(
    SOCKET s,
    struct sockaddr *name,
    int *namelen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "getsockname");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "getsockname");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_getsockname(
            s,
            name,
            namelen
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_getsockname(
        s,
        name,
        namelen
    );
    get_last_error(&lasterror);
    
    const char *ip = NULL; int port = 0;
    get_ip_port(name, &ip, &port);

    log_api(SIG_ws2_32_getsockname,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ip,
        port
    );

    log_debug("Leaving %s\n", "getsockname");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_ioctlsocket(
    SOCKET s,
    long cmd,
    u_long *argp
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "ioctlsocket");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "ioctlsocket");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_ioctlsocket(
            s,
            cmd,
            argp
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_ioctlsocket(
        s,
        cmd,
        argp
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_ioctlsocket,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        argp,
        cmd
    );

    log_debug("Leaving %s\n", "ioctlsocket");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_listen(
    SOCKET s,
    int backlog
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "listen");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "listen");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_listen(
            s,
            backlog
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_listen(
        s,
        backlog
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_listen,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        backlog
    );

    log_debug("Leaving %s\n", "listen");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_recv(
    SOCKET s,
    char *buf,
    int len,
    int flags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "recv");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "recv");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_recv(
            s,
            buf,
            len,
            flags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_recv(
        s,
        buf,
        len,
        flags
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_recv,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ret,
        (uintptr_t)(ret > 0 ? ret : 0), buf
    );

    log_debug("Leaving %s\n", "recv");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_recvfrom(
    SOCKET s,
    char *buf,
    int len,
    int flags,
    struct sockaddr *from,
    int *fromlen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "recvfrom");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "recvfrom");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_recvfrom(
            s,
            buf,
            len,
            flags,
            from,
            fromlen
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_recvfrom(
        s,
        buf,
        len,
        flags,
        from,
        fromlen
    );
    get_last_error(&lasterror);
    
    const char *ip = NULL; int port = 0;
    get_ip_port(from, &ip, &port);

    log_api(SIG_ws2_32_recvfrom,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        flags,
        ip,
        port,
        (uintptr_t)(ret > 0 ? ret : 0), buf
    );

    log_debug("Leaving %s\n", "recvfrom");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_select(
    SOCKET s,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const struct timeval *timeout
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "select");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "select");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_select(
            s,
            readfds,
            writefds,
            exceptfds,
            timeout
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_select(
        s,
        readfds,
        writefds,
        exceptfds,
        timeout
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_select,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s
    );

    log_debug("Leaving %s\n", "select");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_send(
    SOCKET s,
    const char *buf,
    int len,
    int flags
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "send");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "send");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_send(
            s,
            buf,
            len,
            flags
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_send(
        s,
        buf,
        len,
        flags
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_send,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        ret,
        (uintptr_t)(ret > 0 ? ret : 0), buf
    );

    log_debug("Leaving %s\n", "send");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_sendto(
    SOCKET s,
    const char *buf,
    int len,
    int flags,
    const struct sockaddr *to,
    int tolen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "sendto");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "sendto");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_sendto(
            s,
            buf,
            len,
            flags,
            to,
            tolen
        );
        return ret;
    }
    
    const char *ip = NULL; int port = 0;
    get_ip_port(to, &ip, &port);

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_sendto(
        s,
        buf,
        len,
        flags,
        to,
        tolen
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_sendto,
        ret > 0,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        flags,
        ip,
        port,
        ret,
        (uintptr_t)(ret > 0 ? ret : 0), buf
    );

    log_debug("Leaving %s\n", "sendto");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_setsockopt(
    SOCKET s,
    int level,
    int optname,
    const char *optval,
    int optlen
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "setsockopt");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "setsockopt");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_setsockopt(
            s,
            level,
            optname,
            optval,
            optlen
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_setsockopt(
        s,
        level,
        optname,
        optval,
        optlen
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_setsockopt,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        level,
        optname,
        (uintptr_t) optlen, optval
    );

    log_debug("Leaving %s\n", "setsockopt");

    set_last_error(&lasterror);
    return ret;
}

int WINAPI New_ws2_32_shutdown(
    SOCKET s,
    int how
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "shutdown");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "shutdown");

        set_last_error(&lasterror);
        int ret = Old_ws2_32_shutdown(
            s,
            how
        );
        return ret;
    }

    uint64_t hash = 0;

    set_last_error(&lasterror);
    int ret = Old_ws2_32_shutdown(
        s,
        how
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_shutdown,
        ret != SOCKET_ERROR,
        (uintptr_t) ret,
        hash,
        &lasterror,
        s,
        how
    );

    log_debug("Leaving %s\n", "shutdown");

    set_last_error(&lasterror);
    return ret;
}

SOCKET WINAPI New_ws2_32_socket(
    int af,
    int type,
    int protocol
) {
    last_error_t lasterror;
    get_last_error(&lasterror);

    log_debug("Entered %s\n", "socket");

    if(hook_in_monitor() != 0) {
        log_debug("Early leave of %s\n", "socket");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_socket(
            af,
            type,
            protocol
        );
        return ret;
    }

    uint64_t hash = call_hash(
        "iii", 
        af,
        type,
        protocol
    );
    if(is_interesting_hash(hash) == 0) {
        log_debug("Uninteresting %s\n", "socket");

        set_last_error(&lasterror);
        SOCKET ret = Old_ws2_32_socket(
            af,
            type,
            protocol
        );
        return ret;
    }

    set_last_error(&lasterror);
    SOCKET ret = Old_ws2_32_socket(
        af,
        type,
        protocol
    );
    get_last_error(&lasterror);

    log_api(SIG_ws2_32_socket,
        ret != INVALID_SOCKET,
        (uintptr_t) ret,
        hash,
        &lasterror,
        af,
        type,
        protocol,
        ret
    );

    log_debug("Leaving %s\n", "socket");

    set_last_error(&lasterror);
    return ret;
}

static const char *g_explain_apinames[] = {
    "__process__",
    "__anomaly__",
    "__exception__",
    "__missing__",
    "__exploit__",
    "IWbemServices_ExecMethod",
    "IWbemServices_ExecMethodAsync",
    "IWbemServices_ExecQuery",
    "IWbemServices_ExecQueryAsync",
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
    "NotifyBootConfigStatus",
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
    "StartServiceCtrlDispatcherW",
    "StartServiceW",
    "TaskDialog",
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
    "ActiveXObjectFncObj_Construct",
    "COleScript_Compile",
    "AssignProcessToJobObject",
    "CopyFileA",
    "CopyFileExW",
    "CopyFileW",
    "CreateActCtxW",
    "CreateDirectoryExW",
    "CreateDirectoryW",
    "CreateJobObjectW",
    "CreateProcessInternalW",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
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
    "GetTimeZoneInformation",
    "GetVolumeNameForVolumeMountPointW",
    "GetVolumePathNameW",
    "GetVolumePathNamesForVolumeNameW",
    "GlobalMemoryStatus",
    "GlobalMemoryStatusEx",
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
    "SetFileTime",
    "SetInformationJobObject",
    "SetUnhandledExceptionFilter",
    "SizeofResource",
    "Thread32First",
    "Thread32Next",
    "WriteConsoleA",
    "WriteConsoleW",
    "WriteProcessMemory",
    "WNetGetProviderNameW",
    "CDocument_write",
    "CElement_put_innerHTML",
    "CHyperlink_SetUrlComponent",
    "CIFrameElement_CreateElement",
    "CImgElement_put_src",
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
    "NtOpenMutant",
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
    "NtQuerySystemInformation",
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
    "NtShutdownSystem",
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
    "NtOpenMutant",
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
    "NtQuerySystemInformation",
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
    "NtShutdownSystem",
    "NtSuspendThread",
    "NtTerminateProcess",
    "NtTerminateThread",
    "NtUnloadDriver",
    "NtUnmapViewOfSection",
    "NtWriteFile",
    "NtWriteVirtualMemory",
    "RtlCreateUserProcess",
    "RtlCreateUserThread",
    "CoCreateInstance",
    "CoCreateInstanceEx",
    "CoGetClassObject",
    "CoInitializeEx",
    "CoInitializeSecurity",
    "CoUninitialize",
    "OleConvertOLESTREAMToIStorage",
    "OleInitialize",
    "UuidCreate",
    "DecryptMessage",
    "EncryptMessage",
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
    "RegisterHotKey",
    "SendNotifyMessageA",
    "SendNotifyMessageW",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "UnhookWindowsHookEx",
    "vbe6_CallByName",
    "vbe6_Close",
    "vbe6_CreateObject",
    "vbe6_GetIDFromName",
    "vbe6_GetObject",
    "vbe6_Import",
    "vbe6_Invoke",
    "vbe6_Open",
    "vbe6_Print",
    "vbe6_Shell",
    "vbe6_StringConcat",
    "GetFileVersionInfoExW",
    "GetFileVersionInfoSizeExW",
    "GetFileVersionInfoSizeW",
    "GetFileVersionInfoW",
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
    "pdf_unescape",
    "pdf_eval",
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
    // __exploit__
    "__clientexploit__",
    // IWbemServices_ExecMethod
    "misc",
    // IWbemServices_ExecMethodAsync
    "misc",
    // IWbemServices_ExecQuery
    "misc",
    // IWbemServices_ExecQueryAsync
    "misc",
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
    // NotifyBootConfigStatus
    "misc",
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
    // StartServiceCtrlDispatcherW
    "services",
    // StartServiceW
    "services",
    // TaskDialog
    "misc",
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
    // ActiveXObjectFncObj_Construct
    "iexplore",
    // COleScript_Compile
    "iexplore",
    // AssignProcessToJobObject
    "process",
    // CopyFileA
    "file",
    // CopyFileExW
    "file",
    // CopyFileW
    "file",
    // CreateActCtxW
    "misc",
    // CreateDirectoryExW
    "file",
    // CreateDirectoryW
    "file",
    // CreateJobObjectW
    "process",
    // CreateProcessInternalW
    "process",
    // CreateRemoteThread
    "process",
    // CreateRemoteThreadEx
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
    // GetTimeZoneInformation
    "misc",
    // GetVolumeNameForVolumeMountPointW
    "file",
    // GetVolumePathNameW
    "file",
    // GetVolumePathNamesForVolumeNameW
    "file",
    // GlobalMemoryStatus
    "system",
    // GlobalMemoryStatusEx
    "system",
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
    // SetFileTime
    "file",
    // SetInformationJobObject
    "process",
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
    // WNetGetProviderNameW
    "network",
    // CDocument_write
    "iexplore",
    // CElement_put_innerHTML
    "iexplore",
    // CHyperlink_SetUrlComponent
    "iexplore",
    // CIFrameElement_CreateElement
    "iexplore",
    // CImgElement_put_src
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
    // NtOpenMutant
    "synchronisation",
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
    // NtQuerySystemInformation
    "system",
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
    // NtShutdownSystem
    "system",
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
    // NtOpenMutant
    "synchronisation",
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
    // NtQuerySystemInformation
    "system",
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
    // NtShutdownSystem
    "system",
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
    // RtlCreateUserProcess
    "process",
    // RtlCreateUserThread
    "process",
    // CoCreateInstance
    "ole",
    // CoCreateInstanceEx
    "ole",
    // CoGetClassObject
    "ole",
    // CoInitializeEx
    "ole",
    // CoInitializeSecurity
    "ole",
    // CoUninitialize
    "ole",
    // OleConvertOLESTREAMToIStorage
    "ole",
    // OleInitialize
    "ole",
    // UuidCreate
    "misc",
    // DecryptMessage
    "crypto",
    // EncryptMessage
    "crypto",
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
    // RegisterHotKey
    "misc",
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
    // vbe6_CallByName
    "office",
    // vbe6_Close
    "office",
    // vbe6_CreateObject
    "office",
    // vbe6_GetIDFromName
    "office",
    // vbe6_GetObject
    "office",
    // vbe6_Import
    "office",
    // vbe6_Invoke
    "office",
    // vbe6_Open
    "office",
    // vbe6_Print
    "office",
    // vbe6_Shell
    "office",
    // vbe6_StringConcat
    "office",
    // GetFileVersionInfoExW
    "misc",
    // GetFileVersionInfoSizeExW
    "misc",
    // GetFileVersionInfoSizeW
    "misc",
    // GetFileVersionInfoW
    "misc",
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
    // pdf_unescape
    "pdf",
    // pdf_eval
    "pdf",
};

static const char *g_explain_paramtypes[] = {
    // .__process__
    "iiiiuuiiz",
    // .__anomaly__
    "isss",
    // .__exception__
    "zzz",
    // .__missing__
    "s",
    // .__exploit__
    "ssssss",
    // __wmi__.IWbemServices_ExecMethod
    "uui",
    // __wmi__.IWbemServices_ExecMethodAsync
    "tti",
    // __wmi__.IWbemServices_ExecQuery
    "tti",
    // __wmi__.IWbemServices_ExecQueryAsync
    "tti",
    // advapi32.ControlService
    "pi",
    // advapi32.CreateServiceA
    "pssiiiisspus",
    // advapi32.CreateServiceW
    "puuiiiiuupuu",
    // advapi32.CryptAcquireContextA
    "Pssii",
    // advapi32.CryptAcquireContextW
    "Puuii",
    // advapi32.CryptCreateHash
    "pxpiP",
    // advapi32.CryptDecrypt
    "ppii!b",
    // advapi32.CryptEncrypt
    "!bppii",
    // advapi32.CryptExportKey
    "ppiib",
    // advapi32.CryptGenKey
    "pxiP",
    // advapi32.CryptHashData
    "pi!b",
    // advapi32.DeleteService
    "p",
    // advapi32.EnumServicesStatusA
    "pii",
    // advapi32.EnumServicesStatusW
    "pii",
    // advapi32.GetUserNameA
    "S",
    // advapi32.GetUserNameW
    "U",
    // advapi32.LookupAccountSidW
    "uuu",
    // advapi32.LookupPrivilegeValueW
    "uu",
    // advapi32.NotifyBootConfigStatus
    "i",
    // advapi32.OpenSCManagerA
    "ssi",
    // advapi32.OpenSCManagerW
    "uui",
    // advapi32.OpenServiceA
    "psip",
    // advapi32.OpenServiceW
    "puip",
    // advapi32.RegCloseKey
    "p",
    // advapi32.RegCreateKeyExA
    "pssixPIu",
    // advapi32.RegCreateKeyExW
    "puuixPIu",
    // advapi32.RegDeleteKeyA
    "psu",
    // advapi32.RegDeleteKeyW
    "puu",
    // advapi32.RegDeleteValueA
    "psu",
    // advapi32.RegDeleteValueW
    "puu",
    // advapi32.RegEnumKeyExA
    "pissu",
    // advapi32.RegEnumKeyExW
    "piuuu",
    // advapi32.RegEnumKeyW
    "piuu",
    // advapi32.RegEnumValueA
    "pisIur",
    // advapi32.RegEnumValueW
    "piuIuR",
    // advapi32.RegOpenKeyExA
    "psixPu",
    // advapi32.RegOpenKeyExW
    "puixPu",
    // advapi32.RegQueryInfoKeyA
    "psIIIIIIu",
    // advapi32.RegQueryInfoKeyW
    "puIIIIIIu",
    // advapi32.RegQueryValueExA
    "psIur",
    // advapi32.RegQueryValueExW
    "puIuR",
    // advapi32.RegSetValueExA
    "psiur",
    // advapi32.RegSetValueExW
    "puiuR",
    // advapi32.StartServiceA
    "pa",
    // advapi32.StartServiceCtrlDispatcherW
    "zz",
    // advapi32.StartServiceW
    "pA",
    // comctl32.TaskDialog
    "ppiIuuuu",
    // crypt32.CertControlStore
    "pii",
    // crypt32.CertCreateCertificateContext
    "ib",
    // crypt32.CertOpenStore
    "iis",
    // crypt32.CertOpenSystemStoreA
    "s",
    // crypt32.CertOpenSystemStoreW
    "u",
    // crypt32.CryptDecodeMessage
    "!b",
    // crypt32.CryptDecodeObjectEx
    "iis!b",
    // crypt32.CryptDecryptMessage
    "!b",
    // crypt32.CryptEncryptMessage
    "!b",
    // crypt32.CryptHashMessage
    "!b",
    // crypt32.CryptProtectData
    "!bui",
    // crypt32.CryptProtectMemory
    "!bi",
    // crypt32.CryptUnprotectData
    "iub!b",
    // crypt32.CryptUnprotectMemory
    "i!b",
    // dnsapi.DnsQuery_A
    "sii",
    // dnsapi.DnsQuery_UTF8
    "iis",
    // dnsapi.DnsQuery_W
    "uii",
    // iphlpapi.GetAdaptersAddresses
    "ii",
    // iphlpapi.GetAdaptersInfo
    "",
    // iphlpapi.GetBestInterfaceEx
    "",
    // iphlpapi.GetInterfaceInfo
    "",
    // jscript.ActiveXObjectFncObj_Construct
    "u",
    // jscript.COleScript_Compile
    "uu",
    // kernel32.AssignProcessToJobObject
    "ppi",
    // kernel32.CopyFileA
    "iusus",
    // kernel32.CopyFileExW
    "iuuuu",
    // kernel32.CopyFileW
    "iuuuu",
    // kernel32.CreateActCtxW
    "uup",
    // kernel32.CreateDirectoryExW
    "uu",
    // kernel32.CreateDirectoryW
    "uu",
    // kernel32.CreateJobObjectW
    "sp",
    // kernel32.CreateProcessInternalW
    "uiuuuiiippi",
    // kernel32.CreateRemoteThread
    "pippiIi",
    // kernel32.CreateRemoteThreadEx
    "pippiI",
    // kernel32.CreateThread
    "ippiI",
    // kernel32.CreateToolhelp32Snapshot
    "ii",
    // kernel32.DeleteFileW
    "uu",
    // kernel32.DeviceIoControl
    "bpib",
    // kernel32.FindFirstFileExA
    "us",
    // kernel32.FindFirstFileExW
    "uu",
    // kernel32.FindResourceA
    "pss",
    // kernel32.FindResourceExA
    "piss",
    // kernel32.FindResourceExW
    "piuu",
    // kernel32.FindResourceW
    "puu",
    // kernel32.GetComputerNameA
    "S",
    // kernel32.GetComputerNameW
    "U",
    // kernel32.GetDiskFreeSpaceExW
    "uQQQ",
    // kernel32.GetDiskFreeSpaceW
    "uIIII",
    // kernel32.GetFileAttributesExW
    "iuu",
    // kernel32.GetFileAttributesW
    "uui",
    // kernel32.GetFileInformationByHandle
    "p",
    // kernel32.GetFileInformationByHandleEx
    "pi",
    // kernel32.GetFileSize
    "pi",
    // kernel32.GetFileSizeEx
    "pQ",
    // kernel32.GetFileType
    "p",
    // kernel32.GetLocalTime
    "",
    // kernel32.GetNativeSystemInfo
    "i",
    // kernel32.GetShortPathNameW
    "uu",
    // kernel32.GetSystemDirectoryA
    "S",
    // kernel32.GetSystemDirectoryW
    "U",
    // kernel32.GetSystemInfo
    "i",
    // kernel32.GetSystemTime
    "",
    // kernel32.GetSystemTimeAsFileTime
    "",
    // kernel32.GetSystemWindowsDirectoryA
    "S",
    // kernel32.GetSystemWindowsDirectoryW
    "U",
    // kernel32.GetTempPathW
    "U",
    // kernel32.GetTickCount
    "",
    // kernel32.GetTimeZoneInformation
    "",
    // kernel32.GetVolumeNameForVolumeMountPointW
    "uu",
    // kernel32.GetVolumePathNameW
    "uu",
    // kernel32.GetVolumePathNamesForVolumeNameW
    "uu",
    // kernel32.GlobalMemoryStatus
    "",
    // kernel32.GlobalMemoryStatusEx
    "",
    // kernel32.IsDebuggerPresent
    "",
    // kernel32.LoadResource
    "ppp",
    // kernel32.Module32FirstW
    "p",
    // kernel32.Module32NextW
    "p",
    // kernel32.MoveFileWithProgressW
    "iuuuu",
    // kernel32.OutputDebugStringA
    "s",
    // kernel32.Process32FirstW
    "pui",
    // kernel32.Process32NextW
    "pui",
    // kernel32.ReadProcessMemory
    "ppB",
    // kernel32.RemoveDirectoryA
    "us",
    // kernel32.RemoveDirectoryW
    "uu",
    // kernel32.SearchPathW
    "uuuu",
    // kernel32.SetEndOfFile
    "p",
    // kernel32.SetErrorMode
    "i",
    // kernel32.SetFileAttributesW
    "iuu",
    // kernel32.SetFileInformationByHandle
    "pi",
    // kernel32.SetFilePointer
    "piq",
    // kernel32.SetFilePointerEx
    "pQi",
    // kernel32.SetFileTime
    "p",
    // kernel32.SetInformationJobObject
    "pib",
    // kernel32.SetUnhandledExceptionFilter
    "",
    // kernel32.SizeofResource
    "ppi",
    // kernel32.Thread32First
    "p",
    // kernel32.Thread32Next
    "p",
    // kernel32.WriteConsoleA
    "pS",
    // kernel32.WriteConsoleW
    "pU",
    // kernel32.WriteProcessMemory
    "ppi!B",
    // mpr.WNetGetProviderNameW
    "x",
    // mshtml.CDocument_write
    "z",
    // mshtml.CElement_put_innerHTML
    "u",
    // mshtml.CHyperlink_SetUrlComponent
    "ui",
    // mshtml.CIFrameElement_CreateElement
    "z",
    // mshtml.CImgElement_put_src
    "u",
    // mshtml.CScriptElement_put_src
    "u",
    // mshtml.CWindow_AddTimeoutCode
    "uiui",
    // msvcrt.system
    "s",
    // ncrypt.PRF
    "ssss",
    // ncrypt.Ssl3GenerateKeyMaterial
    "sss",
    // netapi32.NetGetJoinInformation
    "uu",
    // netapi32.NetShareEnum
    "ui",
    // netapi32.NetUserGetInfo
    "uui",
    // netapi32.NetUserGetLocalGroups
    "uuii",
    // ntdll.LdrGetDllHandle
    "Pu",
    // ntdll.LdrGetProcedureAddress
    "poiPs",
    // ntdll.LdrLoadDll
    "IPus",
    // ntdll.LdrUnloadDll
    "ps",
    // ntdll.NtAllocateVirtualMemory
    "pPLiii",
    // ntdll.NtClose
    "p",
    // ntdll.NtCreateDirectoryObject
    "Pxuu",
    // ntdll.NtCreateFile
    "Pxiiiiuul",
    // ntdll.NtCreateKey
    "PxiiIuu",
    // ntdll.NtCreateMutant
    "Pxiu",
    // ntdll.NtCreateProcess
    "Pxpiiuu",
    // ntdll.NtCreateProcessEx
    "Pxpiiuu",
    // ntdll.NtCreateSection
    "Pxippu",
    // ntdll.NtCreateThread
    "Pxpiu",
    // ntdll.NtCreateThreadEx
    "Pxppppii",
    // ntdll.NtCreateUserProcess
    "PPxxiiiiuuuuuu",
    // ntdll.NtDelayExecution
    "qi",
    // ntdll.NtDeleteFile
    "uu",
    // ntdll.NtDeleteKey
    "pu",
    // ntdll.NtDeleteValueKey
    "pu",
    // ntdll.NtDeviceIoControlFile
    "bpib",
    // ntdll.NtDuplicateObject
    "pppPxiiii",
    // ntdll.NtEnumerateKey
    "piibu",
    // ntdll.NtEnumerateValueKey
    "piiuuiR",
    // ntdll.NtFreeVirtualMemory
    "pPLii",
    // ntdll.NtGetContextThread
    "p",
    // ntdll.NtLoadDriver
    "u",
    // ntdll.NtLoadKey
    "uu",
    // ntdll.NtLoadKey2
    "iuu",
    // ntdll.NtLoadKeyEx
    "ipuu",
    // ntdll.NtMakePermanentObject
    "p",
    // ntdll.NtMakeTemporaryObject
    "p",
    // ntdll.NtMapViewOfSection
    "ppPiQLiii!b",
    // ntdll.NtOpenDirectoryObject
    "Pxuu",
    // ntdll.NtOpenFile
    "Pxiiuul",
    // ntdll.NtOpenKey
    "Pxu",
    // ntdll.NtOpenKeyEx
    "Pxiu",
    // ntdll.NtOpenMutant
    "Pxu",
    // ntdll.NtOpenProcess
    "Pxi",
    // ntdll.NtOpenSection
    "Pxu",
    // ntdll.NtOpenThread
    "Pxui",
    // ntdll.NtProtectVirtualMemory
    "pPLii",
    // ntdll.NtQueryAttributesFile
    "uu",
    // ntdll.NtQueryDirectoryFile
    "piu",
    // ntdll.NtQueryFullAttributesFile
    "uu",
    // ntdll.NtQueryInformationFile
    "pi",
    // ntdll.NtQueryKey
    "pibu",
    // ntdll.NtQueryMultipleValueKey
    "pibu",
    // ntdll.NtQuerySystemInformation
    "i",
    // ntdll.NtQuerySystemTime
    "",
    // ntdll.NtQueryValueKey
    "piuuiR",
    // ntdll.NtQueueApcThread
    "pppi",
    // ntdll.NtReadFile
    "piQb",
    // ntdll.NtReadVirtualMemory
    "ppB",
    // ntdll.NtRenameKey
    "puu",
    // ntdll.NtReplaceKey
    "puuu",
    // ntdll.NtResumeThread
    "pIi",
    // ntdll.NtSaveKey
    "ppuu",
    // ntdll.NtSaveKeyEx
    "ppiuu",
    // ntdll.NtSetContextThread
    "piz",
    // ntdll.NtSetInformationFile
    "pi",
    // ntdll.NtSetValueKey
    "piiiRu",
    // ntdll.NtShutdownSystem
    "i",
    // ntdll.NtSuspendThread
    "pI",
    // ntdll.NtTerminateProcess
    "pxi",
    // ntdll.NtTerminateThread
    "px",
    // ntdll.NtUnloadDriver
    "u",
    // ntdll.NtUnmapViewOfSection
    "ppil",
    // ntdll.NtWriteFile
    "pQb",
    // ntdll.NtWriteVirtualMemory
    "ppi!B",
    // ntdll.RtlAddVectoredContinueHandler
    "i",
    // ntdll.RtlAddVectoredExceptionHandler
    "i",
    // ntdll.RtlCompressBuffer
    "!biiI",
    // ntdll.RtlCreateUserProcess
    "ipiiiuu",
    // ntdll.RtlCreateUserThread
    "pippP",
    // ntdll.RtlDecompressBuffer
    "iiI!B",
    // ntdll.RtlDecompressFragment
    "iiiI!B",
    // ntdll.RtlDispatchException
    "",
    // ntdll.RtlRemoveVectoredContinueHandler
    "",
    // ntdll.RtlRemoveVectoredExceptionHandler
    "",
    // ntoskrnl.NtAllocateVirtualMemory
    "sssss",
    // ntoskrnl.NtClose
    "p",
    // ntoskrnl.NtCreateDirectoryObject
    "ss",
    // ntoskrnl.NtCreateFile
    "sssssss",
    // ntoskrnl.NtCreateKey
    "sssssss",
    // ntoskrnl.NtCreateMutant
    "ssss",
    // ntoskrnl.NtCreateProcess
    "ssss",
    // ntoskrnl.NtCreateProcessEx
    "ssss",
    // ntoskrnl.NtCreateSection
    "ssssss",
    // ntoskrnl.NtCreateThread
    "sssss",
    // ntoskrnl.NtCreateThreadEx
    "ssssssss",
    // ntoskrnl.NtCreateUserProcess
    "sssssssss",
    // ntoskrnl.NtDeleteFile
    "ss",
    // ntoskrnl.NtDeleteKey
    "ss",
    // ntoskrnl.NtDeleteValueKey
    "sss",
    // ntoskrnl.NtDeviceIoControlFile
    "ssss",
    // ntoskrnl.NtDuplicateObject
    "pppPxiiii",
    // ntoskrnl.NtEnumerateKey
    "sssbu",
    // ntoskrnl.NtEnumerateValueKey
    "sssuuiR",
    // ntoskrnl.NtFreeVirtualMemory
    "ssss",
    // ntoskrnl.NtGetContextThread
    "s",
    // ntoskrnl.NtLoadDriver
    "s",
    // ntoskrnl.NtLoadKey
    "",
    // ntoskrnl.NtLoadKey2
    "s",
    // ntoskrnl.NtLoadKeyEx
    "ss",
    // ntoskrnl.NtMakePermanentObject
    "s",
    // ntoskrnl.NtMakeTemporaryObject
    "s",
    // ntoskrnl.NtMapViewOfSection
    "ssssssss",
    // ntoskrnl.NtOpenDirectoryObject
    "ss",
    // ntoskrnl.NtOpenFile
    "sssss",
    // ntoskrnl.NtOpenKey
    "sss",
    // ntoskrnl.NtOpenKeyEx
    "ssss",
    // ntoskrnl.NtOpenMutant
    "sss",
    // ntoskrnl.NtOpenProcess
    "sss",
    // ntoskrnl.NtOpenSection
    "ss",
    // ntoskrnl.NtOpenThread
    "sss",
    // ntoskrnl.NtProtectVirtualMemory
    "ssss",
    // ntoskrnl.NtQueryAttributesFile
    "",
    // ntoskrnl.NtQueryDirectoryFile
    "ss",
    // ntoskrnl.NtQueryFullAttributesFile
    "",
    // ntoskrnl.NtQueryInformationFile
    "ss",
    // ntoskrnl.NtQueryKey
    "ss",
    // ntoskrnl.NtQueryMultipleValueKey
    "ss",
    // ntoskrnl.NtQuerySystemInformation
    "i",
    // ntoskrnl.NtQueryValueKey
    "sssss",
    // ntoskrnl.NtQueueApcThread
    "ssss",
    // ntoskrnl.NtReadFile
    "ssss",
    // ntoskrnl.NtReadVirtualMemory
    "sss",
    // ntoskrnl.NtRenameKey
    "suu",
    // ntoskrnl.NtReplaceKey
    "suuu",
    // ntoskrnl.NtResumeThread
    "ss",
    // ntoskrnl.NtSaveKey
    "ss",
    // ntoskrnl.NtSaveKeyEx
    "sss",
    // ntoskrnl.NtSetContextThread
    "s",
    // ntoskrnl.NtSetInformationFile
    "ssss",
    // ntoskrnl.NtSetValueKey
    "sssssss",
    // ntoskrnl.NtShutdownSystem
    "i",
    // ntoskrnl.NtSuspendThread
    "ss",
    // ntoskrnl.NtTerminateProcess
    "ss",
    // ntoskrnl.NtTerminateThread
    "ss",
    // ntoskrnl.NtUnloadDriver
    "u",
    // ntoskrnl.NtUnmapViewOfSection
    "ss",
    // ntoskrnl.NtWriteFile
    "sss",
    // ntoskrnl.NtWriteVirtualMemory
    "sss",
    // ntoskrnl.RtlCreateUserProcess
    "sss",
    // ntoskrnl.RtlCreateUserThread
    "sssss",
    // ole32.CoCreateInstance
    "cic",
    // ole32.CoCreateInstanceEx
    "ciz",
    // ole32.CoGetClassObject
    "cic",
    // ole32.CoInitializeEx
    "i",
    // ole32.CoInitializeSecurity
    "",
    // ole32.CoUninitialize
    "",
    // ole32.OleConvertOLESTREAMToIStorage
    "!b",
    // ole32.OleInitialize
    "",
    // rpcrt4.UuidCreate
    "s",
    // secur32.DecryptMessage
    "piI!b",
    // secur32.EncryptMessage
    "pii!b",
    // secur32.GetUserNameExA
    "iS",
    // secur32.GetUserNameExW
    "iU",
    // shell32.ReadCabinetState
    "",
    // shell32.SHGetFolderPathW
    "pipiuu",
    // shell32.SHGetSpecialFolderLocation
    "pi",
    // shell32.ShellExecuteExW
    "uuui",
    // srvcli.NetShareEnum
    "ui",
    // urlmon.ObtainUserAgentString
    "iS",
    // urlmon.URLDownloadToFileW
    "uuu",
    // user32.DrawTextExA
    "S",
    // user32.DrawTextExW
    "U",
    // user32.EnumWindows
    "",
    // user32.ExitWindowsEx
    "ii",
    // user32.FindWindowA
    "ss",
    // user32.FindWindowExA
    "ppss",
    // user32.FindWindowExW
    "ppuu",
    // user32.FindWindowW
    "uu",
    // user32.GetAsyncKeyState
    "i",
    // user32.GetCursorPos
    "II",
    // user32.GetForegroundWindow
    "",
    // user32.GetKeyState
    "i",
    // user32.GetKeyboardState
    "",
    // user32.GetSystemMetrics
    "i",
    // user32.LoadStringA
    "pis",
    // user32.LoadStringW
    "piu",
    // user32.MessageBoxTimeoutA
    "pssii",
    // user32.MessageBoxTimeoutW
    "puuii",
    // user32.RegisterHotKey
    "piii",
    // user32.SendNotifyMessageA
    "pii",
    // user32.SendNotifyMessageW
    "pii",
    // user32.SetWindowsHookExA
    "ippi",
    // user32.SetWindowsHookExW
    "ippi",
    // user32.UnhookWindowsHookEx
    "p",
    // vbe6.vbe6_CallByName
    "",
    // vbe6.vbe6_Close
    "i",
    // vbe6.vbe6_CreateObject
    "ptp",
    // vbe6.vbe6_GetIDFromName
    "upl",
    // vbe6.vbe6_GetObject
    "vp",
    // vbe6.vbe6_Import
    "ss",
    // vbe6.vbe6_Invoke
    "piuzz",
    // vbe6.vbe6_Open
    "iiu",
    // vbe6.vbe6_Print
    "v",
    // vbe6.vbe6_Shell
    "vi",
    // vbe6.vbe6_StringConcat
    "vvv",
    // version.GetFileVersionInfoExW
    "iub",
    // version.GetFileVersionInfoSizeExW
    "iu",
    // version.GetFileVersionInfoSizeW
    "u",
    // version.GetFileVersionInfoW
    "ub",
    // wininet.DeleteUrlCacheEntryA
    "s",
    // wininet.DeleteUrlCacheEntryW
    "u",
    // wininet.HttpOpenRequestA
    "pssssi",
    // wininet.HttpOpenRequestW
    "puuuui",
    // wininet.HttpQueryInfoA
    "piIb",
    // wininet.HttpSendRequestA
    "pSb",
    // wininet.HttpSendRequestW
    "pUb",
    // wininet.InternetCloseHandle
    "p",
    // wininet.InternetConnectA
    "psissii",
    // wininet.InternetConnectW
    "puiuuii",
    // wininet.InternetCrackUrlA
    "iS",
    // wininet.InternetCrackUrlW
    "iU",
    // wininet.InternetGetConnectedState
    "I",
    // wininet.InternetGetConnectedStateExA
    "Is",
    // wininet.InternetGetConnectedStateExW
    "Iu",
    // wininet.InternetOpenA
    "sissi",
    // wininet.InternetOpenUrlA
    "psib",
    // wininet.InternetOpenUrlW
    "puib",
    // wininet.InternetOpenW
    "uiuui",
    // wininet.InternetQueryOptionA
    "pi",
    // wininet.InternetReadFile
    "pb",
    // wininet.InternetSetOptionA
    "pi",
    // wininet.InternetSetStatusCallback
    "pp",
    // wininet.InternetWriteFile
    "pb",
    // winmm.timeGetTime
    "",
    // ws2_32.ConnectEx
    "isib",
    // ws2_32.GetAddrInfoW
    "uu",
    // ws2_32.TransmitFile
    "ipii",
    // ws2_32.WSAAccept
    "isi",
    // ws2_32.WSAConnect
    "isi",
    // ws2_32.WSARecv
    "i!b",
    // ws2_32.WSARecvFrom
    "isi!b",
    // ws2_32.WSASend
    "i!b",
    // ws2_32.WSASendTo
    "isi!b",
    // ws2_32.WSASocketA
    "iiiii",
    // ws2_32.WSASocketW
    "iiiii",
    // ws2_32.WSAStartup
    "i",
    // ws2_32.accept
    "isi",
    // ws2_32.bind
    "isi",
    // ws2_32.closesocket
    "i",
    // ws2_32.connect
    "isi",
    // ws2_32.getaddrinfo
    "ss",
    // ws2_32.gethostbyname
    "s",
    // ws2_32.getsockname
    "isi",
    // ws2_32.ioctlsocket
    "iIx",
    // ws2_32.listen
    "ii",
    // ws2_32.recv
    "ii!b",
    // ws2_32.recvfrom
    "iisi!b",
    // ws2_32.select
    "i",
    // ws2_32.send
    "ii!b",
    // ws2_32.sendto
    "iisii!b",
    // ws2_32.setsockopt
    "iiib",
    // ws2_32.shutdown
    "ii",
    // ws2_32.socket
    "iiii",
    // escript_api.pdf_unescape
    "u",
    // escript_api.pdf_eval
    "u",
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
        "track",
        "modules",
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
    // __exploit__
    {
        "pid",
        "ppid",
        "parent_process",
        "exploit_process",
        "exploit_type",
        "reason",
    },
    // IWbemServices_ExecMethod
    {
        "class",
        "method",
        "flags",
    },
    // IWbemServices_ExecMethodAsync
    {
        "class",
        "method",
        "flags",
    },
    // IWbemServices_ExecQuery
    {
        "query_language",
        "query",
        "flags",
    },
    // IWbemServices_ExecQueryAsync
    {
        "query_language",
        "query",
        "flags",
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
        "service_handle",
        "filepath",
        "filepath_r",
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
        "service_handle",
        "filepath",
        "filepath_r",
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
        "buffer",
        "key_handle",
        "hash_handle",
        "final",
        "flags",
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
        "username",
    },
    // GetUserNameW
    {
        "username",
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
    // NotifyBootConfigStatus
    {
        "boot_acceptable",
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
        "service_handle",
    },
    // OpenServiceW
    {
        "service_manager_handle",
        "service_name",
        "desired_access",
        "service_handle",
    },
    // RegCloseKey
    {
        "key_handle",
    },
    // RegCreateKeyExA
    {
        "base_handle",
        "regkey_r",
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
        "regkey_r",
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
        "regkey_r",
        "regkey",
    },
    // RegDeleteKeyW
    {
        "key_handle",
        "regkey_r",
        "regkey",
    },
    // RegDeleteValueA
    {
        "key_handle",
        "regkey_r",
        "regkey",
    },
    // RegDeleteValueW
    {
        "key_handle",
        "regkey_r",
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
        "regkey_r",
        "reg_type",
        "regkey",
        "value",
    },
    // RegEnumValueW
    {
        "key_handle",
        "index",
        "regkey_r",
        "reg_type",
        "regkey",
        "value",
    },
    // RegOpenKeyExA
    {
        "base_handle",
        "regkey_r",
        "options",
        "access",
        "key_handle",
        "regkey",
    },
    // RegOpenKeyExW
    {
        "base_handle",
        "regkey_r",
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
        "regkey",
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
        "regkey",
    },
    // RegQueryValueExA
    {
        "key_handle",
        "regkey_r",
        "reg_type",
        "regkey",
        "value",
    },
    // RegQueryValueExW
    {
        "key_handle",
        "regkey_r",
        "reg_type",
        "regkey",
        "value",
    },
    // RegSetValueExA
    {
        "key_handle",
        "regkey_r",
        "reg_type",
        "regkey",
        "value",
    },
    // RegSetValueExW
    {
        "key_handle",
        "regkey_r",
        "reg_type",
        "regkey",
        "value",
    },
    // StartServiceA
    {
        "service_handle",
        "arguments",
    },
    // StartServiceCtrlDispatcherW
    {
        "addresses",
        "services",
    },
    // StartServiceW
    {
        "service_handle",
        "arguments",
    },
    // TaskDialog
    {
        "parent_window_handle",
        "instance_handle",
        "buttons",
        "button",
        "title",
        "description",
        "content",
        "icon",
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
    // ActiveXObjectFncObj_Construct
    {
        "objname",
    },
    // COleScript_Compile
    {
        "script",
        "type",
    },
    // AssignProcessToJobObject
    {
        "job_handle",
        "process_handle",
        "process_identifier",
    },
    // CopyFileA
    {
        "fail_if_exists",
        "oldfilepath",
        "oldfilepath_r",
        "newfilepath",
        "newfilepath_r",
    },
    // CopyFileExW
    {
        "flags",
        "oldfilepath",
        "oldfilepath_r",
        "newfilepath",
        "newfilepath_r",
    },
    // CopyFileW
    {
        "fail_if_exists",
        "oldfilepath",
        "oldfilepath_r",
        "newfilepath",
        "newfilepath_r",
    },
    // CreateActCtxW
    {
        "resource_name",
        "application_name",
        "module_handle",
    },
    // CreateDirectoryExW
    {
        "dirpath",
        "dirpath_r",
    },
    // CreateDirectoryW
    {
        "dirpath",
        "dirpath_r",
    },
    // CreateJobObjectW
    {
        "lpName",
        "job_handle",
    },
    // CreateProcessInternalW
    {
        "command_line",
        "inherit_handles",
        "current_directory",
        "filepath",
        "filepath_r",
        "creation_flags",
        "process_identifier",
        "thread_identifier",
        "process_handle",
        "thread_handle",
        "track",
    },
    // CreateRemoteThread
    {
        "process_handle",
        "stack_size",
        "function_address",
        "parameter",
        "flags",
        "thread_identifier",
        "process_identifier",
    },
    // CreateRemoteThreadEx
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
        "filepath_r",
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
        "filepath_r",
    },
    // FindFirstFileExW
    {
        "filepath",
        "filepath_r",
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
        "filepath_r",
    },
    // GetFileAttributesW
    {
        "filepath",
        "filepath_r",
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
    // GetTimeZoneInformation
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
    // GlobalMemoryStatus
    {
    },
    // GlobalMemoryStatusEx
    {
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
        "oldfilepath_r",
        "newfilepath",
        "newfilepath_r",
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
        "dirpath_r",
    },
    // RemoveDirectoryW
    {
        "dirpath",
        "dirpath_r",
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
        "filepath_r",
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
    // SetFileTime
    {
        "file_handle",
    },
    // SetInformationJobObject
    {
        "job_handle",
        "information_class",
        "buf",
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
        "process_identifier",
        "buffer",
    },
    // WNetGetProviderNameW
    {
        "net_type",
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
    // CImgElement_put_src
    {
        "src",
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
        "module",
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
        "library",
    },
    // NtAllocateVirtualMemory
    {
        "process_handle",
        "base_address",
        "region_size",
        "allocation_type",
        "protection",
        "process_identifier",
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
        "dirpath_r",
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
        "filepath_r",
        "status_info",
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
        "parent_process_handle",
        "inherit_handles",
        "process_identifier",
        "filepath",
        "filepath_r",
    },
    // NtCreateProcessEx
    {
        "process_handle",
        "desired_access",
        "parent_process_handle",
        "flags",
        "process_identifier",
        "filepath",
        "filepath_r",
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
        "process_identifier",
        "thread_identifier",
        "process_name",
        "process_name_r",
        "thread_name",
        "thread_name_r",
        "filepath",
        "command_line",
    },
    // NtDelayExecution
    {
        "milliseconds",
        "skipped",
    },
    // NtDeleteFile
    {
        "filepath",
        "filepath_r",
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
        "process_identifier",
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
        "process_identifier",
        "buffer",
    },
    // NtOpenDirectoryObject
    {
        "directory_handle",
        "desired_access",
        "dirpath",
        "dirpath_r",
    },
    // NtOpenFile
    {
        "file_handle",
        "desired_access",
        "open_options",
        "share_access",
        "filepath",
        "filepath_r",
        "status_info",
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
    // NtOpenMutant
    {
        "mutant_handle",
        "desired_access",
        "mutant_name",
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
        "process_identifier",
    },
    // NtQueryAttributesFile
    {
        "filepath",
        "filepath_r",
    },
    // NtQueryDirectoryFile
    {
        "file_handle",
        "information_class",
        "dirpath",
    },
    // NtQueryFullAttributesFile
    {
        "filepath",
        "filepath_r",
    },
    // NtQueryInformationFile
    {
        "file_handle",
        "information_class",
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
    // NtQuerySystemInformation
    {
        "information_class",
    },
    // NtQuerySystemTime
    {
    },
    // NtQueryValueKey
    {
        "key_handle",
        "information_class",
        "regkey",
        "key_name",
        "reg_type",
        "value",
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
        "process_identifier",
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
        "process_identifier",
        "registers",
    },
    // NtSetInformationFile
    {
        "file_handle",
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
    // NtShutdownSystem
    {
        "action",
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
        "process_identifier",
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
        "process_identifier",
        "region_size",
    },
    // NtWriteFile
    {
        "file_handle",
        "offset",
        "buffer",
    },
    // NtWriteVirtualMemory
    {
        "process_handle",
        "base_address",
        "process_identifier",
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
    },
    // RtlCreateUserProcess
    {
        "flags",
        "parent_process_handle",
        "inherit_handles",
        "process_identifier",
        "thread_identifier",
        "filepath",
        "filepath_r",
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
        "format",
        "input_size",
        "output_size",
        "uncompressed",
    },
    // RtlDecompressFragment
    {
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
    },
    // NtCreateFile
    {
        "file_handle",
        "desired_access",
        "file_attributes",
        "share_access",
        "create_disposition",
        "create_options",
        "filepath",
    },
    // NtCreateKey
    {
        "key_handle",
        "desired_access",
        "ObjectAttributes",
        "index",
        "Class",
        "options",
        "disposition",
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
        "parent_process_handle",
        "inherit_handles",
    },
    // NtCreateProcessEx
    {
        "process_handle",
        "desired_access",
        "parent_process_handle",
        "flags",
    },
    // NtCreateSection
    {
        "section_handle",
        "desired_access",
        "protection",
        "file_handle",
        "root_directory",
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
        "process_identifier",
    },
    // NtDeleteFile
    {
        "filepath",
        "filepath_r",
    },
    // NtDeleteKey
    {
        "key_handle",
        "regkey",
    },
    // NtDeleteValueKey
    {
        "key_handle",
        "ValueName",
        "regkey",
    },
    // NtDeviceIoControlFile
    {
        "file_handle",
        "control_code",
        "InputBuffer",
        "OutputBuffer",
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
    },
    // NtLoadKey2
    {
        "flags",
    },
    // NtLoadKeyEx
    {
        "flags",
        "trust_class_key",
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
        "view_size",
        "allocation_type",
        "win32_protect",
        "map_buffer",
    },
    // NtOpenDirectoryObject
    {
        "directory_handle",
        "desired_access",
    },
    // NtOpenFile
    {
        "file_handle",
        "desired_access",
        "share_access",
        "open_options",
        "filepath",
    },
    // NtOpenKey
    {
        "key_handle",
        "desired_access",
        "ObjectAttributes",
    },
    // NtOpenKeyEx
    {
        "key_handle",
        "desired_access",
        "ObjectAttributes",
        "options",
    },
    // NtOpenMutant
    {
        "mutant_handle",
        "desired_access",
        "mutant_name",
    },
    // NtOpenProcess
    {
        "process_handle",
        "desired_access",
        "targetpid",
    },
    // NtOpenSection
    {
        "section_handle",
        "desired_access",
    },
    // NtOpenThread
    {
        "thread_handle",
        "access",
        "target_pid",
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
    },
    // NtQueryDirectoryFile
    {
        "file_handle",
        "information_class",
    },
    // NtQueryFullAttributesFile
    {
    },
    // NtQueryInformationFile
    {
        "file_handle",
        "information_class",
    },
    // NtQueryKey
    {
        "key_handle",
        "information_class",
    },
    // NtQueryMultipleValueKey
    {
        "KeyHandle",
        "EntryCount",
    },
    // NtQuerySystemInformation
    {
        "information_class",
    },
    // NtQueryValueKey
    {
        "key_handle",
        "ValueName",
        "information_class",
        "regkey",
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
        "Buffer",
        "length",
        "offset",
    },
    // NtReadVirtualMemory
    {
        "process_handle",
        "base_address",
        "Buffer",
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
    },
    // NtSaveKeyEx
    {
        "key_handle",
        "file_handle",
        "format",
    },
    // NtSetContextThread
    {
        "thread_handle",
    },
    // NtSetInformationFile
    {
        "file_handle",
        "original_filename",
        "renamed_filename",
        "information_class",
    },
    // NtSetValueKey
    {
        "key_handle",
        "value",
        "index",
        "reg_type",
        "Data",
        "DataSize",
        "regkey",
    },
    // NtShutdownSystem
    {
        "action",
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
    },
    // NtWriteFile
    {
        "file_handle",
        "Buffer",
        "offset",
    },
    // NtWriteVirtualMemory
    {
        "process_handle",
        "base_address",
        "Buffer",
    },
    // RtlCreateUserProcess
    {
        "flags",
        "parent_process_handle",
        "inherit_handles",
    },
    // RtlCreateUserThread
    {
        "process_handle",
        "suspended",
        "function_address",
        "parameter",
        "thread_handle",
    },
    // CoCreateInstance
    {
        "clsid",
        "class_context",
        "iid",
    },
    // CoCreateInstanceEx
    {
        "clsid",
        "class_context",
        "iid",
    },
    // CoGetClassObject
    {
        "clsid",
        "class_context",
        "iid",
    },
    // CoInitializeEx
    {
        "options",
    },
    // CoInitializeSecurity
    {
    },
    // CoUninitialize
    {
    },
    // OleConvertOLESTREAMToIStorage
    {
        "ole2",
    },
    // OleInitialize
    {
    },
    // UuidCreate
    {
        "uuid",
    },
    // DecryptMessage
    {
        "context_handle",
        "number",
        "qop",
        "buffer",
    },
    // EncryptMessage
    {
        "context_handle",
        "qop",
        "number",
        "buffer",
    },
    // GetUserNameExA
    {
        "name_format",
        "username",
    },
    // GetUserNameExW
    {
        "name_format",
        "username",
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
        "dirpath_r",
    },
    // SHGetSpecialFolderLocation
    {
        "window_handle",
        "folder_index",
    },
    // ShellExecuteExW
    {
        "filepath",
        "filepath_r",
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
        "filepath_r",
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
    // RegisterHotKey
    {
        "window_handle",
        "id",
        "modifiers",
        "vk",
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
    // vbe6_CallByName
    {
    },
    // vbe6_Close
    {
        "fd",
    },
    // vbe6_CreateObject
    {
        "this",
        "object_name",
        "this",
    },
    // vbe6_GetIDFromName
    {
        "funcname",
        "this",
        "funcidx",
    },
    // vbe6_GetObject
    {
        "object_name",
        "this",
    },
    // vbe6_Import
    {
        "library",
        "function",
    },
    // vbe6_Invoke
    {
        "this",
        "funcidx",
        "funcname",
        "args",
        "result",
    },
    // vbe6_Open
    {
        "mode",
        "fd",
        "filename",
    },
    // vbe6_Print
    {
        "buf",
    },
    // vbe6_Shell
    {
        "command_line",
        "show_type",
    },
    // vbe6_StringConcat
    {
        "dst",
        "src1",
        "src2",
    },
    // GetFileVersionInfoExW
    {
        "flags",
        "filepath",
        "buffer",
    },
    // GetFileVersionInfoSizeExW
    {
        "flags",
        "filepath",
    },
    // GetFileVersionInfoSizeW
    {
        "filepath",
    },
    // GetFileVersionInfoW
    {
        "filepath",
        "buffer",
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
        "arg",
        "cmd",
    },
    // listen
    {
        "socket",
        "backlog",
    },
    // recv
    {
        "socket",
        "received",
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
    // pdf_unescape
    {
        "string",
    },
    // pdf_eval
    {
        "script",
    },
};

static hook_t g_hooks[] = {
    {
        "__wmi__",
        "IWbemServices_ExecMethod",
        (FARPROC) New___wmi___IWbemServices_ExecMethod,
        (FARPROC *) &Old___wmi___IWbemServices_ExecMethod,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        .addrcb = &hook_addrcb_IWbemServices_ExecMethod,
        
    },
    {
        "__wmi__",
        "IWbemServices_ExecMethodAsync",
        (FARPROC) New___wmi___IWbemServices_ExecMethodAsync,
        (FARPROC *) &Old___wmi___IWbemServices_ExecMethodAsync,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        .addrcb = &hook_addrcb_IWbemServices_ExecMethodAsync,
        
    },
    {
        "__wmi__",
        "IWbemServices_ExecQuery",
        (FARPROC) New___wmi___IWbemServices_ExecQuery,
        (FARPROC *) &Old___wmi___IWbemServices_ExecQuery,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        .addrcb = &hook_addrcb_IWbemServices_ExecQuery,
        
    },
    {
        "__wmi__",
        "IWbemServices_ExecQueryAsync",
        (FARPROC) New___wmi___IWbemServices_ExecQueryAsync,
        (FARPROC *) &Old___wmi___IWbemServices_ExecQueryAsync,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        .addrcb = &hook_addrcb_IWbemServices_ExecQueryAsync,
        
    },
    {
        "advapi32",
        "ControlService",
        (FARPROC) New_advapi32_ControlService,
        (FARPROC *) &Old_advapi32_ControlService,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CreateServiceA",
        (FARPROC) New_advapi32_CreateServiceA,
        (FARPROC *) &Old_advapi32_CreateServiceA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CreateServiceW",
        (FARPROC) New_advapi32_CreateServiceW,
        (FARPROC *) &Old_advapi32_CreateServiceW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptAcquireContextA",
        (FARPROC) New_advapi32_CryptAcquireContextA,
        (FARPROC *) &Old_advapi32_CryptAcquireContextA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptAcquireContextW",
        (FARPROC) New_advapi32_CryptAcquireContextW,
        (FARPROC *) &Old_advapi32_CryptAcquireContextW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptCreateHash",
        (FARPROC) New_advapi32_CryptCreateHash,
        (FARPROC *) &Old_advapi32_CryptCreateHash,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptDecrypt",
        (FARPROC) New_advapi32_CryptDecrypt,
        (FARPROC *) &Old_advapi32_CryptDecrypt,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptEncrypt",
        (FARPROC) New_advapi32_CryptEncrypt,
        (FARPROC *) &Old_advapi32_CryptEncrypt,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptExportKey",
        (FARPROC) New_advapi32_CryptExportKey,
        (FARPROC *) &Old_advapi32_CryptExportKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptGenKey",
        (FARPROC) New_advapi32_CryptGenKey,
        (FARPROC *) &Old_advapi32_CryptGenKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "CryptHashData",
        (FARPROC) New_advapi32_CryptHashData,
        (FARPROC *) &Old_advapi32_CryptHashData,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "DeleteService",
        (FARPROC) New_advapi32_DeleteService,
        (FARPROC *) &Old_advapi32_DeleteService,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "EnumServicesStatusA",
        (FARPROC) New_advapi32_EnumServicesStatusA,
        (FARPROC *) &Old_advapi32_EnumServicesStatusA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "EnumServicesStatusW",
        (FARPROC) New_advapi32_EnumServicesStatusW,
        (FARPROC *) &Old_advapi32_EnumServicesStatusW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "GetUserNameA",
        (FARPROC) New_advapi32_GetUserNameA,
        (FARPROC *) &Old_advapi32_GetUserNameA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "GetUserNameW",
        (FARPROC) New_advapi32_GetUserNameW,
        (FARPROC *) &Old_advapi32_GetUserNameW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "LookupAccountSidW",
        (FARPROC) New_advapi32_LookupAccountSidW,
        (FARPROC *) &Old_advapi32_LookupAccountSidW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "LookupPrivilegeValueW",
        (FARPROC) New_advapi32_LookupPrivilegeValueW,
        (FARPROC *) &Old_advapi32_LookupPrivilegeValueW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "NotifyBootConfigStatus",
        (FARPROC) New_advapi32_NotifyBootConfigStatus,
        (FARPROC *) &Old_advapi32_NotifyBootConfigStatus,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "OpenSCManagerA",
        (FARPROC) New_advapi32_OpenSCManagerA,
        (FARPROC *) &Old_advapi32_OpenSCManagerA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "OpenSCManagerW",
        (FARPROC) New_advapi32_OpenSCManagerW,
        (FARPROC *) &Old_advapi32_OpenSCManagerW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "OpenServiceA",
        (FARPROC) New_advapi32_OpenServiceA,
        (FARPROC *) &Old_advapi32_OpenServiceA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "OpenServiceW",
        (FARPROC) New_advapi32_OpenServiceW,
        (FARPROC *) &Old_advapi32_OpenServiceW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegCloseKey",
        (FARPROC) New_advapi32_RegCloseKey,
        (FARPROC *) &Old_advapi32_RegCloseKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegCreateKeyExA",
        (FARPROC) New_advapi32_RegCreateKeyExA,
        (FARPROC *) &Old_advapi32_RegCreateKeyExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegCreateKeyExW",
        (FARPROC) New_advapi32_RegCreateKeyExW,
        (FARPROC *) &Old_advapi32_RegCreateKeyExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegDeleteKeyA",
        (FARPROC) New_advapi32_RegDeleteKeyA,
        (FARPROC *) &Old_advapi32_RegDeleteKeyA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegDeleteKeyW",
        (FARPROC) New_advapi32_RegDeleteKeyW,
        (FARPROC *) &Old_advapi32_RegDeleteKeyW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegDeleteValueA",
        (FARPROC) New_advapi32_RegDeleteValueA,
        (FARPROC *) &Old_advapi32_RegDeleteValueA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegDeleteValueW",
        (FARPROC) New_advapi32_RegDeleteValueW,
        (FARPROC *) &Old_advapi32_RegDeleteValueW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegEnumKeyExA",
        (FARPROC) New_advapi32_RegEnumKeyExA,
        (FARPROC *) &Old_advapi32_RegEnumKeyExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegEnumKeyExW",
        (FARPROC) New_advapi32_RegEnumKeyExW,
        (FARPROC *) &Old_advapi32_RegEnumKeyExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegEnumKeyW",
        (FARPROC) New_advapi32_RegEnumKeyW,
        (FARPROC *) &Old_advapi32_RegEnumKeyW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegEnumValueA",
        (FARPROC) New_advapi32_RegEnumValueA,
        (FARPROC *) &Old_advapi32_RegEnumValueA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegEnumValueW",
        (FARPROC) New_advapi32_RegEnumValueW,
        (FARPROC *) &Old_advapi32_RegEnumValueW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegOpenKeyExA",
        (FARPROC) New_advapi32_RegOpenKeyExA,
        (FARPROC *) &Old_advapi32_RegOpenKeyExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegOpenKeyExW",
        (FARPROC) New_advapi32_RegOpenKeyExW,
        (FARPROC *) &Old_advapi32_RegOpenKeyExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegQueryInfoKeyA",
        (FARPROC) New_advapi32_RegQueryInfoKeyA,
        (FARPROC *) &Old_advapi32_RegQueryInfoKeyA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegQueryInfoKeyW",
        (FARPROC) New_advapi32_RegQueryInfoKeyW,
        (FARPROC *) &Old_advapi32_RegQueryInfoKeyW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegQueryValueExA",
        (FARPROC) New_advapi32_RegQueryValueExA,
        (FARPROC *) &Old_advapi32_RegQueryValueExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegQueryValueExW",
        (FARPROC) New_advapi32_RegQueryValueExW,
        (FARPROC *) &Old_advapi32_RegQueryValueExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegSetValueExA",
        (FARPROC) New_advapi32_RegSetValueExA,
        (FARPROC *) &Old_advapi32_RegSetValueExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "RegSetValueExW",
        (FARPROC) New_advapi32_RegSetValueExW,
        (FARPROC *) &Old_advapi32_RegSetValueExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "StartServiceA",
        (FARPROC) New_advapi32_StartServiceA,
        (FARPROC *) &Old_advapi32_StartServiceA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "StartServiceCtrlDispatcherW",
        (FARPROC) New_advapi32_StartServiceCtrlDispatcherW,
        (FARPROC *) &Old_advapi32_StartServiceCtrlDispatcherW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "advapi32",
        "StartServiceW",
        (FARPROC) New_advapi32_StartServiceW,
        (FARPROC *) &Old_advapi32_StartServiceW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "comctl32",
        "TaskDialog",
        (FARPROC) New_comctl32_TaskDialog,
        (FARPROC *) &Old_comctl32_TaskDialog,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CertControlStore",
        (FARPROC) New_crypt32_CertControlStore,
        (FARPROC *) &Old_crypt32_CertControlStore,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CertCreateCertificateContext",
        (FARPROC) New_crypt32_CertCreateCertificateContext,
        (FARPROC *) &Old_crypt32_CertCreateCertificateContext,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CertOpenStore",
        (FARPROC) New_crypt32_CertOpenStore,
        (FARPROC *) &Old_crypt32_CertOpenStore,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CertOpenSystemStoreA",
        (FARPROC) New_crypt32_CertOpenSystemStoreA,
        (FARPROC *) &Old_crypt32_CertOpenSystemStoreA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CertOpenSystemStoreW",
        (FARPROC) New_crypt32_CertOpenSystemStoreW,
        (FARPROC *) &Old_crypt32_CertOpenSystemStoreW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptDecodeMessage",
        (FARPROC) New_crypt32_CryptDecodeMessage,
        (FARPROC *) &Old_crypt32_CryptDecodeMessage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptDecodeObjectEx",
        (FARPROC) New_crypt32_CryptDecodeObjectEx,
        (FARPROC *) &Old_crypt32_CryptDecodeObjectEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptDecryptMessage",
        (FARPROC) New_crypt32_CryptDecryptMessage,
        (FARPROC *) &Old_crypt32_CryptDecryptMessage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptEncryptMessage",
        (FARPROC) New_crypt32_CryptEncryptMessage,
        (FARPROC *) &Old_crypt32_CryptEncryptMessage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptHashMessage",
        (FARPROC) New_crypt32_CryptHashMessage,
        (FARPROC *) &Old_crypt32_CryptHashMessage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptProtectData",
        (FARPROC) New_crypt32_CryptProtectData,
        (FARPROC *) &Old_crypt32_CryptProtectData,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptProtectMemory",
        (FARPROC) New_crypt32_CryptProtectMemory,
        (FARPROC *) &Old_crypt32_CryptProtectMemory,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptUnprotectData",
        (FARPROC) New_crypt32_CryptUnprotectData,
        (FARPROC *) &Old_crypt32_CryptUnprotectData,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "crypt32",
        "CryptUnprotectMemory",
        (FARPROC) New_crypt32_CryptUnprotectMemory,
        (FARPROC *) &Old_crypt32_CryptUnprotectMemory,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "dnsapi",
        "DnsQuery_A",
        (FARPROC) New_dnsapi_DnsQuery_A,
        (FARPROC *) &Old_dnsapi_DnsQuery_A,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "dnsapi",
        "DnsQuery_UTF8",
        (FARPROC) New_dnsapi_DnsQuery_UTF8,
        (FARPROC *) &Old_dnsapi_DnsQuery_UTF8,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "dnsapi",
        "DnsQuery_W",
        (FARPROC) New_dnsapi_DnsQuery_W,
        (FARPROC *) &Old_dnsapi_DnsQuery_W,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "iphlpapi",
        "GetAdaptersAddresses",
        (FARPROC) New_iphlpapi_GetAdaptersAddresses,
        (FARPROC *) &Old_iphlpapi_GetAdaptersAddresses,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "iphlpapi",
        "GetAdaptersInfo",
        (FARPROC) New_iphlpapi_GetAdaptersInfo,
        (FARPROC *) &Old_iphlpapi_GetAdaptersInfo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "iphlpapi",
        "GetBestInterfaceEx",
        (FARPROC) New_iphlpapi_GetBestInterfaceEx,
        (FARPROC *) &Old_iphlpapi_GetBestInterfaceEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "iphlpapi",
        "GetInterfaceInfo",
        (FARPROC) New_iphlpapi_GetInterfaceInfo,
        (FARPROC *) &Old_iphlpapi_GetInterfaceInfo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "jscript",
        "ActiveXObjectFncObj_Construct",
        (FARPROC) New_jscript_ActiveXObjectFncObj_Construct,
        (FARPROC *) &Old_jscript_ActiveXObjectFncObj_Construct,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_jscript,
    },
    {
        "jscript",
        "COleScript_Compile",
        (FARPROC) New_jscript_COleScript_Compile,
        (FARPROC *) &Old_jscript_COleScript_Compile,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_jscript,
    },
    {
        "kernel32",
        "AssignProcessToJobObject",
        (FARPROC) New_kernel32_AssignProcessToJobObject,
        (FARPROC *) &Old_kernel32_AssignProcessToJobObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CopyFileA",
        (FARPROC) New_kernel32_CopyFileA,
        (FARPROC *) &Old_kernel32_CopyFileA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CopyFileExW",
        (FARPROC) New_kernel32_CopyFileExW,
        (FARPROC *) &Old_kernel32_CopyFileExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CopyFileW",
        (FARPROC) New_kernel32_CopyFileW,
        (FARPROC *) &Old_kernel32_CopyFileW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateActCtxW",
        (FARPROC) New_kernel32_CreateActCtxW,
        (FARPROC *) &Old_kernel32_CreateActCtxW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateDirectoryExW",
        (FARPROC) New_kernel32_CreateDirectoryExW,
        (FARPROC *) &Old_kernel32_CreateDirectoryExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateDirectoryW",
        (FARPROC) New_kernel32_CreateDirectoryW,
        (FARPROC *) &Old_kernel32_CreateDirectoryW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateJobObjectW",
        (FARPROC) New_kernel32_CreateJobObjectW,
        (FARPROC *) &Old_kernel32_CreateJobObjectW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateProcessInternalW",
        (FARPROC) New_kernel32_CreateProcessInternalW,
        (FARPROC *) &Old_kernel32_CreateProcessInternalW,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateRemoteThread",
        (FARPROC) New_kernel32_CreateRemoteThread,
        (FARPROC *) &Old_kernel32_CreateRemoteThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateRemoteThreadEx",
        (FARPROC) New_kernel32_CreateRemoteThreadEx,
        (FARPROC *) &Old_kernel32_CreateRemoteThreadEx,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateThread",
        (FARPROC) New_kernel32_CreateThread,
        (FARPROC *) &Old_kernel32_CreateThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "CreateToolhelp32Snapshot",
        (FARPROC) New_kernel32_CreateToolhelp32Snapshot,
        (FARPROC *) &Old_kernel32_CreateToolhelp32Snapshot,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "DeleteFileW",
        (FARPROC) New_kernel32_DeleteFileW,
        (FARPROC *) &Old_kernel32_DeleteFileW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "DeviceIoControl",
        (FARPROC) New_kernel32_DeviceIoControl,
        (FARPROC *) &Old_kernel32_DeviceIoControl,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "FindFirstFileExA",
        (FARPROC) New_kernel32_FindFirstFileExA,
        (FARPROC *) &Old_kernel32_FindFirstFileExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "FindFirstFileExW",
        (FARPROC) New_kernel32_FindFirstFileExW,
        (FARPROC *) &Old_kernel32_FindFirstFileExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "FindResourceA",
        (FARPROC) New_kernel32_FindResourceA,
        (FARPROC *) &Old_kernel32_FindResourceA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "FindResourceExA",
        (FARPROC) New_kernel32_FindResourceExA,
        (FARPROC *) &Old_kernel32_FindResourceExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "FindResourceExW",
        (FARPROC) New_kernel32_FindResourceExW,
        (FARPROC *) &Old_kernel32_FindResourceExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "FindResourceW",
        (FARPROC) New_kernel32_FindResourceW,
        (FARPROC *) &Old_kernel32_FindResourceW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetComputerNameA",
        (FARPROC) New_kernel32_GetComputerNameA,
        (FARPROC *) &Old_kernel32_GetComputerNameA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetComputerNameW",
        (FARPROC) New_kernel32_GetComputerNameW,
        (FARPROC *) &Old_kernel32_GetComputerNameW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetDiskFreeSpaceExW",
        (FARPROC) New_kernel32_GetDiskFreeSpaceExW,
        (FARPROC *) &Old_kernel32_GetDiskFreeSpaceExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetDiskFreeSpaceW",
        (FARPROC) New_kernel32_GetDiskFreeSpaceW,
        (FARPROC *) &Old_kernel32_GetDiskFreeSpaceW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileAttributesExW",
        (FARPROC) New_kernel32_GetFileAttributesExW,
        (FARPROC *) &Old_kernel32_GetFileAttributesExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileAttributesW",
        (FARPROC) New_kernel32_GetFileAttributesW,
        (FARPROC *) &Old_kernel32_GetFileAttributesW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileInformationByHandle",
        (FARPROC) New_kernel32_GetFileInformationByHandle,
        (FARPROC *) &Old_kernel32_GetFileInformationByHandle,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileInformationByHandleEx",
        (FARPROC) New_kernel32_GetFileInformationByHandleEx,
        (FARPROC *) &Old_kernel32_GetFileInformationByHandleEx,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileSize",
        (FARPROC) New_kernel32_GetFileSize,
        (FARPROC *) &Old_kernel32_GetFileSize,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileSizeEx",
        (FARPROC) New_kernel32_GetFileSizeEx,
        (FARPROC *) &Old_kernel32_GetFileSizeEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetFileType",
        (FARPROC) New_kernel32_GetFileType,
        (FARPROC *) &Old_kernel32_GetFileType,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetLocalTime",
        (FARPROC) New_kernel32_GetLocalTime,
        (FARPROC *) &Old_kernel32_GetLocalTime,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetNativeSystemInfo",
        (FARPROC) New_kernel32_GetNativeSystemInfo,
        (FARPROC *) &Old_kernel32_GetNativeSystemInfo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetShortPathNameW",
        (FARPROC) New_kernel32_GetShortPathNameW,
        (FARPROC *) &Old_kernel32_GetShortPathNameW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemDirectoryA",
        (FARPROC) New_kernel32_GetSystemDirectoryA,
        (FARPROC *) &Old_kernel32_GetSystemDirectoryA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemDirectoryW",
        (FARPROC) New_kernel32_GetSystemDirectoryW,
        (FARPROC *) &Old_kernel32_GetSystemDirectoryW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemInfo",
        (FARPROC) New_kernel32_GetSystemInfo,
        (FARPROC *) &Old_kernel32_GetSystemInfo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemTime",
        (FARPROC) New_kernel32_GetSystemTime,
        (FARPROC *) &Old_kernel32_GetSystemTime,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemTimeAsFileTime",
        (FARPROC) New_kernel32_GetSystemTimeAsFileTime,
        (FARPROC *) &Old_kernel32_GetSystemTimeAsFileTime,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemWindowsDirectoryA",
        (FARPROC) New_kernel32_GetSystemWindowsDirectoryA,
        (FARPROC *) &Old_kernel32_GetSystemWindowsDirectoryA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetSystemWindowsDirectoryW",
        (FARPROC) New_kernel32_GetSystemWindowsDirectoryW,
        (FARPROC *) &Old_kernel32_GetSystemWindowsDirectoryW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetTempPathW",
        (FARPROC) New_kernel32_GetTempPathW,
        (FARPROC *) &Old_kernel32_GetTempPathW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetTickCount",
        (FARPROC) New_kernel32_GetTickCount,
        (FARPROC *) &Old_kernel32_GetTickCount,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetTimeZoneInformation",
        (FARPROC) New_kernel32_GetTimeZoneInformation,
        (FARPROC *) &Old_kernel32_GetTimeZoneInformation,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetVolumeNameForVolumeMountPointW",
        (FARPROC) New_kernel32_GetVolumeNameForVolumeMountPointW,
        (FARPROC *) &Old_kernel32_GetVolumeNameForVolumeMountPointW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetVolumePathNameW",
        (FARPROC) New_kernel32_GetVolumePathNameW,
        (FARPROC *) &Old_kernel32_GetVolumePathNameW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GetVolumePathNamesForVolumeNameW",
        (FARPROC) New_kernel32_GetVolumePathNamesForVolumeNameW,
        (FARPROC *) &Old_kernel32_GetVolumePathNamesForVolumeNameW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GlobalMemoryStatus",
        (FARPROC) New_kernel32_GlobalMemoryStatus,
        (FARPROC *) &Old_kernel32_GlobalMemoryStatus,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "GlobalMemoryStatusEx",
        (FARPROC) New_kernel32_GlobalMemoryStatusEx,
        (FARPROC *) &Old_kernel32_GlobalMemoryStatusEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "IsDebuggerPresent",
        (FARPROC) New_kernel32_IsDebuggerPresent,
        (FARPROC *) &Old_kernel32_IsDebuggerPresent,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "LoadResource",
        (FARPROC) New_kernel32_LoadResource,
        (FARPROC *) &Old_kernel32_LoadResource,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "Module32FirstW",
        (FARPROC) New_kernel32_Module32FirstW,
        (FARPROC *) &Old_kernel32_Module32FirstW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "Module32NextW",
        (FARPROC) New_kernel32_Module32NextW,
        (FARPROC *) &Old_kernel32_Module32NextW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "MoveFileWithProgressW",
        (FARPROC) New_kernel32_MoveFileWithProgressW,
        (FARPROC *) &Old_kernel32_MoveFileWithProgressW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "OutputDebugStringA",
        (FARPROC) New_kernel32_OutputDebugStringA,
        (FARPROC *) &Old_kernel32_OutputDebugStringA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "Process32FirstW",
        (FARPROC) New_kernel32_Process32FirstW,
        (FARPROC *) &Old_kernel32_Process32FirstW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "Process32NextW",
        (FARPROC) New_kernel32_Process32NextW,
        (FARPROC *) &Old_kernel32_Process32NextW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "ReadProcessMemory",
        (FARPROC) New_kernel32_ReadProcessMemory,
        (FARPROC *) &Old_kernel32_ReadProcessMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "RemoveDirectoryA",
        (FARPROC) New_kernel32_RemoveDirectoryA,
        (FARPROC *) &Old_kernel32_RemoveDirectoryA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "RemoveDirectoryW",
        (FARPROC) New_kernel32_RemoveDirectoryW,
        (FARPROC *) &Old_kernel32_RemoveDirectoryW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SearchPathW",
        (FARPROC) New_kernel32_SearchPathW,
        (FARPROC *) &Old_kernel32_SearchPathW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetEndOfFile",
        (FARPROC) New_kernel32_SetEndOfFile,
        (FARPROC *) &Old_kernel32_SetEndOfFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetErrorMode",
        (FARPROC) New_kernel32_SetErrorMode,
        (FARPROC *) &Old_kernel32_SetErrorMode,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetFileAttributesW",
        (FARPROC) New_kernel32_SetFileAttributesW,
        (FARPROC *) &Old_kernel32_SetFileAttributesW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetFileInformationByHandle",
        (FARPROC) New_kernel32_SetFileInformationByHandle,
        (FARPROC *) &Old_kernel32_SetFileInformationByHandle,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetFilePointer",
        (FARPROC) New_kernel32_SetFilePointer,
        (FARPROC *) &Old_kernel32_SetFilePointer,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetFilePointerEx",
        (FARPROC) New_kernel32_SetFilePointerEx,
        (FARPROC *) &Old_kernel32_SetFilePointerEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetFileTime",
        (FARPROC) New_kernel32_SetFileTime,
        (FARPROC *) &Old_kernel32_SetFileTime,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetInformationJobObject",
        (FARPROC) New_kernel32_SetInformationJobObject,
        (FARPROC *) &Old_kernel32_SetInformationJobObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SetUnhandledExceptionFilter",
        (FARPROC) New_kernel32_SetUnhandledExceptionFilter,
        (FARPROC *) &Old_kernel32_SetUnhandledExceptionFilter,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "SizeofResource",
        (FARPROC) New_kernel32_SizeofResource,
        (FARPROC *) &Old_kernel32_SizeofResource,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "Thread32First",
        (FARPROC) New_kernel32_Thread32First,
        (FARPROC *) &Old_kernel32_Thread32First,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "Thread32Next",
        (FARPROC) New_kernel32_Thread32Next,
        (FARPROC *) &Old_kernel32_Thread32Next,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "WriteConsoleA",
        (FARPROC) New_kernel32_WriteConsoleA,
        (FARPROC *) &Old_kernel32_WriteConsoleA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "WriteConsoleW",
        (FARPROC) New_kernel32_WriteConsoleW,
        (FARPROC *) &Old_kernel32_WriteConsoleW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "kernel32",
        "WriteProcessMemory",
        (FARPROC) New_kernel32_WriteProcessMemory,
        (FARPROC *) &Old_kernel32_WriteProcessMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "mpr",
        "WNetGetProviderNameW",
        (FARPROC) New_mpr_WNetGetProviderNameW,
        (FARPROC *) &Old_mpr_WNetGetProviderNameW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "mshtml",
        "CDocument_write",
        (FARPROC) New_mshtml_CDocument_write,
        (FARPROC *) &Old_mshtml_CDocument_write,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "mshtml",
        "CElement_put_innerHTML",
        (FARPROC) New_mshtml_CElement_put_innerHTML,
        (FARPROC *) &Old_mshtml_CElement_put_innerHTML,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "mshtml",
        "CHyperlink_SetUrlComponent",
        (FARPROC) New_mshtml_CHyperlink_SetUrlComponent,
        (FARPROC *) &Old_mshtml_CHyperlink_SetUrlComponent,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "mshtml",
        "CIFrameElement_CreateElement",
        (FARPROC) New_mshtml_CIFrameElement_CreateElement,
        (FARPROC *) &Old_mshtml_CIFrameElement_CreateElement,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "mshtml",
        "CImgElement_put_src",
        (FARPROC) New_mshtml_CImgElement_put_src,
        (FARPROC *) &Old_mshtml_CImgElement_put_src,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "mshtml",
        "CScriptElement_put_src",
        (FARPROC) New_mshtml_CScriptElement_put_src,
        (FARPROC *) &Old_mshtml_CScriptElement_put_src,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "mshtml",
        "CWindow_AddTimeoutCode",
        (FARPROC) New_mshtml_CWindow_AddTimeoutCode,
        (FARPROC *) &Old_mshtml_CWindow_AddTimeoutCode,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_IEXPLORE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_mshtml,
    },
    {
        "msvcrt",
        "system",
        (FARPROC) New_msvcrt_system,
        (FARPROC *) &Old_msvcrt_system,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ncrypt",
        "PRF",
        (FARPROC) New_ncrypt_PRF,
        (FARPROC *) &Old_ncrypt_PRF,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_DUMPTLS,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_ncrypt,
    },
    {
        "ncrypt",
        "Ssl3GenerateKeyMaterial",
        (FARPROC) New_ncrypt_Ssl3GenerateKeyMaterial,
        (FARPROC *) &Old_ncrypt_Ssl3GenerateKeyMaterial,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_DUMPTLS,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_ncrypt,
    },
    {
        "netapi32",
        "NetGetJoinInformation",
        (FARPROC) New_netapi32_NetGetJoinInformation,
        (FARPROC *) &Old_netapi32_NetGetJoinInformation,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "netapi32",
        "NetShareEnum",
        (FARPROC) New_netapi32_NetShareEnum,
        (FARPROC *) &Old_netapi32_NetShareEnum,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "netapi32",
        "NetUserGetInfo",
        (FARPROC) New_netapi32_NetUserGetInfo,
        (FARPROC *) &Old_netapi32_NetUserGetInfo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "netapi32",
        "NetUserGetLocalGroups",
        (FARPROC) New_netapi32_NetUserGetLocalGroups,
        (FARPROC *) &Old_netapi32_NetUserGetLocalGroups,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "LdrGetDllHandle",
        (FARPROC) New_ntdll_LdrGetDllHandle,
        (FARPROC *) &Old_ntdll_LdrGetDllHandle,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "LdrGetProcedureAddress",
        (FARPROC) New_ntdll_LdrGetProcedureAddress,
        (FARPROC *) &Old_ntdll_LdrGetProcedureAddress,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "LdrLoadDll",
        (FARPROC) New_ntdll_LdrLoadDll,
        (FARPROC *) &Old_ntdll_LdrLoadDll,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        .initcb = &hook_initcb_LdrLoadDll,
        
        
    },
    {
        "ntdll",
        "LdrUnloadDll",
        (FARPROC) New_ntdll_LdrUnloadDll,
        (FARPROC *) &Old_ntdll_LdrUnloadDll,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtAllocateVirtualMemory",
        (FARPROC) New_ntdll_NtAllocateVirtualMemory,
        (FARPROC *) &Old_ntdll_NtAllocateVirtualMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtClose",
        (FARPROC) New_ntdll_NtClose,
        (FARPROC *) &Old_ntdll_NtClose,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateDirectoryObject",
        (FARPROC) New_ntdll_NtCreateDirectoryObject,
        (FARPROC *) &Old_ntdll_NtCreateDirectoryObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateFile",
        (FARPROC) New_ntdll_NtCreateFile,
        (FARPROC *) &Old_ntdll_NtCreateFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateKey",
        (FARPROC) New_ntdll_NtCreateKey,
        (FARPROC *) &Old_ntdll_NtCreateKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateMutant",
        (FARPROC) New_ntdll_NtCreateMutant,
        (FARPROC *) &Old_ntdll_NtCreateMutant,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateProcess",
        (FARPROC) New_ntdll_NtCreateProcess,
        (FARPROC *) &Old_ntdll_NtCreateProcess,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateProcessEx",
        (FARPROC) New_ntdll_NtCreateProcessEx,
        (FARPROC *) &Old_ntdll_NtCreateProcessEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateSection",
        (FARPROC) New_ntdll_NtCreateSection,
        (FARPROC *) &Old_ntdll_NtCreateSection,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateThread",
        (FARPROC) New_ntdll_NtCreateThread,
        (FARPROC *) &Old_ntdll_NtCreateThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateThreadEx",
        (FARPROC) New_ntdll_NtCreateThreadEx,
        (FARPROC *) &Old_ntdll_NtCreateThreadEx,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtCreateUserProcess",
        (FARPROC) New_ntdll_NtCreateUserProcess,
        (FARPROC *) &Old_ntdll_NtCreateUserProcess,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtDelayExecution",
        (FARPROC) New_ntdll_NtDelayExecution,
        (FARPROC *) &Old_ntdll_NtDelayExecution,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtDeleteFile",
        (FARPROC) New_ntdll_NtDeleteFile,
        (FARPROC *) &Old_ntdll_NtDeleteFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtDeleteKey",
        (FARPROC) New_ntdll_NtDeleteKey,
        (FARPROC *) &Old_ntdll_NtDeleteKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtDeleteValueKey",
        (FARPROC) New_ntdll_NtDeleteValueKey,
        (FARPROC *) &Old_ntdll_NtDeleteValueKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtDeviceIoControlFile",
        (FARPROC) New_ntdll_NtDeviceIoControlFile,
        (FARPROC *) &Old_ntdll_NtDeviceIoControlFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtDuplicateObject",
        (FARPROC) New_ntdll_NtDuplicateObject,
        (FARPROC *) &Old_ntdll_NtDuplicateObject,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtEnumerateKey",
        (FARPROC) New_ntdll_NtEnumerateKey,
        (FARPROC *) &Old_ntdll_NtEnumerateKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtEnumerateValueKey",
        (FARPROC) New_ntdll_NtEnumerateValueKey,
        (FARPROC *) &Old_ntdll_NtEnumerateValueKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtFreeVirtualMemory",
        (FARPROC) New_ntdll_NtFreeVirtualMemory,
        (FARPROC *) &Old_ntdll_NtFreeVirtualMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtGetContextThread",
        (FARPROC) New_ntdll_NtGetContextThread,
        (FARPROC *) &Old_ntdll_NtGetContextThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtLoadDriver",
        (FARPROC) New_ntdll_NtLoadDriver,
        (FARPROC *) &Old_ntdll_NtLoadDriver,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtLoadKey",
        (FARPROC) New_ntdll_NtLoadKey,
        (FARPROC *) &Old_ntdll_NtLoadKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtLoadKey2",
        (FARPROC) New_ntdll_NtLoadKey2,
        (FARPROC *) &Old_ntdll_NtLoadKey2,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtLoadKeyEx",
        (FARPROC) New_ntdll_NtLoadKeyEx,
        (FARPROC *) &Old_ntdll_NtLoadKeyEx,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtMakePermanentObject",
        (FARPROC) New_ntdll_NtMakePermanentObject,
        (FARPROC *) &Old_ntdll_NtMakePermanentObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtMakeTemporaryObject",
        (FARPROC) New_ntdll_NtMakeTemporaryObject,
        (FARPROC *) &Old_ntdll_NtMakeTemporaryObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtMapViewOfSection",
        (FARPROC) New_ntdll_NtMapViewOfSection,
        (FARPROC *) &Old_ntdll_NtMapViewOfSection,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenDirectoryObject",
        (FARPROC) New_ntdll_NtOpenDirectoryObject,
        (FARPROC *) &Old_ntdll_NtOpenDirectoryObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenFile",
        (FARPROC) New_ntdll_NtOpenFile,
        (FARPROC *) &Old_ntdll_NtOpenFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenKey",
        (FARPROC) New_ntdll_NtOpenKey,
        (FARPROC *) &Old_ntdll_NtOpenKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenKeyEx",
        (FARPROC) New_ntdll_NtOpenKeyEx,
        (FARPROC *) &Old_ntdll_NtOpenKeyEx,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenMutant",
        (FARPROC) New_ntdll_NtOpenMutant,
        (FARPROC *) &Old_ntdll_NtOpenMutant,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenProcess",
        (FARPROC) New_ntdll_NtOpenProcess,
        (FARPROC *) &Old_ntdll_NtOpenProcess,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenSection",
        (FARPROC) New_ntdll_NtOpenSection,
        (FARPROC *) &Old_ntdll_NtOpenSection,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtOpenThread",
        (FARPROC) New_ntdll_NtOpenThread,
        (FARPROC *) &Old_ntdll_NtOpenThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtProtectVirtualMemory",
        (FARPROC) New_ntdll_NtProtectVirtualMemory,
        (FARPROC *) &Old_ntdll_NtProtectVirtualMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryAttributesFile",
        (FARPROC) New_ntdll_NtQueryAttributesFile,
        (FARPROC *) &Old_ntdll_NtQueryAttributesFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryDirectoryFile",
        (FARPROC) New_ntdll_NtQueryDirectoryFile,
        (FARPROC *) &Old_ntdll_NtQueryDirectoryFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryFullAttributesFile",
        (FARPROC) New_ntdll_NtQueryFullAttributesFile,
        (FARPROC *) &Old_ntdll_NtQueryFullAttributesFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryInformationFile",
        (FARPROC) New_ntdll_NtQueryInformationFile,
        (FARPROC *) &Old_ntdll_NtQueryInformationFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryKey",
        (FARPROC) New_ntdll_NtQueryKey,
        (FARPROC *) &Old_ntdll_NtQueryKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryMultipleValueKey",
        (FARPROC) New_ntdll_NtQueryMultipleValueKey,
        (FARPROC *) &Old_ntdll_NtQueryMultipleValueKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQuerySystemInformation",
        (FARPROC) New_ntdll_NtQuerySystemInformation,
        (FARPROC *) &Old_ntdll_NtQuerySystemInformation,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQuerySystemTime",
        (FARPROC) New_ntdll_NtQuerySystemTime,
        (FARPROC *) &Old_ntdll_NtQuerySystemTime,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueryValueKey",
        (FARPROC) New_ntdll_NtQueryValueKey,
        (FARPROC *) &Old_ntdll_NtQueryValueKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtQueueApcThread",
        (FARPROC) New_ntdll_NtQueueApcThread,
        (FARPROC *) &Old_ntdll_NtQueueApcThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtReadFile",
        (FARPROC) New_ntdll_NtReadFile,
        (FARPROC *) &Old_ntdll_NtReadFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtReadVirtualMemory",
        (FARPROC) New_ntdll_NtReadVirtualMemory,
        (FARPROC *) &Old_ntdll_NtReadVirtualMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtRenameKey",
        (FARPROC) New_ntdll_NtRenameKey,
        (FARPROC *) &Old_ntdll_NtRenameKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtReplaceKey",
        (FARPROC) New_ntdll_NtReplaceKey,
        (FARPROC *) &Old_ntdll_NtReplaceKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtResumeThread",
        (FARPROC) New_ntdll_NtResumeThread,
        (FARPROC *) &Old_ntdll_NtResumeThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtSaveKey",
        (FARPROC) New_ntdll_NtSaveKey,
        (FARPROC *) &Old_ntdll_NtSaveKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtSaveKeyEx",
        (FARPROC) New_ntdll_NtSaveKeyEx,
        (FARPROC *) &Old_ntdll_NtSaveKeyEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtSetContextThread",
        (FARPROC) New_ntdll_NtSetContextThread,
        (FARPROC *) &Old_ntdll_NtSetContextThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtSetInformationFile",
        (FARPROC) New_ntdll_NtSetInformationFile,
        (FARPROC *) &Old_ntdll_NtSetInformationFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtSetValueKey",
        (FARPROC) New_ntdll_NtSetValueKey,
        (FARPROC *) &Old_ntdll_NtSetValueKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtShutdownSystem",
        (FARPROC) New_ntdll_NtShutdownSystem,
        (FARPROC *) &Old_ntdll_NtShutdownSystem,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtSuspendThread",
        (FARPROC) New_ntdll_NtSuspendThread,
        (FARPROC *) &Old_ntdll_NtSuspendThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtTerminateProcess",
        (FARPROC) New_ntdll_NtTerminateProcess,
        (FARPROC *) &Old_ntdll_NtTerminateProcess,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtTerminateThread",
        (FARPROC) New_ntdll_NtTerminateThread,
        (FARPROC *) &Old_ntdll_NtTerminateThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtUnloadDriver",
        (FARPROC) New_ntdll_NtUnloadDriver,
        (FARPROC *) &Old_ntdll_NtUnloadDriver,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtUnmapViewOfSection",
        (FARPROC) New_ntdll_NtUnmapViewOfSection,
        (FARPROC *) &Old_ntdll_NtUnmapViewOfSection,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtWriteFile",
        (FARPROC) New_ntdll_NtWriteFile,
        (FARPROC *) &Old_ntdll_NtWriteFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "NtWriteVirtualMemory",
        (FARPROC) New_ntdll_NtWriteVirtualMemory,
        (FARPROC *) &Old_ntdll_NtWriteVirtualMemory,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlAddVectoredContinueHandler",
        (FARPROC) New_ntdll_RtlAddVectoredContinueHandler,
        (FARPROC *) &Old_ntdll_RtlAddVectoredContinueHandler,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlAddVectoredExceptionHandler",
        (FARPROC) New_ntdll_RtlAddVectoredExceptionHandler,
        (FARPROC *) &Old_ntdll_RtlAddVectoredExceptionHandler,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlCompressBuffer",
        (FARPROC) New_ntdll_RtlCompressBuffer,
        (FARPROC *) &Old_ntdll_RtlCompressBuffer,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlCreateUserProcess",
        (FARPROC) New_ntdll_RtlCreateUserProcess,
        (FARPROC *) &Old_ntdll_RtlCreateUserProcess,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlCreateUserThread",
        (FARPROC) New_ntdll_RtlCreateUserThread,
        (FARPROC *) &Old_ntdll_RtlCreateUserThread,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlDecompressBuffer",
        (FARPROC) New_ntdll_RtlDecompressBuffer,
        (FARPROC *) &Old_ntdll_RtlDecompressBuffer,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlDecompressFragment",
        (FARPROC) New_ntdll_RtlDecompressFragment,
        (FARPROC *) &Old_ntdll_RtlDecompressFragment,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlDispatchException",
        (FARPROC) New_ntdll_RtlDispatchException,
        (FARPROC *) &Old_ntdll_RtlDispatchException,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        .addrcb = &hook_addrcb_RtlDispatchException,
        
    },
    {
        "ntdll",
        "RtlRemoveVectoredContinueHandler",
        (FARPROC) New_ntdll_RtlRemoveVectoredContinueHandler,
        (FARPROC *) &Old_ntdll_RtlRemoveVectoredContinueHandler,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ntdll",
        "RtlRemoveVectoredExceptionHandler",
        (FARPROC) New_ntdll_RtlRemoveVectoredExceptionHandler,
        (FARPROC *) &Old_ntdll_RtlRemoveVectoredExceptionHandler,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "CoCreateInstance",
        (FARPROC) New_ole32_CoCreateInstance,
        (FARPROC *) &Old_ole32_CoCreateInstance,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "CoCreateInstanceEx",
        (FARPROC) New_ole32_CoCreateInstanceEx,
        (FARPROC *) &Old_ole32_CoCreateInstanceEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "CoGetClassObject",
        (FARPROC) New_ole32_CoGetClassObject,
        (FARPROC *) &Old_ole32_CoGetClassObject,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "CoInitializeEx",
        (FARPROC) New_ole32_CoInitializeEx,
        (FARPROC *) &Old_ole32_CoInitializeEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "CoInitializeSecurity",
        (FARPROC) New_ole32_CoInitializeSecurity,
        (FARPROC *) &Old_ole32_CoInitializeSecurity,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "CoUninitialize",
        (FARPROC) New_ole32_CoUninitialize,
        (FARPROC *) &Old_ole32_CoUninitialize,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "OleConvertOLESTREAMToIStorage",
        (FARPROC) New_ole32_OleConvertOLESTREAMToIStorage,
        (FARPROC *) &Old_ole32_OleConvertOLESTREAMToIStorage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "ole32",
        "OleInitialize",
        (FARPROC) New_ole32_OleInitialize,
        (FARPROC *) &Old_ole32_OleInitialize,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "rpcrt4",
        "UuidCreate",
        (FARPROC) New_rpcrt4_UuidCreate,
        (FARPROC *) &Old_rpcrt4_UuidCreate,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "secur32",
        "DecryptMessage",
        (FARPROC) New_secur32_DecryptMessage,
        (FARPROC *) &Old_secur32_DecryptMessage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "secur32",
        "EncryptMessage",
        (FARPROC) New_secur32_EncryptMessage,
        (FARPROC *) &Old_secur32_EncryptMessage,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "secur32",
        "GetUserNameExA",
        (FARPROC) New_secur32_GetUserNameExA,
        (FARPROC *) &Old_secur32_GetUserNameExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "secur32",
        "GetUserNameExW",
        (FARPROC) New_secur32_GetUserNameExW,
        (FARPROC *) &Old_secur32_GetUserNameExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "shell32",
        "ReadCabinetState",
        (FARPROC) New_shell32_ReadCabinetState,
        (FARPROC *) &Old_shell32_ReadCabinetState,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "shell32",
        "SHGetFolderPathW",
        (FARPROC) New_shell32_SHGetFolderPathW,
        (FARPROC *) &Old_shell32_SHGetFolderPathW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "shell32",
        "SHGetSpecialFolderLocation",
        (FARPROC) New_shell32_SHGetSpecialFolderLocation,
        (FARPROC *) &Old_shell32_SHGetSpecialFolderLocation,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "shell32",
        "ShellExecuteExW",
        (FARPROC) New_shell32_ShellExecuteExW,
        (FARPROC *) &Old_shell32_ShellExecuteExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_EXPLOIT,
        .insn = 0,
        
        
        
    },
    {
        "srvcli",
        "NetShareEnum",
        (FARPROC) New_srvcli_NetShareEnum,
        (FARPROC *) &Old_srvcli_NetShareEnum,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "urlmon",
        "ObtainUserAgentString",
        (FARPROC) New_urlmon_ObtainUserAgentString,
        (FARPROC *) &Old_urlmon_ObtainUserAgentString,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "urlmon",
        "URLDownloadToFileW",
        (FARPROC) New_urlmon_URLDownloadToFileW,
        (FARPROC *) &Old_urlmon_URLDownloadToFileW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "DrawTextExA",
        (FARPROC) New_user32_DrawTextExA,
        (FARPROC *) &Old_user32_DrawTextExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "DrawTextExW",
        (FARPROC) New_user32_DrawTextExW,
        (FARPROC *) &Old_user32_DrawTextExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "EnumWindows",
        (FARPROC) New_user32_EnumWindows,
        (FARPROC *) &Old_user32_EnumWindows,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "ExitWindowsEx",
        (FARPROC) New_user32_ExitWindowsEx,
        (FARPROC *) &Old_user32_ExitWindowsEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "FindWindowA",
        (FARPROC) New_user32_FindWindowA,
        (FARPROC *) &Old_user32_FindWindowA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "FindWindowExA",
        (FARPROC) New_user32_FindWindowExA,
        (FARPROC *) &Old_user32_FindWindowExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "FindWindowExW",
        (FARPROC) New_user32_FindWindowExW,
        (FARPROC *) &Old_user32_FindWindowExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "FindWindowW",
        (FARPROC) New_user32_FindWindowW,
        (FARPROC *) &Old_user32_FindWindowW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "GetAsyncKeyState",
        (FARPROC) New_user32_GetAsyncKeyState,
        (FARPROC *) &Old_user32_GetAsyncKeyState,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "GetCursorPos",
        (FARPROC) New_user32_GetCursorPos,
        (FARPROC *) &Old_user32_GetCursorPos,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "GetForegroundWindow",
        (FARPROC) New_user32_GetForegroundWindow,
        (FARPROC *) &Old_user32_GetForegroundWindow,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "GetKeyState",
        (FARPROC) New_user32_GetKeyState,
        (FARPROC *) &Old_user32_GetKeyState,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "GetKeyboardState",
        (FARPROC) New_user32_GetKeyboardState,
        (FARPROC *) &Old_user32_GetKeyboardState,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "GetSystemMetrics",
        (FARPROC) New_user32_GetSystemMetrics,
        (FARPROC *) &Old_user32_GetSystemMetrics,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "LoadStringA",
        (FARPROC) New_user32_LoadStringA,
        (FARPROC *) &Old_user32_LoadStringA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "LoadStringW",
        (FARPROC) New_user32_LoadStringW,
        (FARPROC *) &Old_user32_LoadStringW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "MessageBoxTimeoutA",
        (FARPROC) New_user32_MessageBoxTimeoutA,
        (FARPROC *) &Old_user32_MessageBoxTimeoutA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "MessageBoxTimeoutW",
        (FARPROC) New_user32_MessageBoxTimeoutW,
        (FARPROC *) &Old_user32_MessageBoxTimeoutW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "RegisterHotKey",
        (FARPROC) New_user32_RegisterHotKey,
        (FARPROC *) &Old_user32_RegisterHotKey,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "SendNotifyMessageA",
        (FARPROC) New_user32_SendNotifyMessageA,
        (FARPROC *) &Old_user32_SendNotifyMessageA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "SendNotifyMessageW",
        (FARPROC) New_user32_SendNotifyMessageW,
        (FARPROC *) &Old_user32_SendNotifyMessageW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "SetWindowsHookExA",
        (FARPROC) New_user32_SetWindowsHookExA,
        (FARPROC *) &Old_user32_SetWindowsHookExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "SetWindowsHookExW",
        (FARPROC) New_user32_SetWindowsHookExW,
        (FARPROC *) &Old_user32_SetWindowsHookExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "user32",
        "UnhookWindowsHookEx",
        (FARPROC) New_user32_UnhookWindowsHookEx,
        (FARPROC *) &Old_user32_UnhookWindowsHookEx,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "vbe6",
        "vbe6_CallByName",
        (FARPROC) New_vbe6_vbe6_CallByName,
        (FARPROC *) &Old_vbe6_vbe6_CallByName,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_Close",
        (FARPROC) New_vbe6_vbe6_Close,
        (FARPROC *) &Old_vbe6_vbe6_Close,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_CreateObject",
        (FARPROC) New_vbe6_vbe6_CreateObject,
        (FARPROC *) &Old_vbe6_vbe6_CreateObject,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_GetIDFromName",
        (FARPROC) New_vbe6_vbe6_GetIDFromName,
        (FARPROC *) &Old_vbe6_vbe6_GetIDFromName,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_GetObject",
        (FARPROC) New_vbe6_vbe6_GetObject,
        (FARPROC *) &Old_vbe6_vbe6_GetObject,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_Import",
        (FARPROC) New_vbe6_vbe6_Import,
        (FARPROC *) &Old_vbe6_vbe6_Import,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_Invoke",
        (FARPROC) New_vbe6_vbe6_Invoke,
        (FARPROC *) &Old_vbe6_vbe6_Invoke,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_Open",
        (FARPROC) New_vbe6_vbe6_Open,
        (FARPROC *) &Old_vbe6_vbe6_Open,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_Print",
        (FARPROC) New_vbe6_vbe6_Print,
        (FARPROC *) &Old_vbe6_vbe6_Print,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_Shell",
        (FARPROC) New_vbe6_vbe6_Shell,
        (FARPROC *) &Old_vbe6_vbe6_Shell,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "vbe6",
        "vbe6_StringConcat",
        (FARPROC) New_vbe6_vbe6_StringConcat,
        (FARPROC *) &Old_vbe6_vbe6_StringConcat,
        .special = 1,
        .report = 0,
        .mode = HOOK_MODE_OFFICE,
        .insn = 0,
        
        
        .addrcb = &hook_modulecb_vbe6,
    },
    {
        "version",
        "GetFileVersionInfoExW",
        (FARPROC) New_version_GetFileVersionInfoExW,
        (FARPROC *) &Old_version_GetFileVersionInfoExW,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "version",
        "GetFileVersionInfoSizeExW",
        (FARPROC) New_version_GetFileVersionInfoSizeExW,
        (FARPROC *) &Old_version_GetFileVersionInfoSizeExW,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "version",
        "GetFileVersionInfoSizeW",
        (FARPROC) New_version_GetFileVersionInfoSizeW,
        (FARPROC *) &Old_version_GetFileVersionInfoSizeW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "version",
        "GetFileVersionInfoW",
        (FARPROC) New_version_GetFileVersionInfoW,
        (FARPROC *) &Old_version_GetFileVersionInfoW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "DeleteUrlCacheEntryA",
        (FARPROC) New_wininet_DeleteUrlCacheEntryA,
        (FARPROC *) &Old_wininet_DeleteUrlCacheEntryA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "DeleteUrlCacheEntryW",
        (FARPROC) New_wininet_DeleteUrlCacheEntryW,
        (FARPROC *) &Old_wininet_DeleteUrlCacheEntryW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "HttpOpenRequestA",
        (FARPROC) New_wininet_HttpOpenRequestA,
        (FARPROC *) &Old_wininet_HttpOpenRequestA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "HttpOpenRequestW",
        (FARPROC) New_wininet_HttpOpenRequestW,
        (FARPROC *) &Old_wininet_HttpOpenRequestW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "HttpQueryInfoA",
        (FARPROC) New_wininet_HttpQueryInfoA,
        (FARPROC *) &Old_wininet_HttpQueryInfoA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "HttpSendRequestA",
        (FARPROC) New_wininet_HttpSendRequestA,
        (FARPROC *) &Old_wininet_HttpSendRequestA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "HttpSendRequestW",
        (FARPROC) New_wininet_HttpSendRequestW,
        (FARPROC *) &Old_wininet_HttpSendRequestW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetCloseHandle",
        (FARPROC) New_wininet_InternetCloseHandle,
        (FARPROC *) &Old_wininet_InternetCloseHandle,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetConnectA",
        (FARPROC) New_wininet_InternetConnectA,
        (FARPROC *) &Old_wininet_InternetConnectA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetConnectW",
        (FARPROC) New_wininet_InternetConnectW,
        (FARPROC *) &Old_wininet_InternetConnectW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetCrackUrlA",
        (FARPROC) New_wininet_InternetCrackUrlA,
        (FARPROC *) &Old_wininet_InternetCrackUrlA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetCrackUrlW",
        (FARPROC) New_wininet_InternetCrackUrlW,
        (FARPROC *) &Old_wininet_InternetCrackUrlW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetGetConnectedState",
        (FARPROC) New_wininet_InternetGetConnectedState,
        (FARPROC *) &Old_wininet_InternetGetConnectedState,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetGetConnectedStateExA",
        (FARPROC) New_wininet_InternetGetConnectedStateExA,
        (FARPROC *) &Old_wininet_InternetGetConnectedStateExA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetGetConnectedStateExW",
        (FARPROC) New_wininet_InternetGetConnectedStateExW,
        (FARPROC *) &Old_wininet_InternetGetConnectedStateExW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetOpenA",
        (FARPROC) New_wininet_InternetOpenA,
        (FARPROC *) &Old_wininet_InternetOpenA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetOpenUrlA",
        (FARPROC) New_wininet_InternetOpenUrlA,
        (FARPROC *) &Old_wininet_InternetOpenUrlA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetOpenUrlW",
        (FARPROC) New_wininet_InternetOpenUrlW,
        (FARPROC *) &Old_wininet_InternetOpenUrlW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetOpenW",
        (FARPROC) New_wininet_InternetOpenW,
        (FARPROC *) &Old_wininet_InternetOpenW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetQueryOptionA",
        (FARPROC) New_wininet_InternetQueryOptionA,
        (FARPROC *) &Old_wininet_InternetQueryOptionA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetReadFile",
        (FARPROC) New_wininet_InternetReadFile,
        (FARPROC *) &Old_wininet_InternetReadFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetSetOptionA",
        (FARPROC) New_wininet_InternetSetOptionA,
        (FARPROC *) &Old_wininet_InternetSetOptionA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetSetStatusCallback",
        (FARPROC) New_wininet_InternetSetStatusCallback,
        (FARPROC *) &Old_wininet_InternetSetStatusCallback,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "wininet",
        "InternetWriteFile",
        (FARPROC) New_wininet_InternetWriteFile,
        (FARPROC *) &Old_wininet_InternetWriteFile,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "winmm",
        "timeGetTime",
        (FARPROC) New_winmm_timeGetTime,
        (FARPROC *) &Old_winmm_timeGetTime,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "ConnectEx",
        (FARPROC) New_ws2_32_ConnectEx,
        (FARPROC *) &Old_ws2_32_ConnectEx,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "GetAddrInfoW",
        (FARPROC) New_ws2_32_GetAddrInfoW,
        (FARPROC *) &Old_ws2_32_GetAddrInfoW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "TransmitFile",
        (FARPROC) New_ws2_32_TransmitFile,
        (FARPROC *) &Old_ws2_32_TransmitFile,
        .special = 0,
        .report = HOOK_PRUNE_RESOLVERR,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSAAccept",
        (FARPROC) New_ws2_32_WSAAccept,
        (FARPROC *) &Old_ws2_32_WSAAccept,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSAConnect",
        (FARPROC) New_ws2_32_WSAConnect,
        (FARPROC *) &Old_ws2_32_WSAConnect,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSARecv",
        (FARPROC) New_ws2_32_WSARecv,
        (FARPROC *) &Old_ws2_32_WSARecv,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSARecvFrom",
        (FARPROC) New_ws2_32_WSARecvFrom,
        (FARPROC *) &Old_ws2_32_WSARecvFrom,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSASend",
        (FARPROC) New_ws2_32_WSASend,
        (FARPROC *) &Old_ws2_32_WSASend,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSASendTo",
        (FARPROC) New_ws2_32_WSASendTo,
        (FARPROC *) &Old_ws2_32_WSASendTo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSASocketA",
        (FARPROC) New_ws2_32_WSASocketA,
        (FARPROC *) &Old_ws2_32_WSASocketA,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSASocketW",
        (FARPROC) New_ws2_32_WSASocketW,
        (FARPROC *) &Old_ws2_32_WSASocketW,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "WSAStartup",
        (FARPROC) New_ws2_32_WSAStartup,
        (FARPROC *) &Old_ws2_32_WSAStartup,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "accept",
        (FARPROC) New_ws2_32_accept,
        (FARPROC *) &Old_ws2_32_accept,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "bind",
        (FARPROC) New_ws2_32_bind,
        (FARPROC *) &Old_ws2_32_bind,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "closesocket",
        (FARPROC) New_ws2_32_closesocket,
        (FARPROC *) &Old_ws2_32_closesocket,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "connect",
        (FARPROC) New_ws2_32_connect,
        (FARPROC *) &Old_ws2_32_connect,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "getaddrinfo",
        (FARPROC) New_ws2_32_getaddrinfo,
        (FARPROC *) &Old_ws2_32_getaddrinfo,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "gethostbyname",
        (FARPROC) New_ws2_32_gethostbyname,
        (FARPROC *) &Old_ws2_32_gethostbyname,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "getsockname",
        (FARPROC) New_ws2_32_getsockname,
        (FARPROC *) &Old_ws2_32_getsockname,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "ioctlsocket",
        (FARPROC) New_ws2_32_ioctlsocket,
        (FARPROC *) &Old_ws2_32_ioctlsocket,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "listen",
        (FARPROC) New_ws2_32_listen,
        (FARPROC *) &Old_ws2_32_listen,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "recv",
        (FARPROC) New_ws2_32_recv,
        (FARPROC *) &Old_ws2_32_recv,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "recvfrom",
        (FARPROC) New_ws2_32_recvfrom,
        (FARPROC *) &Old_ws2_32_recvfrom,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "select",
        (FARPROC) New_ws2_32_select,
        (FARPROC *) &Old_ws2_32_select,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "send",
        (FARPROC) New_ws2_32_send,
        (FARPROC *) &Old_ws2_32_send,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "sendto",
        (FARPROC) New_ws2_32_sendto,
        (FARPROC *) &Old_ws2_32_sendto,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "setsockopt",
        (FARPROC) New_ws2_32_setsockopt,
        (FARPROC *) &Old_ws2_32_setsockopt,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "shutdown",
        (FARPROC) New_ws2_32_shutdown,
        (FARPROC *) &Old_ws2_32_shutdown,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "ws2_32",
        "socket",
        (FARPROC) New_ws2_32_socket,
        (FARPROC *) &Old_ws2_32_socket,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_ALL,
        .insn = 0,
        
        
        
    },
    {
        "escript.api",
        "pdf_unescape",
        NULL,
        NULL,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_PDF,
        .insn = 1,
        
        
        .addrcb = &hook_modulecb_escript_api,
    },
    {
        "escript.api",
        "pdf_eval",
        NULL,
        NULL,
        .special = 0,
        .report = 0,
        .mode = HOOK_MODE_PDF,
        .insn = 1,
        
        
        .addrcb = &hook_modulecb_escript_api,
    },
    {NULL},
};

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
    [SIG____exploit__] = {
        FLAG_NONE,
    },
    [SIG___wmi___IWbemServices_ExecMethod] = {
        FLAG_NONE,
    },
    [SIG___wmi___IWbemServices_ExecMethodAsync] = {
        FLAG_NONE,
    },
    [SIG___wmi___IWbemServices_ExecQuery] = {
        FLAG_NONE,
    },
    [SIG___wmi___IWbemServices_ExecQueryAsync] = {
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
    [SIG_advapi32_NotifyBootConfigStatus] = {
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
    [SIG_advapi32_StartServiceCtrlDispatcherW] = {
        FLAG_NONE,
    },
    [SIG_advapi32_StartServiceW] = {
        FLAG_NONE,
    },
    [SIG_comctl32_TaskDialog] = {
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
    [SIG_jscript_ActiveXObjectFncObj_Construct] = {
        FLAG_NONE,
    },
    [SIG_jscript_COleScript_Compile] = {
        FLAG_NONE,
    },
    [SIG_kernel32_AssignProcessToJobObject] = {
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
    [SIG_kernel32_CreateActCtxW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateDirectoryExW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateDirectoryW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateJobObjectW] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateProcessInternalW] = {
        FLAG_CreateProcessInternalW_creation_flags,
        FLAG_NONE,
    },
    [SIG_kernel32_CreateRemoteThread] = {
        FLAG_NONE,
    },
    [SIG_kernel32_CreateRemoteThreadEx] = {
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
    [SIG_kernel32_GetTimeZoneInformation] = {
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
    [SIG_kernel32_GlobalMemoryStatus] = {
        FLAG_NONE,
    },
    [SIG_kernel32_GlobalMemoryStatusEx] = {
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
    [SIG_kernel32_SetFileTime] = {
        FLAG_NONE,
    },
    [SIG_kernel32_SetInformationJobObject] = {
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
    [SIG_mpr_WNetGetProviderNameW] = {
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
    [SIG_mshtml_CImgElement_put_src] = {
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
        FLAG_NtCreateFile_IoStatusBlock_Information,
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
        FLAG_NtCreateSection_DesiredAccess,
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
        FLAG_NtMapViewOfSection_Win32Protect,
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
        FLAG_NtCreateFile_IoStatusBlock_Information,
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
    [SIG_ntdll_NtOpenMutant] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntdll_NtOpenSection] = {
        FLAG_NtOpenSection_DesiredAccess,
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
    [SIG_ntdll_NtQuerySystemInformation] = {
        FLAG_NtQuerySystemInformation_SystemInformationClass,
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
    [SIG_ntdll_NtShutdownSystem] = {
        FLAG_NtShutdownSystem_Action,
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
    [SIG_ntoskrnl_NtAllocateVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtClose] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateDirectoryObject] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateFile] = {
        FLAG_NtCreateFile_DesiredAccess,
        FLAG_NtCreateFile_FileAttributes,
        FLAG_NtCreateFile_ShareAccess,
        FLAG_NtCreateFile_CreateDisposition,
        FLAG_NtCreateFile_CreateOptions,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateKey] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateMutant] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateProcessEx] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateSection] = {
        FLAG_NtCreateSection_DesiredAccess,
        FLAG_NtCreateSection_SectionPageProtection,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateThread] = {
        FLAG_NtCreateThread_DesiredAccess,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateThreadEx] = {
        FLAG_NtCreateThreadEx_DesiredAccess,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtCreateUserProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtDeleteFile] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtDeleteKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtDeleteValueKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtDeviceIoControlFile] = {
        FLAG_NtDeviceIoControlFile_IoControlCode,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtDuplicateObject] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtEnumerateKey] = {
        FLAG_KEY_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtEnumerateValueKey] = {
        FLAG_KEY_VALUE_INFORMATION_CLASS,
        FLAG_NtEnumerateValueKey_reg_type,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtFreeVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtGetContextThread] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtLoadDriver] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtLoadKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtLoadKey2] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtLoadKeyEx] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtMakePermanentObject] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtMakeTemporaryObject] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtMapViewOfSection] = {
        FLAG_NtMapViewOfSection_AllocationType,
        FLAG_NtMapViewOfSection_Win32Protect,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenDirectoryObject] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenFile] = {
        FLAG_NtOpenFile_DesiredAccess,
        FLAG_NtOpenFile_ShareAccess,
        FLAG_NtOpenFile_OpenOptions,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenKey] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenKeyEx] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenMutant] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenProcess] = {
        FLAG_ACCESS_MASK,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenSection] = {
        FLAG_NtOpenSection_DesiredAccess,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtOpenThread] = {
        FLAG_NtOpenThread_DesiredAccess,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtProtectVirtualMemory] = {
        FLAG_NtProtectVirtualMemory_NewAccessProtection,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryAttributesFile] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryDirectoryFile] = {
        FLAG_FILE_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryFullAttributesFile] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryInformationFile] = {
        FLAG_FILE_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryKey] = {
        FLAG_KEY_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryMultipleValueKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQuerySystemInformation] = {
        FLAG_NtQuerySystemInformation_SystemInformationClass,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueryValueKey] = {
        FLAG_KEY_VALUE_INFORMATION_CLASS,
        FLAG_NtQueryValueKey_reg_type,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtQueueApcThread] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtReadFile] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtReadVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtRenameKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtReplaceKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtResumeThread] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtSaveKey] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtSaveKeyEx] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtSetContextThread] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtSetInformationFile] = {
        FLAG_FILE_INFORMATION_CLASS,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtSetValueKey] = {
        FLAG_NtSetValueKey_Type,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtShutdownSystem] = {
        FLAG_NtShutdownSystem_Action,
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtSuspendThread] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtTerminateProcess] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtTerminateThread] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtUnloadDriver] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtUnmapViewOfSection] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtWriteFile] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_NtWriteVirtualMemory] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_RtlCreateUserProcess] = {
        FLAG_NONE,
    },
    [SIG_ntoskrnl_RtlCreateUserThread] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoCreateInstance] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoCreateInstanceEx] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoGetClassObject] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoInitializeEx] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoInitializeSecurity] = {
        FLAG_NONE,
    },
    [SIG_ole32_CoUninitialize] = {
        FLAG_NONE,
    },
    [SIG_ole32_OleConvertOLESTREAMToIStorage] = {
        FLAG_NONE,
    },
    [SIG_ole32_OleInitialize] = {
        FLAG_NONE,
    },
    [SIG_rpcrt4_UuidCreate] = {
        FLAG_NONE,
    },
    [SIG_secur32_DecryptMessage] = {
        FLAG_NONE,
    },
    [SIG_secur32_EncryptMessage] = {
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
    [SIG_user32_RegisterHotKey] = {
        FLAG_RegisterHotKey_fsModifiers,
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
    [SIG_vbe6_vbe6_CallByName] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_Close] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_CreateObject] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_GetIDFromName] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_GetObject] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_Import] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_Invoke] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_Open] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_Print] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_Shell] = {
        FLAG_NONE,
    },
    [SIG_vbe6_vbe6_StringConcat] = {
        FLAG_NONE,
    },
    [SIG_version_GetFileVersionInfoExW] = {
        FLAG_NONE,
    },
    [SIG_version_GetFileVersionInfoSizeExW] = {
        FLAG_NONE,
    },
    [SIG_version_GetFileVersionInfoSizeW] = {
        FLAG_NONE,
    },
    [SIG_version_GetFileVersionInfoW] = {
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
        FLAG_ioctlsocket_cmd,
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
    [SIG_escript_api_pdf_unescape] = {
        FLAG_NONE,
    },
    [SIG_escript_api_pdf_eval] = {
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
    [SIG____exploit__] = {
        NULL,
    },
    [SIG___wmi___IWbemServices_ExecMethod] = {
        NULL,
    },
    [SIG___wmi___IWbemServices_ExecMethodAsync] = {
        NULL,
    },
    [SIG___wmi___IWbemServices_ExecQuery] = {
        NULL,
    },
    [SIG___wmi___IWbemServices_ExecQueryAsync] = {
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
    [SIG_advapi32_NotifyBootConfigStatus] = {
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
    [SIG_advapi32_StartServiceCtrlDispatcherW] = {
        NULL,
    },
    [SIG_advapi32_StartServiceW] = {
        NULL,
    },
    [SIG_comctl32_TaskDialog] = {
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
    [SIG_jscript_ActiveXObjectFncObj_Construct] = {
        NULL,
    },
    [SIG_jscript_COleScript_Compile] = {
        NULL,
    },
    [SIG_kernel32_AssignProcessToJobObject] = {
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
    [SIG_kernel32_CreateActCtxW] = {
        NULL,
    },
    [SIG_kernel32_CreateDirectoryExW] = {
        NULL,
    },
    [SIG_kernel32_CreateDirectoryW] = {
        NULL,
    },
    [SIG_kernel32_CreateJobObjectW] = {
        NULL,
    },
    [SIG_kernel32_CreateProcessInternalW] = {
        "creation_flags",
        NULL,
    },
    [SIG_kernel32_CreateRemoteThread] = {
        NULL,
    },
    [SIG_kernel32_CreateRemoteThreadEx] = {
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
    [SIG_kernel32_GetTimeZoneInformation] = {
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
    [SIG_kernel32_GlobalMemoryStatus] = {
        NULL,
    },
    [SIG_kernel32_GlobalMemoryStatusEx] = {
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
    [SIG_kernel32_SetFileTime] = {
        NULL,
    },
    [SIG_kernel32_SetInformationJobObject] = {
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
    [SIG_mpr_WNetGetProviderNameW] = {
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
    [SIG_mshtml_CImgElement_put_src] = {
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
        "status_info",
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
        "win32_protect",
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
        "status_info",
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
    [SIG_ntdll_NtOpenMutant] = {
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
    [SIG_ntdll_NtQuerySystemInformation] = {
        "information_class",
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
    [SIG_ntdll_NtShutdownSystem] = {
        "action",
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
    [SIG_ntoskrnl_NtAllocateVirtualMemory] = {
        NULL,
    },
    [SIG_ntoskrnl_NtClose] = {
        NULL,
    },
    [SIG_ntoskrnl_NtCreateDirectoryObject] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateFile] = {
        "desired_access",
        "file_attributes",
        "share_access",
        "create_disposition",
        "create_options",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateKey] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateMutant] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateProcess] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateProcessEx] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateSection] = {
        "desired_access",
        "protection",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateThread] = {
        "access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateThreadEx] = {
        "access",
        NULL,
    },
    [SIG_ntoskrnl_NtCreateUserProcess] = {
        "desired_access_process",
        "desired_access_thread",
        NULL,
    },
    [SIG_ntoskrnl_NtDeleteFile] = {
        NULL,
    },
    [SIG_ntoskrnl_NtDeleteKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtDeleteValueKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtDeviceIoControlFile] = {
        "control_code",
        NULL,
    },
    [SIG_ntoskrnl_NtDuplicateObject] = {
        NULL,
    },
    [SIG_ntoskrnl_NtEnumerateKey] = {
        "information_class",
        NULL,
    },
    [SIG_ntoskrnl_NtEnumerateValueKey] = {
        "information_class",
        "reg_type",
        NULL,
    },
    [SIG_ntoskrnl_NtFreeVirtualMemory] = {
        NULL,
    },
    [SIG_ntoskrnl_NtGetContextThread] = {
        NULL,
    },
    [SIG_ntoskrnl_NtLoadDriver] = {
        NULL,
    },
    [SIG_ntoskrnl_NtLoadKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtLoadKey2] = {
        NULL,
    },
    [SIG_ntoskrnl_NtLoadKeyEx] = {
        NULL,
    },
    [SIG_ntoskrnl_NtMakePermanentObject] = {
        NULL,
    },
    [SIG_ntoskrnl_NtMakeTemporaryObject] = {
        NULL,
    },
    [SIG_ntoskrnl_NtMapViewOfSection] = {
        "allocation_type",
        "win32_protect",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenDirectoryObject] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenFile] = {
        "desired_access",
        "share_access",
        "open_options",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenKey] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenKeyEx] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenMutant] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenProcess] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenSection] = {
        "desired_access",
        NULL,
    },
    [SIG_ntoskrnl_NtOpenThread] = {
        "access",
        NULL,
    },
    [SIG_ntoskrnl_NtProtectVirtualMemory] = {
        "protection",
        NULL,
    },
    [SIG_ntoskrnl_NtQueryAttributesFile] = {
        NULL,
    },
    [SIG_ntoskrnl_NtQueryDirectoryFile] = {
        "information_class",
        NULL,
    },
    [SIG_ntoskrnl_NtQueryFullAttributesFile] = {
        NULL,
    },
    [SIG_ntoskrnl_NtQueryInformationFile] = {
        "information_class",
        NULL,
    },
    [SIG_ntoskrnl_NtQueryKey] = {
        "information_class",
        NULL,
    },
    [SIG_ntoskrnl_NtQueryMultipleValueKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtQuerySystemInformation] = {
        "information_class",
        NULL,
    },
    [SIG_ntoskrnl_NtQueryValueKey] = {
        "information_class",
        "reg_type",
        NULL,
    },
    [SIG_ntoskrnl_NtQueueApcThread] = {
        NULL,
    },
    [SIG_ntoskrnl_NtReadFile] = {
        NULL,
    },
    [SIG_ntoskrnl_NtReadVirtualMemory] = {
        NULL,
    },
    [SIG_ntoskrnl_NtRenameKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtReplaceKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtResumeThread] = {
        NULL,
    },
    [SIG_ntoskrnl_NtSaveKey] = {
        NULL,
    },
    [SIG_ntoskrnl_NtSaveKeyEx] = {
        NULL,
    },
    [SIG_ntoskrnl_NtSetContextThread] = {
        NULL,
    },
    [SIG_ntoskrnl_NtSetInformationFile] = {
        "information_class",
        NULL,
    },
    [SIG_ntoskrnl_NtSetValueKey] = {
        "reg_type",
        NULL,
    },
    [SIG_ntoskrnl_NtShutdownSystem] = {
        "action",
        NULL,
    },
    [SIG_ntoskrnl_NtSuspendThread] = {
        NULL,
    },
    [SIG_ntoskrnl_NtTerminateProcess] = {
        NULL,
    },
    [SIG_ntoskrnl_NtTerminateThread] = {
        NULL,
    },
    [SIG_ntoskrnl_NtUnloadDriver] = {
        NULL,
    },
    [SIG_ntoskrnl_NtUnmapViewOfSection] = {
        NULL,
    },
    [SIG_ntoskrnl_NtWriteFile] = {
        NULL,
    },
    [SIG_ntoskrnl_NtWriteVirtualMemory] = {
        NULL,
    },
    [SIG_ntoskrnl_RtlCreateUserProcess] = {
        NULL,
    },
    [SIG_ntoskrnl_RtlCreateUserThread] = {
        NULL,
    },
    [SIG_ole32_CoCreateInstance] = {
        NULL,
    },
    [SIG_ole32_CoCreateInstanceEx] = {
        NULL,
    },
    [SIG_ole32_CoGetClassObject] = {
        NULL,
    },
    [SIG_ole32_CoInitializeEx] = {
        NULL,
    },
    [SIG_ole32_CoInitializeSecurity] = {
        NULL,
    },
    [SIG_ole32_CoUninitialize] = {
        NULL,
    },
    [SIG_ole32_OleConvertOLESTREAMToIStorage] = {
        NULL,
    },
    [SIG_ole32_OleInitialize] = {
        NULL,
    },
    [SIG_rpcrt4_UuidCreate] = {
        NULL,
    },
    [SIG_secur32_DecryptMessage] = {
        NULL,
    },
    [SIG_secur32_EncryptMessage] = {
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
    [SIG_user32_RegisterHotKey] = {
        "modifiers",
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
    [SIG_vbe6_vbe6_CallByName] = {
        NULL,
    },
    [SIG_vbe6_vbe6_Close] = {
        NULL,
    },
    [SIG_vbe6_vbe6_CreateObject] = {
        NULL,
    },
    [SIG_vbe6_vbe6_GetIDFromName] = {
        NULL,
    },
    [SIG_vbe6_vbe6_GetObject] = {
        NULL,
    },
    [SIG_vbe6_vbe6_Import] = {
        NULL,
    },
    [SIG_vbe6_vbe6_Invoke] = {
        NULL,
    },
    [SIG_vbe6_vbe6_Open] = {
        NULL,
    },
    [SIG_vbe6_vbe6_Print] = {
        NULL,
    },
    [SIG_vbe6_vbe6_Shell] = {
        NULL,
    },
    [SIG_vbe6_vbe6_StringConcat] = {
        NULL,
    },
    [SIG_version_GetFileVersionInfoExW] = {
        NULL,
    },
    [SIG_version_GetFileVersionInfoSizeExW] = {
        NULL,
    },
    [SIG_version_GetFileVersionInfoSizeW] = {
        NULL,
    },
    [SIG_version_GetFileVersionInfoW] = {
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
        "cmd",
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
    [SIG_escript_api_pdf_unescape] = {
        NULL,
    },
    [SIG_escript_api_pdf_eval] = {
        NULL,
    },
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

hook_t *sig_hooks()
{
    return g_hooks;
}

uint32_t sig_hook_count()
{
    return MONITOR_HOOKCNT;
}