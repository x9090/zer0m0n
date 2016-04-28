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

#ifndef MONITOR_FLAGS_H
#define MONITOR_FLAGS_H

#include <stdint.h>
#include <windows.h>

typedef enum _flag_t {
    FLAG_NONE,
    FLAG_NtQueryValueKey_reg_type,
    FLAG_RegQueryValueExW_lpType,
    FLAG_RegQueryValueExA_lpType,
    FLAG_NtAllocateVirtualMemory_Protect,
    FLAG_InternetQueryOptions,
    FLAG_RegSetValueExA_dwType,
    FLAG_FILE_INFORMATION_CLASS,
    FLAG_NtCreateFile_FileAttributes,
    FLAG_SetFileAttributesW_dwFileAttributes,
    FLAG_NtCreateFile_DesiredAccess,
    FLAG_NtOpenFile_OpenOptions,
    FLAG_NtCreateFile_CreateOptions,
    FLAG_NtOpenFile_DesiredAccess,
    FLAG_NtEnumerateValueKey_reg_type,
    FLAG_CreateWindowExW_dwExStyle,
    FLAG_GetSystemMetrics_nIndex,
    FLAG_NtMapViewOfSection_AllocationType,
    FLAG_NtDeviceIoControlFile_IoControlCode,
    FLAG_MemoryProtectionFlags,
    FLAG_RegEnumValueA_lpType,
    FLAG_InternetQueryOptionA_dwOption,
    FLAG_NtAllocateVirtualMemory_AllocationType,
    FLAG_NtProtectVirtualMemory_NewAccessProtection,
    FLAG_InternetSetOptionA_dwOption,
    FLAG_NtCreateFile_CreateDisposition,
    FLAG_PRIORITY_CLASS,
    FLAG_NtOpenFile_ShareAccess,
    FLAG_AllocationType,
    FLAG_WindowStyles,
    FLAG_SetErrorMode_uMode,
    FLAG_RegSetValueExW_dwType,
    FLAG_CreateWindowExA_dwExStyle,
    FLAG_ExtendedWindowStyles,
    FLAG_NtCreateFile_ShareAccess,
    FLAG_ShareAccessFlags,
    FLAG_RegEnumValueW_lpType,
    FLAG_WINDOWS_HOOKS,
    FLAG_SHGetFolderPathW_nFolder,
    FLAG_SetWindowsHookExW_idHook,
    FLAG_DeviceIoControl_dwIoControlCode,
    FLAG_ACCESS_MASK,
    FLAG_NtSetValueKey_Type,
    FLAG_REGISTRY_VALUE_TYPE,
    FLAG_CreateWindowExA_dwStyle,
    FLAG_ALG_ID,
    FLAG_KEY_VALUE_INFORMATION_CLASS,
    FLAG_IOCTL_CODES,
    FLAG_VirtualProtectEx_flNewProtect,
    FLAG_CreateProcessInternalW_creation_flags,
    FLAG_KEY_INFORMATION_CLASS,
    FLAG_FileOptions,
    FLAG_FILE_INFO_BY_HANDLE_CLASS,
    FLAG_CreateWindowExW_dwStyle,
    FLAG_SetWindowsHookExA_idHook,
    FLAGCNT,
} flag_t;

#endif