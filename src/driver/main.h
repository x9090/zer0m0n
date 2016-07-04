////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n DRIVER
//
//  Copyright 2014 Nicolas Correia, Adrien Chevalier
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.
//
//
//	File :		main.h
//	Abstract :	Main header for Cuckoo Zero Driver
//	Revision : 	v1.1
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		// à mettre...
//	Date :		2014-10-01	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////

#ifndef __MAIN_H
#define __MAIN_H

#include <fltkernel.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include <windef.h>

//#define DEBUG
#ifdef DEBUG
	#define Dbg(fmt, ...) \
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__);
#else
	#define Dbg(fmt, ...)
#endif

#define TAG_NAME 		'zm0n'
#define PoolAlloc(x)	ExAllocatePoolWithTag(NonPagedPool, x, TAG_NAME)
#define PoolFree(x)		ExFreePoolWithTag(x, TAG_NAME)

// userland communication mutex
KMUTEX mutex;

#define FLT_MAX_CONNECTIONS 	1
#define DRIVER_NAME 			L"zer0m0n"
#define FILTER_PORT_NAME 		L"\\FilterPort"

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////

// some functions needed to import
typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS,PVOID,ULONG,PULONG);
ZWQUERYSYSTEMINFORMATION 	ZwQuerySystemInformation;

typedef NTSTATUS (*ZWQUERYINFORMATIONPROCESS)(HANDLE,ULONG,PVOID,ULONG,PULONG);
ZWQUERYINFORMATIONPROCESS 	ZwQueryInformationProcess;

typedef NTSTATUS (*ZWQUERYINFORMATIONTHREAD)(HANDLE,ULONG,PVOID,ULONG,PULONG);
ZWQUERYINFORMATIONTHREAD 	ZwQueryInformationThread;

typedef NTSTATUS (*ZWQUERYATTRIBUTESFILE)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
ZWQUERYATTRIBUTESFILE 		ZwQueryAttributesFile;

typedef NTSTATUS (*ZWCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
ZWCREATEPROCESS 			ZwCreateProcess;

typedef NTSTATUS (*ZWCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
ZWCREATEPROCESSEX			ZwCreateProcessEx;

typedef NTSTATUS (*ZWCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PVOID, PVOID, PVOID);
ZWCREATEPROCESSEX			ZwCreateUserProcess;

typedef NTSTATUS (*ZWRESUMETHREAD)(HANDLE, PULONG);
ZWRESUMETHREAD				ZwResumeThread;

typedef NTSTATUS (*ZWQUERYSECTION)(HANDLE, ULONG, PVOID, ULONG, PULONG);
ZWQUERYSECTION				ZwQuerySection;

// Dos device driver name
UNICODE_STRING 	usDosDeviceName;

// cuckoo path (where the files about to be delete will be moved)
PWCHAR cuckooPath;

// filter stuff
PFLT_FILTER 	fltFilter;
PFLT_PORT 		fltServerPort;
PFLT_PORT 		fltClientPort;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Initializes the driver, communication and hooks.
//	Parameters : 
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff544113%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff544113%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,
					 __in PUNICODE_STRING pRegistryPath);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//		Unregisters the minifilter.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff557310%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff557310%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Unload(__in PDRIVER_OBJECT pDriverObject);


#endif __MAIN_H