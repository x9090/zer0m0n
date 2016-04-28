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
//	File :		main.c
//	Abstract :	Main function for zer0m0n Driver
//	Revision : 	v1.1
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		// à mettre...
//	Date :		2014-10-01	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////

#include "main.h"
#include "utils.h"
#include "monitor.h"
#include "hooking.h"
#include "comm.h"


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : initializes the driver, communication and hooks.
//
//	Parameters : 
//		__in PDRIVER_OBJECT pDriverObject :	    Data structure used to represent the driver.
//		__in PUNICODE_STRING pRegistryPath :	Registry location where the information for the driver
//												was stored.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if the driver initialization has been well completed
//	Process :
//		Import needed functions
//		Creates the device driver and its symbolic link.
//		Sets IRP callbacks.
//		Creates filter communication port to send logs from the driver to the userland process.
//		Hooks SSDT and Shadow SSDT
//		Creates logs mutex.
//		Register image load.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(__in PDRIVER_OBJECT pDriverObject,
		__in PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING usDriverName;
	PDEVICE_OBJECT pDeviceObject;
	ULONG i;

	Dbg("Driver entry\n");
	
	Resolve_FunctionsAddr();
	
	RtlInitUnicodeString(&usDriverName, L"\\Device\\" DRIVER_NAME);
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\" DRIVER_NAME);

	status = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject); 
	if(!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	if(!NT_SUCCESS(status))
		return status;


	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	for(i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = Ioctl_NotSupported;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Ioctl_DeviceControl;

	status = Init_LinkedLists();
	if(!NT_SUCCESS(status))
		return status;

	status = InitMinifilter(pDriverObject);
	if(!NT_SUCCESS(status))
		return status;


	KeInitializeMutex(&mutex, 0);
	HookSSDT();

	//HookShadowSSDT();

	pDriverObject->DriverUnload = Unload;
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Driver unload callback. Removes hooks, callbacks, and communication stuff.
//
//	Parameters :
//		__in PDRIVER_OBJECT pDriverObject :	Data structure used to represent the driver.
//	Process :
//		Removes hooks, callbacks, device driver symbolic link / device. 
//		Cleans the monitored processes linked list.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Unload(__in PDRIVER_OBJECT pDriverObject) 
{
	//RestoreSSDT();

	FreeList();
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(pDriverObject->DeviceObject);
}
