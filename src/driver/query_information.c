////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n DRIVER
//
//  Copyright 2014 Conix Security, Nicolas Correia, Adrien Chevalier, Cyril Moreau
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distibuted in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.
//
//
//	File :		query_information.c
//	Abstract :	Query information from the system
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia & Cyril Moreau
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr cyril.moreau@conix.fr
//	Date :		2014-08-22	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#include "query_information.h"
#include "main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QuerySystemInformation is a wrapper around ZwQuerySystemInformation.
// 		Retrieve information of the current system, depending of the SystemInformationClass requested
//
//	Parameters :
//		IN SYSTEM_INFORMATION_CLASS SystemInformationClass		The information class requested
//	Return value :
//		PVOID :	An information structure pointer retrieved with ZwQuerySystemInformation depending of the class requested
//	Process :
//		Request the requested structure size
//		Allocate the memory for the requested structure
//		Fill the requested structure
//		Check the structure size requested with the one returned by ZwQuerySystemInformation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID
QuerySystemInformation (
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass
		) {
	NTSTATUS Status;
	PVOID pSystemInformation = NULL;
	ULONG SystemInformationLength = 0;
	ULONG ReturnLength = 0;

	// Retrieve the requested structure size
	if (ZwQuerySystemInformation (SystemInformationClass, &SystemInformationLength, 0, &SystemInformationLength) != STATUS_INFO_LENGTH_MISMATCH) {
		Dbg ("ZwQuerySystemInformation should return STATUS_INFO_LENGTH_MISMATCH");
		return NULL;
	}

	// Allocate the memory for the requested structure
	if ((pSystemInformation = ExAllocatePoolWithTag (NonPagedPool, SystemInformationLength, 'QSI')) == NULL) {
		Dbg ("ExAllocatePoolWithTag failed");
		return NULL;
	}

	// Fill the requested structure
	if (!NT_SUCCESS (ZwQuerySystemInformation (SystemInformationClass, pSystemInformation, SystemInformationLength, &ReturnLength))) {
		Dbg ("ZwQuerySystemInformation should return NT_SUCCESS");
		ExFreePool (pSystemInformation);   
		return NULL;
	}

	// Check the structure size requested with the one returned by ZwQuerySystemInformation
	if (ReturnLength != SystemInformationLength) {
		Dbg ("Warning : ZwQuerySystemInformation ReturnLength is different than SystemInformationLength");
	}

	return pSystemInformation;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QueryProcessInformation is a wrapper around ZwQueryInformationProcess.
// 		Return a pointer to a structure information of the current process, depending of the ProcessInformationClass requested
//
//	Parameters :
//		IN HANDLE Process								The process targeted
//		IN PROCESSINFOCLASS ProcessInformationClass		The information class requested
//		IN DWORD ProcessInformationLength				Size of the structure written
//	Return value :
//		PVOID :	An information structure pointer retrieved with ZwQueryInformationProcess depending of the class requested
//	Process :
//		Request the requested structure size
//		Allocate the memory for the requested structure
//		Fill the requested structure
//		Check the structure size requested with the one returned by ZwQueryInformationProcess
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID
QueryProcessInformation (
		IN HANDLE Process, 
		IN PROCESSINFOCLASS ProcessInformationClass, 
		IN DWORD ProcessInformationLength
		) {
	NTSTATUS Status;
	PVOID pProcessInformation = NULL;
	ULONG ReturnLength = 0;

	// Allocate the memory for the requested structure
	if ((pProcessInformation = ExAllocatePoolWithTag (NonPagedPool, ProcessInformationLength, 'QPI')) == NULL) {
		Dbg ("ExAllocatePoolWithTag failed");
		return NULL;
	}

	// Fill the requested structure
	if (!NT_SUCCESS (ZwQueryInformationProcess (Process, ProcessInformationClass, pProcessInformation, ProcessInformationLength, &ReturnLength))) {
		Dbg ("ZwQueryInformationProcess should return NT_SUCCESS");
		ExFreePool (pProcessInformation);   
		return NULL;
	}

	// Check the requested structure size with the one returned by ZwQueryInformationProcess
	if (ReturnLength != ProcessInformationLength) {
		Dbg ("Warning : ZwQueryInformationProcess ReturnLength is different than ProcessInformationLength");
	}

	return pProcessInformation;
}


