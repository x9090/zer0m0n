#ifndef __QUERY_INFORMATION_H
#define __QUERY_INFORMATION_H

#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>

#include "hooking.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QuerySystemInformation is a wrapper around ZwQuerySystemInformation.
// 		Return a pointer to a structure information of the current process, depending of the SystemInformationClass requested
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
PVOID QuerySystemInformation (
	SYSTEM_INFORMATION_CLASS SystemInformationClass
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QueryProcessInformation is a wrapper around ZwQueryInformationProcess.
// 		Return a pointer to a structure information of the current process, depending of the ProcessInformationClass requested
//
//	Parameters :
//		IN HANDLE Process								The process targeted
//		IN PROCESSINFOCLASS ProcessInformationClass		The information class requested
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
);

#endif