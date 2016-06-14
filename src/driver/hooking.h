#ifndef __HOOKING_H
#define __HOOKING_H

#include <fltkernel.h>
#include <ntimage.h>
#include "hook-info.h"

#pragma intrinsic(__readcr0)
#pragma intrinsic(__writecr0)
#pragma intrinsic(_disable)
#pragma intrinsic(_enable)

#ifdef _M_IX86
	#define SYSTEMSERVICE(_syscall) KeServiceDescriptorTable.ServiceTableBase[_syscall]
#endif

#define ObjectNameInformation	1
#define MAX_SIZE 1024

// from ReactOS code : https://reactos.googlecode.com/svn/trunk/reactos/include/reactos/probe.h
static const LARGE_INTEGER __emptyLargeInteger =  {{0, 0}};

#define ProbeForReadGenericType(Ptr, Type, Default) \
    (((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) || \
      (ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) ? \
        ExRaiseAccessViolation(), Default : \
            *(const volatile Type *)(Ptr))

#define ProbeForReadLargeInteger(Ptr) ProbeForReadGenericType((const LARGE_INTEGER *)(Ptr), LARGE_INTEGER, __emptyLargeInteger)

// log mode
#define LOG_ERROR 0
#define LOG_SUCCESS 1
#define LOG_PARAM 2

#define SEC_IMAGE 0x1000000

/////////////////////////////////////////////////////////////////////////////
// STRUCTS
/////////////////////////////////////////////////////////////////////////////

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    unsigned long *ServiceTableBase;
    unsigned long *ServiceCounterTableBase;
    unsigned long NumberOfServices;
    unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;


typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,	
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemWhatTheFuckInformation,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SECTION_IMAGE_INFORMATION {
  PVOID     EntryPoint;
  ULONG     StackZeroBits;
  ULONG     StackReserved;
  ULONG     StackCommit;
  ULONG     ImageSubsystem;
  ULONG		fuu;
  ULONG     Unknown1;
  ULONG     ImageCharacteristics;
  ULONG     ImageMachineType;
  ULONG     Unknown2[3];

} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////

// SSDT imports
#ifdef _M_IX86
__declspec(dllimport) ServiceDescriptorTableEntry KeServiceDescriptorTable; 
#elif defined _M_X64
pServiceDescriptorTableEntry KeServiceDescriptorTable;
#endif

PVOID Ntdll_ImageBase;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////


PVOID MapNtdllIntoMemory();
ULONG GetSyscallNumber(PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PUCHAR funcName, ULONG offsetSyscall);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve 12 bytes of free space in order to use that space as trampoline 
//	Parameters :
//		PUCHAR pStartSearchAddress : address where we will begin to search for 12 bytes of code cave
//	Return value :
//		PVOID : address of the code cave found
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID SearchCodeCave(PVOID pStartSearchAddress);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve the Nt* address function given its syscall number in the SSDT
//	Parameters :
//		PULONG KiServiceTable : the SSDT base address
//		ULONG  ServiceId 	  : a syscall number
//	Return value :
//		ULONGLONG : the address of the function which has the syscall number given in argument
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
ULONGLONG GetNTAddressFromSSDT(PULONG KiServiceTable, ULONG ServiceId);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve index of the Nt* function (given in parameter) in the SSDT
//	Parameters :
//		PULONG KiServiceTable : the SSDT address
//		PVOID FuncAddress 	  : a Nt* function address
//	Return value :
//		ULONG : the address which stores the Nt* function address (FuncAddress) in the SSDT
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
ULONG GetSSDTEntry(PULONG KiServiceTable, PVOID FuncAddress);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve end address of the .text section of the module given in argument
//	Parameters :
//		PVOID moduleBase : base address of a module
//	Return value :
//		Returns end address of .text section of moduleBase
//	Process :
//		Parse module base PE header to get the number of sections and to retrieve section header address,
//		then parse each section and when we get to the .text section, returns address of the end of the section
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID GetEndOfTextSection(PVOID moduleBase);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve KeServiceDescriptorTable address
//	Parameters :
//		None
//	Return value :
//		ULONGLONG : The service descriptor table address 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONGLONG GetKeServiceDescriptorTable64();

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve kernel base address
//	Parameters :
//		None
//	Return value :
//		PVOID : the kernel base address
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
PVOID GetKernelBase();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		install SSDT hooks
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID HookSSDT();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Modify an entry of the SSDT by an adresse of the corresponding hooked function.
//	Parameters :
//		__in ULONG syscall     : syscall number of the function we want to hook
//		__in PVOID hookedFunc  : address of the hooked function
//		__inout PVOID origFunc : address of the function to hook
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Install_Hook(__in ULONG syscall, 
				  __in PVOID hookedFunc, 
				  __inout PVOID *origFunc,
				  __in PVOID searchAddr,
				  __in PULONG KiServiceTable);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsets WP bit of CR0 register (allows writing into SSDT).
//		See http://en.wikipedia.org/wiki/Control_register#CR0
//	Parameters :
//		None
//	Return value :
//		KIRQL : current IRQL value
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
KIRQL UnsetWP( );

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID SetWP(KIRQL Irql);


#endif
