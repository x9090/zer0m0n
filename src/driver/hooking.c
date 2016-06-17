#include "hooking.h"
#include "main.h"
#include "hook_reg.h"
#include "hook_process.h"
#include "hook_file.h"
#include "hook_misc.h"
#include "struct.h"

PVOID MapNtdllIntoMemory()
{
	NTSTATUS status;
	HANDLE hSection;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING pathFile;
	SECTION_IMAGE_INFORMATION sii;
	USHORT NumberOfSections;
	PVOID pSection = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_NT_HEADERS64 pNtHeader64 = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	DWORD dwExportRVA, dwExportSize;

	RtlInitUnicodeString(&pathFile, L"\\KnownDlls\\ntdll.dll");
	InitializeObjectAttributes(&objAttr, &pathFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	
	if(NT_SUCCESS(status = ZwOpenSection(&hSection, SECTION_MAP_READ, &objAttr)))
	{
			ZwQuerySection(hSection, 1, &sii, sizeof(sii), 0);
			Dbg("ntdll entry point : 0x%08x\n", sii.EntryPoint);
			Ntdll_ImageBase = sii.EntryPoint;
			pDosHeader = (PIMAGE_DOS_HEADER)Ntdll_ImageBase;
			
			#ifdef _M_X64
			pNtHeader64 = (PIMAGE_NT_HEADERS64)((unsigned char*)Ntdll_ImageBase+pDosHeader->e_lfanew); 
			pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader64+sizeof(IMAGE_NT_HEADERS64)); 
			dwExportRVA  = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			dwExportSize = pNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			#endif
			
			pNtHeader = (PIMAGE_NT_HEADERS)((unsigned char*)Ntdll_ImageBase+pDosHeader->e_lfanew); 
			pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader+sizeof(IMAGE_NT_HEADERS)); 
			dwExportRVA  = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			dwExportSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
						
			Dbg("Export table address : 0x%08x\n", dwExportRVA);
			Dbg("Export table size : 0x%08x\n", dwExportSize);
			Dbg("EAT : 0x%08X\n", (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)Ntdll_ImageBase+dwExportRVA));
			pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)Ntdll_ImageBase+dwExportRVA);
			Dbg("number of exported functions : 0x%08x\n", pImageExportDirectory->NumberOfFunctions);
	}
	ZwClose(hSection);
	return pImageExportDirectory;
}

ULONG GetSyscallNumber(PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PUCHAR funcName, ULONG offsetSyscall)
{
	PULONG addrName = NULL, addrFunc = NULL;
	PWORD addrOrdinal = NULL;
	ULONG i = 0;
	PCHAR name = NULL;
	SIZE_T n;
	
	if(pImageExportDirectory && funcName)
	{
		addrName = (PULONG)((unsigned char*)Ntdll_ImageBase + pImageExportDirectory->AddressOfNames);
		addrFunc = (PULONG)((unsigned char*)Ntdll_ImageBase + pImageExportDirectory->AddressOfFunctions);
		addrOrdinal = (PWORD)((unsigned char*)Ntdll_ImageBase + pImageExportDirectory->AddressOfNameOrdinals);
		
		for(i=0; i < pImageExportDirectory->NumberOfNames; ++i)
		{
			name = ((unsigned char*)Ntdll_ImageBase + addrName[i]);
			__try
			{
				ProbeForRead(name, 0, 1);
				RtlStringCchLengthA(funcName, NTSTRSAFE_MAX_CCH, &n);
				if(RtlEqualMemory(funcName, name, n))
				{
					Dbg("[+] FOUND : %s\n", name);
					Dbg("addr : 0x%08x\n", ((unsigned char*)Ntdll_ImageBase + addrFunc[addrOrdinal[i]]));
					Dbg("syscall : %x\n", *(PULONG)((PUCHAR)((unsigned char*)Ntdll_ImageBase + addrFunc[addrOrdinal[i]]+offsetSyscall)));
					return *(PULONG)((PUCHAR)((unsigned char*)Ntdll_ImageBase + addrFunc[addrOrdinal[i]]+offsetSyscall));
					
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				Dbg("Exception : %x\n", GetExceptionCode());
			}
		}
	}
	Dbg("FUUUU : %s\n", funcName);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve index of the Nt* function (given in parameter) in the SSDT
//	Parameters :
//		PULONG KiServiceTable : the SSDT address
//		PVOID FuncAddress 	  : a Nt* function address
//	Return value :
//		ULONG : the address which stores the Nt* function address (FuncAddress) in the SSDT
//	Process :
//		same as GetNtAddressFromSSDT() but in revert order
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONG GetSSDTEntry(PULONG KiServiceTable, PVOID FuncAddress)
{
	return ((ULONG)((ULONGLONG)FuncAddress-(ULONGLONG)KiServiceTable)) << 4;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve 12 bytes of free space in order to use that space as trampoline 
//	Parameters :
//		PUCHAR pStartSearchAddress : address where we will begin to search for 12 bytes of code cave
//	Return value :
//		PVOID : address of the code cave found
//	Process :
//		Search for 12 successive bytes at 0x00 from the address given in argument and returns the address found
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID SearchCodeCave(PUCHAR pStartSearchAddress)
{	
	while(pStartSearchAddress++)
	{		
		if(MmIsAddressValid(pStartSearchAddress))
		{
			if(*(PULONG)pStartSearchAddress == 0x00000000 && *(PULONG)(pStartSearchAddress+4) == 0x00000000 && *(PULONG)(pStartSearchAddress+8) == 0x00000000)
				return pStartSearchAddress-1;	
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve the Nt* address function given its syscall number in the SSDT
//	Parameters :
//		PULONG KiServiceTable : the SSDT base address
//		ULONG  ServiceId 	  : a syscall number
//	Return value :
//		ULONGLONG : the address of the function which has the syscall number given in argument
//	Process :
//		Because the addresses contained in the SSDT have the last four bits reserved to store the number of arguments,
//		in order to retrieve only the address, we shift four bits to the right
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONGLONG GetNTAddressFromSSDT( PULONG KiServiceTable, ULONG ServiceId )
{
	return (LONGLONG)( KiServiceTable[ServiceId] >> 4 ) 
		+ (ULONGLONG)KiServiceTable;
}

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
PVOID GetEndOfTextSection(PVOID moduleBase)
{
	USHORT NumberOfSections;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS64 pNtHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	ULONG i;
	PVOID begin_text, end_text;

	pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	pNtHeader = (PIMAGE_NT_HEADERS64)((unsigned char*)moduleBase+pDosHeader->e_lfanew);

	NumberOfSections = pNtHeader->FileHeader.NumberOfSections;
	Dbg("Number of Sections: %d\n", NumberOfSections);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader+sizeof(IMAGE_NT_HEADERS64));
	Dbg("section header : %llx \n", pSectionHeader);

	// parse each section in order to get to the executable section 
	for(i=0; i<NumberOfSections; i++)
	{
		// this is the .text section
		if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			begin_text = (PVOID)(pSectionHeader->VirtualAddress + (ULONG_PTR)moduleBase);
			end_text = (PVOID)((ULONG_PTR)begin_text + pSectionHeader->Misc.VirtualSize);
			Dbg("%s section is located at : %llx \n", pSectionHeader->Name, begin_text);
			Dbg("end of %s section at : %llx \n", pSectionHeader->Name, end_text);
			break;
		}
		pSectionHeader++;
	}
	return end_text;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve kernel base address
//	Parameters :
//		None
//	Return value :
//		PVOID : the kernel base address
//	Process :
//		Retrieve the ntoskrnl module and returns its base address
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////   
PVOID GetKernelBase()
{
	UNICODE_STRING funcAddr;
	ULONG ulNeededSize = 0, ModuleCount;
	PVOID pBuffer;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	PSYSTEM_MODULE pSystemModule = NULL;
	PVOID imgBaseAddr;

	ZwQuerySystemInformation(SystemModuleInformation, &ulNeededSize, 0, &ulNeededSize);
	if(ulNeededSize)
	{
		pBuffer = PoolAlloc(ulNeededSize);
		if(NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeededSize, &ulNeededSize)))
		{
			pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
			pSystemModule = &pSystemModuleInformation->Modules[0];
			imgBaseAddr = pSystemModule->Base;
			return imgBaseAddr;
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve KeServiceDescriptorTable address
//	Parameters :
//		None
//	Return value :
//		ULONGLONG : The service descriptor table address 
//	Process :
//		Since KeServiceDescriptorTable isn't an exported symbol anymore, we have to retrieve it. 
//		When looking at the disassembly version of nt!KiSystemServiceRepeat, we can see interesting instructions :
//			4c8d15c7202300	lea r10, [nt!KeServiceDescriptorTable (addr)]    => it's the address we are looking for (:
//			4c8d1d00212300	lea r11, [nt!KeServiceDescriptorTableShadow (addr)]
//			f7830001000080  test dword ptr[rbx+100h], 80h
//
//		Furthermore, the LSTAR MSR value (at 0xC0000082) is initialized with nt!KiSystemCall64, which is a function 
//		close to nt!KiSystemServiceRepeat. We will begin to search from this address, the opcodes 0x83f7, the ones 
//		after the two lea instructions, once we get here, we can finally retrieve the KeServiceDescriptorTable address 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR      pStartSearchAddress   = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR      pEndSearchAddress     = (PUCHAR)( ((ULONG_PTR)pStartSearchAddress + PAGE_SIZE) & (~0x0FFF) );
	PULONG      pFindCodeAddress      = NULL;
	ULONG_PTR   pKeServiceDescriptorTable;

	while ( ++pStartSearchAddress < pEndSearchAddress )
	{
		if ( (*(PULONG)pStartSearchAddress & 0xFFFFFF00) == 0x83f70000 )
		{
			pFindCodeAddress = (PULONG)(pStartSearchAddress - 12);
			return (ULONG_PTR)pFindCodeAddress + (((*(PULONG)pFindCodeAddress)>>24)+7) + (ULONG_PTR)(((*(PULONG)(pFindCodeAddress+1))&0x0FFFF)<<8); 
		}
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		install SSDT hooks
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		Retrieve SSDT address and hook SSDT table
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID HookSSDT()
{
	PDWORD func = NULL;
	PULONG KiServiceTable = NULL;
	PVOID kernelBase = NULL;
	PVOID pStartSearchAddress = NULL;
	DWORD offsetSyscall = 1;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

#ifdef _M_X64
	KeServiceDescriptorTable = (pServiceDescriptorTableEntry)GetKeServiceDescriptorTable64();
	Dbg("KeServiceDescriptorTable : %llx\n", KeServiceDescriptorTable);
	KiServiceTable = KeServiceDescriptorTable->ServiceTableBase;
	Dbg("KiServiceTable : %llx\n", KiServiceTable);
	kernelBase = GetKernelBase();
	Dbg("Kernel base addr : %llx\n", kernelBase);
	pStartSearchAddress = GetEndOfTextSection(kernelBase);
	Dbg("pStartSearchAddress : %llx\n", pStartSearchAddress);
	offsetSyscall = 21;
#endif
	// missing LoadDriver hook
	// missing DelayExecution hook
	// missing imageCallback hook

	pImageExportDirectory = MapNtdllIntoMemory();
	Install_Hook(*(PULONG)((PUCHAR)ZwOpenFile+offsetSyscall), (PVOID)Hooked_NtOpenFile, (PVOID*)&Orig_NtOpenFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwCreateSection+offsetSyscall), (PVOID)Hooked_NtCreateSection, (PVOID*)&Orig_NtCreateSection, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwQueryValueKey+offsetSyscall), (PVOID)Hooked_NtQueryValueKey, (PVOID*)&Orig_NtQueryValueKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwOpenProcess+offsetSyscall), (PVOID)Hooked_NtOpenProcess, (PVOID*)&Orig_NtOpenProcess, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwWriteFile+offsetSyscall), (PVOID)Hooked_NtWriteFile, (PVOID*)&Orig_NtWriteFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwCreateFile+offsetSyscall), (PVOID)Hooked_NtCreateFile, (PVOID*)&Orig_NtCreateFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwClose+offsetSyscall), (PVOID)Hooked_NtClose, (PVOID*)&Orig_NtClose, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwOpenKey+offsetSyscall), (PVOID)Hooked_NtOpenKey, (PVOID*)&Orig_NtOpenKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwReadFile+offsetSyscall), (PVOID)Hooked_NtReadFile, (PVOID*)&Orig_NtReadFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwDeleteFile+offsetSyscall), (PVOID)Hooked_NtDeleteFile, (PVOID*)&Orig_NtDeleteFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwSetInformationFile+offsetSyscall), (PVOID)Hooked_NtSetInformationFile, (PVOID*)&Orig_NtSetInformationFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwDeviceIoControlFile+offsetSyscall), (PVOID)Hooked_NtDeviceIoControlFile, (PVOID*)&Orig_NtDeviceIoControlFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwMapViewOfSection+offsetSyscall), (PVOID)Hooked_NtMapViewOfSection, (PVOID*)&Orig_NtMapViewOfSection, pStartSearchAddress, KiServiceTable);		
	Install_Hook(*(PULONG)((PUCHAR)ZwQuerySystemInformation+offsetSyscall), (PVOID)Hooked_NtQuerySystemInformation, (PVOID*)&Orig_NtQuerySystemInformation, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwCreateKey+offsetSyscall), (PVOID)Hooked_NtCreateKey, (PVOID*)&Orig_NtCreateKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(*(PULONG)((PUCHAR)ZwOpenKeyEx+offsetSyscall), (PVOID)Hooked_NtOpenKeyEx, (PVOID*)&Orig_NtOpenKeyEx, pStartSearchAddress, KiServiceTable);
	

	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwReadVirtualMemory", offsetSyscall), (PVOID)Hooked_NtReadVirtualMemory, (PVOID*)&Orig_NtReadVirtualMemory, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwWriteVirtualMemory", offsetSyscall), (PVOID)Hooked_NtWriteVirtualMemory, (PVOID*)&Orig_NtWriteVirtualMemory, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwResumeThread", offsetSyscall), (PVOID)Hooked_NtResumeThread, (PVOID*)&Orig_NtResumeThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateThreadEx", offsetSyscall), (PVOID)Hooked_NtCreateThreadEx, (PVOID*)&Orig_NtCreateThreadEx, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateUserProcess", offsetSyscall), (PVOID)Hooked_NtCreateUserProcess, (PVOID*)&Orig_NtCreateUserProcess, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateProcess", offsetSyscall), (PVOID)Hooked_NtCreateProcess, (PVOID*)&Orig_NtCreateProcess, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateProcessEx", offsetSyscall), (PVOID)Hooked_NtCreateProcessEx, (PVOID*)&Orig_NtCreateProcessEx, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwSetContextThread", offsetSyscall), (PVOID)Hooked_NtSetContextThread, (PVOID*)&Orig_NtSetContextThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateThread", offsetSyscall), (PVOID)Hooked_NtCreateThread, (PVOID*)&Orig_NtCreateThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwSystemDebugControl", offsetSyscall), (PVOID)Hooked_NtSystemDebugControl, (PVOID*)&Orig_NtSystemDebugControl, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwQueueApcThread", offsetSyscall), (PVOID)Hooked_NtQueueApcThread, (PVOID*)&Orig_NtQueueApcThread, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDebugActiveProcess", offsetSyscall), (PVOID)Hooked_NtDebugActiveProcess, (PVOID*)&Orig_NtDebugActiveProcess, pStartSearchAddress, KiServiceTable);	
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwQueryAttributesFile", offsetSyscall), (PVOID)Hooked_NtQueryAttributesFile, (PVOID*)&Orig_NtQueryAttributesFile, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwCreateMutant", offsetSyscall), (PVOID)Hooked_NtCreateMutant, (PVOID*)&Orig_NtCreateMutant, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDeleteKey", offsetSyscall), (PVOID)Hooked_NtDeleteKey, (PVOID*)&Orig_NtDeleteKey, pStartSearchAddress, KiServiceTable);
	Install_Hook(GetSyscallNumber(pImageExportDirectory, "ZwDeleteValueKey", offsetSyscall), (PVOID)Hooked_NtDeleteValueKey, (PVOID*)&Orig_NtDeleteValueKey, pStartSearchAddress, KiServiceTable);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Modify an entry of the SSDT by an address of the corresponding hooked function.
//	Parameters :
//		__in ULONG syscall     : syscall number of the function we want to hook
//		__in PVOID hookedFunc  : address of the hooked function
//		__inout PVOID origFunc : address of the function to hook
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Install_Hook(ULONG syscall, PVOID hookedFunc, PVOID *origFunc, PVOID searchAddr, PULONG KiServiceTable)
{	
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UCHAR jmp_to_newFunction[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0"; //mov rax, xxx ; jmp rax
	KIRQL Irql;
	ULONG SsdtEntry;
	PVOID trampoline = NULL;
	PMDL mdl = NULL;
	PVOID memAddr = NULL;
	KIRQL irql;

	if(syscall > 0)
	{
		irql = UnsetWP();

		#ifdef _M_IX86
		*origFunc = (PVOID)SYSTEMSERVICE(syscall);
		(PVOID)SYSTEMSERVICE(syscall) = hookedFunc;
		
		#elif defined _M_X64
		Dbg("OS : 64 bits !\n");
		*origFunc = (PVOID)GetNTAddressFromSSDT(KiServiceTable, syscall); 
		Dbg("Orig_Func : %llx\n", *origFunc);

		// mov rax, @NewFunc; jmp rax
		*(PULONGLONG)(jmp_to_newFunction+2) = (ULONGLONG)hookedFunc;
		trampoline = SearchCodeCave(searchAddr);
		Dbg("trampoline : %llx\n", trampoline);

		mdl = IoAllocateMdl(trampoline, 12, FALSE, FALSE, NULL);
		MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess); 
		memAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

		RtlMoveMemory(memAddr, jmp_to_newFunction, 12); 

		SsdtEntry = GetSSDTEntry(KiServiceTable, trampoline);
		SsdtEntry &= 0xFFFFFFF0;
		SsdtEntry += KiServiceTable[syscall] & 0x0F;		
		KiServiceTable[syscall] = SsdtEntry;   
		#endif
		
		SetWP(irql);

	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsets WP bit of CR0 register (allows writing into SSDT).
//		See http://en.wikipedia.org/wiki/Control_register#CR0
//	Parameters :
//		None
//	Return value :
//		KIRQL : current IRQL value
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
KIRQL UnsetWP( )
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT_PTR cr0 = __readcr0();

	cr0 &= ~0x10000;
	__writecr0( cr0 );
	_disable();

	return Irql;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID SetWP(KIRQL Irql)
{
	UINT_PTR cr0 = __readcr0();

	cr0 |= 0x10000;
	_enable();  
	__writecr0( cr0 );

	KeLowerIrql( Irql );
}
