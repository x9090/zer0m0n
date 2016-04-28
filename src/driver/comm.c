#include "main.h"
#include "utils.h"
#include "monitor.h"
#include "hooking.h"
#include "comm.h"

// filter callbacks struct
static const FLT_REGISTRATION fltRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP, 
	NULL,
	NULL,
	FltUnregister,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : initializes the filter port
//
//	Parameters : 
//		__in PDRIVER_OBJECT pDriverObject :	    Data structure used to represent the driver.
//
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if the minifilter initialization has been well completed
//	Process :
//		Register filter / Creates communication port
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS InitMinifilter(__in PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;
	PSECURITY_DESCRIPTOR pSecurityDesc = NULL;
	UNICODE_STRING fltPortName;

	status = FltRegisterFilter(pDriverObject, &fltRegistration, &fltFilter);
	if(!NT_SUCCESS(status))
		return status;

	RtlInitUnicodeString(&fltPortName, FILTER_PORT_NAME);
	status = FltBuildDefaultSecurityDescriptor(&pSecurityDesc, FLT_PORT_ALL_ACCESS); 
	if(!NT_SUCCESS(status))
		return status;

	InitializeObjectAttributes(&objAttr, &fltPortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, pSecurityDesc);

	status = FltCreateCommunicationPort(fltFilter, &fltServerPort, &objAttr, NULL, FltConnectCallback, 
			FltDisconnectCallback, NULL, FLT_MAX_CONNECTIONS);
	FltFreeSecurityDescriptor(pSecurityDesc);    
	if(!NT_SUCCESS(status))
		return status;

	return STATUS_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication connection callback.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Process :
//		Sets the global variable "clientPort" with the supplied client port communication.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS FltConnectCallback(__in PFLT_PORT ClientPort, 
		__in PVOID ServerPortCookie, 
		__in PVOID ConnectionContext, 
		__in ULONG SizeOfContext, 
		__out PVOID* ConnectionPortCookie)
{
	if(ClientPort == NULL)
		return STATUS_INVALID_PARAMETER;

	fltClientPort = ClientPort;
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication disconnection callback.
//	Parameters : 
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Process :
//		We don't use it but this callback has to be declared anyway.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID FltDisconnectCallback(__in PVOID ConnectionCookie)
{
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		DEVICE_IO_CONTROL IRP handler. Used for getting informations from Cuckoo.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Process :
//		Handles IRP_MJ_CONTROL IOCTLs.
//		Retrieves PIDs to monitor / hide  
//		Destroys the driver symbolic name for security (we don't want someone to interact with the driver).
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Ioctl_DeviceControl(__in PDEVICE_OBJECT pDeviceObject,
		__in PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	PCHAR buffer;
	ULONG ioControlCode;
	ULONG inputLength;
	ULONG malware_pid = 0;

	if(pIrp == NULL || pDeviceObject == NULL)
		return STATUS_INVALID_PARAMETER;

	// get the current stack location
	pIoStackIrp = IoGetCurrentIrpStackLocation(pIrp);

	// get the io control parameters
	ioControlCode = pIoStackIrp->Parameters.DeviceIoControl.IoControlCode;
	inputLength = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	buffer = pIrp->AssociatedIrp.SystemBuffer;

	switch(ioControlCode)
	{
		case IOCTL_PROC_MALWARE:
			Dbg("IOCTL_PROC_MALWARE received\n");
			status = RtlCharToInteger(buffer, 10, &malware_pid);
			Dbg("malware_pid : %d\n", malware_pid);
			if(NT_SUCCESS(status) && malware_pid > 0)
				StartMonitoringProcess(malware_pid);				
			break;	

		case IOCTL_PROC_TO_HIDE:
			Dbg("pids to hide : %s\n", buffer);
			// à parser et à ajouter dans la liste des pids à cacher !
			break;

		case IOCTL_CUCKOO_PATH:
			cuckooPath = PoolAlloc(MAX_SIZE);
			if(inputLength && inputLength < MAX_SIZE)
				RtlStringCchPrintfW(cuckooPath, MAX_SIZE, L"\\??\\%ws", buffer);
			else
			{
				Dbg("IOCTL_CUCKOO_PATH : Buffer too large\n");
				return STATUS_BUFFER_TOO_SMALL;
			}
			Dbg("cuckoo path : %ws\n", cuckooPath);
			break;

		default:
			break;
	}

	pIrp->IoStatus.Status = status;	
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsupported IRP generic handler. Just completes the request with STATUS_SUCCESS code.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		NTSTATUS : STATUS_NOT_SUPPORTED
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Ioctl_NotSupported(__in PDEVICE_OBJECT pDeviceObject,
		__in PIRP pIrp)
{
	return STATUS_NOT_SUPPORTED;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//		Unregisters the minifilter.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff557310%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff557310%28v=vs.85%29.aspx
//	Process :
//		Closes filter communication port and unregisters the filter.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS FltUnregister(__in FLT_FILTER_UNLOAD_FLAGS flags)
{
	FltCloseCommunicationPort(fltServerPort);

	if(fltFilter != NULL)
		FltUnregisterFilter(fltFilter);

	return STATUS_FLT_DO_NOT_DETACH;
}

NTSTATUS sendLogs(ULONG pid, ULONG sig_func, PWCHAR parameter)
{
	NTSTATUS status = STATUS_SUCCESS;
	CHAR buf[MAX_SIZE];
	UNICODE_STRING processName;
	size_t sizeBuf;

	LARGE_INTEGER timeout;
	timeout.QuadPart = -((LONGLONG)0.5*10*1000*1000);

	if(sig_func <= 0)
		return STATUS_INVALID_PARAMETER;

	Dbg("SendLogs\n");
	Dbg("parameter : %ws\n", parameter);
		
	processName.Length = 0;
	processName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	processName.Buffer = PoolAlloc(processName.MaximumLength);
	if(!processName.Buffer)
	{
		Dbg("Error 1\n");
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		return STATUS_NO_MEMORY;
	}

	status = getProcNameByPID(pid, &processName);
	if(!NT_SUCCESS(status))
	{
		Dbg("Error 2\n");
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		PoolFree(processName.Buffer);
		return status;
	}

	status = RtlStringCbPrintfA(buf, MAX_SIZE, "%d,%wZ,%d,%ws\n", pid, &processName, sig_func, parameter);
	if(!NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
	{
		Dbg("Error 3 : %x\n", status);
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		PoolFree(processName.Buffer);
		return status;
	}

	status = RtlStringCbLengthA(buf, MAX_SIZE, &sizeBuf);
	if(!NT_SUCCESS(status))
	{
		Dbg("Error 4\n");
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(fltFilter, &fltClientPort, "0,error,error,error\n", 20, NULL, 0, &timeout);
		KeReleaseMutex(&mutex, FALSE);
		PoolFree(processName.Buffer);
		return status;
	}


	KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
	Dbg("\tmsg : %s\n", buf);

	status = FltSendMessage(fltFilter, &fltClientPort, buf, sizeBuf, NULL, 0, NULL);
	if(status == STATUS_TIMEOUT)
		Dbg("STATUS_TIMEOUT !!\n");
	KeReleaseMutex(&mutex, FALSE);
	PoolFree(processName.Buffer);

	if(!NT_SUCCESS(status))
		Dbg("return : 0x%08x\n", status);

	return status;
}
