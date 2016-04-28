#ifndef __COMM_H
#define __COMM_H

#include <fltkernel.h>

#define IOCTL_PROC_MALWARE \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
		
#define IOCTL_PROC_TO_HIDE \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_CUCKOO_PATH \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Initializes the filter port
//	Parameters : 
//		__in PDRIVER_OBJECT pDriverObject :	    Data structure used to represent the driver.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if the minifilter initialization has been well completed
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS InitMinifilter(__in PDRIVER_OBJECT);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication connection callback.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS FltConnectCallback(__in PFLT_PORT ClientPort, 
						 __in PVOID ServerPortCookie, 
					     __in PVOID ConnectionContext, 
						 __in ULONG SizeOfContext, 
						 __out PVOID* ConnectionPortCookie);
		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication disconnection callback.
//	Parameters : 
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID FltDisconnectCallback(__in PVOID ConnectionCookie);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//		Unregisters the minifilter.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff544606%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff544606%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS FltUnregister(__in FLT_FILTER_UNLOAD_FLAGS flags);
		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		DEVICE_IO_CONTROL IRP handler. Used for getting informations from Cuckoo.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Ioctl_DeviceControl(__in PDEVICE_OBJECT pDeviceObject,
							 __in PIRP pIrp);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsupported IRP generic handler. Just completes the request with STATUS_SUCCESS code.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS Ioctl_NotSupported(__in PDEVICE_OBJECT pDeviceObject,
                            __in PIRP pIrp);
							
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsupported IRP generic handler. Just completes the request with STATUS_SUCCESS code.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ioctl_NotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Generates a message using "pid", "sig_func" and "parameter" and sends it back to userland through
//		a filter communication port.
//	Parameters :
//		_in_opt_ ULONG pid :		Process ID from which the logs are produced.
//		_in_ ULONG sig_func :	    Function signature 
//		_in_opt_ PWCHAR parameter :	Function args.
//	Return value :
//		NTSTATUS : FltSendMessage return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS sendLogs(ULONG pid, ULONG sig_func, PWCHAR parameter);

#endif
