#include "driver.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

UNICODE_STRING  usDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Rootkit");
UNICODE_STRING  usSymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Rootkit");


// Driver Entry point
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(RegistryPath);
	PDEVICE_OBJECT deviceObject = NULL;
	

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "DKOM: Driver loaded!\n"));


	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCallRootkit;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCallRootkit;
	DriverObject->MajorFunction[IRP_MJ_READ] = IrpCallRootkit;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = IrpCallRootkit;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpCallRootkit;


	// Create the IOCTL Device to handle requests
	status = IoCreateDevice(
		DriverObject,
		0,
		&usDeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&deviceObject);

	// Check to ensure it initialized properly
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Create a symbolic link between the two name
	status = IoCreateSymbolicLink(&usSymbolicLink, &usDeviceName);

	// If the symbolic link fails, delete the IOCTL device and exit
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
		return status;
	} 

	/*
	// Register our low-level NDIS Protocol
	// to sniff on the wire
	if (!NT_SUCCESS(BogusProtocolRegister())) {

		// On failure, delete our device and return
		IoDeleteDevice(deviceObject);
		return status;
	} */


	// Create reference to unload Driver
	DriverObject->DriverUnload = DriverUnload;

	return (status);
}



// Driver unload point
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	
	UNREFERENCED_PARAMETER(DriverObject);
	

	//BogusProtocolUnregister();

	// Delete our driver device and the associated symbolic link 
	IoDeleteSymbolicLink(&usSymbolicLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Driver Unloaded\n"));


	return;
}
