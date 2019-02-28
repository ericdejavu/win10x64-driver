// create 2019.3 by ericdejavu

#include <ntdef.h>
#include <ntifs.h>

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)

NTSTATUS NTAPI MmCopyVirtualMemory (
	PEPROCESS SourceProcess, PVOID SourceAddress,
	PEPROCESS TargetProcess, PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);


NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
	__try {
		PEPROCESS SourceProcess = Process;
		PEPROCESS TargetProcess = PsGetCurrentProcess();
		SIZE_T Result;
		if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result))) {
			return STATUS_SUCCESS;
		}
		else {
			return STATUS_ACCESS_DENIED;
		}
	}
	__except (1) {
		KdPrint(("KeReadProcessMemory excption"));
	}
}

int read = 1024;
LONGLONG DATA_ADDR = 0xea300df9b0;
INT PID = 2804;

NTSTATUS KeWriteProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
	__try {
		PEPROCESS SourceProcess = PsGetCurrentProcess();
		PEPROCESS TargetProcess = Process;
		SIZE_T Result;
		if (NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result))) {
			return STATUS_SUCCESS;
		}
		else {
			return STATUS_ACCESS_DENIED;
		}
	}
	__except (1) {
		KdPrint(("KeWriteProcessMemory excption"));
	}
}

void unload(PDRIVER_OBJECT driver) {
	KdPrint(("unload"));
	__try {
		PEPROCESS process;
		PsLookupProcessByProcessId(PID, &process);
		KeWriteProcessMemory(process, &read, DATA_ADDR, sizeof(__int32));
	}
	__except (1) {
		KdPrint(("unload excption"));
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING str) {
	driver->DriverUnload = unload;
	int val = 64;
	PEPROCESS process;

	__try {
		PsLookupProcessByProcessId(PID, &process);

		KeReadProcessMemory(process, DATA_ADDR, &read, sizeof(__int32));
		KdPrint(("read Value of int i:%d", read));
		KeWriteProcessMemory(process, &val, DATA_ADDR, sizeof(__int32));
		KdPrint(("write Value of int i:%d", val));
	}
	__except (1) {
		KdPrint(("enter excption"));
	}
	return STATUS_SUCCESS;
}
