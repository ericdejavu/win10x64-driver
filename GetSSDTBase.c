#include <ntddk.h>

typedef struct _ServiceDescriptorTable {
	PVOID ServiceTableBase;
	PVOID ServiceTableCounter;
	unsigned int NumberOfServices;
	PVOID ParamTableBase;
} *PServiceDescriptorTable;

PServiceDescriptorTable KeServiceDescriptorTable;

void unload(PDRIVER_OBJECT driver) {
	KdPrint(("[hiDeivce]卸载驱动"));
}


PServiceDescriptorTable GetKeServiceDescriptorTable64() {
	PUCHAR startSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR endSearchAddress = startSearchAddress + 0x500;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG temp = 0;
	ULONGLONG addr = 0;

	for (PUCHAR i = startSearchAddress; i < endSearchAddress; i++) {
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2)) {
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) {
				memcpy(&temp, i + 3, 4);
				addr = (ULONGLONG)temp + (ULONGLONG)i + 7;
				KdPrint(("find ssdt base address:%p",addr));
				return addr;
			}
		}
	}
	return 0;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING str) {
	KdPrint(("[hiDeivce]载入驱动"));
	driver->DriverUnload = unload;
	ULONGLONG CurrentNtOpenProcessAddress;
	__try {
		KdPrint(("Address in processing"));
		ULONG *SSDT_Adr;
		KdPrint(("[hiDeivce]检查1"));
		KeServiceDescriptorTable = GetKeServiceDescriptorTable64();
		KdPrint(("[hiDeivce]检查0"));
		SSDT_Adr = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
		//KdPrint(("[hiDeivce]检查2:%p", t_addr));
		//SSDT_Adr = (PLONG)(t_addr + 0x7A * 4);
		KdPrint(("[hiDeivce]检查3"));
		CurrentNtOpenProcessAddress = (ULONGLONG)((SSDT_Adr[38]) >> 4);
		CurrentNtOpenProcessAddress += (ULONGLONG)SSDT_Adr;
		KdPrint(("[hiDeivce]检查4"));
		KdPrint(("[hiDeivce]当前地址:%p", CurrentNtOpenProcessAddress));
	}
	__except (1) {
		KdPrint(("[hiDeivce]into exception handle"));
	}

	__try {
		UNICODE_STRING processName;
		ULONGLONG originAddr;
		RtlInitUnicodeString(&processName, L"NtOpenProcess");
		originAddr = (ULONGLONG)MmGetSystemRoutineAddress(&processName);
		KdPrint(("[hiDeivce]原始地址:%p", originAddr));
	}
	__except (1) {
		KdPrint(("[hiDeivce]原始地址 into exception handle"));
	}
	return STATUS_SUCCESS;
}
