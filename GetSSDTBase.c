#include <ntddk.h>

// 反编译的SSDT结构体
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

// 匹配特征码 备注特征码通过ida，反编译ntoskrnl.exe，找到ZwXXXX，多次跳转获得
// KeServiceDescriptorTable			  0x4c8d15
// ShadowKeServiceDescriptorTable	0x4c8d1d
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

// 计算公式
// x64 (base[index] >> 4) + base
// x86 base + (0x7a - index) * 4		----- 未测试
ULONGLONG GetCurrentFunctionAddress(int index) {
	ULONGLONG CurrentNtOpenProcessAddress;
	__try {
		ULONG *SSDT_Adr;
		KeServiceDescriptorTable = GetKeServiceDescriptorTable64();
		SSDT_Adr = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
		CurrentNtOpenProcessAddress = (ULONGLONG)((SSDT_Adr[38]) >> 4) + (ULONGLONG)SSDT_Adr;
		KdPrint(("[hiDeivce]当前地址:%p", CurrentNtOpenProcessAddress));
	}
	__except (1) {
		KdPrint(("[hiDeivce]当前地址 into exception handle"));
		return 0;
	}
	return CurrentNtOpenProcessAddress;
}


ULONGLONG GetOriginFunctionAddress(UNICODE_STRING processName) {
	ULONGLONG originAddr;
	__try {
		// RtlInitUnicodeString(&processName, L"NtOpenProcess");
		originAddr = (ULONGLONG)MmGetSystemRoutineAddress(&processName);
		KdPrint(("[hiDeivce]原始地址:%p", originAddr));
	}
	__except (1) {
		KdPrint(("[hiDeivce]原始地址 into exception handle"));
		return 0;
	}
	return originAddr;
}

// 入口
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING str) {
	KdPrint(("[hiDeivce]载入驱动"));
	driver->DriverUnload = unload;
	UNICODE_STRING processName;
	RtlInitUnicodeString(&processName, L"NtOpenProcess");

	ULONGLONG CurrentAddress = GetCurrentFunctionAddress(38);
	ULONGLONG OriginAddress = GetOriginFunctionAddress(processName);

	if (CurrentAddress == OriginAddress) {
		KdPrint(("地址相同"));
	}
	else {
		KdPrint(("地址不同"));
	}

	return STATUS_SUCCESS;
}
