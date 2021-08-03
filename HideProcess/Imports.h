#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <windef.h>
#include <tdi.h>
#include <qos.h>

//obtained through windbg using command "dt _EXHANDLE"
typedef struct _EXHANDLE
{
    union
    {
        struct
        {
            ULONG TagBits : 2;                                                //0x0
            ULONG Index : 30;                                                 //0x0
        };
        VOID* GenericHandleOverlay;                                         //0x0
        ULONGLONG Value;                                                    //0x0
    };
} EXHANDLE, *PEXHANDLE;

//obtained through windbg using command "dt _handle_table_entry"
typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        LONG_PTR VolatileLowValue;
        LONG_PTR LowValue;
        PVOID InfoTable;
        LONG_PTR RefCountField;
        struct
        {
            ULONG_PTR Unlocked : 1;
            ULONG_PTR RefCnt : 16;
            ULONG_PTR Attributes : 3;
            ULONG_PTR ObjectPointerBits : 44;
        };
    };
    union
    {
        LONG_PTR HighValue;
        struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
        EXHANDLE LeafHandleValue;
        struct
        {
            ULONG32 GrantedAccessBits : 25;
            ULONG32 NoRightsUpgrade : 1;
            ULONG32 Spare1 : 6;
        };
        ULONG32 Spare2;
    };
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

//obtained through windbg using command "dt _HANDLE_TABLE_FREE_LIST"
typedef struct _HANDLE_TABLE_FREE_LIST
{
    ULONG_PTR FreeListLock;
    PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
    PHANDLE_TABLE_ENTRY lastFreeHandleEntry;
    LONG32 HandleCount;
    ULONG32 HighWaterMark;
    ULONG32 Reserved[8];
} HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;


//obtained through windbg using command "dt _handle_table"
typedef struct _HANDLE_TABLE
{
    ULONG32 NextHandleNeedingPool;
    LONG32 ExtraInfoPages;
    ULONG_PTR TableCode;
    PEPROCESS QuotaProcess;
    LIST_ENTRY HandleTableList;
    ULONG32 UniqueProcessId;
    union
    {
        ULONG32 Flags;
        struct
        {
            BOOLEAN StrictFIFO : 1;
            BOOLEAN EnableHandleExceptions : 1;
            BOOLEAN Rundown : 1;
            BOOLEAN Duplicated : 1;
            BOOLEAN RaiseUMExceptionOnInvalidHandleClose : 1;
        };
    };
    ULONG_PTR HandleContentionEvent;
    ULONG_PTR HandleTableLock;
    union
    {
        HANDLE_TABLE_FREE_LIST FreeLists[1];
        BOOLEAN ActualEntry[32];
    };
    PVOID DebugInfo;
} HANDLE_TABLE, * PHANDLE_TABLE;

typedef struct _IMAGE_SECTION_HEADER
{
    UCHAR  Name[8];
    union
    {
        ULONG PhysicalAddress;
        ULONG VirtualSize;
    } Misc;
    ULONG VirtualAddress;
    ULONG SizeOfRawData;
    ULONG PointerToRawData;
    ULONG PointerToRelocations;
    ULONG PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER // Size=20
{
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONGLONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    struct _IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

NTSYSAPI PVOID NTAPI RtlPcToFileHeader(
    PVOID PcValue,
    PVOID* BaseOfImage
);

NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
    PVOID Base
);
