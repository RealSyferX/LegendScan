#pragma once
// amdfend — LegendScan kernel driver headers (KDMapper-compatible, no wdf.h)
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>

//=================================================================
//  PEB / LDR structures (for GetModuleBaseAddress via PsGetProcessPeb)
//=================================================================
typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    SHORT          LoadCount;
    SHORT          TlsIndex;
    LIST_ENTRY     HashLinks;
    PVOID          SectionPointer;
    ULONG          CheckSum;
    ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN       InheritedAddressSpace;
    BOOLEAN       ReadImageFileExecOptions;
    BOOLEAN       BeingDebugged;
    BOOLEAN       Spare;
    HANDLE        Mutant;
    PVOID         ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

//=================================================================
//  Stealth structures
//=================================================================
typedef struct _PiDDBCacheEntry {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    ULONG          TimeDateStamp;
    NTSTATUS       LoadStatus;
    CHAR           _pad[64];
} PiDDBCacheEntry, *PPiDDBCacheEntry;

typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          ModuleStart;
    PVOID          ModuleEnd;
    ULONG64        UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

//=================================================================
//  SYSTEM_INFORMATION_CLASS + ZwQuerySystemInformation
//=================================================================
#ifndef _SYSTEM_INFORMATION_CLASS_DEFINED
#define _SYSTEM_INFORMATION_CLASS_DEFINED
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation  = 0,
    SystemModuleInformation = 11,
    SystemHandleInformation = 16,
    MaxSystemInfoClass      = 0xFF
} SYSTEM_INFORMATION_CLASS;
#endif

typedef struct _SYSTEM_MODULE {
    ULONG_PTR Reserved[2];
    PVOID     Base;
    ULONG     Size;
    ULONG     Flags;
    USHORT    Index;
    USHORT    Unknown;
    USHORT    LoadCount;
    USHORT    ModuleNameOffset;
    CHAR      ImageName[256];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_LIST {
    ULONG         Count;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_LIST, *PSYSTEM_MODULE_LIST;

EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(
    IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID                    SystemInformation,
    IN  ULONG                    SystemInformationLength,
    OUT PULONG                   ReturnLength OPTIONAL
);

EXTERN_C NTKERNELAPI PVOID    NTAPI RtlLookupElementGenericTableAvl(PRTL_AVL_TABLE, PVOID);
EXTERN_C NTKERNELAPI BOOLEAN  NTAPI RtlDeleteElementGenericTableAvl(PRTL_AVL_TABLE, PVOID);
EXTERN_C NTKERNELAPI PVOID    NTAPI MmGetSystemRoutineAddress(PUNICODE_STRING);

EXTERN_C NTKERNELAPI NTSTATUS NTAPI PsGetProcessExitStatus(PEPROCESS Process);
EXTERN_C NTKERNELAPI NTSTATUS NTAPI PsCreateSystemThread(
    PHANDLE ThreadHandle, ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PCLIENT_ID ClientId, PKSTART_ROUTINE StartRoutine, PVOID StartContext);
EXTERN_C NTKERNELAPI NTSTATUS NTAPI PsTerminateSystemThread(NTSTATUS ExitStatus);

// ZwQueryVirtualMemory — MEMORY_INFORMATION_CLASS already in ntifs.h, just declare fn
EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL
);
