#include "AmdNeed.h"

extern "C" {
    NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING, PDRIVER_INITIALIZE);
    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
}
extern "C" NTSYSAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

//=================================================================
//  LegendScan IOCTLs — 0x19Cx range (different from nv_disp 0x18Ex)
//=================================================================
constexpr ULONG ls_print_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C0, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_init_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_read_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_write_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_module_code  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_alloc_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_free_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C6, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_version_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C7, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_scan_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C8, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_query_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C9, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_mods_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19CA, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_inject_code  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19CB, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG ls_force_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19CC, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG LS_BUILD_TAG    = 0x00080005; // +FORCE write (commit RESERVE + strip GUARD/RO, kernel VirtualProtect-style)

struct info_t {
    HANDLE  target_pid;
    PVOID   target_address;
    PVOID   buffer_address;
    SIZE_T  size;
    SIZE_T  return_size;
    WCHAR   module_name[260];
    PVOID   base_address;
};

// Kernel-side value/AOB scan request — pattern bytes + mask (1=must match, 0=wildcard)
struct scan_req_t {
    PVOID   start;          // IN: region start VA in target
    SIZE_T  size;           // IN: region size
    UCHAR   pat[32];        // IN: pattern bytes (max 32)
    UCHAR   msk[32];        // IN: mask 1/0 per byte
    ULONG   patLen;         // IN: 1..32
    ULONG   maxHits;        // IN: cap (clamped to 256)
    ULONG   hitCount;       // OUT: hits found
    UINT64  hits[256];      // OUT: VA hits
};

// VirtualQuery request — one region per call, usermode loops 0..0x7FFFFFFFFFFF
struct query_req_t {
    PVOID   addr;           // IN: address to query
    PVOID   base;           // OUT: region base
    SIZE_T  size;           // OUT: region size
    ULONG   state;          // OUT: MEM_COMMIT etc
    ULONG   protect;        // OUT: PAGE_* (masked)
    ULONG   type;           // OUT: MEM_PRIVATE/MAPPED/IMAGE
    UCHAR   ok;             // OUT: 1 = valid
};

// Module-enum request — full PEB LDR walk in kernel (Toolhelp-proof: no usermode handle)
#define LS_MODS_MAX 128
struct ls_mod_t {
    PVOID base;
    ULONG size;
    WCHAR name[64];         // BaseDllName, truncated
};
struct ls_mods_req_t {
    ULONG     count;        // OUT: modules returned
    ULONG     max;          // IN: cap (clamped to LS_MODS_MAX)
    ls_mod_t  mods[LS_MODS_MAX];
};

static PEPROCESS  g_target_process = nullptr;
static KSPIN_LOCK g_procLock;
static BOOLEAN    g_efiGuardMode = TRUE;
static HANDLE     g_watchThread = nullptr;
static BOOLEAN    g_watchStop = FALSE;

static VOID SafeReleaseProcess() {
    if (g_target_process) {
        ObDereferenceObject(g_target_process);
        g_target_process = nullptr;
    }
}

static VOID WatcherThread(PVOID ctx) {
    UNREFERENCED_PARAMETER(ctx);
    while (!g_watchStop) {
        LARGE_INTEGER interval;
        interval.QuadPart = -5000000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
        if (g_watchStop) break;
        KIRQL irql;
        KeAcquireSpinLock(&g_procLock, &irql);
        if (g_target_process) {
            NTSTATUS exitStatus = PsGetProcessExitStatus(g_target_process);
            if (exitStatus != STATUS_PENDING) {
                SafeReleaseProcess();
            }
        }
        KeReleaseSpinLock(&g_procLock, irql);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID StartWatcherThread() {
    if (g_watchThread) return;
    g_watchStop = FALSE;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING threadName;
    RtlInitUnicodeString(&threadName, L"\\SystemRoot\\System32\\ntoskrnl.exe");
    InitializeObjectAttributes(&oa, &threadName, OBJ_KERNEL_HANDLE, nullptr, nullptr);
    PsCreateSystemThread(&g_watchThread, THREAD_ALL_ACCESS, &oa, nullptr, nullptr, WatcherThread, nullptr);
}

static VOID StopWatcherThread() {
    if (!g_watchThread) return;
    g_watchStop = TRUE;
    PVOID threadObj = nullptr;
    if (NT_SUCCESS(ObReferenceObjectByHandle(g_watchThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &threadObj, nullptr))) {
        KeWaitForSingleObject(threadObj, Executive, KernelMode, FALSE, nullptr);
        ObDereferenceObject(threadObj);
    }
    ZwClose(g_watchThread);
    g_watchThread = nullptr;
}

static PVOID  g_NtBase = nullptr;
static SIZE_T g_NtSize = 0;
static PLIST_ENTRY g_PsLoadedModuleList = nullptr;

static PVOID PatternScan(PVOID Base, SIZE_T Size, const CHAR* Pat, const CHAR* Msk) {
    SIZE_T plen = strlen(Msk); PVOID result = nullptr;
    __try {
        for (SIZE_T i = 0; i + plen <= Size; i++) {
            BOOLEAN ok = TRUE;
            for (SIZE_T j = 0; j < plen; j++)
                if (Msk[j] == 'x' && ((PUCHAR)Base)[i + j] != (UCHAR)Pat[j]) { ok = FALSE; break; }
            if (ok) { result = (PVOID)((ULONG_PTR)Base + i); break; }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { result = nullptr; }
    return result;
}

static PVOID RipRelative(PVOID Instr, INT Len) {
    INT32 off = *(INT32*)((ULONG_PTR)Instr + Len - 4);
    return (PVOID)((ULONG_PTR)Instr + Len + off);
}

static BOOLEAN ResolvePsLoadedModuleList() {
    if (g_PsLoadedModuleList) return TRUE;
    UNICODE_STRING name; RtlInitUnicodeString(&name, L"PsLoadedModuleList");
    g_PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&name);
    return g_PsLoadedModuleList != nullptr;
}

static BOOLEAN GetNtBase() {
    if (g_NtBase) return TRUE;
    ULONG needed = 0;
    ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (!needed) return FALSE;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, needed + 0x1000, 'MmSt');
    if (!buf) return FALSE;
    NTSTATUS st = ZwQuerySystemInformation(SystemModuleInformation, buf, needed + 0x1000, nullptr);
    if (NT_SUCCESS(st)) {
        auto list = (PSYSTEM_MODULE_LIST)buf;
        if (list->Count > 0) { g_NtBase = list->Modules[0].Base; g_NtSize = list->Modules[0].Size; }
    }
    ExFreePoolWithTag(buf, 'MmSt');
    return g_NtBase != nullptr;
}

static VOID WipePiDDBCache(PUNICODE_STRING DrvName, ULONG Timestamp) {
    if (g_efiGuardMode) return;
    if (!GetNtBase()) return;
    __try {
        PVOID hit = PatternScan(g_NtBase, g_NtSize, "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C", "xxx????x????xxx");
        if (!hit) return;
        PERESOURCE Lock = (PERESOURCE)RipRelative(hit, 7);
        ULONG_PTR la = (ULONG_PTR)Lock;
        if (!Lock || la < (ULONG_PTR)g_NtBase || la >= (ULONG_PTR)g_NtBase + g_NtSize) return;
        hit = PatternScan(g_NtBase, g_NtSize, "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0", "xxx????x????xxxx");
        if (!hit) return;
        PRTL_AVL_TABLE Table = (PRTL_AVL_TABLE)RipRelative(hit, 7);
        ULONG_PTR ta = (ULONG_PTR)Table;
        if (!Table || ta < (ULONG_PTR)g_NtBase || ta >= (ULONG_PTR)g_NtBase + g_NtSize) return;
        PPiDDBCacheEntry key = (PPiDDBCacheEntry)ExAllocatePoolWithTag(NonPagedPool, sizeof(PiDDBCacheEntry) + 256, 'PDiC');
        if (!key) return;
        RtlZeroMemory(key, sizeof(PiDDBCacheEntry) + 256);
        key->TimeDateStamp = Timestamp;
        key->DriverName = *DrvName;
        ExAcquireResourceExclusiveLite(Lock, TRUE);
        __try {
            PPiDDBCacheEntry found = (PPiDDBCacheEntry)RtlLookupElementGenericTableAvl(Table, key);
            if (found) {
                RemoveEntryList(&found->List);
                RtlDeleteElementGenericTableAvl(Table, found);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        ExReleaseResourceLite(Lock);
        ExFreePoolWithTag(key, 'PDiC');
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static VOID ScrubMmUnloaded(PUNICODE_STRING DrvName) {
    if (!GetNtBase()) return;
    __try {
        PVOID hit = PatternScan(g_NtBase, g_NtSize, "\x4C\x8B\x15\x00\x00\x00\x00\x4D\x85\xD2", "xxx????xxx");
        if (!hit) return;
        PMM_UNLOADED_DRIVER* List = (PMM_UNLOADED_DRIVER*)RipRelative(hit, 7);
        hit = PatternScan(g_NtBase, g_NtSize, "\x8B\x05\x00\x00\x00\x00", "xx????");
        if (!hit) return;
        PULONG LastIdx = (PULONG)RipRelative(hit, 6);
        if (!List || !*List || !LastIdx) return;
        ULONG count = min(*LastIdx, 50u);
        for (ULONG i = 0; i < count; i++) {
            PMM_UNLOADED_DRIVER e = &(*List)[i];
            if (e->Name.Buffer && RtlCompareUnicodeString(&e->Name, DrvName, TRUE) == 0) {
                RtlZeroMemory(e->Name.Buffer, e->Name.MaximumLength);
                RtlZeroMemory(e, sizeof(MM_UNLOADED_DRIVER));
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static VOID PatchETW() {
    if (!GetNtBase()) return;
    PVOID fn = PatternScan(g_NtBase, g_NtSize, "\x48\x89\x5C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57", "xxxxxxxxxxxxxxxx");
    if (!fn) return;
    ULONG_PTR fnAddr = (ULONG_PTR)fn;
    if (fnAddr < (ULONG_PTR)g_NtBase || fnAddr >= (ULONG_PTR)g_NtBase + g_NtSize) return;
    __try {
        ULONG_PTR cr0 = __readcr0();
        _disable();
        __writecr0(cr0 & ~0x10000ULL);
        *(PUCHAR)fn = 0xC3;
        _mm_sfence();
        __writecr0(cr0);
        _enable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); }
}

static VOID PatchEtwTi() {
    if (!GetNtBase()) return;
    const CHAR p[] = "\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x40";
    const CHAR m[] = "xxxxxxxxxxxxxxx";
    PVOID fn = PatternScan(g_NtBase, g_NtSize, p, m);
    if (!fn) return;
    ULONG_PTR a = (ULONG_PTR)fn;
    if (a < (ULONG_PTR)g_NtBase || a >= (ULONG_PTR)g_NtBase + g_NtSize) return;
    __try {
        ULONG_PTR cr0 = __readcr0();
        _disable();
        __writecr0(cr0 & ~0x10000ULL);
        *(PUCHAR)fn = 0xC3;
        _mm_sfence();
        __writecr0(cr0);
        _enable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); }
}

static UCHAR  g_mmCopyOrig[14] = {};
static PVOID  g_mmCopyAddr = nullptr;
static PVOID  g_mmTrampolineAddr = nullptr;

static NTSTATUS NTAPI HookedMmCopy(PEPROCESS SrcProc, PVOID SrcAddr, PEPROCESS DstProc, PVOID DstAddr, SIZE_T Size, KPROCESSOR_MODE Mode, PSIZE_T Copied) {
    if (!g_mmTrampolineAddr) return STATUS_UNSUCCESSFUL;
    using MmCopy_t = NTSTATUS(NTAPI*)(PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T);
    auto trampFn = (MmCopy_t)g_mmTrampolineAddr;
    return trampFn(SrcProc, SrcAddr, DstProc, DstAddr, Size, Mode, Copied);
}

static VOID HookMmCopyVirtualMemory() {
    UNICODE_STRING name; RtlInitUnicodeString(&name, L"MmCopyVirtualMemory");
    g_mmCopyAddr = MmGetSystemRoutineAddress(&name);
    if (!g_mmCopyAddr) return;
    g_mmTrampolineAddr = ExAllocatePoolWithTag(NonPagedPoolExecute, 32, 'pmaT');
    if (!g_mmTrampolineAddr) return;
    memcpy(g_mmCopyOrig, g_mmCopyAddr, 14);
    UCHAR* tramp = (UCHAR*)g_mmTrampolineAddr;
    RtlZeroMemory(tramp, 32);
    memcpy(tramp, g_mmCopyOrig, 14);
    uintptr_t resumeAddr = (uintptr_t)g_mmCopyAddr + 14;
    tramp[14] = 0xFF; tramp[15] = 0x25; *(ULONG*)(&tramp[16]) = 0x00000000; memcpy(&tramp[20], &resumeAddr, 8);
    UCHAR jmp14[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00, 0,0,0,0,0,0,0,0 };
    uintptr_t hookAddr = (uintptr_t)HookedMmCopy; memcpy(&jmp14[6], &hookAddr, 8);
    __try {
        ULONG_PTR cr0 = __readcr0(); _disable(); __writecr0(cr0 & ~0x10000ULL);
        memcpy(g_mmCopyAddr, jmp14, 14); _mm_sfence(); __writecr0(cr0); _enable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); }
}

static VOID UnhookMmCopyVirtualMemory() {
    if (!g_mmCopyAddr) return;
    __try {
        ULONG_PTR cr0 = __readcr0(); _disable(); __writecr0(cr0 & ~0x10000ULL);
        memcpy(g_mmCopyAddr, g_mmCopyOrig, 14); _mm_sfence(); __writecr0(cr0); _enable();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { _enable(); }
    if (g_mmTrampolineAddr) { ExFreePoolWithTag(g_mmTrampolineAddr, 'pmaT'); g_mmTrampolineAddr = nullptr; }
    g_mmCopyAddr = nullptr;
}

static VOID SpoofTPMBootStatus() {
    if (!GetNtBase()) return;
    __try {
        UNICODE_STRING varName; RtlInitUnicodeString(&varName, L"BootStatusPolicy");
        GUID efiGuid = { 0x8BE4DF61, 0x93CA, 0x11D2, {0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C} };
        ULONG policy = 0;
        typedef NTSTATUS(NTAPI* ZwSetSysEnv_t)(PUNICODE_STRING, LPGUID, PVOID, ULONG, ULONG);
        UNICODE_STRING zwName; RtlInitUnicodeString(&zwName, L"ZwSetSystemEnvironmentValueEx");
        auto pFn = (ZwSetSysEnv_t)MmGetSystemRoutineAddress(&zwName);
        if (pFn) pFn(&varName, &efiGuid, &policy, sizeof(policy), 7);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static VOID SpoofDriverName(PDRIVER_OBJECT drvObj) {
    UNICODE_STRING fake; RtlInitUnicodeString(&fake, L"\\Driver\\WdNisDrv");
    if (drvObj->DriverName.MaximumLength >= fake.Length + sizeof(WCHAR)) {
        RtlZeroMemory(drvObj->DriverName.Buffer, drvObj->DriverName.MaximumLength);
        RtlCopyUnicodeString(&drvObj->DriverName, &fake);
    }
}

static VOID WriteBooleanMdl(PVOID addr, BOOLEAN val) {
    if (!addr) return; if ((ULONG_PTR)addr < 0xFFFF000000000000ULL) return;
    PMDL mdl = IoAllocateMdl(addr, sizeof(BOOLEAN), FALSE, FALSE, nullptr);
    if (!mdl) return; MmBuildMdlForNonPagedPool(mdl);
    __try {
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
        if (mapped) { MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE); *(BOOLEAN*)mapped = val; MmUnmapLockedPages(mapped, mdl); }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    IoFreeMdl(mdl);
}

static VOID WriteUlongMdl(PVOID addr, ULONG val) {
    if (!addr) return; if ((ULONG_PTR)addr < 0xFFFF000000000000ULL) return;
    PMDL mdl = IoAllocateMdl(addr, sizeof(ULONG), FALSE, FALSE, nullptr);
    if (!mdl) return; MmBuildMdlForNonPagedPool(mdl);
    __try {
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
        if (mapped) { MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE); *(ULONG*)mapped = val; MmUnmapLockedPages(mapped, mdl); }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    IoFreeMdl(mdl);
}

static VOID SpoofSecureBoot() {
    __try {
        UNICODE_STRING n1; RtlInitUnicodeString(&n1, L"KeSecureBootEnabled"); WriteBooleanMdl(MmGetSystemRoutineAddress(&n1), TRUE);
        UNICODE_STRING n2; RtlInitUnicodeString(&n2, L"g_CiEnabled"); PVOID p = MmGetSystemRoutineAddress(&n2); if (p) WriteBooleanMdl(p, TRUE);
        UNICODE_STRING n3; RtlInitUnicodeString(&n3, L"SeILSigningPolicy"); PVOID q = MmGetSystemRoutineAddress(&n3); if (q) WriteUlongMdl(q, 0x8);
        UNICODE_STRING n4; RtlInitUnicodeString(&n4, L"g_CiOptions"); PVOID r = MmGetSystemRoutineAddress(&n4); if (r) WriteUlongMdl(r, 0x6);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static VOID AddJitter() {
    LARGE_INTEGER delay; delay.QuadPart = -(LONGLONG)((1 + (KeQueryTimeIncrement() % 5)) * 10000);
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
}

static ULONG GetSelfTimestamp() {
    ULONG needed = 0; ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (!needed) return 0;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, needed + 0x1000, 'FMfn');
    if (!buf) return 0;
    ULONG ts = 0;
    if (NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, buf, needed + 0x1000, nullptr))) {
        __try {
            auto list = (PSYSTEM_MODULE_LIST)buf; ULONG_PTR self = (ULONG_PTR)GetSelfTimestamp;
            for (ULONG i = 0; i < list->Count; i++) {
                ULONG_PTR base = (ULONG_PTR)list->Modules[i].Base; ULONG size = list->Modules[i].Size;
                if (self >= base && self < base + size) {
                    auto dos = (IMAGE_DOS_HEADER*)base;
                    if (dos->e_magic == 0x5A4D && dos->e_lfanew < 0x400) {
                        auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
                        if (nt->Signature == 0x00004550) ts = nt->FileHeader.TimeDateStamp;
                    } break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { ts = 0; }
    }
    ExFreePoolWithTag(buf, 'FMfn'); return ts;
}

static VOID StealthInit(PDRIVER_OBJECT drvObj) {
    AddJitter();
    UNICODE_STRING drvName; RtlInitUnicodeString(&drvName, L"amdfend.sys");
    WipePiDDBCache(&drvName, GetSelfTimestamp());
    ScrubMmUnloaded(&drvName);
    SpoofSecureBoot();
    SpoofTPMBootStatus();
    AddJitter();
    if (drvObj) SpoofDriverName(drvObj);
}

//=================================================================
//  Core memory ops
//=================================================================
static PVOID GetModuleBaseAddress(PEPROCESS Process, const WCHAR* ModuleName) {
    if (!Process || !ModuleName) return nullptr;
    KAPC_STATE apc; KeStackAttachProcess(Process, &apc);
    PVOID base = nullptr;
    __try {
        PPEB peb = PsGetProcessPeb(Process);
        if (!peb || !peb->Ldr) __leave;
        UNICODE_STRING target; RtlInitUnicodeString(&target, ModuleName);
        for (PLIST_ENTRY e = peb->Ldr->InLoadOrderModuleList.Flink; e != &peb->Ldr->InLoadOrderModuleList; e = e->Flink) {
            auto mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (mod->BaseDllName.Buffer && RtlCompareUnicodeString(&mod->BaseDllName, &target, TRUE) == 0) { base = mod->DllBase; break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { base = nullptr; }
    KeUnstackDetachProcess(&apc);
    return base;
}

static NTSTATUS SafeCopy(PEPROCESS src, PVOID srcA, PEPROCESS dst, PVOID dstA, SIZE_T sz, PSIZE_T copied) {
    // NOTE: no usermode-range check here on purpose. KernelScanRegion uses a
    // NonPagedPool temp buffer (kernel VA) as one side of the copy, so a
    // blanket user-range check breaks ALL scans (0 hits). Target validation
    // lives in ctl_io (read/write/scan) + MdlWrite + KernelScanRegion start.
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    __try { st = MmCopyVirtualMemory(src, srcA, dst, dstA, sz, KernelMode, copied); }
    __except (EXCEPTION_EXECUTE_HANDLER) { st = GetExceptionCode(); }
    return st;
}

static PEPROCESS AcquireTargetRef() {
    KIRQL irql; PEPROCESS proc = nullptr;
    KeAcquireSpinLock(&g_procLock, &irql);
    if (g_target_process) { proc = g_target_process; ObReferenceObject(proc); }
    KeReleaseSpinLock(&g_procLock, irql);
    return proc;
}

typedef NTSTATUS(NTAPI* ZwFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);

// Write via MDL mapping — succeeds on PAGE_READONLY pages where MmCopy fails.
// Probe IoReadAccess (passes on any readable page), then force mapping writable.
// HARD RULE: usermode targets only. Kernel addresses are rejected outright so a
// bad pointer chain (wrong offset -> garbage addr) can never bugcheck.
static NTSTATUS MdlWrite(PEPROCESS proc, PVOID target, PVOID src, SIZE_T sz, PSIZE_T written) {
    if (!proc || !target || !src || !sz) return STATUS_INVALID_PARAMETER;
    {
        ULONG_PTR a = (ULONG_PTR)target;
        constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
        if (a == 0 || a > kMaxUser || sz > 0x1000000 || sz > kMaxUser || a + sz < a || a + sz - 1 > kMaxUser)
            return STATUS_ACCESS_VIOLATION;
    }
    if (written) *written = 0;
    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    SIZE_T done = 0;
    __try {
        PUCHAR t = (PUCHAR)target;
        PUCHAR s = (PUCHAR)src;
        SIZE_T left = sz;
        while (left) {
            SIZE_T chunk = left > 0x4000 ? 0x4000 : left;
            PMDL mdl = IoAllocateMdl(t, (ULONG)chunk, FALSE, FALSE, nullptr);
            if (!mdl) { st = STATUS_INSUFFICIENT_RESOURCES; __leave; }
            BOOLEAN locked = FALSE;
            __try {
                MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                locked = TRUE;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                IoFreeMdl(mdl);
                st = GetExceptionCode();
                __leave;
            }
            PVOID map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
            if (!map) { MmUnlockPages(mdl); IoFreeMdl(mdl); st = STATUS_UNSUCCESSFUL; __leave; }
            MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            RtlCopyMemory(map, s, chunk);
            MmUnmapLockedPages(map, mdl);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            t += chunk; s += chunk; left -= chunk; done += chunk;
        }
        st = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) { st = GetExceptionCode(); }
    KeUnstackDetachProcess(&apc);
    if (written) *written = done;
    return st;
}

// ZwProtectVirtualMemory: resolved dynamically (zero link risk, codebase style)
typedef NTSTATUS(NTAPI* ZwProtectVirtualMemory_t)(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

//=================================================================
//  FORCE write — kernel VirtualProtect-style + commit-on-demand.
//  Plain VirtualProtect can NEVER make RESERVE memory writable (no
//  physical pages exist) — so this commits first via
//  ZwAllocateVirtualMemory(MEM_COMMIT), strips PAGE_GUARD / read-only
//  via ZwProtectVirtualMemory(RWX), writes (MmCopy, MDL fallback),
//  then restores the original protect when it changed one.
//  Trace bits in outTrace: 0=entered 1=queried 2=committed
//  3=unprotected 4=mmcopy 5=mdl 6=restored.
//  Returns the WRITE ntstatus (transport always STATUS_SUCCESS).
//  HARD RULE: usermode targets only, request capped at 64KB.
//=================================================================
static NTSTATUS KernelForceWrite(PEPROCESS proc, HANDLE hProc, PVOID target,
    PVOID srcScannerVA, SIZE_T sz, UINT64* outTrace) {
    UINT64 trace = 0;
    if (outTrace) *outTrace = 0;
    if (!proc || !hProc || !target || !srcScannerVA || !sz || sz > 0x10000)
        return STATUS_INVALID_PARAMETER;
    {
        ULONG_PTR a = (ULONG_PTR)target;
        constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
        if (a == 0 || a > kMaxUser || a + sz < a || a + sz - 1 > kMaxUser)
            return STATUS_ACCESS_VIOLATION;
    }
    trace |= (1ULL << 0);
    // 1. query the region
    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T retLen = 0;
    PVOID q = (PVOID)((ULONG_PTR)target & ~(PAGE_SIZE - 1));
    NTSTATUS st = ZwQueryVirtualMemory(hProc, q, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
    if (!NT_SUCCESS(st)) { if (outTrace) *outTrace = trace; return st; }
    trace |= (1ULL << 1);
    // 2. commit when RESERVE (this is the step VirtualProtect cannot do)
    if (mbi.State == MEM_RESERVE) {
        PVOID cbase = (PVOID)((ULONG_PTR)target & ~(PAGE_SIZE - 1));
        SIZE_T csize = (((ULONG_PTR)target + sz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - (ULONG_PTR)cbase;
        st = ZwAllocateVirtualMemory(hProc, &cbase, 0, &csize, MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) { if (outTrace) *outTrace = trace; return st; }
        trace |= (1ULL << 2);
        st = ZwQueryVirtualMemory(hProc, q, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
        if (!NT_SUCCESS(st)) { if (outTrace) *outTrace = trace; return st; }
    }
    if (mbi.State != MEM_COMMIT) { if (outTrace) *outTrace = trace; return STATUS_INVALID_ADDRESS; }
    // 3. strip GUARD / force RW when the page is not writable
    ULONG baseProt = mbi.Protect & 0xFF;
    bool writable = (baseProt == 0x04 || baseProt == 0x08 || baseProt == 0x40 || baseProt == 0x80 || baseProt == 0x0C);
    bool guarded = (mbi.Protect & PAGE_GUARD) != 0;
    ULONG oldProt = 0;
    bool changed = false;
    if (!writable || guarded) {
        UNICODE_STRING zpn; RtlInitUnicodeString(&zpn, L"ZwProtectVirtualMemory");
        auto pProt = (ZwProtectVirtualMemory_t)MmGetSystemRoutineAddress(&zpn);
        if (!pProt) { if (outTrace) *outTrace = trace; return STATUS_PROCEDURE_NOT_FOUND; }
        PVOID pbase = mbi.BaseAddress;
        SIZE_T psize = (SIZE_T)((ULONG_PTR)target + sz - (ULONG_PTR)mbi.BaseAddress);
        st = pProt(hProc, &pbase, &psize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (!NT_SUCCESS(st)) { if (outTrace) *outTrace = trace; return st; }
        changed = true;
        trace |= (1ULL << 3);
    }
    // 4. pull source bytes into a kernel temp (caller VA via MmCopy)
    PUCHAR tmp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, sz, 'LSfw');
    if (!tmp) st = STATUS_INSUFFICIENT_RESOURCES;
    else {
        SIZE_T got = 0;
        st = SafeCopy(PsGetCurrentProcess(), srcScannerVA, PsGetCurrentProcess(), tmp, sz, &got);
        if (!NT_SUCCESS(st) || got != sz) {
            ExFreePoolWithTag(tmp, 'LSfw');
            tmp = nullptr;
        }
    }
    // 5. write: MmCopy first, MDL writable-map fallback (covers RO code too)
    if (tmp) {
        SIZE_T wrote = 0;
        st = SafeCopy(PsGetCurrentProcess(), tmp, proc, target, sz, &wrote);
        if (NT_SUCCESS(st) && wrote == sz) trace |= (1ULL << 4);
        else {
            SIZE_T mw = 0;
            st = MdlWrite(proc, target, tmp, sz, &mw);
            if (NT_SUCCESS(st) && mw == sz) trace |= (1ULL << 5);
        }
        ExFreePoolWithTag(tmp, 'LSfw');
    }
    // 6. restore original protect when we changed it
    if (changed) {
        UNICODE_STRING zpn2; RtlInitUnicodeString(&zpn2, L"ZwProtectVirtualMemory");
        auto pProt2 = (ZwProtectVirtualMemory_t)MmGetSystemRoutineAddress(&zpn2);
        if (pProt2) {
            PVOID rbase = mbi.BaseAddress;
            SIZE_T rsize = (SIZE_T)((ULONG_PTR)target + sz - (ULONG_PTR)mbi.BaseAddress);
            ULONG dummy = 0;
            if (NT_SUCCESS(pProt2(hProc, &rbase, &rsize, oldProt, &dummy))) trace |= (1ULL << 6);
        }
    }
    if (outTrace) *outTrace = trace;
    return st;
}

static NTSTATUS OpenTarget(HANDLE* outHandle, PEPROCESS proc) {
    if (!outHandle || !proc) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, nullptr, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, outHandle);
    if (!NT_SUCCESS(st))
        st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, nullptr, (ACCESS_MASK)0x43A, *PsProcessType, KernelMode, outHandle);
    return st;
}

//=================================================================
//  DLL inject — kernel LoadLibraryW remote thread (no usermode handles)
//  Resolves the REAL LoadLibraryW in the target's kernelbase (kernel32
//  only holds a forwarder). 64-bit targets only.
//=================================================================
static SIZE_T k_wcslen(const WCHAR* s) {
    SIZE_T n = 0;
    while (n < 260 && s[n]) n++;
    return n;
}
// Export-table resolve inside target memory (attached). Forwarder RVAs refuse.
static PVOID ResolveTargetExport(PEPROCESS proc, PVOID modBase, const char* want) {
    if (!proc || !modBase || !want) return nullptr;
    size_t wl = strlen(want);
    if (!wl || wl > 64) return nullptr;
    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);
    PVOID result = nullptr;
    __try {
        PUCHAR b = (PUCHAR)modBase;
        if (*(USHORT*)b != 0x5A4D) __leave;
        ULONG lfanew = *(ULONG*)(b + 0x3C);
        if (lfanew > 0x1000) __leave;
        PUCHAR nt = b + lfanew;
        if (*(ULONG*)nt != 0x00004550) __leave;
        if (*(USHORT*)(nt + 24) != 0x20B) __leave; // 64-bit only
        ULONG expRVA = *(ULONG*)(nt + 24 + 112);
        ULONG expSize = *(ULONG*)(nt + 24 + 112 + 4);
        if (!expRVA || !expSize || expSize > 0x100000) __leave;
        PUCHAR exp = b + expRVA;
        ULONG nNames = *(ULONG*)(exp + 24);
        ULONG addrFns = *(ULONG*)(exp + 28);
        ULONG addrNames = *(ULONG*)(exp + 32);
        ULONG addrOrds = *(ULONG*)(exp + 36);
        if (!nNames || nNames > 20000) __leave;
        for (ULONG i = 0; i < nNames; i++) {
            ULONG nameRVA = *(ULONG*)(b + addrNames + (SIZE_T)i * 4);
            if (!nameRVA || nameRVA > 0x10000000) continue;
            char* nm = (char*)(b + nameRVA);
            SIZE_T k = 0;
            for (; k < wl; k++) if (nm[k] != want[k]) break;
            if (k != wl || nm[wl] != 0) continue;
            USHORT ord = *(USHORT*)(b + addrOrds + (SIZE_T)i * 2);
            ULONG fnRVA = *(ULONG*)(b + addrFns + (SIZE_T)ord * 4);
            if (!fnRVA || fnRVA > 0x10000000) break;
            if (fnRVA >= expRVA && fnRVA < expRVA + expSize) break; // forwarder: refuse
            result = (PVOID)(b + fnRVA);
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { result = nullptr; }
    KeUnstackDetachProcess(&apc);
    return result;
}

static VOID FreeRemoteMem(HANDLE hProc, PVOID addr) {
    if (!hProc || !addr) return;
    UNICODE_STRING zfn; RtlInitUnicodeString(&zfn, L"ZwFreeVirtualMemory");
    auto pFree = (ZwFreeVirtualMemory_t)MmGetSystemRoutineAddress(&zfn);
    if (pFree) { PVOID b = addr; SIZE_T s = 0; pFree(hProc, &b, &s, MEM_RELEASE); }
}

// ZwCreateThreadEx: undocumented, resolve dynamically (present on Win10+).
// Creates a USER thread in the target — the thread starts through the normal
// usermode path, so kCFG never sees a kernel guarded-icall into usermode.
typedef NTSTATUS(NTAPI* ZwCreateThreadEx_t)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

// NOTE: ntoskrnl does NOT export Zw/NtCreateThreadEx (verified via dumpbin),
// so injection uses a user-mode APC instead (KeInsertQueueApc with
// NormalRoutine=LoadLibraryW into the main thread). Same kCFG-safe property:
// delivery runs LoadLibraryW in usermode, never through a kernel guarded call.

// LdrLoadDll stub injection (KMDllInjector-proven shape): the APC carries a
// tiny RWX stub that calls ntdll!LdrLoadDll and records executed + NTSTATUS.
// This separates "APC never fired" (target never alerted) from "DLL failed"
// (bitness/deps, with the loader's exact code).
struct InjArgs {
    PVOID ldrLoadDll;     // +0
    WCHAR path[260];      // +8
    USHORT usLen;         // +528
    USHORT usMax;         // +530
    ULONG _pad;           // +532
    PVOID usBuf;          // +536
    PVOID hMod;           // +544 (HANDLE)
    LONG executed;        // +552
    LONG status;          // +556 (NTSTATUS from LdrLoadDll)
    PVOID origRip;        // +560 (hijack resume point)
}; // 568 bytes
// rcx = &InjArgs. Saves flags+volatiles, LdrLoadDll(NULL, 0, &us, &hMod),
// restores everything (RAX=origRip), jmp origRip.
static const UCHAR kInjStub[] = {
    0x9C,                                                 // pushfq
    0x50, 0x51, 0x52,                                     // push rax,rcx,rdx
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,       // push r8-r11
    0x49, 0x89, 0xCA,                                     // mov r10, rcx
    0xC7, 0x81, 0x28, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov dword [rcx+552], 1
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28
    0x31, 0xC9,                                           // xor ecx, ecx
    0x31, 0xD2,                                           // xor edx, edx
    0x4D, 0x8D, 0x82, 0x10, 0x02, 0x00, 0x00,             // lea r8, [r10+528]
    0x4D, 0x8D, 0x8A, 0x20, 0x02, 0x00, 0x00,             // lea r9, [r10+544]
    0x49, 0x8B, 0x02,                                     // mov rax, [r10]
    0xFF, 0xD0,                                           // call rax
    0x41, 0x89, 0x82, 0x2C, 0x02, 0x00, 0x00,             // mov [r10+556], eax
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    0x49, 0x8B, 0x82, 0x30, 0x02, 0x00, 0x00,             // mov rax, [r10+560]
    0x48, 0x89, 0x44, 0x24, 0x30,                         // mov [rsp+48], rax
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,       // pop r11,r10,r9,r8
    0x5A, 0x59, 0x58,                                     // pop rdx,rcx,rax(=orig)
    0x9D,                                                 // popfq
    0xFF, 0xE0                                            // jmp rax
};
#define LS_INJ_STUB_SZ 128
typedef VOID(NTAPI* KeAlertThread_t)(PKTHREAD Thread, KPROCESSOR_MODE AlertMode);

// Suspend/context APIs: verified exported via dumpbin; signatures confirmed
// against disassembly (Suspend/Resume take PEPROCESS only; Get/Set take
// Thread+Context+Mode). Resolved dynamically: zero link risk.
typedef NTSTATUS(NTAPI* PsSuspendProcess_t)(PEPROCESS Process);
typedef NTSTATUS(NTAPI* PsResumeProcess_t)(PEPROCESS Process);
typedef NTSTATUS(NTAPI* PsGetContextThread_t)(PETHREAD Thread, PVOID Context, KPROCESSOR_MODE Mode);
typedef NTSTATUS(NTAPI* PsSetContextThread_t)(PETHREAD Thread, PVOID Context, KPROCESSOR_MODE Mode);
#define LS_CTX_SIZE 1232      // sizeof(CONTEXT) x64
#define LS_CTX_FLAGS_OFF 48   // ContextFlags
#define LS_CTX_RCX_OFF 128
#define LS_CTX_RIP_OFF 248
#define LS_CONTEXT_FULL 0x10000B

// Local APC import declarations (this WDK config doesn't expose them via
// ntddk.h — declare directly). x64 KAPC = 0x58 bytes (Type..Inserted;
// ApcStateIndex/ApcMode/Inserted live at +80..82 — a short alloc breaks
// KeInsertQueueApc AND overruns the pool).
#define LS_KAPC_SIZE 0x58
EXTERN_C NTKERNELAPI VOID NTAPI KeInitializeApc(
    PVOID Apc, PVOID Thread, INT Environment,
    PVOID KernelRoutine, PVOID RundownRoutine, PVOID NormalRoutine,
    KPROCESSOR_MODE ApcMode, PVOID NormalContext);
EXTERN_C NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    PVOID Apc, PVOID SystemArgument1, PVOID SystemArgument2, UCHAR Increment);

extern "C" {
    NTKERNELAPI HANDLE NTAPI PsGetProcessId(PEPROCESS Process);
    NTKERNELAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread);
}

static VOID NTAPI InjectApcKernel(PVOID Apc, PVOID NormalRoutine,
    PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Apc); UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1); UNREFERENCED_PARAMETER(SystemArgument2);
    // delivery vehicle only — real work happens in usermode NormalRoutine
}
static VOID NTAPI InjectApcRundown(PVOID Apc) {
    if (Apc) ExFreePoolWithTag(Apc, 'LSap'); // thread died with APC pending
}

// First-thread TIDs of a PID via SystemProcessInformation (x64 offsets:
// Threads[] @ +256, stride 80, ClientId.UniqueThread @ +48 within).
// Queues to several threads: whichever alerts first runs LoadLibrary
// (ref-counted, harmless if more than one fires).
static int FindTargetTids(HANDLE pidH, HANDLE* out, int max) {
    if (!pidH || !out || max <= 0) return 0;
    int n = 0;
    ULONG needed = 0;
    ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, nullptr, 0, &needed);
    if (!needed || needed > 0x2000000) return 0;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, needed + 0x1000, 'LSth');
    if (!buf) return 0;
    __try {
        if (NT_SUCCESS(ZwQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, buf, needed + 0x1000, nullptr))) {
            PUCHAR e = (PUCHAR)buf;
            for (;;) {
                HANDLE ep = *(HANDLE*)(e + 80); // UniqueProcessId
                if (ep == pidH) {
                    ULONG nTh = *(ULONG*)(e + 4);
                    for (ULONG i = 0; i < nTh && n < max; i++) {
                        HANDLE tid = *(HANDLE*)(e + 256 + (SIZE_T)i * 80 + 48);
                        if (tid) out[n++] = tid;
                    }
                    break;
                }
                ULONG next = *(ULONG*)e;
                if (!next) break;
                e += next;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    ExFreePoolWithTag(buf, 'LSth');
    return n;
}
// First thread (main thread) of a PID via SystemProcessInformation (x64 offsets).
static BOOLEAN FindMainThreadId(HANDLE pidH, HANDLE* outTid) {
    HANDLE t = nullptr;
    if (FindTargetTids(pidH, &t, 1) < 1) return FALSE;
    if (outTid) *outTid = t;
    return TRUE;
}

static NTSTATUS KernelInjectDll(PEPROCESS proc, const WCHAR* dllPath, PVOID* outBase, UINT64* outTrace) {
    UINT64 trace = 0;
#define INJ_T(b) do { trace |= (1ULL << (b)); } while (0)
#define INJ_RET(x) do { if (outTrace) *outTrace = trace; return (x); } while (0)
    // bits: 0=entered 1=apis 2=thread 3=suspended 4=gotctx 5=setctx 6=apc
    //       7=exec 8=ldrok 9=module
    if (outBase) *outBase = nullptr;
    if (!proc || !dllPath) INJ_RET(STATUS_INVALID_PARAMETER);
    INJ_T(0);
    WCHAR path[260]{};
    SIZE_T pl = k_wcslen(dllPath);
    if (!pl || pl > 259) INJ_RET(STATUS_INVALID_PARAMETER);
    for (SIZE_T i = 0; i < pl; i++) path[i] = dllPath[i];
    const WCHAR* fn = path;
    for (const WCHAR* p = path; *p; p++) if (*p == L'\\' || *p == L'/') fn = p + 1;
    if (!*fn) INJ_RET(STATUS_INVALID_PARAMETER);
    // LdrLoadDll lives in ntdll (implemented there — no forwarder games).
    // We call it through a tiny RWX stub so we get its exact NTSTATUS back
    // (deps missing? bitness?) instead of LoadLibraryW's bare NULL.
    PVOID nt = GetModuleBaseAddress(proc, L"ntdll.dll");
    if (!nt) INJ_RET(STATUS_DLL_NOT_FOUND);
    PVOID ldrLoadDll = ResolveTargetExport(proc, nt, "LdrLoadDll");
    if (!ldrLoadDll) INJ_RET(STATUS_PROCEDURE_NOT_FOUND);
    {
        // sanity: must be a canonical usermode RX address, never kernel
        ULONG_PTR la = (ULONG_PTR)ldrLoadDll;
        constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
        if (la < 0x10000 || la > kMaxUser) INJ_RET(STATUS_PROCEDURE_NOT_FOUND);
    }
    HANDLE hProc = nullptr;
    NTSTATUS st = OpenTarget(&hProc, proc);
    if (!NT_SUCCESS(st)) INJ_RET(st);
    // args page (RW) + stub page (RWX) in target
    PVOID rArgs = nullptr;
    SIZE_T asz = sizeof(InjArgs);
    st = ZwAllocateVirtualMemory(hProc, &rArgs, 0, &asz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !rArgs) { ZwClose(hProc); INJ_RET(NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st); }
    PVOID rStub = nullptr;
    SIZE_T ssz = LS_INJ_STUB_SZ;
    st = ZwAllocateVirtualMemory(hProc, &rStub, 0, &ssz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st) || !rStub) { FreeRemoteMem(hProc, rArgs); ZwClose(hProc); INJ_RET(NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st); }
    {
        InjArgs a{};
        a.ldrLoadDll = ldrLoadDll;
        for (SIZE_T i = 0; i < pl; i++) a.path[i] = path[i];
        a.usLen = (USHORT)(pl * sizeof(WCHAR));
        a.usMax = (USHORT)sizeof(a.path);
        a.usBuf = (PVOID)((ULONG_PTR)rArgs + 8);
        // hMod/executed/status already zero
        KAPC_STATE apc2;
        KeStackAttachProcess(proc, &apc2);
        __try {
            RtlCopyMemory(rArgs, &a, sizeof(a));
            RtlCopyMemory(rStub, kInjStub, sizeof(kInjStub));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { st = GetExceptionCode(); }
        KeUnstackDetachProcess(&apc2);
        if (!NT_SUCCESS(st)) { FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs); ZwClose(hProc); INJ_RET(st); }
    }
    // kernel handle for the thread: Ob* + Zw* stay in one consistent domain.
    // NOTE: must NOT be a SYSTEM thread (PsCreateSystemThread starts via
    // PspSystemThreadStartup's kernel guarded-icall, and kCFG bugchecks
    // 0x139 guard_icall_bugcheck on usermode targets — proven by dump).
    // And ntoskrnl exports no Zw/NtCreateThreadEx.
    // PRIMARY: hijack (deterministic, needs no alertable wait): suspend
    // process -> main-thread Rip=stub, Rcx=args -> resume. Stub restores
    // regs/flags and jmps back to origRip. FALLBACK: one user-mode APC, used
    // ONLY when hijack didn't apply — never both (a stale second run would
    // jmp to a dead resume point).
    bool hijacked = false;
    {
        UNICODE_STRING s1, s2, s3, s4;
        RtlInitUnicodeString(&s1, L"PsSuspendProcess");
        RtlInitUnicodeString(&s2, L"PsResumeProcess");
        RtlInitUnicodeString(&s3, L"PsGetContextThread");
        RtlInitUnicodeString(&s4, L"PsSetContextThread");
        auto pSusp = (PsSuspendProcess_t)MmGetSystemRoutineAddress(&s1);
        auto pResm = (PsResumeProcess_t)MmGetSystemRoutineAddress(&s2);
        auto pGetC = (PsGetContextThread_t)MmGetSystemRoutineAddress(&s3);
        auto pSetC = (PsSetContextThread_t)MmGetSystemRoutineAddress(&s4);
        if (pSusp && pResm && pGetC && pSetC) {
            INJ_T(1);
            PETHREAD th = nullptr;
            HANDLE mtid = nullptr;
            if (FindMainThreadId(PsGetProcessId(proc), &mtid) && mtid &&
                NT_SUCCESS(PsLookupThreadByThreadId(mtid, &th)) && th) {
                INJ_T(2);
                if (NT_SUCCESS(pSusp(proc))) {
                    INJ_T(3);
                    UCHAR ctx[LS_CTX_SIZE]{};
                    *(ULONG*)(ctx + LS_CTX_FLAGS_OFF) = LS_CONTEXT_FULL;
                    if (NT_SUCCESS(pGetC(th, ctx, UserMode))) {
                        UINT64 origRip = 0;
                        memcpy(&origRip, ctx + LS_CTX_RIP_OFF, 8);
                        if (origRip) {
                            INJ_T(4);
                            KAPC_STATE apc3;
                            KeStackAttachProcess(proc, &apc3);
                            __try {
                                RtlCopyMemory((PVOID)((ULONG_PTR)rArgs + 560), &origRip, 8);
                                memcpy(ctx + LS_CTX_RIP_OFF, &rStub, 8);
                                memcpy(ctx + LS_CTX_RCX_OFF, &rArgs, 8);
                            }
                            __except (EXCEPTION_EXECUTE_HANDLER) {}
                            KeUnstackDetachProcess(&apc3);
                            if (NT_SUCCESS(pSetC(th, ctx, UserMode))) INJ_T(5);
                            hijacked = (trace & (1ULL << 5)) != 0;
                        }
                    }
                    pResm(proc); // ALWAYS resume — never leave the game frozen
                }
                ObDereferenceObject(th);
            }
        }
    }
    if (!hijacked) {
    HANDLE tid = nullptr;
    if (!FindMainThreadId(PsGetProcessId(proc), &tid) || !tid) {
        FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs);
        ZwClose(hProc);
        INJ_RET(STATUS_NOT_FOUND);
    }
    PETHREAD th = nullptr;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(tid, &th)) || !th) {
        FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs);
        ZwClose(hProc);
        INJ_RET(STATUS_NOT_FOUND);
    }
    PVOID apc = ExAllocatePoolWithTag(NonPagedPool, LS_KAPC_SIZE, 'LSap');
    if (!apc) {
        ObDereferenceObject(th);
        FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs);
        ZwClose(hProc);
        INJ_RET(STATUS_INSUFFICIENT_RESOURCES);
    }
    KeInitializeApc(apc, (PVOID)th, 0 /*OriginalApcEnvironment*/,
        (PVOID)InjectApcKernel, (PVOID)InjectApcRundown, rStub, UserMode, rArgs);
    if (!KeInsertQueueApc(apc, nullptr, nullptr, 0)) {
        ExFreePoolWithTag(apc, 'LSap'); // never queued: rundown won't run
        ObDereferenceObject(th);
        FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs);
        ZwClose(hProc);
        INJ_RET(STATUS_UNSUCCESSFUL);
    }
    INJ_T(6);
    ObDereferenceObject(th); // APC now holds its own thread reference
    // poke alertable waiters so delivery doesn't wait for the next wait call
    {
        UNICODE_STRING an; RtlInitUnicodeString(&an, L"KeAlertThread");
        auto pAlert = (KeAlertThread_t)MmGetSystemRoutineAddress(&an);
        if (pAlert) {
            PETHREAD th2 = nullptr;
            if (NT_SUCCESS(PsLookupThreadByThreadId(tid, &th2)) && th2) {
                __try { pAlert((PKTHREAD)th2, UserMode); }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
                ObDereferenceObject(th2);
            }
        }
    }
    // NOTE: KAPC intentionally not freed on success (no owner after delivery).
    } // end APC fallback
    // Poll stub's executed/status: separates "APC never fired" (STATUS_TIMEOUT)
    // from "LdrLoadDll failed" (exact loader code: bitness/deps).
    LONG exec = 0, ldrSt = 0;
    for (int i = 0; i < 20 && !exec; i++) {
        LARGE_INTEGER dly; dly.QuadPart = -5000000LL; // 500ms
        KeDelayExecutionThread(KernelMode, FALSE, &dly);
        UCHAR s[8]{}; SIZE_T got = 0;
        if (NT_SUCCESS(SafeCopy(proc, (PVOID)((ULONG_PTR)rArgs + 552), PsGetCurrentProcess(), s, 8, &got)) && got == 8) {
            memcpy(&exec, s, 4); memcpy(&ldrSt, s + 4, 4);
        }
    }
    if (!exec) {
        // leak both pages: the APC may still fire later (timeout beats UAF)
        ZwClose(hProc);
        INJ_RET(STATUS_TIMEOUT);
    }
    INJ_T(7);
    if (!NT_SUCCESS((NTSTATUS)ldrSt)) {
        FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs);
        ZwClose(hProc);
        INJ_RET((NTSTATUS)ldrSt);
    }
    INJ_T(8);
    PVOID mb = GetModuleBaseAddress(proc, fn);
    if (mb) { INJ_T(9); FreeRemoteMem(hProc, rStub); FreeRemoteMem(hProc, rArgs); }
    if (outBase) *outBase = mb;
    ZwClose(hProc);
    INJ_RET(mb ? STATUS_SUCCESS : STATUS_DLL_NOT_FOUND);
}

//=================================================================
//  Kernel scan — chunked read + masked compare, overlap-safe
//=================================================================
#define LS_SCAN_CHUNK 0x10000  // 64KB per copy
#define LS_SCAN_MAXHITS 256

static NTSTATUS KernelScanRegion(PEPROCESS proc, PVOID start, SIZE_T size,
    const UCHAR* pat, const UCHAR* msk, ULONG patLen,
    UINT64* outHits, ULONG maxHits, PULONG outCount) {
    if (!proc || !start || !size || !pat || !msk || !patLen || patLen > 32) return STATUS_INVALID_PARAMETER;
    if (!outHits || !outCount || !maxHits) return STATUS_INVALID_PARAMETER;
    {
        ULONG_PTR a = (ULONG_PTR)start;
        constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
        if (a == 0 || a > kMaxUser || size > kMaxUser || a + size < a || a + size - 1 > kMaxUser)
            return STATUS_ACCESS_VIOLATION;
    }
    if (maxHits > LS_SCAN_MAXHITS) maxHits = LS_SCAN_MAXHITS;
    *outCount = 0;

    PUCHAR buf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, LS_SCAN_CHUNK + 32, 'LSsc');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T done = 0;
    ULONG found = 0;
    // overlap so matches crossing chunk edges are caught
    ULONG overlap = (patLen > 1) ? (patLen - 1) : 0;

    while (done < size && found < maxHits) {
        SIZE_T want = min((SIZE_T)LS_SCAN_CHUNK, size - done);
        SIZE_T copied = 0;
        PVOID src = (PVOID)((ULONG_PTR)start + done);
        NTSTATUS st = SafeCopy(proc, src, PsGetCurrentProcess(), buf, want, &copied);
        if (!NT_SUCCESS(st) || !copied) {
            // skip unreadable page granularity — advance 0x1000 and continue
            done += 0x1000;
            // clear overlap carry
            continue;
        }
        // linear masked compare inside this chunk
        if (copied >= patLen) {
            for (SIZE_T i = 0; i + patLen <= copied && found < maxHits; i++) {
                BOOLEAN ok = TRUE;
                for (ULONG j = 0; j < patLen; j++) {
                    if (msk[j] && buf[i + j] != pat[j]) { ok = FALSE; break; }
                }
                if (ok) {
                    outHits[found++] = (UINT64)((ULONG_PTR)start + done + i);
                    if (found >= maxHits) break;
                    // skip overlap to avoid duplicate reports on same bytes
                    if (patLen > 1) i += patLen - 1;
                }
            }
        }
        if (copied < want) {
            done += copied ? copied : 0x1000;
        } else {
            // rewind overlap for next chunk
            if (done + want < size && overlap && want > overlap) done += want - overlap;
            else done += want;
        }
        // guard against infinite loop on tiny regions
        if (want == 0) break;
    }

    ExFreePoolWithTag(buf, 'LSsc');
    *outCount = found;
    return STATUS_SUCCESS;
}

//=================================================================
//  IRP dispatch — LegendScan memory ops
//=================================================================
NTSTATUS ctl_io(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    auto stk = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
    PVOID sysbuf = irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stk->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (code) {
    case ls_init_code: {
        if (!sysbuf || inLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        KIRQL irql; KeAcquireSpinLock(&g_procLock, &irql);
        SafeReleaseProcess();
        NTSTATUS s = PsLookupProcessByProcessId(buf->target_pid, &g_target_process);
        status = NT_SUCCESS(s) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        KeReleaseSpinLock(&g_procLock, irql);
        break;
    }
    case ls_module_code: {
        if (!sysbuf || inLen < sizeof(info_t) || outLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        buf->base_address = GetModuleBaseAddress(proc, buf->module_name);
        ObDereferenceObject(proc);
        status = buf->base_address ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        break;
    }
    case ls_read_code: {
        if (!sysbuf || inLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        {
            ULONG_PTR a = (ULONG_PTR)buf->target_address;
            constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
            if (!a || a > kMaxUser || !buf->size || buf->size > kMaxUser || a + buf->size < a || a + buf->size - 1 > kMaxUser) { status = STATUS_ACCESS_VIOLATION; break; }
        }
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        status = SafeCopy(proc, buf->target_address, PsGetCurrentProcess(), buf->buffer_address, buf->size, &buf->return_size);
        ObDereferenceObject(proc);
        break;
    }
    case ls_write_code: {
        if (!sysbuf || inLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        if (buf->size == 0 || buf->size > 0x1000000) { status = STATUS_INVALID_PARAMETER; break; }
        {
            ULONG_PTR a = (ULONG_PTR)buf->target_address;
            constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
            if (!a || a > kMaxUser || a + buf->size < a || a + buf->size - 1 > kMaxUser) { status = STATUS_ACCESS_VIOLATION; break; }
        }
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        status = SafeCopy(PsGetCurrentProcess(), buf->buffer_address, proc, buf->target_address, buf->size, &buf->return_size);
        if (!NT_SUCCESS(status) || buf->return_size != buf->size) {
            // Fallback for PAGE_READONLY / guarded pages: MDL writable mapping
            // Copy usermode source into kernel temp first (sysbuf is kernel-readable buffered IO)
            SIZE_T sz = buf->size;
            PUCHAR tmp = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, sz, 'LSwr');
            if (tmp) {
                // buffer_address lives in caller (Scanner) VA — pull via MmCopy, not direct deref
                SIZE_T got = 0;
                NTSTATUS sc = SafeCopy(PsGetCurrentProcess(), buf->buffer_address, PsGetCurrentProcess(), tmp, sz, &got);
                if (!NT_SUCCESS(sc) || got != sz) { ExFreePoolWithTag(tmp, 'LSwr'); tmp = nullptr; }
            }
            if (tmp) {
                SIZE_T wrote = 0;
                NTSTATUS s2 = MdlWrite(proc, buf->target_address, tmp, sz, &wrote);
                buf->return_size = wrote;
                if (NT_SUCCESS(s2) && wrote == sz) status = STATUS_SUCCESS;
                ExFreePoolWithTag(tmp, 'LSwr');
            }
        }
        ObDereferenceObject(proc);
        break;
    }
    case ls_force_code: {
        if (!sysbuf || inLen < sizeof(info_t) || outLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        if (buf->size == 0 || buf->size > 0x10000) { status = STATUS_INVALID_PARAMETER; break; }
        {
            ULONG_PTR a = (ULONG_PTR)buf->target_address;
            constexpr ULONG_PTR kMaxUser = 0x7FFFFFFFFFFFULL;
            if (!a || a > kMaxUser || a + buf->size < a || a + buf->size - 1 > kMaxUser) { status = STATUS_ACCESS_VIOLATION; break; }
        }
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        HANDLE hProc = nullptr;
        status = OpenTarget(&hProc, proc);
        if (!NT_SUCCESS(status)) { ObDereferenceObject(proc); break; }
        UINT64 trace = 0;
        NTSTATUS wst = KernelForceWrite(proc, hProc, buf->target_address, buf->buffer_address, buf->size, &trace);
        buf->return_size = (SIZE_T)wst; // real write NTSTATUS for usermode
        buf->size = (SIZE_T)trace;      // step trace (size unused for force)
        ZwClose(hProc);
        ObDereferenceObject(proc);
        status = STATUS_SUCCESS; // transport OK: guarantees output copy-back
        break;
    }
    case ls_alloc_code: {
        if (!sysbuf || inLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        HANDLE hProcess = nullptr;
        status = OpenTarget(&hProcess, proc);
        ObDereferenceObject(proc);
        if (!NT_SUCCESS(status)) break;
        PVOID  baseAddr = buf->target_address;
        SIZE_T regionSz = buf->size;
        status = ZwAllocateVirtualMemory(hProcess, &baseAddr, 0, &regionSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (NT_SUCCESS(status)) { buf->base_address = baseAddr; buf->return_size = regionSz; }
        else buf->base_address = nullptr;
        ZwClose(hProcess);
        break;
    }
    case ls_free_code: {
        if (!sysbuf || inLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        HANDLE hProc = nullptr;
        status = OpenTarget(&hProc, proc);
        ObDereferenceObject(proc);
        if (!NT_SUCCESS(status)) break;
        PVOID base = buf->target_address; SIZE_T sz = buf->size;
        UNICODE_STRING fn; RtlInitUnicodeString(&fn, L"ZwFreeVirtualMemory");
        auto pFree = (ZwFreeVirtualMemory_t)MmGetSystemRoutineAddress(&fn);
        if (pFree) status = pFree(hProc, &base, &sz, MEM_RELEASE); else status = ZwFreeVirtualMemory(hProc, &base, &sz, MEM_RELEASE);
        ZwClose(hProc);
        break;
    }
    case ls_version_code: {
        if (!sysbuf || outLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        buf->return_size = (SIZE_T)LS_BUILD_TAG;
        buf->base_address = (PVOID)(ULONG_PTR)LS_BUILD_TAG;
        status = STATUS_SUCCESS;
        break;
    }
    case ls_scan_code: {
        if (!sysbuf || inLen < sizeof(scan_req_t) || outLen < sizeof(scan_req_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto req = (scan_req_t*)sysbuf;
        if (req->patLen == 0 || req->patLen > 32 || req->size == 0) { status = STATUS_INVALID_PARAMETER; break; }
        if (req->maxHits == 0 || req->maxHits > LS_SCAN_MAXHITS) req->maxHits = LS_SCAN_MAXHITS;
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        ULONG found = 0;
        status = KernelScanRegion(proc, req->start, req->size, req->pat, req->msk, req->patLen, req->hits, req->maxHits, &found);
        req->hitCount = found;
        ObDereferenceObject(proc);
        break;
    }
    case ls_mods_code: {
        if (!sysbuf || inLen < sizeof(ls_mods_req_t) || outLen < sizeof(ls_mods_req_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto req = (ls_mods_req_t*)sysbuf;
        if (req->max == 0 || req->max > LS_MODS_MAX) req->max = LS_MODS_MAX;
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        ULONG found = 0;
        KAPC_STATE apc;
        KeStackAttachProcess(proc, &apc);
        __try {
            PPEB peb = PsGetProcessPeb(proc);
            if (peb && peb->Ldr) {
                for (PLIST_ENTRY e = peb->Ldr->InLoadOrderModuleList.Flink;
                     e != &peb->Ldr->InLoadOrderModuleList && found < req->max;
                     e = e->Flink) {
                    auto mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    if (!mod->DllBase) continue;
                    req->mods[found].base = mod->DllBase;
                    req->mods[found].size = mod->SizeOfImage;
                    RtlZeroMemory(req->mods[found].name, sizeof(req->mods[found].name));
                    if (mod->BaseDllName.Buffer && mod->BaseDllName.Length) {
                        ULONG copy = mod->BaseDllName.Length;
                        if (copy > sizeof(req->mods[found].name) - sizeof(WCHAR))
                            copy = sizeof(req->mods[found].name) - sizeof(WCHAR);
                        RtlCopyMemory(req->mods[found].name, mod->BaseDllName.Buffer, copy);
                    }
                    found++;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        req->count = found;
        status = STATUS_SUCCESS;
        break;
    }
    case ls_inject_code: {
        if (!sysbuf || inLen < sizeof(info_t) || outLen < sizeof(info_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto buf = (info_t*)sysbuf;
        if (!buf->module_name[0]) { status = STATUS_INVALID_PARAMETER; break; }
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        PVOID loaded = nullptr;
        UINT64 trace = 0;
        NTSTATUS ist = KernelInjectDll(proc, buf->module_name, &loaded, &trace);
        buf->base_address = loaded;
        buf->return_size = (SIZE_T)ist; // real NTSTATUS for usermode messages
        buf->size = (SIZE_T)trace;      // step trace (size unused for inject)
        ObDereferenceObject(proc);
        status = STATUS_SUCCESS; // transport OK: guarantees output copy-back
        break;
    }
    case ls_query_code: {
        if (!sysbuf || inLen < sizeof(query_req_t) || outLen < sizeof(query_req_t)) { status = STATUS_INVALID_PARAMETER; break; }
        auto req = (query_req_t*)sysbuf;
        PEPROCESS proc = AcquireTargetRef();
        if (!proc) { status = STATUS_INVALID_HANDLE; break; }
        HANDLE hProc = nullptr;
        status = OpenTarget(&hProc, proc);
        ObDereferenceObject(proc);
        if (!NT_SUCCESS(status)) break;
        MEMORY_BASIC_INFORMATION mbi{};
        SIZE_T retLen = 0;
        // round query addr down to page
        PVOID q = (PVOID)((ULONG_PTR)req->addr & ~(PAGE_SIZE - 1));
        status = ZwQueryVirtualMemory(hProc, q, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
        if (NT_SUCCESS(status)) {
            req->base = mbi.BaseAddress;
            req->size = mbi.RegionSize;
            req->state = mbi.State;
            req->protect = mbi.Protect;
            req->type = mbi.Type;
            req->ok = 1;
        } else {
            req->ok = 0;
        }
        ZwClose(hProc);
        break;
    }
    default: status = STATUS_INVALID_DEVICE_REQUEST; break;
    }

    irp->IoStatus.Status = status;
    // report full struct size per code so usermode gets OUT fields
    if (code == ls_scan_code) irp->IoStatus.Information = sizeof(scan_req_t);
    else if (code == ls_query_code) irp->IoStatus.Information = sizeof(query_req_t);
    else if (code == ls_mods_code) irp->IoStatus.Information = sizeof(ls_mods_req_t);
    else irp->IoStatus.Information = sizeof(info_t);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return STATUS_NOT_SUPPORTED;
}
NTSTATUS create_io(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return STATUS_SUCCESS;
}
NTSTATUS close_io(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT drvObj) {
    UnhookMmCopyVirtualMemory();
    StopWatcherThread();
    KIRQL irql; KeAcquireSpinLock(&g_procLock, &irql);
    SafeReleaseProcess();
    KeReleaseSpinLock(&g_procLock, irql);
    UNICODE_STRING drvName; RtlInitUnicodeString(&drvName, L"amdfend.sys");
    ScrubMmUnloaded(&drvName);
    UNICODE_STRING sym; RtlInitUnicodeString(&sym, L"\\DosDevices\\AMD_CrashDefend");
    IoDeleteSymbolicLink(&sym);
    if (drvObj->DeviceObject) IoDeleteDevice(drvObj->DeviceObject);
}

NTSTATUS real_main(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath) {
    UNREFERENCED_PARAMETER(regPath);
    KeInitializeSpinLock(&g_procLock);
    UNICODE_STRING devName, symLink; PDEVICE_OBJECT devObj = nullptr;
    RtlInitUnicodeString(&devName, L"\\Device\\AMD_CrashDefend");
    NTSTATUS status = IoCreateDevice(drvObj, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
    if (!NT_SUCCESS(status)) return status;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\AMD_CrashDefend");
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(devObj); return status; }
    SetFlag(devObj->Flags, DO_BUFFERED_IO);
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) drvObj->MajorFunction[i] = unsupported_io;
    drvObj->MajorFunction[IRP_MJ_CREATE] = create_io;
    drvObj->MajorFunction[IRP_MJ_CLOSE] = close_io;
    drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
    drvObj->DriverUnload = UnloadDriver;
    ClearFlag(devObj->Flags, DO_DEVICE_INITIALIZING);
    StartWatcherThread();
    StealthInit(drvObj);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath) {
    UNREFERENCED_PARAMETER(drvObj); UNREFERENCED_PARAMETER(regPath);
    UNICODE_STRING name; RtlInitUnicodeString(&name, L"\\Driver\\AmdPpkg");
    return IoCreateDriver(&name, real_main);
}
