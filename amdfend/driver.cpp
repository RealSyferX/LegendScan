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
constexpr ULONG LS_BUILD_TAG    = 0x00080002; // LegendScan build: init/read/write(+MDL fallback)/module/alloc/free/version/scan/query

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
static NTSTATUS MdlWrite(PEPROCESS proc, PVOID target, PVOID src, SIZE_T sz, PSIZE_T written) {
    if (!proc || !target || !src || !sz) return STATUS_INVALID_PARAMETER;
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

static NTSTATUS OpenTarget(HANDLE* outHandle, PEPROCESS proc) {
    if (!outHandle || !proc) return STATUS_INVALID_PARAMETER;
    NTSTATUS st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, nullptr, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, outHandle);
    if (!NT_SUCCESS(st))
        st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, nullptr, (ACCESS_MASK)0x43A, *PsProcessType, KernelMode, outHandle);
    return st;
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
