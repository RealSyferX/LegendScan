/*
 * LegendScan — kernel Cheat Engine clone (CE-look UI)
 * Driver: amdfend.sys (\\.\AMD_CrashDefend), kernel scan via ls_scan_code
 * Layout mirrors Cheat Engine 7.x: found list + scan opts + address table
 * Subsystem: Windows. Libs: Advapi32 user32 gdi32 comctl32
 */
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include "scanner.hpp"
#include <TlHelp32.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <intrin.h> // __readgsqword for PEB masquerade
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

//=================================================================
//  Config / stealth strings (XOR 0x5A)
//=================================================================
static constexpr BYTE STR_KEY = 0x5A;
static char* XDec(char* buf, const BYTE* enc, int len) {
    for (int i = 0; i < len; i++) buf[i] = (char)(enc[i] ^ STR_KEY);
    buf[len] = 0; return buf;
}
static const BYTE _s_dev[] = { 0x06,0x06,0x74,0x06,0x1B,0x17,0x1E,0x05,0x19,0x28,0x3B,0x29,0x32,0x1E,0x3F,0x3C,0x3F,0x34,0x3E }; // "\\.\AMD_CrashDefend"
static const BYTE _s_drv[] = { 0x3B,0x37,0x3E,0x3C,0x3F,0x34,0x3E,0x74,0x29,0x23,0x29 }; // "amdfend.sys"
static const BYTE _s_ldr[] = { 0x74,0x06,0x16,0x35,0x3B,0x3E,0x3F,0x28,0x74,0x3F,0x22,0x3F }; // ".\\Loader.exe"
static const BYTE _s_efi[] = { 0x1F,0x3C,0x33,0x1E,0x09,0x1F,0x1C,0x33,0x22,0x74,0x3F,0x22,0x3F }; // "EfiDSEFix.exe"
#define SSTR(name, enc) char name[128]{}; XDec(name, enc, sizeof(enc))

static void HideThreadFromDebugger() {
    typedef NTSTATUS(NTAPI* Fn)(HANDLE, UINT, PVOID, ULONG);
    auto fn = (Fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (fn) fn(GetCurrentThread(), 0x11, nullptr, 0);
}

//=================================================================
//  USERMODE STEALTH (ported from DesAnime) — PEB masquerade as Chrome,
//  fake Chrome IPC mutex, VERSION_INFO patch, DbgBreakPoint patch,
//  random window classes + spoofed captions.
//  If BE bans based on this, they'd be banning Chrome worldwide.
//=================================================================
static void PatchDbgBreakPoint() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PVOID bp = GetProcAddress(ntdll, "DbgBreakPoint");
    if (!bp) return;
    DWORD old;
    VirtualProtect(bp, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)bp = 0xC3;
    VirtualProtect(bp, 1, old, &old);
}

static void GenRandomStr(char* out, int len) {
    const char* c = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len - 1; i++) out[i] = c[rand() % 36];
    out[len - 1] = '\0';
}

static void SpoofWindowTitle(HWND hwnd) {
    const char* names[] = {
        "NVIDIA GeForce Experience", "Discord",
        "Windows Security", "Microsoft Edge", "System Settings"
    };
    SetWindowTextA(hwnd, names[rand() % 5]);
}

// Spoof PEB ImagePathName and CommandLine to look like Chrome
static void SpoofPEB() {
    typedef struct _UNICODE_STR {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STR;

    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE Reserved1[16];
        PVOID Reserved2[10];
        UNICODE_STR ImagePathName;
        UNICODE_STR CommandLine;
    } RTL_USER_PROC_PARAMS;

    PVOID peb = nullptr;
#ifdef _WIN64
    peb = (PVOID)__readgsqword(0x60);
#else
    peb = (PVOID)__readfsdword(0x30);
#endif
    if (!peb) return;

#ifdef _WIN64
    auto params = *(RTL_USER_PROC_PARAMS**)((BYTE*)peb + 0x20);
#else
    auto params = *(RTL_USER_PROC_PARAMS**)((BYTE*)peb + 0x10);
#endif
    if (!params) return;

    wchar_t fakePath[MAX_PATH] = {};
    wchar_t localAppData[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH)) {
        wsprintfW(fakePath, L"%s\\Google\\Chrome\\Application\\chrome.exe", localAppData);
    }
    else {
        wcscpy_s(fakePath, L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    }

    wchar_t fakeCmdLine[512] = {};
    wsprintfW(fakeCmdLine, L"\"%s\" --type=utility --utility-sub-type=network.mojom.NetworkService", fakePath);

    size_t pathLen = wcslen(fakePath) * sizeof(wchar_t);
    if (params->ImagePathName.MaximumLength >= (USHORT)(pathLen + 2)) {
        RtlZeroMemory(params->ImagePathName.Buffer, params->ImagePathName.MaximumLength);
        memcpy(params->ImagePathName.Buffer, fakePath, pathLen);
        params->ImagePathName.Length = (USHORT)pathLen;
    }

    size_t cmdLen = wcslen(fakeCmdLine) * sizeof(wchar_t);
    if (params->CommandLine.MaximumLength >= (USHORT)(cmdLen + 2)) {
        RtlZeroMemory(params->CommandLine.Buffer, params->CommandLine.MaximumLength);
        memcpy(params->CommandLine.Buffer, fakeCmdLine, cmdLen);
        params->CommandLine.Length = (USHORT)cmdLen;
    }
}

// Fake Chrome named objects — anti-cheat mutex scans see Chrome artifacts
static HANDLE g_fakeMutex = nullptr;
static void CreateChromeMutexes() {
    g_fakeMutex = CreateMutexW(nullptr, FALSE, L"GoogleChromeIPCMutex");
}

// Spoof the main module's PE version info in memory ("LegendScan" -> "Google Chrome")
static void SpoofModuleDescription() {
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod) return;

    HRSRC hRes = FindResourceA(hMod, MAKEINTRESOURCEA(1), MAKEINTRESOURCEA(16)); // RT_VERSION = 16
    if (!hRes) return;

    HGLOBAL hGlobal = LoadResource(hMod, hRes);
    if (!hGlobal) return;

    PVOID pVer = LockResource(hGlobal);
    DWORD szVer = SizeofResource(hMod, hRes);
    if (!pVer || !szVer) return;

    DWORD oldProt;
    VirtualProtect(pVer, szVer, PAGE_READWRITE, &oldProt);

    const wchar_t* needles[] = { L"LegendScan", L"Scanner", L"amdfend" };
    const wchar_t* replacement = L"Google Chrome  ";

    for (DWORD off = 0; off + 32 < szVer; off += 2) {
        wchar_t* scan = (wchar_t*)((BYTE*)pVer + off);
        for (auto needle : needles) {
            size_t nLen = wcslen(needle);
            if (wcsncmp(scan, needle, nLen) == 0) {
                size_t rLen = wcslen(replacement);
                size_t copyLen = (std::min)(rLen, nLen + 4);
                memcpy(scan, replacement, copyLen * sizeof(wchar_t));
            }
        }
    }

    VirtualProtect(pVer, szVer, oldProt, &oldProt);
}

static char g_clsMain[16]{}, g_clsDlg[16]{}, g_clsMem[16]{}, g_clsPSP[16]{}, g_clsPSR[16]{};

//=================================================================
//  Globals
//=================================================================
static HWND g_hwnd = nullptr;
static HFONT g_fUI = nullptr;
static ls_driver* g_drv = nullptr;
static std::atomic<bool> g_running{ true };
static std::atomic<bool> g_connected{ false };
static std::atomic<bool> g_attached{ false };
static std::atomic<bool> g_scanning{ false };
static DWORD g_pid = 0;
static char g_proc[128] = "notepad.exe";
static char g_status[256] = "Initializing...";

// Scan model — CE naming
enum VType { V_U8 = 0, V_U16, V_U32, V_U64, V_F32, V_F64, V_STR, V_AOB };
enum SType { S_EXACT = 0, S_BIGGER, S_SMALLER, S_BETWEEN, S_INCREASED, S_DECREASED, S_CHANGED, S_UNCHANGED };

struct Cand { UINT64 addr = 0; BYTE prev[32]{}; };
static std::vector<Cand> g_cands;
static std::vector<std::vector<Cand>> g_undo; // Undo Scan stack
static std::mutex g_candsMtx;
static int g_vtype = V_U32;   // index into CE value-type combo
static int g_stype = S_EXACT; // index into CE scan-type combo
static ULONG g_valLen = 4;
static bool g_hexMode = false;
static bool g_optWritable = true;
static bool g_optExecutable = false;
static bool g_optCow = false;
static bool g_optFast = true;
static int  g_optAlign = 4;
static UINT64 g_optStart = 0;
static UINT64 g_optStop = 0x7FFFFFFFFFFFULL;
static int  g_optPreset = 0; // 0=All 1=Private 2=Image 3=Mapped
static const size_t MAX_HITS = 500000;

// Address table (bottom, like CE). Two base kinds: absolute addr, or "module"+modOff (static).
// Pointer chain (CE semantic): p=base; for each offs[i]: p=*(p+offs[i]); final=p.
struct TblEntry {
    bool active = false;
    char desc[64]{};
    UINT64 addr = 0;      // absolute base (when mod empty)
    char mod[64]{};       // module name, "" = absolute
    UINT64 modOff = 0;    // offset from module base
    int vtype = V_U32;
    BYTE bytes[32]{};
    ULONG len = 4;
    bool isSigned = false;
    bool hexDisp = false;
    bool isPtr = false;
    UINT64 ptrOffs[5]{};
    int nOff = 0;
};
#define PTR_MAX 5
static int g_editRow = -1; // table row targeted by Change Value/Type/Desc popups
static bool g_editReplace = false; // true = Address dialog edits row in place (Cancel keeps it)
static bool g_showModAddr = true; // Settings: show "mod"+OFF when possible (green = static)
static std::vector<char> g_foundStatic; // per-row static flags for green font (found list)
static std::vector<char> g_tblStatic;   // per-row static flags for green font (table)
static std::vector<TblEntry> g_table;
static std::mutex g_tableMtx;
static std::atomic<bool> g_tblRefresh{ false }; // guard: ignore LVN_ITEMCHANGED while we rebuild

// Control IDs
enum {
    IDC_PROC_BTN = 101, IDC_PROC_LBL, IDC_FOUND_LBL,
    IDC_FOUND_LIST,
    IDC_FIRST_BTN, IDC_NEXT_BTN, IDC_UNDO_BTN,
    IDC_HEX_CHK, IDC_VAL_EDIT,
    IDC_STYPE_CB, IDC_VTYPE_CB,
    IDC_PRESET_CB, IDC_START_EDIT, IDC_STOP_EDIT,
    IDC_WRITABLE_CHK, IDC_EXEC_CHK, IDC_COW_CHK,
    IDC_FAST_CHK, IDC_ALIGN_EDIT, IDC_ALIGN_RADIO, IDC_LASTDIG_RADIO,
    IDC_MEMVIEW_BTN, IDC_ADDADDR_BTN,
    IDC_TBL_LIST,
    IDC_STATUS_TXT,
    // manual-add dialog (popup)
    DLG_X = 1000, DLG_DESC_EDIT, DLG_ADDR_EDIT, DLG_TYPE_CB, DLG_VAL_EDIT, DLG_OK_BTN, DLG_CANCEL_BTN,
    DLG_HEX_CHK = 1020, DLG_SIGNED_CHK, DLG_PTR_CHK, DLG_OFF_EDIT, DLG_PREVIEW,
    DLG_OFF0 = 1030, DLG_OFF1, DLG_OFF2, DLG_OFF3, DLG_OFF4,
    DLG_CHAIN = 1035, DLG_ADD_OFF, DLG_REM_OFF, DLG_BROWSE = 1041,
    // process list dialog
    PL_LIST = 1010, PL_REFRESH, PL_EDIT,
    // table/found context menu
    CTX_DEL = 9110, CTX_VAL, CTX_TYPE, CTX_DESC, CTX_ADDR, CTX_ADD, CTX_PS,
    CTX_COPY_ASIS, CTX_COPY_MOD, CTX_DISM,
    // pointer scan windows
    PS_PROG_STAT = 1060, PS_STOP,
    PS_RES_LIST = 1062, PS_RESCAN, PS_ADD, PS_SAVE, PS_CLOSEB, PS_OPENB,
    PSO_ADDR = 1070, PSO_DIFF, PSO_THR, PSO_MAXOFF, PSO_LVL,
    PSR_ADDR = 1080, PSR_VALID,
    // settings dialog
    SET_MODCHK = 1040,
    // mem viewer popup
    MV_X = 1100, MV_ADDR_EDIT, MV_SIZE_EDIT, MV_DUMP_BTN, MV_WRITE_EDIT, MV_WRITE_BTN, MV_HEX_EDIT,
    MV_DIS_LIST, MV_DIS_BTN,
};
static HWND g_ctl[1200]{};
static HWND ctl(int id) { return (id >= 0 && id < 1200) ? g_ctl[id] : nullptr; }
static HWND g_dlg = nullptr; // manual-add popup
static HWND g_mv = nullptr;  // memory viewer popup
static HWND g_dlgTypeCb = nullptr;

static void setStatus(const char* s) {
    snprintf(g_status, sizeof(g_status), "%s", s);
    if (ctl(IDC_STATUS_TXT)) SetWindowTextA(ctl(IDC_STATUS_TXT), s);
    if (ctl(IDC_FOUND_LBL)) {
        char f[160];
        size_t n = 0;
        { std::lock_guard<std::mutex> lk(g_candsMtx); n = g_cands.size(); }
        snprintf(f, sizeof(f), "Found:%zu", n);
        SetWindowTextA(ctl(IDC_FOUND_LBL), f);
    }
}

//=================================================================
//  Helpers: PID, parse, format
//=================================================================
static DWORD FindPID(const char* name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    wchar_t wname[128]{};
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname, 128);
    if (Process32FirstW(snap, &pe)) do {
        if (_wcsicmp(pe.szExeFile, wname) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap); return pid;
}
static bool hexNib(char c, BYTE& out) {
    if (c >= '0' && c <= '9') { out = (BYTE)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { out = (BYTE)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { out = (BYTE)(c - 'A' + 10); return true; }
    return false;
}
static bool parse_aob(const char* s, UCHAR* pat, UCHAR* msk, ULONG& len) {
    len = 0;
    const char* p = s;
    while (*p && len < 32) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p == '?') {
            pat[len] = 0; msk[len] = 0; len++;
            while (*p == '?') p++;
            continue;
        }
        BYTE hi, lo;
        if (!hexNib(p[0], hi)) return false;
        if (!p[1] || isspace((unsigned char)p[1])) {
            pat[len] = (UCHAR)(hi << 4); msk[len] = 1; len++; p += 1; continue;
        }
        if (!hexNib(p[1], lo)) return false;
        pat[len] = (UCHAR)((hi << 4) | lo); msk[len] = 1; len++; p += 2;
    }
    return len > 0;
}
// Parse value text by CE value-type index. Hex checkbox => base 16 for ints.
static bool parse_val1(int vtype, const char* s1, bool hex, UCHAR* pat, UCHAR* msk, ULONG& len) {
    memset(pat, 0, 32); memset(msk, 0, 32);
    char tmp[512]; snprintf(tmp, sizeof(tmp), "%s", s1 ? s1 : "");
    while (*tmp && isspace((unsigned char)*tmp)) memmove(tmp, tmp + 1, strlen(tmp));
    size_t L = strlen(tmp);
    while (L && isspace((unsigned char)tmp[L - 1])) tmp[--L] = 0;
    if (!L) return false;
    int base = hex ? 16 : 0;
    if (vtype == V_AOB) return parse_aob(tmp, pat, msk, len);
    if (vtype == V_STR) {
        len = (ULONG)(std::min<size_t>)(L, 32);
        memcpy(pat, tmp, len);
        memset(msk, 1, len);
        return len > 0;
    }
    if (vtype == V_U8) { unsigned long v = strtoul(tmp, nullptr, base); pat[0] = (UCHAR)v; msk[0] = 1; len = 1; return true; }
    if (vtype == V_U16) { unsigned long v = strtoul(tmp, nullptr, base); uint16_t x = (uint16_t)v; memcpy(pat, &x, 2); memset(msk, 1, 2); len = 2; return true; }
    if (vtype == V_U32) { unsigned long long v = strtoull(tmp, nullptr, base); uint32_t x = (uint32_t)v; memcpy(pat, &x, 4); memset(msk, 1, 4); len = 4; return true; }
    if (vtype == V_U64) { unsigned long long v = strtoull(tmp, nullptr, base); memcpy(pat, &v, 8); memset(msk, 1, 8); len = 8; return true; }
    if (vtype == V_F32) { float f = (float)strtod(tmp, nullptr); memcpy(pat, &f, 4); memset(msk, 1, 4); len = 4; return true; }
    if (vtype == V_F64) { double d = strtod(tmp, nullptr); memcpy(pat, &d, 8); memset(msk, 1, 8); len = 8; return true; }
    return false;
}
static int cmp_num(int vtype, const BYTE* cur, const BYTE* ref, ULONG len) {
    if (vtype == V_U8) { return (cur[0] < ref[0]) ? -1 : (cur[0] > ref[0]) ? 1 : 0; }
    if (vtype == V_U16) { uint16_t a, b; memcpy(&a, cur, 2); memcpy(&b, ref, 2); return (a < b) ? -1 : (a > b) ? 1 : 0; }
    if (vtype == V_U32) { uint32_t a, b; memcpy(&a, cur, 4); memcpy(&b, ref, 4); return (a < b) ? -1 : (a > b) ? 1 : 0; }
    if (vtype == V_U64) { uint64_t a, b; memcpy(&a, cur, 8); memcpy(&b, ref, 8); return (a < b) ? -1 : (a > b) ? 1 : 0; }
    if (vtype == V_F32) { float a, b; memcpy(&a, cur, 4); memcpy(&b, ref, 4); if (isnan(a) && isnan(b)) return 0; return (a < b) ? -1 : (a > b) ? 1 : 0; }
    if (vtype == V_F64) { double a, b; memcpy(&a, cur, 8); memcpy(&b, ref, 8); if (isnan(a) && isnan(b)) return 0; return (a < b) ? -1 : (a > b) ? 1 : 0; }
    int r = memcmp(cur, ref, len);
    return (r < 0) ? -1 : (r > 0) ? 1 : 0;
}
static std::string fmt_val(int vtype, const BYTE* b, ULONG len, bool hex) {
    char out[128]{};
    if (vtype == V_U8) { if (hex) snprintf(out, sizeof(out), "%02X", b[0]); else snprintf(out, sizeof(out), "%u", b[0]); }
    else if (vtype == V_U16) { uint16_t v; memcpy(&v, b, 2); if (hex) snprintf(out, sizeof(out), "%04X", v); else snprintf(out, sizeof(out), "%u", v); }
    else if (vtype == V_U32) { uint32_t v; memcpy(&v, b, 4); if (hex) snprintf(out, sizeof(out), "%08X", v); else snprintf(out, sizeof(out), "%u", v); }
    else if (vtype == V_U64) { uint64_t v; memcpy(&v, b, 8); if (hex) snprintf(out, sizeof(out), "%016llX", (unsigned long long)v); else snprintf(out, sizeof(out), "%llu", (unsigned long long)v); }
    else if (vtype == V_F32) { float v; memcpy(&v, b, 4); snprintf(out, sizeof(out), "%.4f", v); }
    else if (vtype == V_F64) { double v; memcpy(&v, b, 8); snprintf(out, sizeof(out), "%.6f", v); }
    else if (vtype == V_STR) { size_t n = (std::min<ULONG>)(len, 24); for (size_t i = 0; i < n; i++) out[i] = (b[i] >= 32 && b[i] < 127) ? (char)b[i] : '.'; out[n] = 0; }
    else { char* p = out; for (ULONG i = 0; i < len && i < 10; i++) p += snprintf(p, sizeof(out) - (p - out), "%02X ", b[i]); }
    return out;
}
static std::string fmt_valx(int vtype, const BYTE* b, ULONG len, bool hex, bool sgn) {
    if (!sgn) return fmt_val(vtype, b, len, hex);
    char out[128]{};
    if (vtype == V_U8) { int8_t v; memcpy(&v, b, 1); snprintf(out, sizeof(out), "%d", v); }
    else if (vtype == V_U16) { int16_t v; memcpy(&v, b, 2); snprintf(out, sizeof(out), "%d", v); }
    else if (vtype == V_U32) { int32_t v; memcpy(&v, b, 4); snprintf(out, sizeof(out), "%d", v); }
    else if (vtype == V_U64) { int64_t v; memcpy(&v, b, 8); snprintf(out, sizeof(out), "%lld", (long long)v); }
    else return fmt_val(vtype, b, len, hex);
    return out;
}
// Parse CE address expression: "mod"+OFF | "mod" | mod+OFF | plain hex (absolute)
static bool parse_addr_expr(const char* s, std::string& mod, UINT64& absOut, UINT64& modOff, bool& isMod) {
    char tmp[320]; snprintf(tmp, sizeof(tmp), "%s", s ? s : "");
    while (*tmp && isspace((unsigned char)*tmp)) memmove(tmp, tmp + 1, strlen(tmp));
    size_t L = strlen(tmp);
    while (L && isspace((unsigned char)tmp[L - 1])) tmp[--L] = 0;
    if (!L) return false;
    mod.clear(); absOut = 0; modOff = 0; isMod = false;
    if (tmp[0] == '"') {
        char* end = strchr(tmp + 1, '"');
        if (!end) return false;
        *end = 0;
        if (!tmp[1]) return false;
        mod = tmp + 1; isMod = true;
        char* rest = end + 1;
        while (*rest && isspace((unsigned char)*rest)) rest++;
        if (*rest == '+') modOff = strtoull(rest + 1, nullptr, 16);
        return true;
    }
    char* plus = strrchr(tmp, '+');
    if (plus && plus != tmp) {
        *plus = 0;
        char* left = tmp;
        while (*left && isspace((unsigned char)*left)) left++;
        size_t ll = strlen(left);
        while (ll && isspace((unsigned char)left[ll - 1])) left[--ll] = 0;
        bool hasDot = strchr(left, '.') != nullptr;
        if (hasDot && ll) {
            mod = left; modOff = strtoull(plus + 1, nullptr, 16); isMod = true;
            return true;
        }
        // absolute base + offset arithmetic
        absOut = strtoull(left, nullptr, 16) + strtoull(plus + 1, nullptr, 16);
        return true;
    }
    absOut = strtoull(tmp, nullptr, 16);
    return true;
}
static UINT64 mod_base(const char* mod) {
    if (!g_drv || !g_attached || !mod || !*mod) return 0;
    wchar_t w[260]{};
    MultiByteToWideChar(CP_ACP, 0, mod, -1, w, 260);
    return (UINT64)g_drv->module_base(w);
}
// Final address of a table entry (module rebase-safe + pointer chain)
// CE semantic (matches PSLevel generation): deref-then-add.
//   p = base; for each off: p = *(p) + off;  final = p holds the value.
static bool entry_final(const TblEntry& e, UINT64& out) {
    UINT64 base = e.addr;
    if (e.mod[0]) {
        base = mod_base(e.mod);
        if (!base) return false;
        base += e.modOff;
    }
    if (!e.isPtr || e.nOff <= 0) { out = base; return true; }
    if (!g_drv || !g_attached) return false;
    if (!ls_driver::is_user_range(base, 8)) return false;
    UINT64 p = base;
    for (int i = 0; i < e.nOff && i < PTR_MAX; i++) {
        UINT64 v = 0;
        if (!g_drv->read_u64_checked(p, v)) return false;
        if (!v) return false;
        UINT64 nxt = v + e.ptrOffs[i];
        if (nxt < v) return false; // overflow -> reject (would wrap into kernel)
        if (!ls_driver::is_user_range(nxt, 1)) return false;
        p = nxt;
    }
    out = p;
    return true;
}
// Printable base of an entry: "mod"+OFF or hex
static std::string entry_base_str(const TblEntry& e, char* buf, size_t n) {
    if (e.mod[0]) snprintf(buf, n, "\"%s\"+%llX", e.mod, (unsigned long long)e.modOff);
    else snprintf(buf, n, "%llX", (unsigned long long)e.addr);
    return buf;
}
static const char* vtypeName(int v) {
    switch (v) {
    case V_U8: return "1 Byte"; case V_U16: return "2 Bytes"; case V_U32: return "4 Bytes";
    case V_U64: return "8 Bytes"; case V_F32: return "Float"; case V_F64: return "Double";
    case V_STR: return "String"; default: return "Array of Byte";
    }
}
static bool readable_protect(ULONG p) {
    ULONG base = p & 0xFF;
    if (p & 0x100) return false;
    if (base == 0x01) return false;
    return (base == 0x02 || base == 0x04 || base == 0x08 || base == 0x20 || base == 0x40 || base == 0x80);
}
static bool writeable_protect(ULONG p) {
    ULONG base = p & 0xFF;
    return (base == 0x04 || base == 0x08 || base == 0x40 || base == 0x80 || base == 0x0C);
}
static bool exec_protect(ULONG p) {
    ULONG base = p & 0xFF;
    return (base == 0x10 || base == 0x20 || base == 0x40 || base == 0x80);
}
static bool cow_protect(ULONG p) {
    ULONG base = p & 0xFF;
    return (base == 0x08 || base == 0x80);
}
struct ModInfo { std::string name; UINT64 base = 0; UINT64 size = 0; };
static std::vector<ModInfo> g_mods;
static DWORD g_modsPid = 0;
// Refresh module list for scan-scope combo (All + exe/dll). Keeps selection when same PID.
// Toolhelp first; on protected games (stripped handles) fall back to kernel PEB walk.
static void RefreshMods(DWORD pid) {
    if (pid == g_modsPid && !g_mods.empty()) return;
    g_mods.clear(); g_modsPid = pid;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{}; me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) do {
            char eb[MAX_PATH]{};
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, eb, MAX_PATH, nullptr, nullptr);
            g_mods.push_back({ eb, (UINT64)me.modBaseAddr, (UINT64)me.modBaseSize });
        } while (Module32NextW(snap, &me));
        CloseHandle(snap);
    }
    if (g_mods.empty() && g_drv && g_attached) {
        // BattlEye & co strip usermode query handles — ask the driver instead
        auto km = g_drv->kernel_modules();
        for (auto& m : km) g_mods.push_back({ m.name, m.base, m.size });
    }
    std::sort(g_mods.begin(), g_mods.end(), [](const ModInfo& a, const ModInfo& b) {
        std::string al = a.name, bl = b.name;
        for (auto& c : al) c = (char)tolower((unsigned char)c);
        for (auto& c : bl) c = (char)tolower((unsigned char)c);
        return al < bl;
    });
    HWND cb = ctl(IDC_PRESET_CB);
    if (cb) {
        SendMessageA(cb, CB_RESETCONTENT, 0, 0);
        SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)"All");
        for (auto& m : g_mods) SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)m.name.c_str());
        SendMessageA(cb, CB_SETCURSEL, 0, 0);
    }
}
// Module-form display for any address: "mod"+OFF when inside a known module.
// Returns true = static (green font), false = plain hex.
static bool addr_display(UINT64 addr, char* buf, size_t n) {
    if (g_showModAddr) {
        for (auto& m : g_mods) {
            if (!m.size) continue;
            if (addr >= m.base && addr < m.base + m.size) {
                snprintf(buf, n, "\"%s\"+%llX", m.name.c_str(), (unsigned long long)(addr - m.base));
                return true;
            }
        }
    }
    snprintf(buf, n, "%016llX", (unsigned long long)addr);
    return false;
}

//=================================================================
//  ListView helpers (found list + table)
//=================================================================
static void lv_cols(HWND lv, const char* const* names, const int* widths, int n) {
    // NOTE: project is Unicode so ListView_* macros map to W — use A messages explicitly
    LVCOLUMNA c{}; c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; c.fmt = LVCFMT_LEFT;
    for (int i = 0; i < n; i++) {
        c.pszText = (LPSTR)names[i]; c.cx = widths[i];
        SendMessageA(lv, LVM_INSERTCOLUMNA, (WPARAM)i, (LPARAM)&c);
    }
}
static void lv_set_text(HWND lv, int row, int col, LPSTR txt) {
    LVITEMA lvi{}; lvi.iSubItem = col; lvi.pszText = txt;
    SendMessageA(lv, LVM_SETITEMTEXTA, (WPARAM)row, (LPARAM)&lvi);
}
static void refresh_found() {
    HWND lv = ctl(IDC_FOUND_LIST);
    if (!lv) return;
    ListView_DeleteAllItems(lv);
    std::lock_guard<std::mutex> lk(g_candsMtx);
    LVITEMA it{}; it.mask = LVIF_TEXT;
    char a[128], v[128], pv[128];
    g_foundStatic.clear();
    size_t show = (std::min<size_t>)(g_cands.size(), 20000);
    for (size_t i = 0; i < show; i++) {
        BYTE cur[32]{};
        if (g_drv && g_attached) g_drv->read_raw(g_cands[i].addr, cur, g_valLen);
        g_foundStatic.push_back(addr_display(g_cands[i].addr, a, sizeof(a)) ? 1 : 0);
        std::string vs = fmt_val(g_vtype, cur, g_valLen, g_hexMode);
        std::string ps = fmt_val(g_vtype, g_cands[i].prev, g_valLen, g_hexMode);
        snprintf(v, sizeof(v), "%s", vs.c_str());
        snprintf(pv, sizeof(pv), "%s", ps.c_str());
        it.iItem = (int)i; it.iSubItem = 0; it.pszText = a;
        SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
        lv_set_text(lv, (int)i, 1, v);
        lv_set_text(lv, (int)i, 2, pv);
    }
    char f[128]; snprintf(f, sizeof(f), "Found:%zu%s", g_cands.size(), g_cands.size() >= MAX_HITS ? " (capped)" : "");
    SetWindowTextA(ctl(IDC_FOUND_LBL), f);
}
static void refresh_table() {
    HWND lv = ctl(IDC_TBL_LIST);
    if (!lv) return;
    g_tblRefresh = true;
    ListView_DeleteAllItems(lv);
    std::lock_guard<std::mutex> lk(g_tableMtx);
    LVITEMA it{}; it.mask = LVIF_TEXT | LVIF_STATE;
    it.stateMask = LVIS_STATEIMAGEMASK;
    char a[160], v[128];
    g_tblStatic.clear();
    for (size_t i = 0; i < g_table.size(); i++) {
        auto& e = g_table[i];
        BYTE cur[32]{};
        bool have = false;
        UINT64 f = e.addr;
        if (g_drv && g_attached && entry_final(e, f)) {
            g_drv->read_raw(f, cur, e.len);
            have = true;
        }
        if (!have) memcpy(cur, e.bytes, e.len);
        bool st = false;
        if (e.mod[0]) {
            char bs[128]; entry_base_str(e, bs, sizeof(bs));
            if (e.isPtr) snprintf(a, sizeof(a), "P->%s", bs);
            else snprintf(a, sizeof(a), "%s", bs);
            st = true; // module-anchored = static
        }
        else if (e.isPtr) {
            char bb[128]; st = addr_display(e.addr, bb, sizeof(bb));
            snprintf(a, sizeof(a), "P->%s", bb);
        }
        else st = addr_display(e.addr, a, sizeof(a));
        g_tblStatic.push_back(st ? 1 : 0);
        std::string vs = have ? fmt_valx(e.vtype, cur, e.len, e.hexDisp, e.isSigned) : std::string("??");
        snprintf(v, sizeof(v), "%s", vs.c_str());
        it.iItem = (int)i; it.iSubItem = 0; it.pszText = (LPSTR)"";
        it.state = INDEXTOSTATEIMAGEMASK(e.active ? 2 : 1); // checked=2 unchecked=1, no extra notify
        SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
        lv_set_text(lv, (int)i, 1, e.desc);
        lv_set_text(lv, (int)i, 2, a);
        lv_set_text(lv, (int)i, 3, (LPSTR)vtypeName(e.vtype));
        lv_set_text(lv, (int)i, 4, v);
    }
    g_tblRefresh = false;
}
// Live tick: update Address+Value cells IN PLACE (no rebuild => selection, ticks, scroll stay)
static void refresh_table_live() {
    HWND lv = ctl(IDC_TBL_LIST);
    if (!lv) return;
    size_t n = 0;
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        n = g_table.size();
    }
    if (ListView_GetItemCount(lv) != (int)n) { refresh_table(); return; } // rows added/removed: rebuild
    if (g_tblStatic.size() != n) g_tblStatic.assign(n, 0);
    char a[160], v[128];
    for (size_t i = 0; i < n; i++) {
        TblEntry e;
        {
            std::lock_guard<std::mutex> lk(g_tableMtx);
            e = g_table[i];
        }
        BYTE cur[32]{};
        bool have = false;
        UINT64 f = e.addr;
        if (g_drv && g_attached && entry_final(e, f)) {
            g_drv->read_raw(f, cur, e.len);
            have = true;
        }
        if (!have) memcpy(cur, e.bytes, e.len);
        bool st = false;
        if (e.mod[0]) {
            char bs[128]; entry_base_str(e, bs, sizeof(bs));
            if (e.isPtr) snprintf(a, sizeof(a), "P->%s", bs);
            else snprintf(a, sizeof(a), "%s", bs);
            st = true;
        }
        else if (e.isPtr) {
            char bb[128]; st = addr_display(e.addr, bb, sizeof(bb));
            snprintf(a, sizeof(a), "P->%s", bb);
        }
        else st = addr_display(e.addr, a, sizeof(a));
        g_tblStatic[i] = st ? 1 : 0;
        std::string vs = have ? fmt_valx(e.vtype, cur, e.len, e.hexDisp, e.isSigned) : std::string("??");
        snprintf(v, sizeof(v), "%s", vs.c_str());
        lv_set_text(lv, (int)i, 2, a);
        lv_set_text(lv, (int)i, 4, v);
    }
}
static void push_undo() {
    std::lock_guard<std::mutex> lk(g_candsMtx);
    if (g_cands.empty()) return;
    g_undo.push_back(g_cands);
    if (g_undo.size() > 10) g_undo.erase(g_undo.begin());
}

//=================================================================
//  Scan workers
//=================================================================
#define WM_SCAN_DONE (WM_APP+1)
static char g_scanMsg[256]{};

struct ScanOpts {
    bool writable, executable, cow;
    UINT64 modBase = 0, modSize = 0; // module scope (0 = All)
    UINT64 start, stop;
    int align;
};

static void FirstScanThread(std::string s1, std::string s2, int vtype, int stype, bool hex, ScanOpts o) {
    HideThreadFromDebugger();
    g_scanning = true;
    snprintf(g_scanMsg, sizeof(g_scanMsg), "Scanning...");
    PostMessageA(g_hwnd, WM_SCAN_DONE, 2, 0);

    std::vector<Cand> out;
    out.reserve(65536);

    UCHAR pat[32]{}, msk[32]{};
    ULONG plen = 0;
    UCHAR pat2[32]{};
    ULONG plen2 = 0;
    if (vtype == V_AOB) {
        if (!parse_aob(s1.c_str(), pat, msk, plen)) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad Array of Byte (ex: 89 5F 30 ?? 74 08)"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }
    }
    else if (stype == S_EXACT || stype == S_BIGGER || stype == S_SMALLER || stype == S_BETWEEN) {
        if (!parse_val1(vtype, s1.c_str(), hex, pat, msk, plen)) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad value"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }
        if (stype == S_BETWEEN && !parse_val1(vtype, s2.c_str(), hex, pat2, msk, plen2)) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad second value"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }
    }
    else {
        if (vtype == V_STR) plen = (ULONG)(std::min<size_t>)(s1.size() ? s1.size() : 4, 32);
        else { UCHAR d[32]{}; ULONG l = 0; parse_val1(vtype, "0", false, d, d, l); plen = l ? l : 4; }
        if (vtype == V_STR && s1.empty()) plen = 4;
    }
    ULONG useLen = 0;
    if (vtype == V_AOB) useLen = plen;
    else if (stype <= S_BETWEEN) useLen = plen;
    else useLen = (vtype == V_U8) ? 1 : (vtype == V_U16) ? 2 : (vtype == V_U32 || vtype == V_F32) ? 4 : (vtype == V_U64 || vtype == V_F64) ? 8 : (plen ? plen : 4);

    g_valLen = useLen;
    if (!g_drv || !g_attached) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Select a process first"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }

    int step = 1;
    if (stype == S_EXACT && o.align > 1 && useLen > 1) step = 1; // kernel scan covers exact unaligned
    else step = (o.align > 0) ? o.align : 1;
    if (step < 1) step = 1;

    auto pass_region = [&](const LsRegion& r) {
        if (r.state != 0x1000) return false;
        if (!readable_protect(r.protect)) return false;
        if (o.writable && !writeable_protect(r.protect)) return false;
        if (!o.executable && exec_protect(r.protect)) return false;
        if (!o.cow && cow_protect(r.protect)) return false;
        UINT64 b = r.base, e = r.base + r.size;
        if (e <= o.start || b >= o.stop) return false;
        if (o.modSize) {
            if (e <= o.modBase || b >= o.modBase + o.modSize) return false;
        }
        return true;
    };
    auto clip_seg = [&](const LsRegion& r, UINT64& cb, UINT64& ce) {
        cb = (std::max<UINT64>)(r.base, o.start);
        ce = (std::min<UINT64>)(r.base + r.size, o.stop);
        if (o.modSize) {
            cb = (std::max<UINT64>)(cb, o.modBase);
            ce = (std::min<UINT64>)(ce, o.modBase + o.modSize);
        }
    };

    auto regs = g_drv->regions();
    size_t scanned = 0;
    bool ok = false;

    if (stype == S_EXACT) {
        for (auto& r : regs) {
            if (!g_running || !g_scanning) break;
            if (!pass_region(r)) continue;
            UINT64 base = 0, end = 0;
            clip_seg(r, base, end);
            if (end <= base || end - base < useLen) continue;
            UINT64 left = end - base;
            while (left && out.size() < MAX_HITS) {
                SIZE_T want = (SIZE_T)(std::min<UINT64>)(left, 0x2000000);
                auto hits = g_drv->kscan(base, want, pat, msk, useLen, 256);
                for (auto h : hits) {
                    if (out.size() >= MAX_HITS) break;
                    Cand c{}; c.addr = h;
                    g_drv->read_raw(h, c.prev, useLen);
                    out.push_back(c);
                }
                if (hits.size() >= 256) break; // dense area capped per 32MB slice
                base += want; left -= want;
            }
            scanned++;
            if (out.size() >= MAX_HITS) break;
        }
        ok = true;
    }
    else {
        std::vector<BYTE> chunk;
        chunk.resize(0x100000);
        for (auto& r : regs) {
            if (!g_running || !g_scanning) break;
            if (!pass_region(r)) continue;
            UINT64 base = 0, end = 0;
            clip_seg(r, base, end);
            if (end <= base || end - base < useLen) continue;
            UINT64 left = end - base;
            UINT64 off = 0;
            while (left && out.size() < MAX_HITS) {
                SIZE_T want = (SIZE_T)(std::min<UINT64>)(left, chunk.size());
                if (!g_drv->read_raw_checked(base + off, chunk.data(), want)) { off += 0x1000; left -= (std::min<UINT64>)(left, 0x1000); continue; }
                for (SIZE_T i = 0; i + useLen <= want && out.size() < MAX_HITS; i += (SIZE_T)step) {
                    BYTE* cur = chunk.data() + i;
                    bool keep = false;
                    if (stype == S_BETWEEN) {
                        int lo = cmp_num(vtype, cur, pat, useLen);
                        int hi = cmp_num(vtype, cur, pat2, useLen);
                        if (cmp_num(vtype, pat, pat2, useLen) > 0) keep = (hi >= 0 && lo <= 0);
                        else keep = (lo >= 0 && hi <= 0);
                    }
                    else if (stype == S_BIGGER) keep = (cmp_num(vtype, cur, pat, useLen) > 0);
                    else if (stype == S_SMALLER) keep = (cmp_num(vtype, cur, pat, useLen) < 0);
                    else keep = true;
                    if (keep) {
                        Cand c{}; c.addr = base + off + i;
                        memcpy(c.prev, cur, useLen);
                        out.push_back(c);
                    }
                }
                off += want; left -= want;
            }
            scanned++;
            if (out.size() >= MAX_HITS) break;
        }
        ok = true;
    }

    push_undo();
    { std::lock_guard<std::mutex> lk(g_candsMtx); g_cands.swap(out); }
    if (ok) {
        if (scanned == 0)
            snprintf(g_scanMsg, sizeof(g_scanMsg), "0 regions pass filters (tick Executable for code/AOB)");
        else if (out.empty() && vtype == V_AOB && !o.executable)
            snprintf(g_scanMsg, sizeof(g_scanMsg), "%zu regions, 0 hits - code lives in exec pages: tick Executable", scanned);
        else snprintf(g_scanMsg, sizeof(g_scanMsg), "First scan done: %zu regions", scanned);
    }
    else snprintf(g_scanMsg, sizeof(g_scanMsg), "Scan failed");
    PostMessageA(g_hwnd, WM_SCAN_DONE, 1, 0);
    g_scanning = false;
}

static void NextScanThread(std::string s1, std::string s2, int vtype, int stype, bool hex) {
    HideThreadFromDebugger();
    g_scanning = true;
    snprintf(g_scanMsg, sizeof(g_scanMsg), "Next scan...");
    PostMessageA(g_hwnd, WM_SCAN_DONE, 2, 0);

    UCHAR pat[32]{}, msk[32]{};
    ULONG plen = 0;
    UCHAR pat2[32]{};
    if ((stype == S_EXACT || stype == S_BIGGER || stype == S_SMALLER || stype == S_BETWEEN)) {
        if (vtype == V_AOB) { if (!parse_aob(s1.c_str(), pat, msk, plen)) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad Array of Byte"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; } }
        else if (!parse_val1(vtype, s1.c_str(), hex, pat, msk, plen)) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad value"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }
        if (stype == S_BETWEEN && !parse_val1(vtype, s2.c_str(), hex, pat2, msk, plen)) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad second value"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }
    }
    if (!g_drv || !g_attached) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Select a process first"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); g_scanning = false; return; }

    std::vector<Cand> cur;
    { std::lock_guard<std::mutex> lk(g_candsMtx); cur = g_cands; }
    std::vector<Cand> out;
    out.reserve(cur.size());
    ULONG useLen = g_valLen;
    BYTE buf[32]{};
    for (auto& c : cur) {
        if (!g_running || !g_scanning) break;
        if (!g_drv->read_raw_checked(c.addr, buf, useLen)) continue;
        bool keep = false;
        if (stype == S_EXACT) {
            if (vtype == V_AOB) {
                keep = true;
                for (ULONG i = 0; i < useLen; i++) if (msk[i] && buf[i] != pat[i]) { keep = false; break; }
            }
            else keep = (cmp_num(vtype, buf, pat, useLen) == 0);
        }
        else if (stype == S_BIGGER) keep = (cmp_num(vtype, buf, pat, useLen) > 0);
        else if (stype == S_SMALLER) keep = (cmp_num(vtype, buf, pat, useLen) < 0);
        else if (stype == S_BETWEEN) {
            int lo = cmp_num(vtype, buf, pat, useLen);
            int hi = cmp_num(vtype, buf, pat2, useLen);
            if (cmp_num(vtype, pat, pat2, useLen) > 0) keep = (hi >= 0 && lo <= 0);
            else keep = (lo >= 0 && hi <= 0);
        }
        else if (stype == S_INCREASED) keep = (cmp_num(vtype, buf, c.prev, useLen) > 0);
        else if (stype == S_DECREASED) keep = (cmp_num(vtype, buf, c.prev, useLen) < 0);
        else if (stype == S_CHANGED) keep = (memcmp(buf, c.prev, useLen) != 0);
        else if (stype == S_UNCHANGED) keep = (memcmp(buf, c.prev, useLen) == 0);
        if (keep) { Cand n{}; n.addr = c.addr; memcpy(n.prev, buf, useLen); out.push_back(n); }
    }
    push_undo();
    { std::lock_guard<std::mutex> lk(g_candsMtx); g_cands.swap(out); }
    snprintf(g_scanMsg, sizeof(g_scanMsg), "Next scan done");
    PostMessageA(g_hwnd, WM_SCAN_DONE, 1, 0);
    g_scanning = false;
}

// Freeze thread — rewrites Active table entries
static std::atomic<bool> g_freezeRun{ true };
static void FreezeThread() {
    HideThreadFromDebugger();
    while (g_freezeRun && g_running) {
        Sleep(120);
        if (!g_drv || !g_attached) continue;
        std::lock_guard<std::mutex> lk(g_tableMtx);
        for (auto& e : g_table) {
            if (!e.active) continue;
            UINT64 f = e.addr;
            if (!entry_final(e, f)) continue;
            g_drv->write_bytes(f, e.bytes, e.len);
        }
    }
}

//=================================================================
//  POINTER SCAN (CE-style reverse brute force)
//  L0 = target address. Each level: find 8B-aligned qwords in writable
//  memory with value V in [t-maxOff, t] for any frontier t -> holder H
//  gives (H, off=t-V). Holders inside a module close a static path.
//  Rescan re-resolves saved paths against a new target (checkpoint flow).
//=================================================================
struct PSPath {
    std::string mod;
    UINT64 modOff = 0;
    UINT64 offs[PTR_MAX]{};
    int nOff = 0;
    UINT64 pointsTo = 0;
};
static bool TableFileDlg(bool save, char* out, int outSz); // defined in Legend Table section
static void PS_ForFoundRow();
struct PSState {
    std::atomic<bool> run{ false };
    std::atomic<bool> stop{ false };
    std::atomic<uint64_t> paths{ 0 };   // qwords evaluated
    std::atomic<uint64_t> results{ 0 };
    std::atomic<int> level{ 0 };
    std::atomic<int> regionsDone{ 0 };
    std::atomic<int> regionsTotal{ 0 };
    DWORD startTick = 0;
    UINT64 target = 0;
    int vtype = V_U32;
    ULONG vlen = 4;
    int maxLevel = 5, maxOff = 4095, maxDiff = 3, nThreads = 4;
    std::string savePath;
};
static PSState g_ps;
static std::vector<PSPath> g_psRes;
static std::mutex g_psResMtx;
static HWND g_psProg = nullptr; // progress window
static HWND g_psWin = nullptr;  // results window
static std::atomic<bool> g_pscanning{ false };

static bool ps_in_module(UINT64 a, const std::vector<ModInfo>& mods, size_t& idx) {
    for (size_t i = 0; i < mods.size(); i++) {
        if (mods[i].size && a >= mods[i].base && a < mods[i].base + mods[i].size) { idx = i; return true; }
    }
    return false;
}

struct PSCand { UINT64 holder = 0; UINT64 off = 0; UINT64 parent = 0; };

// One level of reverse scan, regions fanned over N threads (own driver handles)
static void PSLevel(const std::vector<UINT64>& frontier, const std::vector<LsRegion>& regs,
    int maxOff, std::vector<PSCand>& out, int nThreads) {
    if (frontier.empty() || regs.empty()) return;
    std::vector<UINT64> sorted = frontier;
    std::sort(sorted.begin(), sorted.end());
    std::atomic<size_t> ri{ 0 };
    std::mutex mtx;
    auto worker = [&]() {
        HideThreadFromDebugger();
        SSTR(_dev, _s_dev);
        ls_driver drv(_dev, g_pid);
        if (!drv.valid()) return;
        std::vector<BYTE> chunk;
        chunk.resize(0x100000);
        std::vector<PSCand> local;
        local.reserve(8192);
        for (;;) {
            if (g_ps.stop || !g_running) break;
            size_t idx = ri++;
            if (idx >= regs.size()) break;
            const LsRegion& r = regs[idx];
            UINT64 base = r.base;
            UINT64 left = r.size;
            UINT64 off = 0;
            while (left && !g_ps.stop) {
                SIZE_T want = (SIZE_T)(std::min<UINT64>)(left, chunk.size());
                // 8B-align the window
                UINT64 a0 = (base + off + 7) & ~7ULL;
                UINT64 a1 = base + off + want;
                if (a1 <= a0 || a1 - a0 < 8) { off += want; left -= want; continue; }
                SIZE_T rwant = (SIZE_T)(a1 - a0);
                if (!drv.read_raw_checked(a0, chunk.data(), rwant)) { off += want; left -= want; continue; }
                for (SIZE_T i = 0; i + 8 <= rwant; i += 8) {
                    UINT64 v = 0;
                    memcpy(&v, chunk.data() + i, 8);
                    g_ps.paths++;
                    // frontier targets t with V <= t <= V+maxOff
                    auto lo = std::lower_bound(sorted.begin(), sorted.end(), v);
                    for (auto it = lo; it != sorted.end(); it++) {
                        UINT64 t = *it;
                        if (t - v > (UINT64)maxOff) break;
                        PSCand c{}; c.holder = a0 + i; c.off = t - v; c.parent = t;
                        local.push_back(c);
                        if (local.size() >= 8192) {
                            std::lock_guard<std::mutex> lk(mtx);
                            out.insert(out.end(), local.begin(), local.end());
                            local.clear();
                        }
                    }
                }
                off += want; left -= want;
            }
            g_ps.regionsDone++;
        }
        if (!local.empty()) {
            std::lock_guard<std::mutex> lk(mtx);
            out.insert(out.end(), local.begin(), local.end());
        }
    };
    if (nThreads < 1) nThreads = 1;
    if (nThreads > 16) nThreads = 16;
    std::vector<std::thread> th;
    for (int i = 0; i < nThreads; i++) th.emplace_back(worker);
    for (auto& t : th) t.join();
}

// Full multilevel scan (runs on a detached thread)
static void PSScanThread(UINT64 target, int vtype, ULONG vlen, int maxLevel, int maxOff, int maxDiff, int nThreads, std::string savePath) {
    HideThreadFromDebugger();
    g_pscanning = true;
    g_ps.run = true; g_ps.stop = false;
    g_ps.paths = 0; g_ps.results = 0; g_ps.level = 0;
    g_ps.target = target; g_ps.vtype = vtype; g_ps.vlen = vlen;
    g_ps.maxLevel = maxLevel; g_ps.maxOff = maxOff; g_ps.nThreads = nThreads;
    g_ps.savePath = savePath;
    g_ps.startTick = GetTickCount();
    PostMessageA(g_hwnd, WM_SCAN_DONE, 3, 0); // open progress window

    // snapshot writable regions + modules once
    std::vector<LsRegion> regs;
    std::vector<ModInfo> mods;
    if (g_drv && g_attached) {
        auto all = g_drv->regions();
        for (auto& r : all) {
            if (r.state != 0x1000) continue;
            if (!readable_protect(r.protect)) continue;
            if (!writeable_protect(r.protect)) continue; // pointers live in RW memory
            if (r.size < 8 || r.size > 0x40000000) continue;
            regs.push_back(r);
        }
        mods = g_mods;
    }
    // module ranges sorted for binary search-ish checks
    std::sort(mods.begin(), mods.end(), [](const ModInfo& a, const ModInfo& b) { return a.base < b.base; });

    std::vector<UINT64> frontier;
    frontier.push_back(target);
    std::unordered_map<UINT64, std::pair<UINT64, UINT64>> parent; // holder -> (parentTarget, off)
    std::unordered_set<UINT64> visited;
    visited.insert(target);
    std::vector<PSPath> results;

    const size_t LVL_CAP = 500000;
    const size_t RES_CAP = 500000;

    for (int lvl = 1; lvl <= maxLevel && !g_ps.stop && g_running; lvl++) {
        g_ps.level = lvl;
        g_ps.regionsDone = 0;
        g_ps.regionsTotal = (int)regs.size();
        std::vector<PSCand> cands;
        PSLevel(frontier, regs, maxOff, cands, nThreads);
        if (g_ps.stop || !g_running) break;
        if (cands.empty()) break;
        // sort by (holder, off), dedup, cap distinct offsets per holder
        std::sort(cands.begin(), cands.end(), [](const PSCand& a, const PSCand& b) {
            return a.holder < b.holder || (a.holder == b.holder && a.off < b.off);
        });
        std::vector<UINT64> next;
        next.reserve(cands.size());
        size_t i = 0;
        while (i < cands.size() && next.size() < LVL_CAP && results.size() < RES_CAP) {
            size_t j = i;
            int kept = 0;
            while (j < cands.size() && cands[j].holder == cands[i].holder) {
                if (kept < maxDiff && !visited.count(cands[j].holder)) {
                    UINT64 H = cands[j].holder;
                    size_t mi = 0;
                    if (ps_in_module(H, mods, mi)) {
                        // static path closed — reconstruct chain H -> ... -> target
                        PSPath p;
                        p.mod = mods[mi].name;
                        p.modOff = H - mods[mi].base;
                        UINT64 walk[PTR_MAX + 1]{};
                        UINT64 no = cands[j].off;
                        walk[0] = H;
                        std::vector<UINT64> ro;
                        ro.push_back(no);
                        UINT64 node = cands[j].parent;
                        while (node != target) {
                            auto f = parent.find(node);
                            if (f == parent.end()) break;
                            ro.push_back(f->second.second);
                            node = f->second.first;
                        }
                        if (node != target) { j++; continue; } // broken link (shouldn't happen)
                        p.nOff = (int)(std::min<size_t>)(ro.size(), PTR_MAX);
                        for (int k = 0; k < p.nOff; k++) p.offs[k] = ro[(size_t)k];
                        p.pointsTo = target;
                        results.push_back(p);
                        g_ps.results = results.size();
                    }
                    else {
                        parent[H] = { cands[j].parent, cands[j].off };
                        next.push_back(H);
                    }
                    visited.insert(H);
                    kept++;
                }
                j++;
            }
            i = j;
            if (g_ps.stop) break;
        }
        // unique next frontier
        std::sort(next.begin(), next.end());
        next.erase(std::unique(next.begin(), next.end()), next.end());
        frontier.swap(next);
        if (frontier.empty()) break;
    }

    {
        std::lock_guard<std::mutex> lk(g_psResMtx);
        g_psRes.swap(results);
    }
    // checkpoint file (CE asks to save results — ours writes the chosen path)
    if (!savePath.empty() && !g_psRes.empty()) {
        FILE* f = nullptr;
        fopen_s(&f, savePath.c_str(), "wb");
        if (f) {
            fprintf(f, "<LegendPointers target=\"%llX\" vtype=\"%d\" vlen=\"%lu\">\n",
                (unsigned long long)target, vtype, vlen);
            std::lock_guard<std::mutex> lk(g_psResMtx);
            for (auto& p : g_psRes) {
                char offs[128]{};
                for (int k = 0; k < p.nOff; k++)
                    snprintf(offs + strlen(offs), sizeof(offs) - strlen(offs), "%s%llX", k ? "," : "", (unsigned long long)p.offs[k]);
                fprintf(f, "<P mod=\"%s\" moff=\"%llX\" n=\"%d\" offs=\"%s\" points=\"%llX\"/>\n",
                    p.mod.c_str(), (unsigned long long)p.modOff, p.nOff, offs, (unsigned long long)p.pointsTo);
            }
            fprintf(f, "</LegendPointers>\n");
            fclose(f);
        }
    }
    g_ps.run = false;
    g_pscanning = false;
    PostMessageA(g_hwnd, WM_SCAN_DONE, 4, 0); // done -> open results window
}

//=================================================================
//  Driver thread — auto load amdfend.sys via Loader
//=================================================================
static void DriverThread() {
    HideThreadFromDebugger();
    SSTR(_dev, _s_dev);
    {
        char exe[MAX_PATH]{};
        GetModuleFileNameA(nullptr, exe, MAX_PATH);
        char* s = strrchr(exe, '\\');
        if (s) { *s = 0; SetCurrentDirectoryA(exe); }
    }
    auto RunWait = [](const char* exe, const char* args, DWORD to) {
        char cmd[256]{}; snprintf(cmd, sizeof(cmd), "%s %s", exe, args ? args : "");
        STARTUPINFOA si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        if (CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE, nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, to);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
    };
    setStatus("Loading driver...");
    { SSTR(_efi, _s_efi); RunWait(_efi, "-d", 8000); }
    {
        SSTR(_drv, _s_drv);
        char args[128]{}; snprintf(args, sizeof(args), "%s --no-dsefix --keep", _drv);
        const char* cands[] = { ".\\Loader.exe", "Loader.exe", nullptr };
        for (auto c : cands) {
            if (!c) break;
            if (GetFileAttributesA(c) != INVALID_FILE_ATTRIBUTES) { RunWait(c, args, 12000); break; }
        }
    }
    { SSTR(_efi, _s_efi); RunWait(_efi, "-e", 8000); }
    for (int t = 0; t < 20 && g_running; t++) {
        Sleep(500);
        HANDLE h = CreateFileA(_dev, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); g_connected = true; break; }
        char s[64]; snprintf(s, sizeof(s), "Starting... (%ds)", t / 2 + 1); setStatus(s);
    }
    if (!g_connected) { setStatus("Driver MISSING (run as Admin + EfiGuard)"); return; }
    {
        ls_driver tmp(_dev, 0);
        DWORD v = tmp.version();
        char s[96]; snprintf(s, sizeof(s), v == LS_BUILD_TAG ? "Driver OK v%08X" : "Driver tag %08X (update!)", v);
        setStatus(s);
    }
}

//=================================================================
//  UI construction — CE layout
//=================================================================
static void AddComboItems(HWND cb, const char* const* items, int n, int sel) {
    for (int i = 0; i < n; i++) SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)items[i]);
    SendMessageA(cb, CB_SETCURSEL, sel, 0);
}
static HWND mk(const char* cls, const char* txt, DWORD style, int x, int y, int w, int hh, int id, HWND parent = nullptr) {
    HWND hCtl = CreateWindowExA(0, cls, txt, style | WS_CHILD | WS_VISIBLE, x, y, w, hh, parent ? parent : g_hwnd, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
    if (id >= 0 && id < 1200) g_ctl[id] = hCtl;
    if (g_fUI) SendMessageA(hCtl, WM_SETFONT, (WPARAM)g_fUI, TRUE);
    return hCtl;
}
static std::string getText(int id) {
    HWND h = ctl(id); if (!h) return "";
    char b[1024]{}; GetWindowTextA(h, b, sizeof(b) - 1); return b;
}
static std::string dlgText(HWND parent, int id) {
    HWND h = GetDlgItem(parent, id); if (!h) return "";
    char b[1024]{}; GetWindowTextA(h, b, sizeof(b) - 1); return b;
}

static void BuildUI() {
    // ---- toolbar row (CE style): process button + label ----
    mk("BUTTON", "PC", BS_PUSHBUTTON, 8, 8, 34, 28, IDC_PROC_BTN);
    mk("STATIC", "No Process Selected", SS_LEFT, 48, 14, 560, 20, IDC_PROC_LBL);
    mk("STATIC", "Found:0", SS_LEFT, 8, 44, 120, 18, IDC_FOUND_LBL);

    // ---- left: found list (Address | Value | Previous) ----
    HWND lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 8, 64, 400, 330, g_hwnd, (HMENU)(INT_PTR)IDC_FOUND_LIST, GetModuleHandleA(nullptr), nullptr);
    g_ctl[IDC_FOUND_LIST] = lv;
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    {
        const char* n[] = { "Address", "Value", "Previous" };
        int w[] = { 130, 130, 130 };
        lv_cols(lv, n, w, 3);
    }

    // ---- right: scan buttons ----
    mk("BUTTON", "First Scan", BS_PUSHBUTTON, 420, 64, 100, 26, IDC_FIRST_BTN);
    mk("BUTTON", "Next Scan", BS_PUSHBUTTON, 528, 64, 100, 26, IDC_NEXT_BTN);
    mk("BUTTON", "Undo Scan", BS_PUSHBUTTON, 636, 64, 100, 26, IDC_UNDO_BTN);
    mk("BUTTON", "Memory View", BS_PUSHBUTTON, 420, 398, 110, 26, IDC_MEMVIEW_BTN);

    // Value + Hex
    mk("STATIC", "Value:", SS_RIGHT, 420, 100, 45, 20, -1);
    mk("EDIT", "100", WS_BORDER | ES_AUTOHSCROLL, 470, 98, 200, 24, IDC_VAL_EDIT);
    mk("BUTTON", "Hex", BS_AUTOCHECKBOX, 676, 100, 55, 22, IDC_HEX_CHK);

    // Scan Type / Value Type
    mk("STATIC", "Scan Type:", SS_RIGHT, 420, 130, 70, 20, -1);
    HWND scb = mk("COMBOBOX", "", WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL, 496, 128, 240, 220, IDC_STYPE_CB);
    {
        const char* sts[] = { "Exact Value", "Bigger than...", "Smaller than...", "Value Between...", "Increased value", "Decreased value", "Changed value", "Unchanged value" };
        AddComboItems(scb, sts, 8, 0);
    }
    mk("STATIC", "Value Type:", SS_RIGHT, 420, 158, 70, 20, -1);
    HWND vcb = mk("COMBOBOX", "", WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL, 496, 156, 240, 220, IDC_VTYPE_CB);
    {
        const char* vts[] = { "1 Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "String", "Array of Byte" };
        AddComboItems(vcb, vts, 8, 2);
    }

    // ---- Memory Scan Options group ----
    HWND grp = mk("BUTTON", "Memory Scan Options", BS_GROUPBOX, 420, 186, 330, 206, -1);
    (void)grp;
    HWND pcb = mk("COMBOBOX", "", WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL, 430, 208, 200, 220, IDC_PRESET_CB);
    {
        const char* ps[] = { "All" };
        AddComboItems(pcb, ps, 1, 0);
    }
    mk("STATIC", "Start", SS_RIGHT, 430, 236, 35, 20, -1);
    mk("EDIT", "00000000", WS_BORDER | ES_AUTOHSCROLL, 470, 234, 120, 22, IDC_START_EDIT);
    mk("STATIC", "Stop", SS_RIGHT, 430, 260, 35, 20, -1);
    mk("EDIT", "ffffffffffff", WS_BORDER | ES_AUTOHSCROLL, 470, 258, 120, 22, IDC_STOP_EDIT);
    mk("BUTTON", "Writable", BS_AUTOCHECKBOX, 430, 284, 80, 22, IDC_WRITABLE_CHK);
    mk("BUTTON", "Executable", BS_AUTOCHECKBOX, 520, 284, 95, 22, IDC_EXEC_CHK);
    mk("BUTTON", "CopyOnWrite", BS_AUTOCHECKBOX, 430, 306, 110, 22, IDC_COW_CHK);
    mk("BUTTON", "Fast Scan", BS_AUTOCHECKBOX, 430, 330, 90, 22, IDC_FAST_CHK);
    mk("EDIT", "4", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 525, 330, 40, 22, IDC_ALIGN_EDIT);
    mk("BUTTON", "Alignment", BS_AUTORADIOBUTTON, 575, 330, 80, 22, IDC_ALIGN_RADIO);
    SendMessageA(ctl(IDC_WRITABLE_CHK), BM_SETCHECK, BST_CHECKED, 0);
    SendMessageA(ctl(IDC_FAST_CHK), BM_SETCHECK, BST_CHECKED, 0);
    SendMessageA(ctl(IDC_ALIGN_RADIO), BM_SETCHECK, BST_CHECKED, 0);

    // ---- bottom: add-address + table ----
    mk("BUTTON", "Add Address Manually", BS_PUSHBUTTON, 620, 398, 150, 26, IDC_ADDADDR_BTN);
    HWND tv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 8, 432, 762, 170, g_hwnd, (HMENU)(INT_PTR)IDC_TBL_LIST, GetModuleHandleA(nullptr), nullptr);
    g_ctl[IDC_TBL_LIST] = tv;
    ListView_SetExtendedListViewStyle(tv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);
    {
        const char* n[] = { "", "Description", "Address", "Type", "Value" };
        int w[] = { 24, 220, 150, 110, 250 };
        lv_cols(tv, n, w, 5);
    }

    // ---- status bar ----
    mk("STATIC", g_status, SS_LEFT, 8, 608, 762, 20, IDC_STATUS_TXT);
}

// Manual-add popup — CE layout: Address =??? / Description / Type / Hex+Signed / Pointer+Offset
static int dlgRealVtype(HWND h) {
    int vt = (int)SendMessageA(GetDlgItem(h, DLG_TYPE_CB), CB_GETCURSEL, 0, 0);
    if (vt < 0) vt = 2;
    if (vt == 4) return V_F32; if (vt == 5) return V_F64;
    if (vt == 6) return V_STR; if (vt == 7) return V_AOB;
    if (vt == 0) return V_U8; if (vt == 1) return V_U16;
    if (vt == 2) return V_U32; return V_U64;
}
static ULONG dlgTypeLen(int realVt) {
    if (realVt == V_U8) return 1; if (realVt == V_U16) return 2;
    if (realVt == V_U32 || realVt == V_F32) return 4;
    if (realVt == V_U64 || realVt == V_F64) return 8;
    return 16; // String / AoB default window
}
static int g_dlgNOff = 1; // visible offset rows in manual dialog
static int dlgOffId(int i) { return DLG_OFF0 + i; }
// Gather dialog base expression + pointer chain. Returns false when base empty.
static bool dlgGather(HWND h, std::string& mod, UINT64& absBase, UINT64& modOff, bool& isMod, UINT64 offs[PTR_MAX], int& n) {
    n = 0;
    if (!parse_addr_expr(dlgText(h, DLG_ADDR_EDIT).c_str(), mod, absBase, modOff, isMod)) return false;
    bool isPtr = SendMessageA(GetDlgItem(h, DLG_PTR_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (isPtr) {
        n = (std::min)(g_dlgNOff, PTR_MAX);
        if (n < 1) n = 1;
        for (int i = 0; i < n; i++)
            offs[i] = strtoull(dlgText(h, dlgOffId(i)).c_str(), nullptr, 16);
    }
    return true;
}
static void updateManualPreview(HWND h) {
    std::string mod; UINT64 absBase = 0, modOff = 0; bool isMod = false;
    UINT64 offs[PTR_MAX]{}; int n = 0;
    int rv = dlgRealVtype(h);
    ULONG len = dlgTypeLen(rv);
    bool isHex = SendMessageA(GetDlgItem(h, DLG_HEX_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    bool isSgn = SendMessageA(GetDlgItem(h, DLG_SIGNED_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    char prev[128]; snprintf(prev, sizeof(prev), "=???");
    std::string chain;
    if (dlgGather(h, mod, absBase, modOff, isMod, offs, n)) {
        // resolve base
        UINT64 base = 0; bool baseOk = false;
        char baseLine[160]{};
        if (isMod) {
            base = mod_base(mod.c_str());
            if (base) { base += modOff; baseOk = true; snprintf(baseLine, sizeof(baseLine), "\"%s\"+%llX = %llX", mod.c_str(), (unsigned long long)modOff, (unsigned long long)base); }
            else snprintf(baseLine, sizeof(baseLine), "\"%s\"+%llX = ???", mod.c_str(), (unsigned long long)modOff);
        }
        else { base = absBase; baseOk = base != 0; snprintf(baseLine, sizeof(baseLine), "%llX", (unsigned long long)base); }
        chain = baseLine;
        UINT64 p = base; bool ok = baseOk && g_drv && g_attached;
        if (ok && !ls_driver::is_user_range(p, 8)) ok = false;
        for (int i = 0; ok && i < n; i++) {
            UINT64 v = 0;
            if (!g_drv->read_u64_checked(p, v) || !v) { ok = false; break; }
            UINT64 nxt = v + offs[i];
            if (nxt < v || !ls_driver::is_user_range(nxt, 1)) { ok = false; break; }
            char step[96]; snprintf(step, sizeof(step), "\r\n*%llX=%llX+%llX -> %llX", (unsigned long long)p, (unsigned long long)v, (unsigned long long)offs[i], (unsigned long long)nxt);
            chain += step;
            p = nxt;
        }
        if (ok && p) {
            BYTE cur[32]{};
            g_drv->read_raw(p, cur, len);
            std::string vs = fmt_valx(rv, cur, len, isHex, isSgn);
            snprintf(prev, sizeof(prev), "=%.60s", vs.c_str());
        }
    }
    SetDlgItemTextA(h, DLG_PREVIEW, prev);
    HWND ch = GetDlgItem(h, DLG_CHAIN);
    if (ch) SetWindowTextA(ch, chain.c_str());
}
// Parse Change-Value text into entry bytes (hex when 0x-prefixed or hex flag)
static bool parse_entry_value(const TblEntry& e, const char* txt, bool hex, BYTE out[32]) {
    char tmp[256]; snprintf(tmp, sizeof(tmp), "%s", txt ? txt : "");
    while (*tmp && isspace((unsigned char)*tmp)) memmove(tmp, tmp + 1, strlen(tmp));
    size_t L = strlen(tmp);
    while (L && isspace((unsigned char)tmp[L - 1])) tmp[--L] = 0;
    if (!L) return false;
    memset(out, 0, 32);
    if (e.vtype == V_STR) {
        size_t n = (std::min<size_t>)(L, e.len);
        memcpy(out, tmp, n);
        return true;
    }
    if (e.vtype == V_AOB) {
        UCHAR p[32]{}, m[32]{}; ULONG l = 0;
        if (!parse_aob(tmp, p, m, l) || l != e.len) return false;
        for (ULONG i = 0; i < l; i++) if (!m[i]) return false;
        memcpy(out, p, l);
        return true;
    }
    bool hx = hex;
    if (L > 2 && tmp[0] == '0' && (tmp[1] == 'x' || tmp[1] == 'X')) hx = true;
    int base = hx ? 16 : 0;
    if (e.vtype == V_F32) { float f = (float)strtod(tmp, nullptr); memcpy(out, &f, 4); return true; }
    if (e.vtype == V_F64) { double d = strtod(tmp, nullptr); memcpy(out, &d, 8); return true; }
    if (e.isSigned) {
        long long v = strtoll(tmp, nullptr, base);
        if (e.vtype == V_U8) { int8_t x = (int8_t)v; memcpy(out, &x, 1); }
        else if (e.vtype == V_U16) { int16_t x = (int16_t)v; memcpy(out, &x, 2); }
        else if (e.vtype == V_U32) { int32_t x = (int32_t)v; memcpy(out, &x, 4); }
        else { int64_t x = (int64_t)v; memcpy(out, &x, 8); }
        return true;
    }
    unsigned long long v = strtoull(tmp, nullptr, base);
    if (e.vtype == V_U8) out[0] = (BYTE)v;
    else if (e.vtype == V_U16) { uint16_t x = (uint16_t)v; memcpy(out, &x, 2); }
    else if (e.vtype == V_U32) { uint32_t x = (uint32_t)v; memcpy(out, &x, 4); }
    else { uint64_t x = (uint64_t)v; memcpy(out, &x, 8); }
    return true;
}
static void layoutManualDlg(HWND h) {
    // small (plain address) vs big (pointer chain) layout
    bool isPtr = SendMessageA(GetDlgItem(h, DLG_PTR_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    int okY = isPtr ? 424 : 222;
    SetWindowPos(GetDlgItem(h, DLG_OK_BTN), nullptr, 12, okY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    SetWindowPos(GetDlgItem(h, DLG_CANCEL_BTN), nullptr, 152, okY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    SetWindowPos(h, nullptr, 0, 0, 300, isPtr ? 510 : 300, SWP_NOMOVE | SWP_NOZORDER);
    for (int i = 0; i < PTR_MAX; i++) {
        HWND oe = GetDlgItem(h, dlgOffId(i));
        if (oe) ShowWindow(oe, (isPtr && i < g_dlgNOff) ? SW_SHOW : SW_HIDE);
    }
    ShowWindow(GetDlgItem(h, DLG_CHAIN), isPtr ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(h, DLG_ADD_OFF), isPtr ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(h, DLG_REM_OFF), isPtr ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(h, DLG_OFF_EDIT), SW_HIDE); // legacy single offset retired
}
static void OpenManualAdd(const char* addrPref, int vtypePref, bool isPtrPref = false, const UINT64* offsPref = nullptr, int nOffPref = 0, bool signedPref = false, const char* descPref = nullptr, const char* titlePref = nullptr) {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlgNOff = (isPtrPref && nOffPref > 0) ? (std::min)(nOffPref, PTR_MAX) : 1;
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, titlePref ? titlePref : "Add address", WS_POPUP | WS_CAPTION | WS_SYSMENU, 300, 200, 300, 300, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Address:", SS_LEFT, 12, 12, 60, 20, -1);
    c("EDIT", addrPref ? addrPref : "", WS_BORDER | ES_AUTOHSCROLL, 12, 32, 170, 24, DLG_ADDR_EDIT);
    c("STATIC", "=???", SS_LEFT, 190, 34, 90, 20, DLG_PREVIEW);
    c("STATIC", "Description", SS_LEFT, 12, 62, 90, 20, -1);
    c("EDIT", descPref ? descPref : "No description", WS_BORDER | ES_AUTOHSCROLL, 12, 82, 260, 24, DLG_DESC_EDIT);
    c("STATIC", "Type", SS_LEFT, 12, 112, 60, 20, -1);
    g_dlgTypeCb = c("COMBOBOX", "", WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL, 12, 132, 260, 160, DLG_TYPE_CB);
    {
        const char* vts[] = { "1 Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "String", "Array of Byte" };
        AddComboItems(g_dlgTypeCb, vts, 8, vtypePref);
    }
    HWND hx = c("BUTTON", "Hexadecimal", BS_AUTOCHECKBOX, 12, 162, 110, 22, DLG_HEX_CHK);
    HWND sg = c("BUTTON", "Signed", BS_AUTOCHECKBOX, 130, 162, 80, 22, DLG_SIGNED_CHK);
    HWND pc = c("BUTTON", "Pointer", BS_AUTOCHECKBOX, 12, 188, 80, 22, DLG_PTR_CHK);
    c("EDIT", "0", WS_BORDER | ES_AUTOHSCROLL, 100, 186, 172, 24, DLG_OFF_EDIT); // hidden legacy
    // offset rows + chain (pointer mode)
    for (int i = 0; i < PTR_MAX; i++)
        c("EDIT", "0", WS_BORDER | ES_AUTOHSCROLL, 100, 214 + i * 26, 100, 22, dlgOffId(i));
    c("STATIC", "", SS_LEFT, 12, 344, 260, 56, DLG_CHAIN);
    c("BUTTON", "Add Offset", BS_PUSHBUTTON, 12, 404, 120, 24, DLG_ADD_OFF);
    c("BUTTON", "Remove Offset", BS_PUSHBUTTON, 142, 404, 130, 24, DLG_REM_OFF);
    if (signedPref) SendMessageA(sg, BM_SETCHECK, BST_CHECKED, 0);
    if (isPtrPref) {
        SendMessageA(pc, BM_SETCHECK, BST_CHECKED, 0);
        for (int i = 0; i < g_dlgNOff && offsPref; i++) {
            char ob[32]; snprintf(ob, sizeof(ob), "%llX", (unsigned long long)offsPref[i]);
            SetDlgItemTextA(p, dlgOffId(i), ob);
        }
    }
    (void)hx;
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 12, 222, 120, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 152, 222, 120, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 0); // mode 0 = manual add
    layoutManualDlg(p);
    ShowWindow(p, SW_SHOW);
    updateManualPreview(p);
}
// --- Settings popup (mode 6) ---
static void OpenSettings() {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Settings", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 340, 150, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    HWND chk = c("BUTTON", "Show Module+Address (When Possible)", BS_AUTOCHECKBOX, 12, 16, 300, 22, SET_MODCHK);
    if (g_showModAddr) SendMessageA(chk, BM_SETCHECK, BST_CHECKED, 0);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 70, 60, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 170, 60, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 6); // mode 6 = settings
    ShowWindow(p, SW_SHOW);
}
// --- CE column popups (modes 3/4/5) ---
static void OpenChangeValue(const TblEntry& e) {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Change Value", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 330, 150, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "what value to change this to?", SS_LEFT, 12, 12, 290, 20, -1);
    BYTE cur[32]{};
    UINT64 f = e.addr;
    bool have = (g_drv && g_attached && entry_final(e, f));
    if (have) g_drv->read_raw(f, cur, e.len); else memcpy(cur, e.bytes, e.len);
    std::string vs = fmt_valx(e.vtype, cur, e.len, e.hexDisp, e.isSigned);
    c("EDIT", vs.c_str(), WS_BORDER | ES_AUTOHSCROLL, 12, 36, 290, 24, DLG_VAL_EDIT);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 70, 76, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 170, 76, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 3); // mode 3 = change value
    ShowWindow(p, SW_SHOW);
    HWND eb = GetDlgItem(p, DLG_VAL_EDIT);
    SendMessageA(eb, EM_SETSEL, 0, -1);
    SetFocus(eb);
}
static void OpenChangeType(const TblEntry& e) {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Type", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 300, 200, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Select the new type:", SS_LEFT, 12, 12, 260, 20, -1);
    HWND cb = c("COMBOBOX", "", WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL, 12, 34, 260, 160, DLG_TYPE_CB);
    {
        const char* vts[] = { "1 Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "String", "Array of Byte" };
        int sel = (e.vtype == V_U8) ? 0 : (e.vtype == V_U16) ? 1 : (e.vtype == V_U32) ? 2 : (e.vtype == V_U64) ? 3 : (e.vtype == V_F32) ? 4 : (e.vtype == V_F64) ? 5 : (e.vtype == V_STR) ? 6 : 7;
        AddComboItems(cb, vts, 8, sel);
    }
    HWND hx = c("BUTTON", "Hexadecimal", BS_AUTOCHECKBOX, 12, 64, 110, 22, DLG_HEX_CHK);
    HWND sg = c("BUTTON", "Signed", BS_AUTOCHECKBOX, 130, 64, 80, 22, DLG_SIGNED_CHK);
    if (e.hexDisp) SendMessageA(hx, BM_SETCHECK, BST_CHECKED, 0);
    if (e.isSigned) SendMessageA(sg, BM_SETCHECK, BST_CHECKED, 0);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 50, 100, 90, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 160, 100, 90, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 4); // mode 4 = change type
    ShowWindow(p, SW_SHOW);
}
static void OpenChangeDesc(const TblEntry& e) {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Change Description", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 360, 140, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "What will be the new description?", SS_LEFT, 12, 12, 320, 20, -1);
    c("EDIT", e.desc, WS_BORDER | ES_AUTOHSCROLL, 12, 36, 320, 24, DLG_DESC_EDIT);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 150, 70, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 245, 70, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 5); // mode 5 = change description
    ShowWindow(p, SW_SHOW);
    HWND eb = GetDlgItem(p, DLG_DESC_EDIT);
    SendMessageA(eb, EM_SETSEL, 0, -1);
    SetFocus(eb);
}
//=================================================================
//  x64 disassembler (64-bit mode, common subset) + single-line assembler
//  Unknown bytes fall back to `db XX`. Assembler numbers are HEX by
//  default (CE-style: `28` = 0x28, `0x28` and `28h` also accepted).
//=================================================================
static std::string xa_rname(int code, int ext, int bits, bool hasRex) {
    int r = (code & 7) | (ext ? 8 : 0);
    static const char* q[] = { "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15" };
    static const char* d[] = { "eax","ecx","edx","ebx","esp","ebp","esi","edi","r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d" };
    static const char* w[] = { "ax","cx","dx","bx","sp","bp","si","di","r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w" };
    static const char* bl[] = { "al","cl","dl","bl","spl","bpl","sil","dil","r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b" };
    static const char* bh[] = { "al","cl","dl","bl","ah","ch","dh","bh" };
    if (bits == 64) return q[r];
    if (bits == 32) return d[r];
    if (bits == 16) return w[r];
    if (!hasRex && !ext && code >= 4) return bh[code & 7];
    return bl[r];
}
// Decode r/m operand at c[pos] (modrm, 64-bit mode). Emits register name when
// mod==3, else [mem]. Returns bytes consumed (0 = truncated). hasRex includes
// any REX byte (for spl vs ah selection).
static int xa_rm(const BYTE* c, int avail, int pos, int regBits, bool hasRex, bool rx, bool rb,
    std::string& out, bool ripOk = true) {
    if (pos >= avail) return 0;
    int modrm = c[pos];
    int mod = (modrm >> 6) & 3, rm = modrm & 7;
    if (mod == 3) { out = xa_rname(rm, rb, regBits, hasRex); return 1; }
    std::string mem;
    int p = pos + 1;
    int index = -1, ix = 0, scale = 1, base = -1, bx = 0;
    bool noBase = false;
    if ((rm & 7) == 4) {
        if (p >= avail) return 0;
        int sib = c[p++];
        scale = 1 << ((sib >> 6) & 3);
        int idx = (sib >> 3) & 7;
        base = sib & 7;
        if (idx == 4) index = -1; else { index = idx; ix = rx ? 1 : 0; }
        if (base == 5 && mod == 0) { noBase = true; }
        else { bx = rb ? 1 : 0; }
        if (noBase) base = -1;
    }
    else if (rm == 5 && mod == 0) {
        // RIP-relative
        if (p + 4 > avail) return 0;
        int32_t d = 0; memcpy(&d, c + p, 4); p += 4;
        char tb[160];
        // setStatus-free helper: show module+off when inside a known module
        bool shown = false;
        if (ripOk) {
            // target computed by caller (needs full len); show raw disp here,
            // caller rewrites [rip+..] when it knows va+len. Keep simple text:
            snprintf(tb, sizeof(tb), "[rip+0x%X]", (unsigned)d);
            shown = true;
        }
        if (shown) { out = tb; return p - pos; }
        out = "[rip]";
        return p - pos;
    }
    else { base = rm; bx = rb ? 1 : 0; }
    int64_t disp = 0; int dispSz = 0;
    if (mod == 1) { if (p >= avail) return 0; disp = (int8_t)c[p++]; dispSz = 1; }
    else if (mod == 2 || noBase) { if (p + 4 > avail) return 0; int32_t d = 0; memcpy(&d, c + p, 4); p += 4; disp = d; dispSz = 4; }
    char mb[128]{};
    if (base < 0 && index < 0) snprintf(mb, sizeof(mb), "[0x%llX]", (unsigned long long)(uint32_t)disp);
    else if (base < 0) snprintf(mb, sizeof(mb), "[%s*%d+0x%llX]", xa_rname(index, ix, 64, true).c_str(), scale, (unsigned long long)(uint32_t)disp);
    else {
        std::string b = xa_rname(base, bx, 64, true);
        if (index >= 0) {
            char ib[64]; snprintf(ib, sizeof(ib), "+%s*%d", xa_rname(index, ix, 64, true).c_str(), scale);
            if (!disp) snprintf(mb, sizeof(mb), "[%s%s]", b.c_str(), ib);
            else if (disp > 0) snprintf(mb, sizeof(mb), "[%s%s+0x%llX]", b.c_str(), ib, (unsigned long long)disp);
            else snprintf(mb, sizeof(mb), "[%s%s-0x%llX]", b.c_str(), ib, (unsigned long long)-disp);
        }
        else {
            if (!disp) snprintf(mb, sizeof(mb), "[%s]", b.c_str());
            else if (disp > 0) snprintf(mb, sizeof(mb), "[%s+0x%llX]", b.c_str(), (unsigned long long)disp);
            else snprintf(mb, sizeof(mb), "[%s-0x%llX]", b.c_str(), (unsigned long long)-disp);
        }
    }
    (void)dispSz;
    out = mb;
    return p - pos;
}
// Target address display: "mod"+OFF when inside a known module, else hex.
static std::string xa_target(UINT64 t) {
    char b[160];
    for (auto& m : g_mods) {
        if (m.size && t >= m.base && t < m.base + m.size) {
            snprintf(b, sizeof(b), "\"%s\"+%llX", m.name.c_str(), (unsigned long long)(t - m.base));
            return b;
        }
    }
    snprintf(b, sizeof(b), "%llX", (unsigned long long)t);
    return b;
}
// Decode one instruction. Returns length (>=1). ops = "mnemonic operands".
static int xa_decode(const BYTE* c, int avail, UINT64 va, std::string& ops) {
    ops.clear();
    if (avail <= 0) return 0;
    int pos = 0;
    bool hasRex = false, w = false, rr = false, rx = false, rb = false, op16 = false;
    int pfxStart = 0;
    for (;;) {
        if (pos >= avail) break;
        BYTE b = c[pos];
        if (b >= 0x40 && b <= 0x4F) { hasRex = true; w = (b & 8) != 0; rr = (b & 4) != 0; rx = (b & 2) != 0; rb = (b & 1) != 0; pos++; }
        else if (b == 0x66) { op16 = true; pos++; }
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || b == 0x67) pos++;
        else break;
        if (pos - pfxStart > 5) break;
    }
    if (pos >= avail) { ops = "db"; return avail; }
    int obits = w ? 64 : (op16 ? 16 : 32);
    BYTE op = c[pos++];
    bool esc = false; BYTE op2 = 0;
    if (op == 0x0F) {
        if (pos >= avail) { ops = "db 0F"; return pos; }
        op2 = c[pos++]; esc = true;
    }
    char tmp[160]{};
    std::string rm, rg;
    int cons = 0;
    auto need = [&](int n) { return pos + n <= avail; };
    static const char* alu[] = { "add","or","adc","sbb","and","sub","xor","cmp" };
    static const char* shf[] = { "rol","ror","rcl","rcr","shl","shr","sal","sar" };
    static const char* jcc[] = { "jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg" };
    if (!esc) {
        if ((op & 0xF8) == 0x50) { snprintf(tmp, sizeof(tmp), "push %s", xa_rname(op & 7, rb, w ? 64 : (op16 ? 16 : 64), hasRex).c_str()); ops = tmp; return pos; }
        if ((op & 0xF8) == 0x58) { snprintf(tmp, sizeof(tmp), "pop %s", xa_rname(op & 7, rb, w ? 64 : (op16 ? 16 : 64), hasRex).c_str()); ops = tmp; return pos; }
        if ((op & 0xF8) == 0x90) {
            if (!hasRex && (op & 7) == 0) { ops = "nop"; return pos; }
            snprintf(tmp, sizeof(tmp), "xchg %s, %s", xa_rname(0, false, obits, hasRex).c_str(), xa_rname(op & 7, rb, obits, hasRex).c_str());
            ops = tmp; return pos;
        }
        if ((op & 0xF8) == 0xB8) {
            int64_t im = 0; int isz = (obits == 64) ? 8 : (obits == 16 ? 2 : 4);
            if (!need(isz)) goto db;
            memcpy(&im, c + pos, isz); pos += isz;
            if (obits == 64) snprintf(tmp, sizeof(tmp), "mov %s, 0x%llX", xa_rname(op & 7, rb, 64, hasRex).c_str(), (unsigned long long)im);
            else snprintf(tmp, sizeof(tmp), "mov %s, 0x%llX", xa_rname(op & 7, rb, obits, hasRex).c_str(), (unsigned long long)(uint32_t)im);
            ops = tmp; return pos;
        }
        if ((op & 0xF8) == 0xB0) {
            if (!need(1)) goto db;
            snprintf(tmp, sizeof(tmp), "mov %s, 0x%X", xa_rname(op & 7, rb, 8, hasRex).c_str(), c[pos++]);
            ops = tmp; return pos;
        }
        if (op >= 0x70 && op <= 0x7F) {
            if (!need(1)) goto db;
            int8_t r = (int8_t)c[pos++];
            snprintf(tmp, sizeof(tmp), "%s %s", jcc[op & 15], xa_target(va + pos + r).c_str());
            ops = tmp; return pos;
        }
        switch (op) {
        case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C:
            if (!need(1)) goto db;
            snprintf(tmp, sizeof(tmp), "%s al, 0x%X", alu[(op >> 3) & 7], c[pos++]);
            ops = tmp; return pos;
        case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D: {
            int isz = (obits == 16) ? 2 : 4; if (!need(isz)) goto db;
            uint32_t im = 0; memcpy(&im, c + pos, isz); pos += isz;
            snprintf(tmp, sizeof(tmp), "%s %s, 0x%X", alu[(op >> 3) & 7], xa_rname(0, false, obits, hasRex).c_str(), im);
            ops = tmp; return pos;
        }
        case 0x63: { // movsxd
            if (pos >= avail) goto db;
            int mod = (c[pos] >> 6) & 3, reg = (c[pos] >> 3) & 7;
            cons = xa_rm(c, avail, pos, 32, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            if (mod == 3) { snprintf(tmp, sizeof(tmp), "movsxd %s, %s", xa_rname(reg, rr, w ? 64 : 32, hasRex).c_str(), rm.c_str()); }
            else snprintf(tmp, sizeof(tmp), "movsxd %s, %s", xa_rname(reg, rr, w ? 64 : 32, hasRex).c_str(), rm.c_str());
            ops = tmp; return pos;
        }
        case 0x68: { int isz = (obits == 16) ? 2 : 4; if (!need(isz)) goto db; uint32_t im = 0; memcpy(&im, c + pos, isz); pos += isz; snprintf(tmp, sizeof(tmp), "push 0x%X", im); ops = tmp; return pos; }
        case 0x69: case 0x6B: {
            if (pos >= avail) goto db;
            int mod = (c[pos] >> 6) & 3, reg = (c[pos] >> 3) & 7;
            cons = xa_rm(c, avail, pos, obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            int isz = (op == 0x6B) ? 1 : ((obits == 16) ? 2 : 4);
            if (!need(isz)) goto db;
            int64_t im = (isz == 1) ? (int8_t)c[pos] : 0;
            if (isz > 1) { int32_t t = 0; memcpy(&t, c + pos, isz); im = t; }
            pos += isz;
            rg = xa_rname(reg, rr, obits, hasRex);
            if (mod == 3) snprintf(tmp, sizeof(tmp), "imul %s, %s, 0x%llX", rg.c_str(), rm.c_str(), (unsigned long long)im);
            else snprintf(tmp, sizeof(tmp), "imul %s, %s, 0x%llX", rg.c_str(), rm.c_str(), (unsigned long long)im);
            ops = tmp; return pos;
        }
        case 0x80: case 0x82: case 0x81: case 0x83: {
            if (pos >= avail) goto db;
            int mod = (c[pos] >> 6) & 3, reg = (c[pos] >> 3) & 7;
            int eb = (op == 0x80 || op == 0x82);
            cons = xa_rm(c, avail, pos, eb ? 8 : obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            int isz = (op == 0x81) ? ((obits == 16) ? 2 : 4) : 1;
            if (!need(isz)) goto db;
            int64_t im = 0;
            if (isz == 1) im = (op == 0x83) ? (int8_t)c[pos] : c[pos];
            else { int32_t t = 0; memcpy(&t, c + pos, isz); im = (op == 0x83) ? (int8_t)c[pos] : t; }
            pos += isz;
            if (mod == 3) snprintf(tmp, sizeof(tmp), "%s %s, 0x%llX", alu[reg], rm.c_str(), (unsigned long long)im);
            else snprintf(tmp, sizeof(tmp), "%s %s, 0x%llX", alu[reg], rm.c_str(), (unsigned long long)im);
            ops = tmp; return pos;
        }
        case 0x84: case 0x85: case 0x86: case 0x87: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            int b = (op == 0x84 || op == 0x86) ? 8 : obits;
            cons = xa_rm(c, avail, pos, b, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            const char* mn = (op == 0x84 || op == 0x85) ? "test" : "xchg";
            rg = xa_rname(reg, rr, b, hasRex);
            snprintf(tmp, sizeof(tmp), "%s %s, %s", mn, rm.c_str(), rg.c_str());
            ops = tmp; return pos;
        }
        case 0x88: case 0x89: case 0x8A: case 0x8B: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            int b = (op == 0x88 || op == 0x8A) ? 8 : obits;
            cons = xa_rm(c, avail, pos, b, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            rg = xa_rname(reg, rr, b, hasRex);
            if (op == 0x88 || op == 0x89) snprintf(tmp, sizeof(tmp), "mov %s, %s", rm.c_str(), rg.c_str());
            else snprintf(tmp, sizeof(tmp), "mov %s, %s", rg.c_str(), rm.c_str());
            ops = tmp; return pos;
        }
        case 0x8D: {
            if (pos >= avail) goto db;
            if (((c[pos] >> 6) & 3) == 3) goto db;
            int reg = (c[pos] >> 3) & 7;
            cons = xa_rm(c, avail, pos, 8, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            snprintf(tmp, sizeof(tmp), "lea %s, %s", xa_rname(reg, rr, obits, hasRex).c_str(), rm.c_str());
            ops = tmp; return pos;
        }
        case 0x8F: {
            if (pos >= avail) goto db;
            if (((c[pos] >> 3) & 7) != 0) goto db;
            cons = xa_rm(c, avail, pos, obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            snprintf(tmp, sizeof(tmp), "pop %s", rm.c_str());
            ops = tmp; return pos;
        }
        case 0x98: ops = w ? "cdqe" : (op16 ? "cbw" : "cwde"); return pos;
        case 0x99: ops = w ? "cqo" : (op16 ? "cwd" : "cdq"); return pos;
        case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
            int asz = 4; // disp size (ignore 0x67 nuance, assume 32-bit addr)
            if (!need(asz)) goto db;
            uint32_t am = 0; memcpy(&am, c + pos, 4); pos += asz;
            rg = xa_rname(0, false, (op == 0xA0 || op == 0xA2) ? 8 : obits, hasRex);
            if (op == 0xA0 || op == 0xA1) snprintf(tmp, sizeof(tmp), "mov %s, [0x%X]", rg.c_str(), am);
            else snprintf(tmp, sizeof(tmp), "mov [0x%X], %s", am, rg.c_str());
            ops = tmp; return pos;
        }
        case 0xA8: if (!need(1)) goto db; snprintf(tmp, sizeof(tmp), "test al, 0x%X", c[pos++]); ops = tmp; return pos;
        case 0xA9: { int isz = (obits == 16) ? 2 : 4; if (!need(isz)) goto db; uint32_t im = 0; memcpy(&im, c + pos, isz); pos += isz; snprintf(tmp, sizeof(tmp), "test %s, 0x%X", xa_rname(0, false, obits, hasRex).c_str(), im); ops = tmp; return pos; }
        case 0xC2: if (!need(2)) goto db; { uint16_t im = 0; memcpy(&im, c + pos, 2); pos += 2; snprintf(tmp, sizeof(tmp), "ret 0x%X", im); } ops = tmp; return pos;
        case 0xC3: ops = "ret"; return pos;
        case 0xC6: case 0xC7: {
            if (pos >= avail) goto db;
            if (((c[pos] >> 3) & 7) != 0) goto db;
            int eb = (op == 0xC6);
            cons = xa_rm(c, avail, pos, eb ? 8 : obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            int isz = eb ? 1 : ((obits == 16) ? 2 : 4);
            if (!need(isz)) goto db;
            uint32_t im = 0; memcpy(&im, c + pos, isz); pos += isz;
            snprintf(tmp, sizeof(tmp), "mov %s, 0x%X", rm.c_str(), im);
            ops = tmp; return pos;
        }
        case 0xC8: if (!need(3)) goto db; { uint16_t iw = 0; memcpy(&iw, c + pos, 2); snprintf(tmp, sizeof(tmp), "enter 0x%X, 0x%X", iw, c[pos + 2]); pos += 3; } ops = tmp; return pos;
        case 0xC9: ops = "leave"; return pos;
        case 0xCC: ops = "int3"; return pos;
        case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            int eb = (op == 0xC0 || op == 0xD0 || op == 0xD2);
            cons = xa_rm(c, avail, pos, eb ? 8 : obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            if (op == 0xC0 || op == 0xC1) { if (!need(1)) goto db; snprintf(tmp, sizeof(tmp), "%s %s, 0x%X", shf[reg], rm.c_str(), c[pos++]); }
            else if (op == 0xD0 || op == 0xD1) snprintf(tmp, sizeof(tmp), "%s %s, 1", shf[reg], rm.c_str());
            else snprintf(tmp, sizeof(tmp), "%s %s, cl", shf[reg], rm.c_str());
            ops = tmp; return pos;
        }
        case 0xE3: if (!need(1)) goto db; { int8_t r = (int8_t)c[pos++]; snprintf(tmp, sizeof(tmp), "jrcxz %s", xa_target(va + pos + r).c_str()); } ops = tmp; return pos;
        case 0xE8: if (!need(4)) goto db; { int32_t r = 0; memcpy(&r, c + pos, 4); pos += 4; snprintf(tmp, sizeof(tmp), "call %s", xa_target(va + pos + r).c_str()); } ops = tmp; return pos;
        case 0xE9: if (!need(4)) goto db; { int32_t r = 0; memcpy(&r, c + pos, 4); pos += 4; snprintf(tmp, sizeof(tmp), "jmp %s", xa_target(va + pos + r).c_str()); } ops = tmp; return pos;
        case 0xEB: if (!need(1)) goto db; { int8_t r = (int8_t)c[pos++]; snprintf(tmp, sizeof(tmp), "jmp %s", xa_target(va + pos + r).c_str()); } ops = tmp; return pos;
        case 0xF6: case 0xF7: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            if (reg != 0 && reg != 2 && reg != 3 && reg != 4 && reg != 5 && reg != 6 && reg != 7) goto db;
            static const char* fn[] = { "test", "test", "not", "neg", "mul", "imul", "div", "idiv" };
            int eb = (op == 0xF6);
            cons = xa_rm(c, avail, pos, eb ? 8 : obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            if (reg == 0) {
                int isz = eb ? 1 : ((obits == 16) ? 2 : 4);
                if (!need(isz)) goto db;
                uint32_t im = 0; memcpy(&im, c + pos, isz); pos += isz;
                snprintf(tmp, sizeof(tmp), "test %s, 0x%X", rm.c_str(), im);
            }
            else snprintf(tmp, sizeof(tmp), "%s %s", fn[reg], rm.c_str());
            ops = tmp; return pos;
        }
        case 0xFE: case 0xFF: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            static const char* fn[] = { "inc", "dec", "call", "callf", "jmp", "jmpf", "push", "??" };
            if (op == 0xFE && reg > 1) goto db;
            if (op == 0xFF && (reg == 3 || reg == 5 || reg == 7)) goto db;
            int eb = (op == 0xFE);
            cons = xa_rm(c, avail, pos, eb ? 8 : ((op == 0xFF && reg == 6) ? (w ? 64 : (op16 ? 16 : 64)) : obits), hasRex, rr, rb, rm);
            if (!cons) goto db; pos += cons;
            // rewrite call/jmp target when it's a rip-relative mem (nice CE touch)
            if (!eb && (reg == 2 || reg == 4) && rm.rfind("[rip+", 0) == 0) {
                // resolve [rip+disp] -> pointer value -> show it
                unsigned d = 0;
                if (sscanf_s(rm.c_str(), "[rip+0x%X]", &d) == 1) {
                    UINT64 slot = va + pos + (int32_t)d;
                    UINT64 pv = 0;
                    if (g_drv && g_attached) g_drv->read_raw(slot, (BYTE*)&pv, 8);
                    if (pv) snprintf(tmp, sizeof(tmp), "%s %s ; -> %s", fn[reg], rm.c_str(), xa_target(pv).c_str());
                    else snprintf(tmp, sizeof(tmp), "%s %s", fn[reg], rm.c_str());
                    ops = tmp; return pos;
                }
            }
            snprintf(tmp, sizeof(tmp), "%s %s", fn[reg], rm.c_str());
            ops = tmp; return pos;
        }
        default: goto db;
        }
    }
    else {
        // two-byte opcodes
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (!need(4)) goto db;
            int32_t r = 0; memcpy(&r, c + pos, 4); pos += 4;
            snprintf(tmp, sizeof(tmp), "%s %s", jcc[op2 & 15], xa_target(va + pos + r).c_str());
            ops = tmp; return pos;
        }
        switch (op2) {
        case 0x05: ops = "syscall"; return pos;
        case 0x0B: ops = "ud2"; return pos;
        case 0x1F: {
            if (pos >= avail) goto db;
            if (((c[pos] >> 3) & 7) != 0) goto db;
            cons = xa_rm(c, avail, pos, obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            snprintf(tmp, sizeof(tmp), "nop %s", rm.c_str());
            ops = tmp; return pos;
        }
        case 0x31: ops = "rdtsc"; return pos;
        case 0xA2: ops = "cpuid"; return pos;
        case 0xAF: case 0xBC: case 0xBD: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            cons = xa_rm(c, avail, pos, obits, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            const char* mn = (op2 == 0xAF) ? "imul" : (op2 == 0xBC ? "bsf" : "bsr");
            snprintf(tmp, sizeof(tmp), "%s %s, %s", mn, xa_rname(reg, rr, obits, hasRex).c_str(), rm.c_str());
            ops = tmp; return pos;
        }
        case 0xB6: case 0xB7: case 0xBE: case 0xBF: {
            if (pos >= avail) goto db;
            int reg = (c[pos] >> 3) & 7;
            int eb = (op2 == 0xB6 || op2 == 0xBE);
            cons = xa_rm(c, avail, pos, eb ? 8 : 16, hasRex, rr, rb, rm); if (!cons) goto db; pos += cons;
            const char* mn = (op2 == 0xB6 || op2 == 0xB7) ? "movzx" : "movsx";
            snprintf(tmp, sizeof(tmp), "%s %s, %s", mn, xa_rname(reg, rr, obits, hasRex).c_str(), rm.c_str());
            ops = tmp; return pos;
        }
        default: goto db;
        }
    }
db: {
    char b[64]{}, *q = b;
    int n = (std::min)(pos - pfxStart, 8);
    if (n <= 0) n = 1;
    for (int i = 0; i < n; i++) q += snprintf(q, sizeof(b) - (q - b), "%s0x%02X", i ? " " : "db ", c[pfxStart + i]);
    ops = b;
    return pfxStart + ((pos - pfxStart > 0) ? 1 : 1);
}
}
// Memory viewer popup — CE style: disassembly on top, hex dump below.
// Double-click an opcode row -> single-line assembler for that address.
static void doMemDump(); // fwd: defined below OpenMemView
static std::vector<UINT64> g_disAddr;
static std::vector<std::string> g_disText;
static std::vector<int> g_disLen;
static UINT64 g_asmAddr = 0;
static UINT64 g_mvGoAddr = 0; // Go-to-Dism pending address (consumed by OpenMemView)
static void doMemDisasm() {
    HWND lv = g_mv ? GetDlgItem(g_mv, MV_DIS_LIST) : nullptr;
    if (!lv) return;
    SendMessageA(lv, LVM_DELETEALLITEMS, 0, 0);
    g_disAddr.clear(); g_disText.clear(); g_disLen.clear();
    if (!g_drv || !g_attached) return;
    UINT64 addr = strtoull(dlgText(g_mv, MV_ADDR_EDIT).c_str(), nullptr, 16);
    if (!addr) return;
    const SIZE_T kRead = 512;
    std::vector<BYTE> buf(kRead);
    g_drv->read_raw(addr, buf.data(), kRead);
    LVITEMA it{}; it.mask = LVIF_TEXT;
    char a[32], bs[64];
    int zeros = 0;
    for (SIZE_T off = 0; off < kRead && g_disAddr.size() < 64;) {
        if (off + 16 <= kRead) {
            bool all0 = true;
            for (int i = 0; i < 16; i++) if (buf[off + i]) { all0 = false; break; }
            if (all0) { zeros++; if (zeros >= 1) break; }
            else zeros = 0;
        }
        std::string ops;
        int len = xa_decode(buf.data() + off, (int)(kRead - off), addr + off, ops);
        if (len <= 0) len = 1;
        if ((SIZE_T)len > kRead - off) len = (int)(kRead - off);
        char* q = bs;
        for (int i = 0; i < len && i < 10; i++) q += snprintf(q, sizeof(bs) - (q - bs), "%02X ", buf[off + i]);
        snprintf(a, sizeof(a), "%llX", (unsigned long long)(addr + off));
        int row = (int)g_disAddr.size();
        g_disAddr.push_back(addr + off); g_disText.push_back(ops); g_disLen.push_back(len);
        it.iItem = row; it.iSubItem = 0; it.pszText = a;
        SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
        lv_set_text(lv, row, 1, bs);
        lv_set_text(lv, row, 2, (LPSTR)ops.c_str());
        off += (SIZE_T)len;
    }
}
static void OpenAsmDialog(UINT64 addr, const char* curText) {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_asmAddr = addr;
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Assemble", WS_POPUP | WS_CAPTION | WS_SYSMENU, 300, 250, 420, 190, g_mv ? g_mv : g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Type your assembler code here:", SS_LEFT, 12, 12, 380, 20, -1);
    char al[64]; snprintf(al, sizeof(al), "(address=%llX)", (unsigned long long)addr);
    c("STATIC", al, SS_LEFT, 12, 34, 380, 20, -1);
    c("EDIT", curText ? curText : "", WS_BORDER | ES_AUTOHSCROLL, 12, 58, 380, 24, DLG_VAL_EDIT);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 110, 100, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 210, 100, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 9); // mode 9 = single-line assembler
    ShowWindow(p, SW_SHOW);
    HWND eb = GetDlgItem(p, DLG_VAL_EDIT);
    SendMessageA(eb, EM_SETSEL, 0, -1);
    SetFocus(eb);
}
static void OpenMemView() {
    if (g_mv) { SetForegroundWindow(g_mv); return; }
    g_mv = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsMem, "System Settings", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MAXIMIZEBOX, 200, 150, 760, 520, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_mv;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    // prefill address: Go-to-Dism override wins, else selected table row (CE habit)
    char preAddr[32]{}; snprintf(preAddr, sizeof(preAddr), "0");
    if (g_mvGoAddr) snprintf(preAddr, sizeof(preAddr), "%llX", (unsigned long long)g_mvGoAddr);
    else {
        HWND tv = ctl(IDC_TBL_LIST);
        int sel = tv ? ListView_GetNextItem(tv, -1, LVNI_SELECTED) : -1;
        if (sel >= 0) {
            TblEntry e; bool got = false;
            { std::lock_guard<std::mutex> lk(g_tableMtx); if ((size_t)sel < g_table.size()) { e = g_table[(size_t)sel]; got = true; } }
            if (got) { UINT64 f = e.addr; if (g_drv && g_attached && entry_final(e, f)) snprintf(preAddr, sizeof(preAddr), "%llX", (unsigned long long)f); }
        }
    }
    c("STATIC", "Address:", SS_LEFT, 12, 12, 60, 20, -1);
    c("EDIT", preAddr, WS_BORDER | ES_AUTOHSCROLL, 75, 10, 150, 24, MV_ADDR_EDIT);
    c("STATIC", "Size:", SS_LEFT, 235, 12, 35, 20, -1);
    c("EDIT", "256", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 275, 10, 60, 24, MV_SIZE_EDIT);
    c("BUTTON", "Dump", BS_PUSHBUTTON, 345, 9, 70, 26, MV_DUMP_BTN);
    c("BUTTON", "Disasm", BS_PUSHBUTTON, 420, 9, 70, 26, MV_DIS_BTN);
    c("EDIT", "90 90 90", WS_BORDER | ES_AUTOHSCROLL, 495, 10, 150, 24, MV_WRITE_EDIT);
    c("BUTTON", "Write", BS_PUSHBUTTON, 650, 9, 80, 26, MV_WRITE_BTN);
    HWND lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 12, 44, 720, 190, p, (HMENU)(INT_PTR)MV_DIS_LIST, GetModuleHandleA(nullptr), nullptr);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    {
        const char* n[] = { "Address", "Bytes", "Opcode" };
        int w[] = { 150, 200, 360 };
        lv_cols(lv, n, w, 3);
    }
    HWND hex = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "Attach first, set address, Dump.", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY, 12, 240, 720, 228, p, (HMENU)(INT_PTR)MV_HEX_EDIT, GetModuleHandleA(nullptr), nullptr);
    (void)hex;
    ShowWindow(p, SW_SHOW);
    doMemDump();
    doMemDisasm();
}
static void doMemDump() {
    if (!g_mv) return;
    if (!g_drv || !g_attached) { SetDlgItemTextA(g_mv, MV_HEX_EDIT, "Attach first."); return; }
    std::string a = dlgText(g_mv, MV_ADDR_EDIT);
    std::string sz = dlgText(g_mv, MV_SIZE_EDIT);
    UINT64 addr = strtoull(a.c_str(), nullptr, 16); // CE: address boxes are hex
    SIZE_T size = (SIZE_T)strtoul(sz.c_str(), nullptr, 0);
    if (!size || size > 0x10000) size = 256;
    std::vector<BYTE> buf(size);
    g_drv->read_raw(addr, buf.data(), size);
    std::string out;
    char line[160];
    for (SIZE_T row = 0; row < size; row += 16) {
        char h[80]{}, asc[20]{};
        int p = 0;
        for (int ci = 0; ci < 16; ci++) {
            if (row + (SIZE_T)ci < size) p += snprintf(h + p, sizeof(h) - (size_t)p, "%02X ", buf[row + ci]);
            else p += snprintf(h + p, sizeof(h) - (size_t)p, "   ");
        }
        size_t an = (std::min<SIZE_T>)(16, size - row);
        for (size_t ci = 0; ci < an; ci++) { BYTE b = buf[row + ci]; asc[ci] = (b >= 32 && b < 127) ? (char)b : '.'; }
        asc[an] = 0;
        snprintf(line, sizeof(line), "%016llX  %s %s\r\n", (unsigned long long)(addr + row), h, asc);
        out += line;
    }
    SetDlgItemTextA(g_mv, MV_HEX_EDIT, out.c_str());
}
static void doMemWrite() {
    if (!g_mv) return;
    if (!g_drv || !g_attached) return;
    std::string a = dlgText(g_mv, MV_ADDR_EDIT);
    std::string hb = dlgText(g_mv, MV_WRITE_EDIT);
    UINT64 addr = strtoull(a.c_str(), nullptr, 16); // CE: address boxes are hex
    std::vector<BYTE> bytes;
    const char* p = hb.c_str();
    while (*p && bytes.size() < 256) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p == '?') { bytes.push_back(0); while (*p == '?') p++; continue; }
        BYTE hi, lo;
        if (!hexNib(p[0], hi)) break;
        if (!p[1] || isspace((unsigned char)p[1])) { bytes.push_back((BYTE)(hi << 4)); p++; continue; }
        if (!hexNib(p[1], lo)) break;
        bytes.push_back((BYTE)((hi << 4) | lo)); p += 2;
    }
    if (bytes.empty()) return;
    if (g_drv->write_bytes(addr, bytes.data(), bytes.size())) {
        BYTE chk[256]{};
        g_drv->read_raw(addr, chk, bytes.size());
        SetDlgItemTextA(g_mv, MV_HEX_EDIT, memcmp(chk, bytes.data(), bytes.size()) == 0 ? "Write OK (verified)." : "Write verify FAILED.");
    }
    else SetDlgItemTextA(g_mv, MV_HEX_EDIT, "Write FAILED.");
}
//=================================================================
//  Single-line assembler (pairs with xa_decode above)
//=================================================================
struct AsmReg { int code = 0, ext = 0, bits = 0, fr = 0; }; // fr = forces REX (spl/bpl/sil/dil)
static bool asm_reg(const char* t, AsmReg& r) {
    char b[16]{}; size_t n = strlen(t);
    if (!n || n > 4) return false;
    for (size_t i = 0; i < n && i < 15; i++) b[i] = (char)tolower((unsigned char)t[i]);
    static const struct { const char* n; int c; int e; int w; } tab[] = {
        {"al",0,0,8},{"cl",1,0,8},{"dl",2,0,8},{"bl",3,0,8},{"spl",4,0,8},{"bpl",5,0,8},{"sil",6,0,8},{"dil",7,0,8},
        {"r8b",0,1,8},{"r9b",1,1,8},{"r10b",2,1,8},{"r11b",3,1,8},{"r12b",4,1,8},{"r13b",5,1,8},{"r14b",6,1,8},{"r15b",7,1,8},
        {"ah",4,0,-8},{"ch",5,0,-8},{"dh",6,0,-8},{"bh",7,0,-8},
        {"ax",0,0,16},{"cx",1,0,16},{"dx",2,0,16},{"bx",3,0,16},{"sp",4,0,16},{"bp",5,0,16},{"si",6,0,16},{"di",7,0,16},
        {"r8w",0,1,16},{"r9w",1,1,16},{"r10w",2,1,16},{"r11w",3,1,16},{"r12w",4,1,16},{"r13w",5,1,16},{"r14w",6,1,16},{"r15w",7,1,16},
        {"eax",0,0,32},{"ecx",1,0,32},{"edx",2,0,32},{"ebx",3,0,32},{"esp",4,0,32},{"ebp",5,0,32},{"esi",6,0,32},{"edi",7,0,32},
        {"r8d",0,1,32},{"r9d",1,1,32},{"r10d",2,1,32},{"r11d",3,1,32},{"r12d",4,1,32},{"r13d",5,1,32},{"r14d",6,1,32},{"r15d",7,1,32},
        {"rax",0,0,64},{"rcx",1,0,64},{"rdx",2,0,64},{"rbx",3,0,64},{"rsp",4,0,64},{"rbp",5,0,64},{"rsi",6,0,64},{"rdi",7,0,64},
        {"r8",0,1,64},{"r9",1,1,64},{"r10",2,1,64},{"r11",3,1,64},{"r12",4,1,64},{"r13",5,1,64},{"r14",6,1,64},{"r15",7,1,64},
    };
    for (auto& e : tab) if (strcmp(b, e.n) == 0) { r.code = e.c; r.ext = e.e; r.bits = e.w; r.fr = (strcmp(b, "spl") == 0 || strcmp(b, "bpl") == 0 || strcmp(b, "sil") == 0 || strcmp(b, "dil") == 0) ? 1 : 0; return true; }
    return false;
}
// HEX by default (CE-style). Accepts 0x.., ..h, decimals only via 0d..? plain = hex.
static bool asm_num(const char* t, int64_t& v) {
    char b[64]{}; size_t n = strlen(t);
    if (!n || n > 20) return false;
    for (size_t i = 0; i < n && i < 63; i++) b[i] = (char)tolower((unsigned char)t[i]);
    int neg = 0; const char* s = b;
    if (*s == '-') { neg = 1; s++; } else if (*s == '+') s++;
    int base = 16; size_t L = strlen(s);
    if (L > 2 && s[0] == '0' && s[1] == 'x') { s += 2; }
    else if (L && s[L - 1] == 'h') { char c2[64]{}; memcpy(c2, s, L - 1); strcpy_s(b, sizeof(b), neg ? "-" : ""); strcat_s(b, sizeof(b), c2); s = b + (neg ? 1 : 0); }
    if (!*s) return false;
    for (const char* p = s; *p; p++) if (!isxdigit((unsigned char)*p)) return false;
    v = (int64_t)strtoull(s, nullptr, base);
    if (neg) v = -v;
    return true;
}
struct AsmMem { bool rip = false; int base = -1, bExt = 0, index = -1, iExt = 0, scale = 1; int64_t disp = 0; bool hasDisp = false; };
static bool asm_mem(const char* t, AsmMem& m) {
    m = AsmMem{};
    std::string s = t;
    std::string ns;
    for (char c : s) if (!isspace((unsigned char)c)) ns += (char)tolower((unsigned char)c);
    if (ns.size() < 3 || ns.front() != '[' || ns.back() != ']') return false;
    std::string inner = ns.substr(1, ns.size() - 2);
    if (inner.empty()) return false;
    // split on +/- keeping sign
    std::vector<std::pair<char, std::string>> toks;
    std::string cur; char sign = '+';
    for (char c : inner) {
        if (c == '+' || c == '-') { if (!cur.empty()) { toks.push_back({ sign, cur }); cur.clear(); } sign = c; }
        else cur += c;
    }
    if (!cur.empty()) toks.push_back({ sign, cur });
    int regs = 0;
    for (auto& tk : toks) {
        std::string tok = tk.second;
        size_t star = tok.find('*');
        if (tok == "rip") { m.rip = true; continue; }
        if (star != std::string::npos) {
            std::string rs = tok.substr(0, star), ss = tok.substr(star + 1);
            AsmReg r{};
            int sc = atoi(ss.c_str());
            if (!asm_reg(rs.c_str(), r) || (sc != 1 && sc != 2 && sc != 4 && sc != 8)) return false;
            if (m.index >= 0) return false;
            m.index = r.code; m.iExt = r.ext; m.scale = sc; regs++;
            continue;
        }
        AsmReg r{};
        if (asm_reg(tok.c_str(), r)) {
            if (r.bits == 8 || r.bits == -8 || r.bits == 16 || r.bits == 32) return false; // addr regs must be 64-bit
            if (m.base < 0) { m.base = r.code; m.bExt = r.ext; }
            else if (m.index < 0) { m.index = r.code; m.iExt = r.ext; m.scale = 1; }
            else return false;
            regs++;
            continue;
        }
        int64_t v = 0;
        if (!asm_num(tok.c_str(), v)) return false;
        m.disp += (tk.first == '-' ? -v : v); m.hasDisp = true;
    }
    if (!regs && !m.hasDisp) return false;
    return true;
}
static int asm_rex(BYTE* o, int w, int r, int x, int b, int f = 0) {
    int v = 0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0);
    if (v == 0x40 && !f) return 0;
    o[0] = (BYTE)v; return 1;
}
// Emit modrm(+sib+disp) for [mem]. reg3 = reg field. va+oplen = address AFTER
// this modrm block (needed for RIP-relative). Returns bytes written (0 = fail).
static int asm_modrm(BYTE* o, int reg3, const AsmMem& m, UINT64 va, int oplen, char* err, int errSz) {
    bool sib = (m.index >= 0) || ((m.base & 7) == 4 && m.base >= 0);
    int mod = 0, rm = 0;
    int64_t disp = m.disp;
    int dispSz = 0;
    if (m.rip) {
        // [rip+disp]: disp32 is relative — user value is the raw displacement
        mod = 0; rm = 5; dispSz = 4;
        if (m.base >= 0 || m.index >= 0) { snprintf(err, errSz, "rip cannot mix with regs"); return 0; }
    }
    else if (m.base < 0 && m.index < 0) {
        // absolute [addr] -> encode as RIP-relative reaching it
        int pli = oplen + (sib ? 2 : 1) + 4; // predicted full len
        int64_t rel = disp - (int64_t)(va + pli);
        if (rel < INT32_MIN || rel > INT32_MAX) { snprintf(err, errSz, "address out of range"); return 0; }
        mod = 0; rm = 5; disp = rel; dispSz = 4;
    }
    else if (m.base < 0) {
        // [index*scale + disp] (no base)
        mod = 0; sib = true; dispSz = 4;
    }
    else {
        bool noDisp = !m.hasDisp || disp == 0;
        if ((m.base & 7) == 5 && noDisp) { mod = 1; disp = 0; dispSz = 1; } // [rbp] needs disp0
        else if (noDisp) { mod = 0; dispSz = 0; }
        else if (disp >= -128 && disp <= 127) { mod = 1; dispSz = 1; }
        else if (disp >= INT32_MIN && disp <= INT32_MAX) { mod = 2; dispSz = 4; }
        else { snprintf(err, errSz, "displacement out of range"); return 0; }
    }
    int p = 0;
    if (sib) {
        rm = 4;
        o[p++] = (BYTE)((mod << 6) | ((reg3 & 7) << 3) | rm);
        int idx = (m.index < 0) ? 4 : (m.index & 7);
        int bse = (m.base < 0) ? 5 : (m.base & 7);
        int ss = (m.scale == 8) ? 3 : (m.scale == 4) ? 2 : (m.scale == 2) ? 1 : 0;
        o[p++] = (BYTE)((ss << 6) | (idx << 3) | bse);
    }
    else {
        rm = m.rip ? 5 : (m.base & 7);
        o[p++] = (BYTE)((mod << 6) | ((reg3 & 7) << 3) | rm);
    }
    if (m.rip) {
        int32_t d = (int32_t)disp;
        memcpy(o + p, &d, 4); p += 4;
    }
    else if (dispSz == 1) o[p++] = (BYTE)(int8_t)disp;
    else if (dispSz == 4) { int32_t d = (int32_t)disp; memcpy(o + p, &d, 4); p += 4; }
    return p;
}
// Assemble one line at `va`. Returns byte count (>0) or -1 + err text.
static int AssembleLine(const char* text, UINT64 va, BYTE* out, char* err, int errSz) {
    snprintf(err, errSz, "?");
    char b[256]{}; snprintf(b, sizeof(b), "%s", text ? text : "");
    // trim
    char* s = b;
    while (*s && isspace((unsigned char)*s)) s++;
    size_t L = strlen(s);
    while (L && isspace((unsigned char)s[L - 1])) s[--L] = 0;
    if (!*s) { snprintf(err, errSz, "empty line"); return -1; }
    // mnemonic
    char mn[16]{}; size_t mi = 0;
    while (*s && !isspace((unsigned char)*s) && mi < 15) mn[mi++] = (char)tolower((unsigned char)*s++);
    while (*s && isspace((unsigned char)*s)) s++;
    // operands split by ',' outside brackets
    std::vector<std::string> ops;
    { std::string cur; int dep = 0; for (char* p = s; ; p++) { char c = *p; if (!c || (c == ',' && !dep)) { size_t a = 0, e = cur.size(); while (a < e && isspace((unsigned char)cur[a])) a++; while (e > a && isspace((unsigned char)cur[e - 1])) e--; if (e > a) ops.push_back(cur.substr(a, e - a)); cur.clear(); if (!c) break; } else { if (c == '[') dep++; if (c == ']') dep--; cur += c; } } }
    auto isMem = [](const std::string& t) { return t.size() >= 2 && t.front() == '['; };
    int p = 0;
    auto aluIdx = [&](const char* m) -> int {
        if (!strcmp(m, "add")) return 0; if (!strcmp(m, "or")) return 1; if (!strcmp(m, "adc")) return 2;
        if (!strcmp(m, "sbb")) return 3; if (!strcmp(m, "and")) return 4; if (!strcmp(m, "sub")) return 5;
        if (!strcmp(m, "xor")) return 6; if (!strcmp(m, "cmp")) return 7; return -1;
    };
    if ((!strcmp(mn, "nop") || !strcmp(mn, "ret") || !strcmp(mn, "int3") || !strcmp(mn, "leave")) && ops.empty()) {
        out[p++] = !strcmp(mn, "nop") ? (BYTE)0x90 : !strcmp(mn, "ret") ? (BYTE)0xC3 : !strcmp(mn, "int3") ? (BYTE)0xCC : (BYTE)0xC9;
        return p;
    }
    if (!strcmp(mn, "db")) {
        if (ops.empty()) { snprintf(err, errSz, "db needs bytes"); return -1; }
        for (auto& t : ops) { int64_t v = 0; if (!asm_num(t.c_str(), v) || v < -128 || v > 255) { snprintf(err, errSz, "bad db byte '%s'", t.c_str()); return -1; } out[p++] = (BYTE)v; if (p > 15) { snprintf(err, errSz, "line too long"); return -1; } }
        return p;
    }
    if ((!strcmp(mn, "push") || !strcmp(mn, "pop")) && ops.size() == 1 && !isMem(ops[0])) {
        AsmReg r{};
        if (!asm_reg(ops[0].c_str(), r)) { snprintf(err, errSz, "bad register '%s'", ops[0].c_str()); return -1; }
        if (r.bits == 8 || r.bits == -8 || r.bits == 16 || r.bits == 32) {
            if (!strcmp(mn, "pop") || r.bits != 32) { snprintf(err, errSz, "use 64-bit reg"); return -1; }
        }
        if (r.bits == -8) { snprintf(err, errSz, "high byte regs need REX-less form"); return -1; }
        p += asm_rex(out + p, 0, 0, 0, r.ext);
        out[p++] = (BYTE)((!strcmp(mn, "push") ? 0x50 : 0x58) + (r.code & 7));
        return p;
    }
    if (!strcmp(mn, "push") && ops.size() == 1 && !isMem(ops[0])) {
        int64_t v = 0; // push imm
        if (!asm_num(ops[0].c_str(), v)) { snprintf(err, errSz, "bad operand"); return -1; }
        if (v >= -128 && v <= 127) { out[p++] = 0x6A; out[p++] = (BYTE)(int8_t)v; }
        else if (v >= INT32_MIN && v <= INT32_MAX) { out[p++] = 0x68; int32_t t = (int32_t)v; memcpy(out + p, &t, 4); p += 4; }
        else { snprintf(err, errSz, "imm out of range"); return -1; }
        return p;
    }
    if ((!strcmp(mn, "inc") || !strcmp(mn, "dec") || !strcmp(mn, "not") || !strcmp(mn, "neg") ||
         !strcmp(mn, "mul") || !strcmp(mn, "imul") || !strcmp(mn, "div") || !strcmp(mn, "idiv") ||
         !strcmp(mn, "call") || !strcmp(mn, "jmp") || !strcmp(mn, "push")) && ops.size() == 1) {
        int grp = -1, opc = 0xFF; bool fw = true;
        if (!strcmp(mn, "inc")) grp = 0; else if (!strcmp(mn, "dec")) grp = 1;
        else if (!strcmp(mn, "call")) grp = 2; else if (!strcmp(mn, "jmp")) grp = 4;
        else if (!strcmp(mn, "push")) grp = 6;
        else { opc = 0xF7; if (!strcmp(mn, "not")) grp = 2; else if (!strcmp(mn, "neg")) grp = 3; else if (!strcmp(mn, "mul")) grp = 4; else if (!strcmp(mn, "imul")) grp = 5; else if (!strcmp(mn, "div")) grp = 6; else grp = 7; }
        bool mem = isMem(ops[0]);
        if (mem) {
            AsmMem m{};
            if (!asm_mem(ops[0].c_str(), m)) { snprintf(err, errSz, "bad memory '%s'", ops[0].c_str()); return -1; }
            int w = 1;
            p += asm_rex(out + p, w, 0, m.iExt, m.bExt);
            out[p++] = (BYTE)opc;
            int n = asm_modrm(out + p, grp, m, va, p + 2, err, errSz); if (!n) return -1; p += n;
            return p;
        }
        AsmReg r{};
        if (!asm_reg(ops[0].c_str(), r)) { snprintf(err, errSz, "bad operand '%s'", ops[0].c_str()); return -1; }
        if (!strcmp(mn, "call") || !strcmp(mn, "jmp")) {
            if (r.bits == 8 || r.bits == -8 || r.bits == 16 || r.bits == 32) { snprintf(err, errSz, "use 64-bit reg"); return -1; }
            p += asm_rex(out + p, 0, 0, 0, r.ext);
            out[p++] = 0xFF; out[p++] = (BYTE)((grp << 3) | 0xC0 | (r.code & 7));
            return p;
        }
        if (r.bits == 8 && opc == 0xFF) { snprintf(err, errSz, "needs 16/32/64-bit reg"); return -1; }
        if (r.bits == -8) { snprintf(err, errSz, "high byte regs unsupported here"); return -1; }
        int w = (r.bits == 64) ? 1 : 0, op16 = (r.bits == 16) ? 1 : 0;
        if (op16) out[p++] = 0x66;
        int useOpc = opc;
        if (opc == 0xF7 && r.bits == 8) useOpc = 0xF6;
        p += asm_rex(out + p, w && useOpc == 0xF7, 0, 0, r.ext, (useOpc == 0xF6) ? r.fr : 0);
        out[p++] = (BYTE)useOpc; out[p++] = (BYTE)((grp << 3) | 0xC0 | (r.code & 7));
        return p;
    }
    if ((!strcmp(mn, "call") || !strcmp(mn, "jmp")) && ops.size() == 1) {
        int64_t t = 0;
        if (!asm_num(ops[0].c_str(), t)) { snprintf(err, errSz, "bad address"); return -1; }
        int64_t rel = t - (int64_t)(va + 5);
        if (rel < INT32_MIN || rel > INT32_MAX) { snprintf(err, errSz, "target out of range"); return -1; }
        out[p++] = (BYTE)(!strcmp(mn, "call") ? 0xE8 : 0xE9);
        int32_t r = (int32_t)rel; memcpy(out + p, &r, 4); p += 4;
        return p;
    }
    { // jcc addr
        static const char* jn[] = { "jo","jno","jb","jae","je","jne","jbe","ja","js","jns","jp","jnp","jl","jge","jle","jg", nullptr };
        int ji = -1;
        for (int i = 0; jn[i]; i++) if (!strcmp(mn, jn[i])) ji = i;
        if (ji >= 0 && ops.size() == 1) {
            int64_t t = 0;
            if (!asm_num(ops[0].c_str(), t)) { snprintf(err, errSz, "bad address"); return -1; }
            int64_t rs = t - (int64_t)(va + 2);
            if (rs >= -128 && rs <= 127) { out[p++] = (BYTE)(0x70 + ji); out[p++] = (BYTE)(int8_t)rs; }
            else { int64_t rl = t - (int64_t)(va + 6); if (rl < INT32_MIN || rl > INT32_MAX) { snprintf(err, errSz, "target out of range"); return -1; } out[p++] = 0x0F; out[p++] = (BYTE)(0x80 + ji); int32_t r = (int32_t)rl; memcpy(out + p, &r, 4); p += 4; }
            return p;
        }
    }
    if ((!strcmp(mn, "mov") || !strcmp(mn, "movzx") || !strcmp(mn, "movsx") || !strcmp(mn, "lea") || !strcmp(mn, "xchg")) && ops.size() == 2) {
        bool zx = !strcmp(mn, "movzx"), sx = !strcmp(mn, "movsx"), lea = !strcmp(mn, "lea"), xg = !strcmp(mn, "xchg");
        bool dMem = isMem(ops[0]), sMem = isMem(ops[1]);
        if (dMem && sMem) { snprintf(err, errSz, "cannot mov mem, mem"); return -1; }
        AsmReg rd{}, rs{};
        bool dR = !dMem && asm_reg(ops[0].c_str(), rd);
        bool sR = !sMem && asm_reg(ops[1].c_str(), rs);
        AsmMem dm{}, sm{};
        if (dMem && !asm_mem(ops[0].c_str(), dm)) { snprintf(err, errSz, "bad memory '%s'", ops[0].c_str()); return -1; }
        if (sMem && !asm_mem(ops[1].c_str(), sm)) { snprintf(err, errSz, "bad memory '%s'", ops[1].c_str()); return -1; }
        if (lea && (dMem || !sMem || !dR)) { snprintf(err, errSz, "lea reg, [mem]"); return -1; }
        if ((zx || sx) && (dMem || !sMem || !sR)) { snprintf(err, errSz, "movzx/movsx reg, r/m8/16"); return -1; }
        if (!dR && !dMem) { snprintf(err, errSz, "bad destination '%s'", ops[0].c_str()); return -1; }
        if (!sR && !sMem && !(dR && !zx && !sx && !lea && !xg)) { snprintf(err, errSz, "bad source '%s'", ops[1].c_str()); return -1; }
        // mov reg, imm
        if (dR && !sR && !sMem && !zx && !sx && !lea) {
            int64_t v = 0;
            if (!asm_num(ops[1].c_str(), v)) { snprintf(err, errSz, "bad immediate '%s'", ops[1].c_str()); return -1; }
            if (rd.bits == -8) { snprintf(err, errSz, "cannot mov to high byte reg here"); return -1; }
            if (rd.bits == 64) {
                p += asm_rex(out + p, 1, 0, 0, rd.ext);
                out[p++] = (BYTE)(0xB8 + (rd.code & 7));
                memcpy(out + p, &v, 8); p += 8;
            }
            else if (rd.bits == 8) {
                if (v < -128 || v > 255) { snprintf(err, errSz, "imm out of range"); return -1; }
                p += asm_rex(out + p, 0, 0, 0, rd.ext, rd.fr);
                out[p++] = (BYTE)(0xB0 + (rd.code & 7)); out[p++] = (BYTE)v;
            }
            else {
                if (v < INT32_MIN || v > UINT32_MAX) { snprintf(err, errSz, "imm out of range"); return -1; }
                if (rd.bits == 16) out[p++] = 0x66;
                p += asm_rex(out + p, 0, 0, 0, rd.ext);
                out[p++] = (BYTE)(0xB8 + (rd.code & 7));
                if (rd.bits == 16) { uint16_t t = (uint16_t)v; memcpy(out + p, &t, 2); p += 2; }
                else { uint32_t t = (uint32_t)v; memcpy(out + p, &t, 4); p += 4; }
            }
            return p;
        }
        // mov [mem], imm
        if (dMem && !sR && !sMem && !strcmp(mn, "mov")) {
            int64_t v = 0;
            if (!asm_num(ops[1].c_str(), v)) { snprintf(err, errSz, "bad immediate"); return -1; }
            // need width: default 32-bit unless value fits byte? CE: mov [rax], 1 -> dword. Use 32-bit.
            if (v < INT32_MIN || v > UINT32_MAX) { snprintf(err, errSz, "imm out of range (32-bit)"); return -1; }
            p += asm_rex(out + p, 0, 0, dm.iExt, dm.bExt);
            out[p++] = 0xC7;
            int n = asm_modrm(out + p, 0, dm, va, p + 2, err, errSz); if (!n) return -1; p += n;
            uint32_t t = (uint32_t)v; memcpy(out + p, &t, 4); p += 4;
            return p;
        }
        int bits = dR ? rd.bits : rs.bits;
        if (bits == -8) { snprintf(err, errSz, "high byte regs unsupported here"); return -1; }
        bool byte = (bits == 8);
        int w = (bits == 64) ? 1 : 0, op16 = (bits == 16) ? 1 : 0;
        int opc = 0;
        if (lea) opc = 0x8D;
        else if (zx) opc = -1; // two-byte B6/B7
        else if (sx) opc = -2; // BE/BF
        else if (xg) opc = byte ? 0x86 : 0x87;
        else if (!strcmp(mn, "mov")) {
            if (dR && sMem) opc = byte ? 0x8A : 0x8B;
            else if (dMem && sR) opc = byte ? 0x88 : 0x89;
            else opc = byte ? 0x88 : 0x89; // reg,reg via 89 form
        }
        if (op16) out[p++] = 0x66;
        if (opc == -1 || opc == -2) {
            int sb = sR ? rs.bits : 8; // mem source width from reg or default byte? need explicit: movzx eax, [rbx] -> byte
            if (sMem) { // width ambiguous: pick byte unless user reg implies? default byte, document
                sb = 8;
            }
            if (sb != 8 && sb != 16) { snprintf(err, errSz, "movzx/movsx source must be 8/16-bit"); return -1; }
            // order: [66] REX 0F op modrm
            p += asm_rex(out + p, w, dR ? rd.ext : 0, sMem ? sm.iExt : (sR ? rs.ext : 0), 0, (sR && sb == 8) ? rs.fr : 0);
            out[p++] = 0x0F;
            out[p++] = (BYTE)((opc == -1 ? (sb == 8 ? 0xB6 : 0xB7) : (sb == 8 ? 0xBE : 0xBF)));
            int reg3 = dR ? rd.code : 0;
            if (sMem) { int n = asm_modrm(out + p, reg3, sm, va, p + 2, err, errSz); if (!n) return -1; p += n; }
            else { out[p++] = (BYTE)(0xC0 | ((reg3 & 7) << 3) | (rs.code & 7)); }
            return p;
        }
        int rE = 0, bE = 0;
        const AsmMem* mm = nullptr;
        int reg3 = 0;
        if (dR && sR) { rE = rs.ext; bE = rd.ext; reg3 = rs.code; }
        else if (dR && sMem) { rE = rd.ext; bE = 0; mm = &sm; reg3 = rd.code; }
        else if (dMem && sR) { rE = 0; bE = 0; mm = &dm; reg3 = rs.code; }
        else { snprintf(err, errSz, "unsupported operands"); return -1; }
        // NOTE: for dR&&sR form with 89, reg field = source. REX.R = source ext, REX.B = dest ext.
        int rexR = (dR && sR) ? rs.ext : (dR ? rd.ext : rs.ext);
        int rexB = (dR && sR) ? rd.ext : 0;
        int rexX = mm ? mm->iExt : 0;
        int rexBm = mm ? mm->bExt : 0;
        if (dMem && sR) { rexR = rs.ext; rexBm = dm.bExt; rexX = dm.iExt; }
        if (dR && sMem) { rexR = rd.ext; }
        (void)rE; (void)bE; (void)rexB; (void)rexBm;
        p += asm_rex(out + p, (byte || opc == 0x8D) ? (w && !byte) : w, rexR, rexX, (dR && sR) ? rd.ext : (mm ? mm->bExt : 0),
            byte ? ((dR ? rd.fr : 0) | (sR ? rs.fr : 0)) : 0);
        out[p++] = (BYTE)opc;
        if (mm) { int n = asm_modrm(out + p, reg3, *mm, va, p + 2, err, errSz); if (!n) return -1; p += n; }
        else {
            int dst = dR ? rd.code : 0, src = sR ? rs.code : 0;
            int dstR = dMem ? 0 : rd.code, srcR = sMem ? 0 : rs.code;
            (void)dst; (void)src;
            int rmSide = (opc == 0x8B || opc == 0x8A) ? dstR : ((opc == 0x89 || opc == 0x88) ? dstR : dstR);
            // reg field vs rm: for 8B/8A reg=dest; for 89/88 reg=source; reg,reg default 89
            int rf = ((opc == 0x8B || opc == 0x8A || opc == 0x8D || lea) ? dstR : srcR);
            int rmf = ((opc == 0x8B || opc == 0x8A || opc == 0x8D || lea) ? srcR : dstR);
            out[p++] = (BYTE)(0xC0 | ((rf & 7) << 3) | (rmf & 7));
            (void)rmSide;
        }
        return p;
    }
    { // ALU r,r / r,imm / m,r / m,imm + test + imul r,r[,imm] + shifts
        int ai = aluIdx(mn);
        bool tst = !strcmp(mn, "test");
        bool iml = !strcmp(mn, "imul");
        bool ish = !strcmp(mn, "shl") || !strcmp(mn, "shr") || !strcmp(mn, "sar") || !strcmp(mn, "rol") || !strcmp(mn, "ror");
        if ((ai >= 0 || tst) && ops.size() == 2) {
            bool dM = isMem(ops[0]);
            AsmReg dr{}, sr2{};
            bool drR = !dM && asm_reg(ops[0].c_str(), dr);
            bool srR = !isMem(ops[1]) && asm_reg(ops[1].c_str(), sr2);
            if (drR && srR) {
                if (dr.bits != sr2.bits || dr.bits == -8 || sr2.bits == -8) { snprintf(err, errSz, "operand size mismatch"); return -1; }
                bool byte = (dr.bits == 8);
                int w = (dr.bits == 64);
                if (dr.bits == 16) out[p++] = 0x66;
                p += asm_rex(out + p, w && !byte, sr2.ext, 0, dr.ext, byte ? (dr.fr | sr2.fr) : 0);
                out[p++] = (BYTE)((tst ? 0x84 : 0x00) + (ai >= 0 ? (ai << 3) + 1 : 0) + (byte ? 0 : 0));
                // 01-family: 01/09/11/... = 0x01 + ai*8 ; test = 0x85
                out[p - 1] = (BYTE)(tst ? (byte ? 0x84 : 0x85) : (0x01 + ai * 8 + (byte ? 0 : 0)));
                if (!byte && tst) out[p - 1] = 0x85;
                if (byte && ai >= 0) out[p - 1] = (BYTE)(0x00 + ai * 8);
                out[p++] = (BYTE)(0xC0 | ((sr2.code & 7) << 3) | (dr.code & 7));
                return p;
            }
            if (drR && !srR && !isMem(ops[1])) {
                int64_t v = 0;
                if (!asm_num(ops[1].c_str(), v)) { snprintf(err, errSz, "bad immediate"); return -1; }
                if (dr.bits == -8) { snprintf(err, errSz, "unsupported"); return -1; }
                bool byte = (dr.bits == 8);
                if (tst) {
                    if (byte) { p += asm_rex(out + p, 0, 0, 0, dr.ext, dr.fr); out[p++] = 0xF6; out[p++] = (BYTE)(0xC0 | (dr.code & 7)); if (v < 0 || v > 255) { snprintf(err, errSz, "imm out of range"); return -1; } out[p++] = (BYTE)v; }
                    else { int w = (dr.bits == 64); if (dr.bits == 16) out[p++] = 0x66; p += asm_rex(out + p, w, 0, 0, dr.ext); out[p++] = 0xF7; out[p++] = (BYTE)(0xC0 | (dr.code & 7)); if (v < INT32_MIN || v > UINT32_MAX) { snprintf(err, errSz, "imm out of range"); return -1; } if (dr.bits == 16) { uint16_t t = (uint16_t)v; memcpy(out + p, &t, 2); p += 2; } else { uint32_t t = (uint32_t)v; memcpy(out + p, &t, 4); p += 4; } }
                    return p;
                }
                if (byte) {
                    if (v < -128 || v > 255) { snprintf(err, errSz, "imm out of range"); return -1; }
                    p += asm_rex(out + p, 0, 0, 0, dr.ext, dr.fr);
                    out[p++] = 0x80; out[p++] = (BYTE)((ai << 3) | 0xC0 | (dr.code & 7)); out[p++] = (BYTE)v;
                }
                else if (v >= -128 && v <= 127) {
                    int w = (dr.bits == 64); if (dr.bits == 16) out[p++] = 0x66;
                    p += asm_rex(out + p, w, 0, 0, dr.ext);
                    out[p++] = 0x83; out[p++] = (BYTE)((ai << 3) | 0xC0 | (dr.code & 7)); out[p++] = (BYTE)(int8_t)v;
                }
                else {
                    if (v < INT32_MIN || v > UINT32_MAX) { snprintf(err, errSz, "imm out of range"); return -1; }
                    int w = (dr.bits == 64); if (dr.bits == 16) out[p++] = 0x66;
                    p += asm_rex(out + p, w, 0, 0, dr.ext);
                    out[p++] = 0x81; out[p++] = (BYTE)((ai << 3) | 0xC0 | (dr.code & 7));
                    if (dr.bits == 16) { uint16_t t = (uint16_t)v; memcpy(out + p, &t, 2); p += 2; } else { uint32_t t = (uint32_t)v; memcpy(out + p, &t, 4); p += 4; }
                }
                return p;
            }
            // r,[m] and [m],r
            if ((drR && isMem(ops[1])) || (dM && srR)) {
                bool dstM = dM;
                AsmMem mm{}; AsmReg rr{};
                if (dstM) { if (!asm_mem(ops[0].c_str(), mm) || !asm_reg(ops[1].c_str(), rr)) { snprintf(err, errSz, "bad operands"); return -1; } }
                else { if (!asm_mem(ops[1].c_str(), mm) || true) {} rr = dr; AsmMem t2{}; if (!asm_mem(ops[1].c_str(), t2)) { snprintf(err, errSz, "bad memory"); return -1; } mm = t2; sr2 = dr; }
                AsmReg& r = dstM ? rr : sr2;
                if (r.bits == -8) { snprintf(err, errSz, "unsupported"); return -1; }
                bool byte = (r.bits == 8);
                int w = (r.bits == 64); if (r.bits == 16) out[p++] = 0x66;
                p += asm_rex(out + p, w && !byte, r.ext, mm.iExt, mm.bExt);
                BYTE opc = tst ? (byte ? 0x84 : 0x85) : (BYTE)(dstM ? (byte ? 0x00 : 0x01) + ai * 8 : (byte ? 0x02 : 0x03) + ai * 8);
                out[p++] = opc;
                int n = asm_modrm(out + p, r.code, mm, va, p + 2, err, errSz); if (!n) return -1; p += n;
                return p;
            }
            snprintf(err, errSz, "unsupported operands"); return -1;
        }
        if (iml && (ops.size() == 2 || ops.size() == 3)) {
            AsmReg d{}, s2{};
            if (isMem(ops[0]) || !asm_reg(ops[0].c_str(), d)) { snprintf(err, errSz, "imul dst must be reg"); return -1; }
            if (ops.size() == 2) {
                if (isMem(ops[1])) { AsmMem mm{}; if (!asm_mem(ops[1].c_str(), mm)) { snprintf(err, errSz, "bad memory"); return -1; } if (d.bits == 8 || d.bits == -8 || d.bits == 16) { /* allow 16 */ } int w = (d.bits == 64); if (d.bits == 16) out[p++] = 0x66; p += asm_rex(out + p, w, d.ext, mm.iExt, mm.bExt); out[p++] = 0x0F; out[p++] = 0xAF; int n = asm_modrm(out + p, d.code, mm, va, p + 2, err, errSz); if (!n) return -1; p += n; return p; }
                if (!asm_reg(ops[1].c_str(), s2) || s2.bits != d.bits) { snprintf(err, errSz, "size mismatch"); return -1; }
                int w = (d.bits == 64); if (d.bits == 16) out[p++] = 0x66;
                p += asm_rex(out + p, w, d.ext, 0, s2.ext);
                out[p++] = 0x0F; out[p++] = 0xAF; out[p++] = (BYTE)(0xC0 | ((d.code & 7) << 3) | (s2.code & 7));
                return p;
            }
            else {
                int64_t v = 0;
                if (!asm_num(ops[2].c_str(), v)) { snprintf(err, errSz, "bad immediate"); return -1; }
                bool use8 = (v >= -128 && v <= 127);
                AsmMem mm{}; bool sm = isMem(ops[1]);
                if (sm && !asm_mem(ops[1].c_str(), mm)) { snprintf(err, errSz, "bad memory"); return -1; }
                if (!sm && !asm_reg(ops[1].c_str(), s2)) { snprintf(err, errSz, "bad source"); return -1; }
                int w = (d.bits == 64); if (d.bits == 16) out[p++] = 0x66;
                p += asm_rex(out + p, w, d.ext, sm ? mm.iExt : s2.ext, 0);
                out[p++] = (BYTE)(use8 ? 0x6B : 0x69);
                if (sm) { int n = asm_modrm(out + p, d.code, mm, va, p + 2 + (use8 ? 1 : (d.bits == 16 ? 2 : 4)), err, errSz); if (!n) return -1; p += n; }
                else out[p++] = (BYTE)(0xC0 | ((d.code & 7) << 3) | (s2.code & 7));
                if (use8) out[p++] = (BYTE)(int8_t)v;
                else if (d.bits == 16) { if (v < -32768 || v > 65535) { snprintf(err, errSz, "imm out of range"); return -1; } uint16_t t = (uint16_t)v; memcpy(out + p, &t, 2); p += 2; }
                else { if (v < INT32_MIN || v > INT32_MAX) { snprintf(err, errSz, "imm out of range"); return -1; } int32_t t = (int32_t)v; memcpy(out + p, &t, 4); p += 4; }
                return p;
            }
        }
        if (ish && ops.size() == 2) {
            bool dM = isMem(ops[0]);
            AsmReg dr2{};
            if (!dM && !asm_reg(ops[0].c_str(), dr2)) { snprintf(err, errSz, "bad destination"); return -1; }
            AsmMem mm{}; if (dM && !asm_mem(ops[0].c_str(), mm)) { snprintf(err, errSz, "bad memory"); return -1; }
            int bits = dM ? 32 : dr2.bits; // default dword for mem (explicit reg width preferred)
            if (!dM) bits = dr2.bits;
            if (bits == -8) { snprintf(err, errSz, "unsupported"); return -1; }
            bool byte = (bits == 8);
            int grp = !strcmp(mn, "rol") ? 0 : !strcmp(mn, "ror") ? 1 : !strcmp(mn, "shl") ? 4 : !strcmp(mn, "shr") ? 5 : 7;
            std::string c2 = ops[1];
            for (auto& ch : c2) ch = (char)tolower((unsigned char)ch);
            if (c2 == "1") {
                int w = (bits == 64); if (bits == 16) out[p++] = 0x66;
                if (!dM) { p += asm_rex(out + p, w && !byte, 0, 0, dr2.ext, byte ? dr2.fr : 0); out[p++] = (BYTE)(byte ? 0xD0 : 0xD1); out[p++] = (BYTE)((grp << 3) | 0xC0 | (dr2.code & 7)); }
                else { p += asm_rex(out + p, w && !byte, 0, mm.iExt, mm.bExt); out[p++] = (BYTE)(byte ? 0xD0 : 0xD1); int n = asm_modrm(out + p, grp, mm, va, p + 2, err, errSz); if (!n) return -1; p += n; }
                return p;
            }
            if (c2 == "cl") {
                int w = (bits == 64); if (bits == 16) out[p++] = 0x66;
                if (!dM) { p += asm_rex(out + p, w && !byte, 0, 0, dr2.ext, byte ? dr2.fr : 0); out[p++] = (BYTE)(byte ? 0xD2 : 0xD3); out[p++] = (BYTE)((grp << 3) | 0xC0 | (dr2.code & 7)); }
                else { p += asm_rex(out + p, w && !byte, 0, mm.iExt, mm.bExt); out[p++] = (BYTE)(byte ? 0xD2 : 0xD3); int n = asm_modrm(out + p, grp, mm, va, p + 2, err, errSz); if (!n) return -1; p += n; }
                return p;
            }
            int64_t v = 0;
            if (!asm_num(c2.c_str(), v) || v < 0 || v > 255) { snprintf(err, errSz, "bad count"); return -1; }
            int w = (bits == 64); if (bits == 16) out[p++] = 0x66;
            if (!dM) { p += asm_rex(out + p, w && !byte, 0, 0, dr2.ext, byte ? dr2.fr : 0); out[p++] = (BYTE)(byte ? 0xC0 : 0xC1); out[p++] = (BYTE)((grp << 3) | 0xC0 | (dr2.code & 7)); }
            else { p += asm_rex(out + p, w && !byte, 0, mm.iExt, mm.bExt); out[p++] = (BYTE)(byte ? 0xC0 : 0xC1); int n = asm_modrm(out + p, grp, mm, va, p + 3, err, errSz); if (!n) return -1; p += n; }
            out[p++] = (BYTE)v;
            return p;
        }
    }
    snprintf(err, errSz, "unsupported: '%s' (try db xx)", mn);
    return -1;
}

//=================================================================
//  Actions
//=================================================================
static ScanOpts curOpts() {
    ScanOpts o{};
    o.writable = SendMessageA(ctl(IDC_WRITABLE_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    o.executable = SendMessageA(ctl(IDC_EXEC_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    o.cow = SendMessageA(ctl(IDC_COW_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    int modSel = (int)SendMessageA(ctl(IDC_PRESET_CB), CB_GETCURSEL, 0, 0);
    if (modSel > 0 && (size_t)(modSel - 1) < g_mods.size()) {
        o.modBase = g_mods[(size_t)modSel - 1].base;
        o.modSize = g_mods[(size_t)modSel - 1].size;
    }
    std::string ss = getText(IDC_START_EDIT), se = getText(IDC_STOP_EDIT);
    o.start = strtoull(ss.c_str(), nullptr, 16); // CE Start/Stop are hex
    o.stop = strtoull(se.c_str(), nullptr, 16);
    if (o.stop <= o.start) o.stop = 0x7FFFFFFFFFFFULL;
    bool fast = SendMessageA(ctl(IDC_FAST_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::string sa = getText(IDC_ALIGN_EDIT);
    int al = atoi(sa.c_str());
    if (!fast) al = 1;
    if (al < 1) al = 1;
    if (al > 8) al = 8;
    o.align = al;
    return o;
}
static void doAttachStr(const std::string& input) {
    // trim
    char tmp[128]{};
    snprintf(tmp, sizeof(tmp), "%s", input.c_str());
    char* s = tmp;
    while (*s && isspace((unsigned char)*s)) s++;
    size_t L = strlen(s);
    while (L && isspace((unsigned char)s[L - 1])) s[--L] = 0;
    if (!*s) { setStatus("Enter a process name or PID"); return; }
    // numeric => PID, else process name
    bool numeric = true;
    for (const char* p = s; *p; p++) if (!isdigit((unsigned char)*p)) { numeric = false; break; }
    DWORD pid = 0;
    char pname[128]{};
    if (numeric) {
        pid = (DWORD)strtoul(s, nullptr, 0);
        snprintf(pname, sizeof(pname), "PID %lu", pid);
    }
    else {
        pid = FindPID(s);
        snprintf(pname, sizeof(pname), "%s", s);
    }
    if (!pid) { setStatus("Process not found"); g_attached = false; return; }
    // verify PID exists
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        bool found = false;
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) do {
                if (pe.th32ProcessID == pid) {
                    char eb[MAX_PATH]{};
                    WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, eb, MAX_PATH, nullptr, nullptr);
                    if (numeric) snprintf(pname, sizeof(pname), "%s", eb);
                    found = true; break;
                }
            } while (Process32NextW(snap, &pe));
            CloseHandle(snap);
        }
        if (!found) { setStatus("PID not running"); g_attached = false; return; }
    }
    if (!g_connected) { setStatus("Driver MISSING"); return; }
    SSTR(_dev, _s_dev);
    if (g_drv) { delete g_drv; g_drv = nullptr; }
    g_drv = new ls_driver(_dev, pid);
    if (!g_drv->valid()) { setStatus("CreateFile failed"); g_attached = false; return; }
    DWORD v = g_drv->version();
    g_pid = pid;
    g_modsPid = 0; // force module refresh for new target
    snprintf(g_proc, sizeof(g_proc), "%s", pname);
    g_attached = true;
    RefreshMods(pid);
    char lbl[200]; snprintf(lbl, sizeof(lbl), "%s  (PID %lu)  [drv %08X]", pname, pid, v);
    SetWindowTextA(ctl(IDC_PROC_LBL), lbl);
    // NOTE: window caption stays spoofed (Chrome cover) — target info lives in PROC_LBL
    char st[160]; snprintf(st, sizeof(st), "Attached PID %lu", pid);
    setStatus(st);
}
static void doAttach() { doAttachStr(g_proc); }
// Process-select dialog: CE-style list + manual entry
static void FillProcList(HWND lv) {
    SendMessageA(lv, LVM_DELETEALLITEMS, 0, 0);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    struct Row { std::string name; DWORD pid; };
    std::vector<Row> rows;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) do {
        if (pe.th32ProcessID <= 4) continue; // skip System/Registry
        char eb[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, eb, MAX_PATH, nullptr, nullptr);
        rows.push_back({ eb, pe.th32ProcessID });
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        std::string al = a.name, bl = b.name;
        for (auto& c : al) c = (char)tolower((unsigned char)c);
        for (auto& c : bl) c = (char)tolower((unsigned char)c);
        return al < bl;
    });
    char pidb[32];
    for (size_t i = 0; i < rows.size(); i++) {
        LVITEMA it{}; it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = (int)i; it.iSubItem = 0;
        it.pszText = (LPSTR)rows[i].name.c_str();
        it.lParam = (LPARAM)rows[i].pid;
        SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
        snprintf(pidb, sizeof(pidb), "%lu", rows[i].pid);
        lv_set_text(lv, (int)i, 1, pidb);
    }
}
static void ProcOkFromDialog(HWND h) {
    // list selection wins; else manual text
    HWND lv = GetDlgItem(h, PL_LIST);
    std::string pick;
    if (lv) {
        int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
        if (sel >= 0) {
            LVITEMA it{}; it.mask = LVIF_PARAM; it.iItem = sel;
            if (SendMessageA(lv, LVM_GETITEMA, 0, (LPARAM)&it)) {
                char pb[32]; snprintf(pb, sizeof(pb), "%lu", (DWORD)it.lParam);
                pick = pb;
            }
        }
    }
    if (pick.empty()) pick = dlgText(h, PL_EDIT);
    DestroyWindow(h);
    doAttachStr(pick);
}
static void OpenProcDialog() {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Process List", WS_POPUP | WS_CAPTION | WS_SYSMENU, 250, 150, 420, 480, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    HWND lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 12, 12, 380, 320, p, (HMENU)(INT_PTR)PL_LIST, GetModuleHandleA(nullptr), nullptr);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    {
        const char* n[] = { "Process", "PID" };
        int w[] = { 250, 120 };
        // local cols (lv_cols targets main window lists only by handle — reuse is handle-based, fine)
        lv_cols(lv, n, w, 2);
    }
    FillProcList(lv);
    c("BUTTON", "Refresh", BS_PUSHBUTTON, 12, 340, 90, 26, PL_REFRESH);
    c("STATIC", "Name or PID:", SS_LEFT, 112, 344, 80, 20, -1);
    c("EDIT", g_proc, WS_BORDER | ES_AUTOHSCROLL, 196, 342, 196, 24, PL_EDIT);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 110, 380, 100, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 220, 380, 100, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 1); // mode 1 = proc dialog
    ShowWindow(p, SW_SHOW);
}
static void doAddSelectedToTable() {
    // "Add Address Manually" button: prefill CE dialog from selection (or blank)
    UINT64 addr = 0;
    HWND lv = ctl(IDC_FOUND_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel >= 0) {
        std::lock_guard<std::mutex> lk(g_candsMtx);
        if ((size_t)sel < g_cands.size()) addr = g_cands[(size_t)sel].addr;
    }
    char ab[32]; snprintf(ab, sizeof(ab), "%llX", (unsigned long long)addr);
    OpenManualAdd(ab, g_vtype);
}
static bool CopyText(const char* s) {
    if (!s || !*s || !OpenClipboard(g_hwnd)) return false;
    EmptyClipboard();
    size_t n = strlen(s) + 1;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
    if (!h) { CloseClipboard(); return false; }
    memcpy(GlobalLock(h), s, n);
    GlobalUnlock(h);
    bool ok = (SetClipboardData(CF_TEXT, h) != nullptr);
    CloseClipboard();
    if (!ok) GlobalFree(h); // owned by clipboard on success
    return ok;
}
// Copy table address cell. modForm=false -> literally as displayed (may have
// P-> prefix); true -> clean "mod"+OFF (static, rebase-safe) or plain hex.
static void TableCopy(bool modForm) {
    HWND lv = ctl(IDC_TBL_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a table row first"); return; }
    char out[192]{};
    if (!modForm) {
        LVITEMA lvi{}; lvi.iSubItem = 2; lvi.pszText = out; lvi.cchTextMax = sizeof(out);
        SendMessageA(lv, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&lvi);
    }
    else {
        TblEntry e; bool got = false;
        { std::lock_guard<std::mutex> lk(g_tableMtx); if ((size_t)sel < g_table.size()) { e = g_table[(size_t)sel]; got = true; } }
        if (!got) return;
        if (e.mod[0]) snprintf(out, sizeof(out), "\"%s\"+%llX", e.mod, (unsigned long long)e.modOff);
        else {
            UINT64 f = e.addr;
            if (g_drv && g_attached && e.isPtr && !entry_final(e, f)) { setStatus("Unresolvable pointer"); return; }
            char mb[160];
            if (addr_display(f, mb, sizeof(mb))) snprintf(out, sizeof(out), "%s", mb);
            else snprintf(out, sizeof(out), "%llX", (unsigned long long)f);
        }
    }
    if (CopyText(out)) { char s[220]; snprintf(s, sizeof(s), "Copied %s", out); setStatus(s); }
    else setStatus("Copy failed");
}
static void FoundCopy(bool modForm) {
    HWND lv = ctl(IDC_FOUND_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a found row first"); return; }
    char out[192]{};
    if (!modForm) {
        LVITEMA lvi{}; lvi.iSubItem = 0; lvi.pszText = out; lvi.cchTextMax = sizeof(out);
        SendMessageA(lv, LVM_GETITEMTEXTA, (WPARAM)sel, (LPARAM)&lvi);
    }
    else {
        UINT64 addr = 0;
        { std::lock_guard<std::mutex> lk(g_candsMtx); if ((size_t)sel >= g_cands.size()) return; addr = g_cands[(size_t)sel].addr; }
        char mb[160];
        if (addr_display(addr, mb, sizeof(mb))) snprintf(out, sizeof(out), "%s", mb);
        else snprintf(out, sizeof(out), "%llX", (unsigned long long)addr);
    }
    if (CopyText(out)) { char s[220]; snprintf(s, sizeof(s), "Copied %s", out); setStatus(s); }
    else setStatus("Copy failed");
}
// Open Memory Viewer disassembling `addr` (existing window retargeted, else opened).
static void GoToDism(UINT64 addr) {
    if (!addr) { setStatus("Bad address"); return; }
    if (!g_drv || !g_attached) { setStatus("Attach first"); return; }
    if (g_mv) {
        char a[32]; snprintf(a, sizeof(a), "%llX", (unsigned long long)addr);
        SetDlgItemTextA(g_mv, MV_ADDR_EDIT, a);
        doMemDump(); doMemDisasm();
        SetForegroundWindow(g_mv);
        return;
    }
    g_mvGoAddr = addr;
    OpenMemView();
    g_mvGoAddr = 0;
}
static void TableDism() {
    HWND lv = ctl(IDC_TBL_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a table row first"); return; }
    TblEntry e; bool got = false;
    { std::lock_guard<std::mutex> lk(g_tableMtx); if ((size_t)sel < g_table.size()) { e = g_table[(size_t)sel]; got = true; } }
    if (!got) return;
    UINT64 f = e.addr;
    if (!g_drv || !g_attached || !entry_final(e, f)) { setStatus("Unresolvable address"); return; }
    GoToDism(f);
}
static void FoundDism() {
    HWND lv = ctl(IDC_FOUND_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a found row first"); return; }
    UINT64 addr = 0;
    { std::lock_guard<std::mutex> lk(g_candsMtx); if ((size_t)sel >= g_cands.size()) return; addr = g_cands[(size_t)sel].addr; }
    GoToDism(addr);
}
static void TableDeleteSel() {
    HWND lv = ctl(IDC_TBL_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a table row first"); return; }
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        if ((size_t)sel >= g_table.size()) return;
        g_table.erase(g_table.begin() + sel);
    }
    refresh_table();
    setStatus("Deleted address");
}
// Column action shared by double-click + right-click menu (col: 4=Value 3=Type 1=Desc else Address)
static void TableAct(int sel, int col) {
    if (sel < 0) return;
    TblEntry e; bool got = false;
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        if ((size_t)sel < g_table.size()) { e = g_table[(size_t)sel]; got = true; }
    }
    if (!got) return;
    g_editRow = sel;
    if (col == 4) OpenChangeValue(e);
    else if (col == 3) OpenChangeType(e);
    else if (col == 1) OpenChangeDesc(e);
    else {
        char ab[160];
        if (e.mod[0]) snprintf(ab, sizeof(ab), "\"%s\"+%llX", e.mod, (unsigned long long)e.modOff);
        else snprintf(ab, sizeof(ab), "%llX", (unsigned long long)e.addr);
        int dlgVt = (e.vtype == V_U8) ? 0 : (e.vtype == V_U16) ? 1 : (e.vtype == V_U32) ? 2 : (e.vtype == V_U64) ? 3 : (e.vtype == V_F32) ? 4 : (e.vtype == V_F64) ? 5 : (e.vtype == V_STR) ? 6 : 7;
        g_editReplace = true;
        OpenManualAdd(ab, dlgVt, e.isPtr, e.ptrOffs, e.nOff, e.isSigned, e.desc, "Change address");
    }
}
// CE behavior: double-click found row drops it straight into the table, no dialog
static void doAddFoundToTableDirect() {
    HWND lv = ctl(IDC_FOUND_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a found row first"); return; }
    UINT64 addr = 0;
    {
        std::lock_guard<std::mutex> lk(g_candsMtx);
        if ((size_t)sel >= g_cands.size()) return;
        addr = g_cands[(size_t)sel].addr;
    }
    TblEntry e{};
    e.active = false;
    snprintf(e.desc, sizeof(e.desc), "No description");
    e.addr = addr; e.vtype = g_vtype; e.len = g_valLen ? g_valLen : 4;
    e.isSigned = false; e.isPtr = false; e.nOff = 0;
    if (g_drv && g_attached) g_drv->read_raw(addr, e.bytes, e.len);
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        g_table.push_back(e);
    }
    refresh_table();
    char s[128]; snprintf(s, sizeof(s), "Added %016llX (%s)", (unsigned long long)addr, vtypeName(e.vtype));
    setStatus(s);
}

//=================================================================
//  POINTER SCAN UI — options / progress / results / rescan (.LPS)
//=================================================================
static bool g_ctxFound = false; // context menu source: found list vs table

// .lps file dialog (pointerlist) — separate from .ltb table dialog
static std::string xml_unesc(const std::string& s); // fwd: defined in Legend Table section
static std::string getAttr(const std::string& tag, const char* name); // fwd
static bool PS_FileDlg(bool save, char* out, int outSz) {
    OPENFILENAMEA of{};
    of.lStructSize = sizeof(of);
    of.hwndOwner = g_psWin ? g_psWin : g_hwnd;
    of.lpstrFilter = "Legend Pointerlist (*.lps)\0*.lps\0All files (*.*)\0*.*\0";
    of.lpstrDefExt = "lps";
    of.nFilterIndex = 1;
    of.lpstrFile = out;
    of.nMaxFile = (DWORD)outSz;
    of.Flags = save ? (OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST) : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST);
    return save ? (GetSaveFileNameA(&of) == TRUE) : (GetOpenFileNameA(&of) == TRUE);
}
static void PS_RefreshResList(); // fwd (defined below, used by Load)
static bool PS_LoadList(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "rb");
    if (!f) { setStatus("Open pointerlist failed"); return false; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 100000000) { fclose(f); setStatus("Bad pointerlist file"); return false; }
    std::string data((size_t)sz, 0);
    if (fread(&data[0], 1, (size_t)sz, f) != (size_t)sz) { fclose(f); setStatus("Read failed"); return false; }
    fclose(f);
    size_t hp = data.find("<LegendPointers");
    if (hp == std::string::npos) { setStatus("Not a pointerlist (.lps)"); return false; }
    size_t he = data.find('>', hp);
    std::string head = (he == std::string::npos) ? "" : data.substr(hp, he - hp);
    UINT64 target = strtoull(getAttr(head, "target").c_str(), nullptr, 16);
    int vt = atoi(getAttr(head, "vtype").c_str());
    ULONG vl = (ULONG)strtoul(getAttr(head, "vlen").c_str(), nullptr, 0);
    if (vt < 0 || vt > 7) vt = V_U32;
    if (!vl || vl > 32) vl = 4;
    std::vector<PSPath> tmp;
    size_t p = 0;
    while ((p = data.find("<P ", p)) != std::string::npos) {
        size_t q = data.find("/>", p);
        if (q == std::string::npos) break;
        std::string tag = data.substr(p, q - p);
        p = q + 2;
        PSPath e{};
        e.mod = xml_unesc(getAttr(tag, "mod"));
        if (e.mod.empty()) continue;
        e.modOff = strtoull(getAttr(tag, "moff").c_str(), nullptr, 16);
        e.nOff = atoi(getAttr(tag, "n").c_str());
        if (e.nOff < 1 || e.nOff > PTR_MAX) continue;
        std::string lo = getAttr(tag, "offs");
        e.nOff = 0;
        if (!lo.empty()) {
            size_t s = 0;
            while (s < lo.size() && e.nOff < PTR_MAX) {
                size_t c = lo.find(',', s);
                std::string one = (c == std::string::npos) ? lo.substr(s) : lo.substr(s, c - s);
                e.offs[e.nOff++] = strtoull(one.c_str(), nullptr, 16);
                if (c == std::string::npos) break;
                s = c + 1;
            }
        }
        if (!e.nOff) continue;
        e.pointsTo = strtoull(getAttr(tag, "points").c_str(), nullptr, 16);
        tmp.push_back(e);
        if (tmp.size() >= 500000) break;
    }
    {
        std::lock_guard<std::mutex> lk(g_psResMtx);
        g_psRes.swap(tmp);
    }
    g_ps.target = target; g_ps.vtype = vt; g_ps.vlen = vl;
    PS_RefreshResList();
    char s[160]; snprintf(s, sizeof(s), "Loaded pointerlist: %zu paths (target %llX)", g_psRes.size(), (unsigned long long)target);
    setStatus(s);
    return true;
}
static void PS_SaveList(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) { setStatus("Pointerlist save failed"); return; }
    fprintf(f, "<LegendPointers target=\"%llX\" vtype=\"%d\" vlen=\"%lu\">\n",
        (unsigned long long)g_ps.target, g_ps.vtype, g_ps.vlen);
    std::lock_guard<std::mutex> lk(g_psResMtx);
    for (auto& p : g_psRes) {
        char offs[128]{};
        for (int k = 0; k < p.nOff; k++)
            snprintf(offs + strlen(offs), sizeof(offs) - strlen(offs), "%s%llX", k ? "," : "", (unsigned long long)p.offs[k]);
        fprintf(f, "<P mod=\"%s\" moff=\"%llX\" n=\"%d\" offs=\"%s\" points=\"%llX\"/>\n",
            p.mod.c_str(), (unsigned long long)p.modOff, p.nOff, offs, (unsigned long long)p.pointsTo);
    }
    fprintf(f, "</LegendPointers>\n");
    fclose(f);
    char s[160]; snprintf(s, sizeof(s), "Pointerlist saved: %zu paths", g_psRes.size());
    setStatus(s);
}
// Resolve one saved path against CURRENT module bases (rebase-safe rescan)
// CE semantic: p = base; for each off: p = *(p) + off.
static bool PS_ResolveByName(const std::string& mod, UINT64 modOff, const UINT64* offs, int n, UINT64& out) {
    UINT64 base = 0;
    for (auto& m : g_mods) {
        if (_stricmp(m.name.c_str(), mod.c_str()) == 0 && m.size) { base = m.base + modOff; break; }
    }
    if (!base || !g_drv || !g_attached) return false;
    if (!ls_driver::is_user_range(base, 8)) return false;
    UINT64 p = base;
    for (int i = 0; i < n && i < PTR_MAX; i++) {
        UINT64 v = 0;
        if (!g_drv->read_u64_checked(p, v)) return false;
        if (!v) return false;
        UINT64 nxt = v + offs[i];
        if (nxt < v) return false;
        if (!ls_driver::is_user_range(nxt, 1)) return false;
        p = nxt;
    }
    out = p;
    return true;
}
static void PS_OpenOptions(UINT64 target, int vtype, ULONG vlen) {
    if (!g_drv || !g_attached) { setStatus("Attach first"); return; }
    if (g_pscanning) { setStatus("Pointer scan already running"); return; }
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_ps.target = target; g_ps.vtype = vtype; g_ps.vlen = vlen;
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Pointerscanner scanoptions", WS_POPUP | WS_CAPTION | WS_SYSMENU, 300, 200, 380, 300, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Scan for address", SS_LEFT, 12, 12, 120, 20, -1);
    char ab[32]; snprintf(ab, sizeof(ab), "%llX", (unsigned long long)target);
    c("EDIT", ab, WS_BORDER | ES_AUTOHSCROLL, 140, 10, 210, 24, PSO_ADDR);
    c("STATIC", "Max different offsets per node:", SS_LEFT, 12, 44, 200, 20, -1);
    c("EDIT", "3", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 220, 42, 60, 24, PSO_DIFF);
    c("STATIC", "Nr of threads scanning:", SS_LEFT, 12, 74, 200, 20, -1);
    c("EDIT", "4", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 220, 72, 60, 24, PSO_THR);
    c("STATIC", "Maximum offset value:", SS_LEFT, 12, 104, 200, 20, -1);
    c("EDIT", "4095", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 220, 102, 60, 24, PSO_MAXOFF);
    c("STATIC", "Max level (1-5):", SS_LEFT, 12, 134, 200, 20, -1);
    c("EDIT", "5", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 220, 132, 60, 24, PSO_LVL);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 90, 180, 90, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 200, 180, 90, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 7); // mode 7 = pointerscan options
    ShowWindow(p, SW_SHOW);
}
static void PS_OpenProgress() {
    if (g_psProg) { SetForegroundWindow(g_psProg); return; }
    g_psProg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsPSP, "Pointer scan", WS_POPUP | WS_CAPTION | WS_SYSMENU, 300, 200, 420, 250, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_psProg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Starting...", SS_LEFT, 12, 12, 380, 170, PS_PROG_STAT);
    c("BUTTON", "Stop", BS_PUSHBUTTON, 150, 190, 100, 28, PS_STOP);
    ShowWindow(p, SW_SHOW);
}
static void PS_UpdateProgress() {
    if (!g_psProg) return;
    DWORD el = (GetTickCount() - g_ps.startTick) / 1000;
    char s[512];
    snprintf(s, sizeof(s),
        "Target: %llX\r\nLevel: %d / %d   Regions: %d / %d\r\nPaths evaluated: %llu\r\nResults found: %llu\r\nTime: %lus\r\n%s",
        (unsigned long long)g_ps.target, (int)g_ps.level, g_ps.maxLevel,
        (int)g_ps.regionsDone, (int)g_ps.regionsTotal,
        (unsigned long long)g_ps.paths.load(), (unsigned long long)g_ps.results.load(), el,
        g_ps.run ? "Scanning..." : "Finishing...");
    SetDlgItemTextA(g_psProg, PS_PROG_STAT, s);
}
static void PS_RefreshResList() {
    HWND lv = nullptr;
    if (g_psWin) lv = GetDlgItem(g_psWin, PS_RES_LIST);
    if (!lv) return;
    SendMessageA(lv, LVM_DELETEALLITEMS, 0, 0);
    std::lock_guard<std::mutex> lk(g_psResMtx);
    LVITEMA it{}; it.mask = LVIF_TEXT;
    char b[160], o[32], pt[48];
    size_t show = (std::min<size_t>)(g_psRes.size(), 20000);
    for (size_t i = 0; i < show; i++) {
        auto& p = g_psRes[i];
        snprintf(b, sizeof(b), "\"%s\"+%llX", p.mod.c_str(), (unsigned long long)p.modOff);
        it.iItem = (int)i; it.iSubItem = 0; it.pszText = b;
        SendMessageA(lv, LVM_INSERTITEMA, 0, (LPARAM)&it);
        for (int k = 0; k < 5; k++) {
            if (k < p.nOff) snprintf(o, sizeof(o), "%llX", (unsigned long long)p.offs[k]);
            else snprintf(o, sizeof(o), "-");
            lv_set_text(lv, (int)i, 1 + k, o);
        }
        snprintf(pt, sizeof(pt), "%llX", (unsigned long long)p.pointsTo);
        lv_set_text(lv, (int)i, 6, pt);
    }
    char t[128]; snprintf(t, sizeof(t), "Pointer paths:%zu", g_psRes.size());
    SetWindowTextA(g_psWin, t);
}
static void PS_OpenResults() {
    if (g_psWin) { PS_RefreshResList(); SetForegroundWindow(g_psWin); return; }
    g_psWin = CreateWindowExA(0, g_clsPSR, "Pointer paths:0", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME | WS_MAXIMIZEBOX,
        120, 80, 900, 520, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_psWin;
    HWND lv = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        8, 8, 868, 400, p, (HMENU)(INT_PTR)PS_RES_LIST, GetModuleHandleA(nullptr), nullptr);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    {
        const char* n[] = { "Base Address", "Offset 0", "Offset 1", "Offset 2", "Offset 3", "Offset 4", "Points to:" };
        int w[] = { 220, 90, 90, 90, 90, 90, 150 };
        lv_cols(lv, n, w, 7);
    }
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("BUTTON", "Rescan...", BS_PUSHBUTTON, 8, 420, 110, 28, PS_RESCAN);
    c("BUTTON", "Add Selected", BS_PUSHBUTTON, 128, 420, 110, 28, PS_ADD);
    c("BUTTON", "Save", BS_PUSHBUTTON, 248, 420, 90, 28, PS_SAVE);
    c("BUTTON", "Open", BS_PUSHBUTTON, 348, 420, 90, 28, PS_OPENB);
    c("BUTTON", "Close", BS_PUSHBUTTON, 448, 420, 90, 28, PS_CLOSEB);
    ShowWindow(p, SW_SHOW);
    PS_RefreshResList();
}
static void PS_AddSelected() {
    if (!g_psWin) return;
    HWND lv = GetDlgItem(g_psWin, PS_RES_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a pointer path first"); return; }
    PSPath p; bool got = false;
    {
        std::lock_guard<std::mutex> lk(g_psResMtx);
        if ((size_t)sel < g_psRes.size()) { p = g_psRes[(size_t)sel]; got = true; }
    }
    if (!got) return;
    TblEntry e{};
    snprintf(e.desc, sizeof(e.desc), "Pointer");
    snprintf(e.mod, sizeof(e.mod), "%s", p.mod.c_str());
    e.modOff = p.modOff;
    e.vtype = g_ps.vtype; e.len = g_ps.vlen ? g_ps.vlen : 4;
    e.isPtr = true; e.nOff = p.nOff;
    for (int i = 0; i < p.nOff && i < PTR_MAX; i++) e.ptrOffs[i] = p.offs[i];
    UINT64 f = 0;
    if (g_drv && g_attached && entry_final(e, f)) g_drv->read_raw(f, e.bytes, e.len);
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        g_table.push_back(e);
    }
    refresh_table();
    char s[160]; snprintf(s, sizeof(s), "Added P->\"%s\"+%llX (%d offs)", p.mod.c_str(), (unsigned long long)p.modOff, p.nOff);
    setStatus(s);
}
static void PS_OpenRescan() {
    if (!g_attached) { setStatus("Attach first"); return; }
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    char cur[32]; snprintf(cur, sizeof(cur), "%llX", (unsigned long long)g_ps.target);
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Rescan pointerlist", WS_POPUP | WS_CAPTION | WS_SYSMENU, 320, 220, 380, 200, g_psWin ? g_psWin : g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Address to find:", SS_LEFT, 12, 14, 110, 20, -1);
    c("EDIT", cur, WS_BORDER | ES_AUTOHSCROLL, 130, 12, 220, 24, PSR_ADDR);
    c("BUTTON", "Only filter out invalid pointers", BS_AUTOCHECKBOX, 12, 46, 340, 22, PSR_VALID);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 100, 84, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 200, 84, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 8); // mode 8 = pointer rescan
    ShowWindow(p, SW_SHOW);
}
static void PS_DoRescan(const std::string& txt) {
    UINT64 newT = strtoull(txt.c_str(), nullptr, 16);
    if (!newT) { setStatus("Bad address"); return; }
    if (!g_attached || !g_drv) { setStatus("Attach first"); return; }
    RefreshMods(g_pid); // current bases (post-restart ASLR)
    std::vector<PSPath> kept;
    {
        std::lock_guard<std::mutex> lk(g_psResMtx);
        for (auto& p : g_psRes) {
            UINT64 f = 0;
            if (PS_ResolveByName(p.mod, p.modOff, p.offs, p.nOff, f) && f == newT) {
                p.pointsTo = newT;
                kept.push_back(p);
            }
        }
        g_psRes.swap(kept);
    }
    g_ps.target = newT;
    PS_RefreshResList();
    char s[160]; snprintf(s, sizeof(s), "Rescan: %zu paths still point to %llX", g_psRes.size(), (unsigned long long)newT);
    setStatus(s);
    // checkpoint again, like CE asks to save after rescan (.lps pointerlist)
    char path[MAX_PATH]{};
    if (PS_FileDlg(true, path, MAX_PATH)) {
        PS_SaveList(path);
    }
}
// Valid-only rescan: no target address needed. Keeps paths that still resolve
// to anything live, drops the ?? ones. Checkbox mode in the rescan dialog.
static void PS_DoRescanValid() {
    if (!g_attached || !g_drv) { setStatus("Attach first"); return; }
    RefreshMods(g_pid); // current bases (post-restart ASLR)
    size_t total = 0;
    {
        std::lock_guard<std::mutex> lk(g_psResMtx);
        total = g_psRes.size();
        std::vector<PSPath> kept;
        kept.reserve(total);
        for (auto& p : g_psRes) {
            UINT64 f = 0;
            if (PS_ResolveByName(p.mod, p.modOff, p.offs, p.nOff, f)) {
                p.pointsTo = f;
                kept.push_back(p);
            }
        }
        g_psRes.swap(kept);
    }
    PS_RefreshResList();
    char s[160]; snprintf(s, sizeof(s), "Rescan: %zu live of %zu (invalid removed)", g_psRes.size(), total);
    setStatus(s);
    char path[MAX_PATH]{};
    if (PS_FileDlg(true, path, MAX_PATH)) {
        PS_SaveList(path);
    }
}
// Entry points (table row / found row)
static void PS_ForTableRow() {
    HWND lv = ctl(IDC_TBL_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) {
        // fall back to found list
        HWND fl = ctl(IDC_FOUND_LIST);
        sel = fl ? ListView_GetNextItem(fl, -1, LVNI_SELECTED) : -1;
        if (sel < 0) { setStatus("Select a table or found row first"); return; }
        PS_ForFoundRow();
        return;
    }
    TblEntry e; bool got = false;
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        if ((size_t)sel < g_table.size()) { e = g_table[(size_t)sel]; got = true; }
    }
    if (!got) return;
    UINT64 f = e.addr;
    if (!g_drv || !g_attached || !entry_final(e, f)) { setStatus("Attach first"); return; }
    PS_OpenOptions(f, e.vtype, e.len);
}
static void PS_ForFoundRow() {
    HWND lv = ctl(IDC_FOUND_LIST);
    int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
    if (sel < 0) { setStatus("Select a found row first"); return; }
    UINT64 addr = 0;
    {
        std::lock_guard<std::mutex> lk(g_candsMtx);
        if ((size_t)sel >= g_cands.size()) return;
        addr = g_cands[(size_t)sel].addr;
    }
    PS_OpenOptions(addr, g_vtype, g_valLen ? g_valLen : 4);
}
static LRESULT CALLBACK PSProgProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_COMMAND && LOWORD(w) == PS_STOP) {
        g_ps.stop = true;
        SetDlgItemTextA(h, PS_STOP, "Stopping...");
        EnableWindow(GetDlgItem(h, PS_STOP), FALSE);
        return 0;
    }
    if (m == WM_CLOSE) {
        if (g_ps.run) {
            g_ps.stop = true;
            return 0;
        }
        DestroyWindow(h);
        return 0;
    }
    if (m == WM_DESTROY) { if (h == g_psProg) g_psProg = nullptr; return 0; }
    return DefWindowProcA(h, m, w, l);
}
static LRESULT CALLBACK PSResProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_COMMAND) {
        int id = LOWORD(w);
        if (id == PS_CLOSEB) { DestroyWindow(h); return 0; }
        if (id == PS_ADD) { PS_AddSelected(); return 0; }
        if (id == PS_RESCAN) { PS_OpenRescan(); return 0; }
        if (id == PS_SAVE) {
            char path[MAX_PATH]{};
            if (PS_FileDlg(true, path, MAX_PATH)) PS_SaveList(path);
            return 0;
        }
        if (id == PS_OPENB) {
            char path[MAX_PATH]{};
            if (PS_FileDlg(false, path, MAX_PATH)) {
                if (!g_psWin) PS_OpenResults();
                PS_LoadList(path);
            }
            return 0;
        }
        return 0;
    }
    if (m == WM_NOTIFY) {
        LPNMHDR nh = (LPNMHDR)l;
        if (nh->idFrom == (UINT_PTR)PS_RES_LIST && nh->code == NM_DBLCLK) {
            PS_AddSelected();
            return 0;
        }
    }
    if (m == WM_CLOSE) { DestroyWindow(h); return 0; }
    if (m == WM_DESTROY) { if (h == g_psWin) g_psWin = nullptr; return 0; }
    if (m == WM_GETMINMAXINFO) {
        LPMINMAXINFO mm = (LPMINMAXINFO)l;
        mm->ptMinTrackSize.x = 500;
        mm->ptMinTrackSize.y = 300;
        return 0;
    }
    if (m == WM_SIZE) {
        // Keep list filling the window + buttons anchored bottom-left (maximize-safe)
        int cw = LOWORD(l), ch = HIWORD(l);
        HWND lv = GetDlgItem(h, PS_RES_LIST);
        if (lv) SetWindowPos(lv, nullptr, 8, 8, (std::max)(cw - 16, 100), (std::max)(ch - 60, 80), SWP_NOZORDER);
        int by = (std::max)(ch - 40, 90);
        const int bx[] = { 8, 128, 248, 348, 448 };
        const int bid[] = { PS_RESCAN, PS_ADD, PS_SAVE, PS_OPENB, PS_CLOSEB };
        for (int i = 0; i < 5; i++) {
            HWND b = GetDlgItem(h, bid[i]);
            if (b) SetWindowPos(b, nullptr, bx[i], by, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        }
        return 0;
    }
    return DefWindowProcA(h, m, w, l);
}

//=================================================================
//  Dump Process (KsDumper-style) — PE rebuild from driver reads.
//  Zero usermode handles: works on protected targets. Import table
//  is NOT rebuilt (same limitation as KsDumper).
//=================================================================
static std::vector<ModInfo> g_dumpMods;
// Best-effort page-granular read: unreadable pages stay zeroed, dump continues.
static SIZE_T dump_read_best(UINT64 addr, BYTE* dst, SIZE_T sz) {
    if (!g_drv || !g_attached || !dst) return 0;
    memset(dst, 0, sz);
    SIZE_T done = 0;
    std::vector<BYTE> tmp;
    tmp.resize(0x1000);
    while (done < sz) {
        UINT64 cur = addr + done;
        SIZE_T want = (std::min<SIZE_T>)(0x1000, sz - done);
        SIZE_T pg = (SIZE_T)(cur & 0xFFF);
        if (pg + want > 0x1000) want = 0x1000 - pg; // never cross pages
        if (g_drv->read_bulk(cur, tmp.data(), want)) memcpy(dst + done, tmp.data(), want);
        done += want;
    }
    return done;
}
static void doDumpModule(const ModInfo& m, const char* path);
static void OpenDumpDialog() {
    if (!g_drv || !g_attached) { setStatus("Attach first"); return; }
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    RefreshMods(g_pid);
    g_dumpMods = g_mods;
    if (g_dumpMods.empty()) { setStatus("No modules (protected target?)"); return; }
    int def = -1;
    for (size_t i = 0; i < g_dumpMods.size(); i++)
        if (_stricmp(g_dumpMods[i].name.c_str(), g_proc) == 0) { def = (int)i; break; }
    if (def < 0) {
        UINT64 lb = ~0ULL;
        for (size_t i = 0; i < g_dumpMods.size(); i++)
            if (g_dumpMods[i].base && g_dumpMods[i].base < lb) { lb = g_dumpMods[i].base; def = (int)i; }
    }
    if (def < 0) def = 0;
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Dump Process", WS_POPUP | WS_CAPTION | WS_SYSMENU, 340, 240, 400, 175, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Module:", SS_LEFT, 12, 14, 60, 20, -1);
    HWND cb = c("COMBOBOX", "", WS_BORDER | CBS_DROPDOWNLIST | WS_VSCROLL, 12, 36, 360, 220, DLG_TYPE_CB);
    for (auto& mm : g_dumpMods) {
        char it[160]; snprintf(it, sizeof(it), "%s  [%llX]", mm.name.c_str(), (unsigned long long)mm.base);
        SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)it);
    }
    SendMessageA(cb, CB_SETCURSEL, def, 0);
    c("BUTTON", "OK", BS_DEFPUSHBUTTON, 110, 88, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 210, 88, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 10); // mode 10 = dump picker
    ShowWindow(p, SW_SHOW);
}
//=================================================================
//  Inject DLL (Tools menu, Ctrl+I) — kernel LoadLibraryW remote thread.
//  No OpenProcess/CreateRemoteThread handles: lands on protected targets.
//=================================================================
// Classic usermode inject (OpenProcess + CreateRemoteThread). Reliable on
// unprotected targets (no alertable-wait needed); protected ones refuse the
// handle and the caller falls through to the driver APC path.
static bool InjectClassic(DWORD pid, const std::string& dllPath, UINT64& outBase) {
    outBase = 0;
    HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!h || h == INVALID_HANDLE_VALUE) return false; // protected: use driver
    wchar_t w[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, dllPath.c_str(), -1, w, MAX_PATH);
    SIZE_T bytes = (wcslen(w) + 1) * sizeof(wchar_t);
    LPVOID rem = VirtualAllocEx(h, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    bool ok = false;
    if (rem && WriteProcessMemory(h, rem, w, bytes, nullptr)) {
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        FARPROC ll = k32 ? GetProcAddress(k32, "LoadLibraryW") : nullptr;
        if (ll) {
            HANDLE th = CreateRemoteThread(h, nullptr, 0, (LPTHREAD_START_ROUTINE)ll, rem, 0, nullptr);
            if (th) {
                DWORD wr = WaitForSingleObject(th, 15000);
                DWORD exit = 0;
                if (wr == WAIT_OBJECT_0 && GetExitCodeThread(th, &exit) && exit) {
                    const char* fn = strrchr(dllPath.c_str(), '\\'); fn = fn ? fn + 1 : dllPath.c_str();
                    wchar_t wf[64]{}; MultiByteToWideChar(CP_ACP, 0, fn, -1, wf, 64);
                    if (g_drv && g_attached) outBase = (UINT64)g_drv->module_base(wf);
                    else outBase = exit;
                    ok = (outBase != 0);
                }
                CloseHandle(th);
            }
        }
    }
    if (rem) VirtualFreeEx(h, rem, 0, MEM_RELEASE);
    CloseHandle(h);
    return ok;
}
static void InjectThread(std::string dllPath) {
    HideThreadFromDebugger();
    snprintf(g_scanMsg, sizeof(g_scanMsg), "Injecting...");
    PostMessageA(g_hwnd, WM_SCAN_DONE, 2, 0);
    if (!g_drv || !g_attached) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Attach first"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); return; }
    wchar_t w[MAX_PATH]{};
    MultiByteToWideChar(CP_ACP, 0, dllPath.c_str(), -1, w, MAX_PATH);
    if (!w[0]) { snprintf(g_scanMsg, sizeof(g_scanMsg), "Bad path"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); return; }
    { // pre-flight: DLL must be 64-bit PE (target is 64-bit)
        FILE* f = nullptr;
        fopen_s(&f, dllPath.c_str(), "rb");
        BYTE h[0x1000]{}; size_t n = f ? fread(h, 1, sizeof(h), f) : 0;
        if (f) fclose(f);
        bool ok64 = false;
        if (n > 0x40 && h[0] == 'M' && h[1] == 'Z') {
            uint32_t lf = 0; memcpy(&lf, h + 0x3C, 4);
            if (lf <= (uint32_t)n - 6 && h[lf] == 'P' && h[lf + 1] == 'E') {
                uint16_t mc = 0; memcpy(&mc, h + lf + 4, 2);
                ok64 = (mc == 0x8664);
            }
        }
        if (!ok64) { snprintf(g_scanMsg, sizeof(g_scanMsg), "DLL is not 64-bit (need x64 DLL)"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); return; }
    }
    const char* fn0 = strrchr(dllPath.c_str(), '\\'); fn0 = fn0 ? fn0 + 1 : dllPath.c_str();
    UINT64 cbase = 0;
    if (InjectClassic(g_pid, dllPath, cbase) && cbase) {
        snprintf(g_scanMsg, sizeof(g_scanMsg), "Injected %s at %llX (usermode)", fn0, (unsigned long long)cbase);
        PostMessageA(g_hwnd, WM_SCAN_DONE, 5, 0);
        return;
    }
    SSTR(_dev, _s_dev);
    ls_driver drv(_dev, g_pid); // own handle: thread-safe
    if (!drv.valid()) { snprintf(g_scanMsg, sizeof(g_scanMsg), "CreateFile failed"); PostMessageA(g_hwnd, WM_SCAN_DONE, 0, 0); return; }
    LONG st = 0; UINT64 trace = 0;
    PVOID base = drv.inject(w, &st, &trace);
    const char* fn = strrchr(dllPath.c_str(), '\\');
    fn = fn ? fn + 1 : dllPath.c_str();
    const char* step = "early fail";
    if (trace & (1ULL << 9)) step = "module found";
    else if (trace & (1ULL << 8)) step = "loader ok";
    else if (trace & (1ULL << 7)) step = "stub ran";
    else if (trace & (1ULL << 6)) step = "apc queued";
    else if (trace & (1ULL << 5)) step = "ctx set";
    else if (trace & (1ULL << 4)) step = "got ctx";
    else if (trace & (1ULL << 3)) step = "suspended";
    else if (trace & (1ULL << 2)) step = "thread ok";
    else if (trace & (1ULL << 1)) step = "apis ok";
    else if (trace & (1ULL << 0)) step = "entered";
    if (base) snprintf(g_scanMsg, sizeof(g_scanMsg), "Injected %s at %llX (kernel)", fn, (unsigned long long)base);
    else if (st == (LONG)0xC0000008) snprintf(g_scanMsg, sizeof(g_scanMsg), "Attach first");
    else if (st == (LONG)0x00000102) snprintf(g_scanMsg, sizeof(g_scanMsg), "Inject timeout t=0x%llX (%s)", trace, step);
    else if (st == (LONG)0xC0000135) snprintf(g_scanMsg, sizeof(g_scanMsg), "LdrLoadDll: DLL or dependency not found (t=0x%llX)", trace);
    else if (st == (LONG)0xC000007B) snprintf(g_scanMsg, sizeof(g_scanMsg), "LdrLoadDll: bitness mismatch");
    else if (st == (LONG)0xC000007A) snprintf(g_scanMsg, sizeof(g_scanMsg), "Inject failed: LdrLoadDll not found");
    else if (st == (LONG)0xC000000B) snprintf(g_scanMsg, sizeof(g_scanMsg), "Inject failed: target thread gone (retry?)");
    else snprintf(g_scanMsg, sizeof(g_scanMsg), "Inject failed: 0x%08X", (unsigned)st);
    PostMessageA(g_hwnd, WM_SCAN_DONE, 5, 0); // UI thread: refresh modules + status
}
static void OpenInjectDialog() {
    if (!g_drv || !g_attached) { setStatus("Attach first"); return; }
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, g_clsDlg, "Inject DLL", WS_POPUP | WS_CAPTION | WS_SYSMENU, 320, 230, 420, 210, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_dlg;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "DLL path (64-bit DLL for 64-bit target):", SS_LEFT, 12, 12, 380, 20, -1);
    c("EDIT", "", WS_BORDER | ES_AUTOHSCROLL, 12, 36, 280, 24, DLG_ADDR_EDIT);
    c("BUTTON", "Browse...", BS_PUSHBUTTON, 300, 35, 92, 26, DLG_BROWSE);
    c("STATIC", "Kernel LoadLibraryW thread — no handle needed.", SS_LEFT, 12, 68, 380, 20, -1);
    c("BUTTON", "Inject", BS_DEFPUSHBUTTON, 110, 104, 80, 28, DLG_OK_BTN);
    c("BUTTON", "Cancel", BS_PUSHBUTTON, 210, 104, 80, 28, DLG_CANCEL_BTN);
    SetWindowLongPtrA(p, GWLP_USERDATA, 11); // mode 11 = inject picker
    ShowWindow(p, SW_SHOW);
}
static void doDumpModule(const ModInfo& m, const char* path) {
    setStatus("Dumping...");
    UINT64 base = m.base;
    { UINT64 live = mod_base(m.name.c_str()); if (live) base = live; } // ASLR-fresh
    if (!base) { setStatus("Module base gone (re-attach?)"); return; }
    std::vector<BYTE> h1(0x1000);
    if (!g_drv->read_bulk(base, h1.data(), h1.size())) { setStatus("Dump: cannot read headers"); return; }
    auto u16 = [&](size_t o) -> uint16_t { uint16_t v = 0; if (o + 2 <= h1.size()) memcpy(&v, h1.data() + o, 2); return v; };
    auto u32 = [&](size_t o) -> uint32_t { uint32_t v = 0; if (o + 4 <= h1.size()) memcpy(&v, h1.data() + o, 4); return v; };
    if (u16(0) != 0x5A4D) { setStatus("Dump: bad MZ"); return; }
    uint32_t lf = u32(0x3C);
    if (!lf || lf > 0x10000) { setStatus("Dump: bad e_lfanew"); return; }
    uint32_t need = lf + 4 + 20 + 240 + 96 * 40 + 16;
    std::vector<BYTE> hdr;
    if (need <= h1.size()) hdr.assign(h1.begin(), h1.end());
    else { hdr.resize(need); if (dump_read_best(base, hdr.data(), need) != need) { setStatus("Dump: header read failed"); return; } }
    auto h32 = [&](size_t o) -> uint32_t { uint32_t v = 0; if (o + 4 <= hdr.size()) memcpy(&v, hdr.data() + o, 4); return v; };
    if (h32(lf) != 0x00004550) { setStatus("Dump: bad PE sig"); return; }
    size_t fh = (size_t)lf + 4;
    uint16_t nSec = 0, optSz = 0;
    memcpy(&nSec, hdr.data() + fh + 2, 2); memcpy(&optSz, hdr.data() + fh + 16, 2);
    if (!nSec || nSec > 96) { setStatus("Dump: bad section count"); return; }
    size_t oh = fh + 20;
    if (oh + 64 > hdr.size()) { setStatus("Dump: truncated headers"); return; }
    uint16_t magic = 0; memcpy(&magic, hdr.data() + oh, 2);
    if (magic != 0x10B && magic != 0x20B) { setStatus("Dump: bad optional magic"); return; }
    uint32_t sizeHdr = 0, fileAlign = 0, sizeImg = 0;
    memcpy(&sizeHdr, hdr.data() + oh + 60, 4);
    memcpy(&fileAlign, hdr.data() + oh + 36, 4);
    memcpy(&sizeImg, hdr.data() + oh + 56, 4);
    if (!fileAlign || (fileAlign & (fileAlign - 1))) fileAlign = 0x200;
    if (!sizeHdr || sizeHdr > 0x100000 || !sizeImg || sizeImg > 0x80000000) { setStatus("Dump: insane sizes"); return; }
    std::vector<BYTE> fhdr(sizeHdr);
    if (dump_read_best(base, fhdr.data(), sizeHdr) != sizeHdr) { setStatus("Dump: header read failed"); return; }
    size_t secTab = oh + optSz;
    struct DumpSec { uint32_t vs = 0, va = 0; std::vector<BYTE> data; };
    std::vector<DumpSec> secs;
    auto align = [](uint32_t v, uint32_t a) -> uint32_t { return (v + a - 1) & ~(a - 1); };
    for (int i = 0; i < nSec; i++) {
        size_t e = secTab + (size_t)i * 40;
        if (e + 40 > fhdr.size()) { setStatus("Dump: section table OOB"); return; }
        DumpSec s{};
        memcpy(&s.vs, fhdr.data() + e + 8, 4);
        memcpy(&s.va, fhdr.data() + e + 12, 4);
        uint32_t memSz = s.vs;
        if (!memSz) memcpy(&memSz, fhdr.data() + e + 16, 4);
        if (s.va >= sizeImg) memSz = 0;
        else if ((uint64_t)s.va + memSz > sizeImg) memSz = sizeImg - s.va;
        if (memSz > 0x10000000) memSz = 0x10000000;
        if (memSz) {
            std::vector<BYTE> raw(memSz);
            dump_read_best(base + s.va, raw.data(), memSz);
            size_t keep = memSz;
            if (memSz > 100) { // KsDumper-style trim: last nonzero + 4
                size_t last = 0; bool any = false;
                for (size_t k = 0; k < memSz; k++) if (raw[k]) { last = k; any = true; }
                keep = !any ? 0 : (std::min<size_t>)(memSz, last + 4);
            }
            raw.resize(keep);
            s.data.swap(raw);
        }
        secs.push_back(std::move(s));
    }
    // KsDumper parity (FixPEHeader/AlignSectionHeaders): bound-import + IAT dirs
    // zeroed (IAT section marked R+W), extra dirs zeroed, VA/VS aligned to
    // SectionAlignment, SizeOfImage + SizeOfHeaders recomputed.
    uint32_t sectAlign = 0;
    memcpy(&sectAlign, fhdr.data() + oh + 32, 4);
    if (!sectAlign || (sectAlign & (sectAlign - 1))) sectAlign = 0x1000;
    bool is64 = (magic == 0x20B);
    uint32_t optSize = is64 ? 240 : 224;
    size_t rvaCountOff = oh + (is64 ? 108 : 92);
    size_t dirBase = oh + (is64 ? 112 : 96);
    if (dirBase + 16 * 8 > fhdr.size()) { setStatus("Dump: dirs OOB"); return; }
    uint32_t numRva = 0;
    memcpy(&numRva, fhdr.data() + rvaCountOff, 4);
    if (numRva > 16) numRva = 16;
    uint32_t iatVA = 0;
    if (numRva > 12) memcpy(&iatVA, fhdr.data() + dirBase + 12 * 8, 4);
    for (uint32_t i = 0; i < 16; i++) {
        if (i == 11 || i == 12 || i >= numRva) {
            uint64_t zero = 0;
            memcpy(fhdr.data() + dirBase + i * 8, &zero, 8);
        }
    }
    uint32_t n16 = 16;
    memcpy(fhdr.data() + rvaCountOff, &n16, 4);
    uint16_t osz = (uint16_t)optSize;
    memcpy(fhdr.data() + fh + 16, &osz, 2);
    if (iatVA) {
        for (size_t i = 0; i < secs.size(); i++) {
            size_t e = secTab + i * 40;
            uint32_t c = 0;
            memcpy(&c, fhdr.data() + e + 36, 4);
            uint32_t vs = secs[i].vs ? secs[i].vs : (uint32_t)secs[i].data.size();
            if (secs[i].va <= iatVA && iatVA < secs[i].va + (vs ? vs : 1)) {
                c |= 0x40000000 | 0x80000000;
                memcpy(fhdr.data() + e + 36, &c, 4);
            }
        }
    }
    uint32_t maxEnd = 0;
    for (size_t i = 0; i < secs.size(); i++) {
        size_t e = secTab + i * 40;
        uint32_t va = align(secs[i].va, sectAlign);
        uint32_t vs = align(secs[i].vs ? secs[i].vs : (uint32_t)secs[i].data.size(), sectAlign);
        memcpy(fhdr.data() + e + 8, &vs, 4);
        memcpy(fhdr.data() + e + 12, &va, 4);
        secs[i].va = va; secs[i].vs = vs;
        if (va + vs > maxEnd) maxEnd = va + vs;
    }
    uint32_t newImg = align(maxEnd, sectAlign);
    memcpy(fhdr.data() + oh + 56, &newImg, 4);
    uint32_t newHdr = align((uint32_t)((uint32_t)lf + 4 + 20 + optSize + (uint32_t)nSec * 40), fileAlign);
    memcpy(fhdr.data() + oh + 60, &newHdr, 4);
    sizeHdr = newHdr;
    uint32_t fileHdrSz = align(sizeHdr, fileAlign);
    std::vector<BYTE> file;
    file.insert(file.end(), fhdr.begin(), fhdr.end());
    file.resize(fileHdrSz, 0);
    for (size_t i = 0; i < secs.size(); i++) {
        size_t e = secTab + i * 40;
        uint32_t rawPtr = (uint32_t)file.size();
        uint32_t rawSz = align((uint32_t)secs[i].data.size(), fileAlign);
        if (secs[i].data.empty()) { rawPtr = fileHdrSz; rawSz = 0; }
        memcpy(file.data() + e + 16, &rawSz, 4);
        memcpy(file.data() + e + 20, &rawPtr, 4);
        file.insert(file.end(), secs[i].data.begin(), secs[i].data.end());
        file.resize(file.size() + (rawSz - (uint32_t)secs[i].data.size()), 0);
    }
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { setStatus("Dump: cannot create file"); return; }
    DWORD wr = 0;
    BOOL ok = WriteFile(hf, file.data(), (DWORD)file.size(), &wr, nullptr);
    CloseHandle(hf);
    if (!ok || wr != file.size()) { setStatus("Dump: write failed"); return; }
    char s[256]; snprintf(s, sizeof(s), "Dumped %s (%u sections, %.1f MB) -> %s", m.name.c_str(), nSec, file.size() / 1048576.0, path);
    setStatus(s);
}

//=================================================================
//  WndProcs
//=================================================================
static LRESULT CALLBACK ManualProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_COMMAND) {
        int id = LOWORD(w), code = HIWORD(w);
        LONG_PTR mode0 = GetWindowLongPtrA(h, GWLP_USERDATA);
        if (mode0 == 1 && id == PL_REFRESH) {
            HWND lv = GetDlgItem(h, PL_LIST);
            if (lv) FillProcList(lv);
            return 0;
        }
        if (mode0 == 0) {
            // live preview triggers (manual-add dialog)
            bool offEdit = (id >= DLG_OFF0 && id <= DLG_OFF4);
            if (((id == DLG_ADDR_EDIT || offEdit) && code == EN_CHANGE) ||
                (id == DLG_TYPE_CB && code == CBN_SELCHANGE) ||
                ((id == DLG_HEX_CHK || id == DLG_SIGNED_CHK) && code == BN_CLICKED)) {
                updateManualPreview(h);
                return 0;
            }
            if (id == DLG_PTR_CHK && code == BN_CLICKED) {
                layoutManualDlg(h);
                updateManualPreview(h);
                return 0;
            }
            if (id == DLG_ADD_OFF) {
                if (g_dlgNOff < PTR_MAX) g_dlgNOff++;
                layoutManualDlg(h);
                updateManualPreview(h);
                return 0;
            }
            if (id == DLG_REM_OFF) {
                if (g_dlgNOff > 1) g_dlgNOff--;
                layoutManualDlg(h);
                updateManualPreview(h);
                return 0;
            }
        }
        if (mode0 == 8 && id == PSR_VALID && code == BN_CLICKED) {
            // valid-only ticked => address box irrelevant: disable it
            bool on = SendMessageA(GetDlgItem(h, PSR_VALID), BM_GETCHECK, 0, 0) == BST_CHECKED;
            EnableWindow(GetDlgItem(h, PSR_ADDR), on ? FALSE : TRUE);
            return 0;
        }
        if (mode0 == 11 && id == DLG_BROWSE) {
            char path[MAX_PATH]{};
            OPENFILENAMEA of{};
            of.lStructSize = sizeof(of);
            of.hwndOwner = h;
            of.lpstrFilter = "DLL (*.dll)\0*.dll\0All files (*.*)\0*.*\0";
            of.lpstrDefExt = "dll";
            of.lpstrFile = path;
            of.nMaxFile = MAX_PATH;
            of.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameA(&of)) SetDlgItemTextA(h, DLG_ADDR_EDIT, path);
            return 0;
        }
        if (id == DLG_CANCEL_BTN) { DestroyWindow(h); return 0; }
        if (id == DLG_OK_BTN) {
            LONG_PTR mode = mode0;
            if (mode == 1) {
                // process list dialog: selection wins, else manual text
                ProcOkFromDialog(h);
                return 0;
            }
            if (mode == 3) {
                // Change Value popup
                TblEntry e; bool got = false;
                {
                    std::lock_guard<std::mutex> lk(g_tableMtx);
                    if (g_editRow >= 0 && (size_t)g_editRow < g_table.size()) { e = g_table[(size_t)g_editRow]; got = true; }
                }
                if (!got) { DestroyWindow(h); return 0; }
                std::string t = dlgText(h, DLG_VAL_EDIT);
                BYTE nb[32]{};
                if (!parse_entry_value(e, t.c_str(), e.hexDisp, nb)) { SetFocus(GetDlgItem(h, DLG_VAL_EDIT)); return 0; }
                UINT64 f = e.addr;
                if (!g_drv || !g_attached || !entry_final(e, f)) { setStatus("Attach first"); DestroyWindow(h); return 0; }
                if (!g_drv->write_bytes(f, nb, e.len)) { setStatus("Write FAILED"); DestroyWindow(h); return 0; }
                BYTE rb[32]{};
                g_drv->read_raw(f, rb, e.len);
                if (memcmp(rb, nb, e.len) != 0) setStatus("Write verify FAILED");
                else {
                    std::lock_guard<std::mutex> lk(g_tableMtx);
                    if ((size_t)g_editRow < g_table.size()) memcpy(g_table[(size_t)g_editRow].bytes, nb, e.len);
                    char s[128]; snprintf(s, sizeof(s), "Changed to %s", t.c_str());
                    setStatus(s);
                }
                g_editRow = -1;
                refresh_table();
                DestroyWindow(h);
                return 0;
            }
            if (mode == 4) {
                // Type popup
                int vt = (int)SendMessageA(GetDlgItem(h, DLG_TYPE_CB), CB_GETCURSEL, 0, 0);
                if (vt < 0) vt = 2;
                int realVt = (vt == 4) ? V_F32 : (vt == 5) ? V_F64 : (vt == 6) ? V_STR : (vt == 7) ? V_AOB : (vt == 0) ? V_U8 : (vt == 1) ? V_U16 : (vt == 2) ? V_U32 : V_U64;
                bool hx = SendMessageA(GetDlgItem(h, DLG_HEX_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
                bool sg = SendMessageA(GetDlgItem(h, DLG_SIGNED_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
                {
                    std::lock_guard<std::mutex> lk(g_tableMtx);
                    if (g_editRow >= 0 && (size_t)g_editRow < g_table.size()) {
                        auto& te = g_table[(size_t)g_editRow];
                        te.vtype = realVt; te.len = dlgTypeLen(realVt);
                        te.hexDisp = hx; te.isSigned = sg;
                        UINT64 f = te.addr;
                        if (g_drv && g_attached && entry_final(te, f))
                            g_drv->read_raw(f, te.bytes, te.len);
                    }
                }
                g_editRow = -1;
                refresh_table();
                setStatus("Type changed");
                DestroyWindow(h);
                return 0;
            }
            if (mode == 6) {
                // Settings popup
                g_showModAddr = SendMessageA(GetDlgItem(h, SET_MODCHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
                g_editRow = -1;
                refresh_found();
                refresh_table();
                setStatus(g_showModAddr ? "Module addresses ON" : "Module addresses OFF");
                DestroyWindow(h);
                return 0;
            }
            if (mode == 7) {
                // Pointerscan options -> checkpoint save dialog -> scan
                UINT64 t = strtoull(dlgText(h, PSO_ADDR).c_str(), nullptr, 16);
                int diff = atoi(dlgText(h, PSO_DIFF).c_str());
                int thr = atoi(dlgText(h, PSO_THR).c_str());
                int moff = atoi(dlgText(h, PSO_MAXOFF).c_str());
                int lvl = atoi(dlgText(h, PSO_LVL).c_str());
                if (!t) { SetFocus(GetDlgItem(h, PSO_ADDR)); return 0; }
                if (diff < 1) diff = 1; if (diff > 20) diff = 20;
                if (thr < 1) thr = 1; if (thr > 16) thr = 16;
                if (moff < 8) moff = 8; if (moff > 0x100000) moff = 0x100000;
                if (lvl < 1) lvl = 1; if (lvl > PTR_MAX) lvl = PTR_MAX;
                if (!g_drv || !g_attached) { setStatus("Attach first"); DestroyWindow(h); return 0; }
                char path[MAX_PATH]{};
                snprintf(path, sizeof(path), "pointers");
                // ask where to store results (CE checkpoint), then scan
                OPENFILENAMEA of{};
                of.lStructSize = sizeof(of);
                of.hwndOwner = h;
                of.lpstrFilter = "Legend Pointerlist (*.lps)\0*.lps\0All files (*.*)\0*.*\0";
                of.lpstrDefExt = "lps";
                of.lpstrFile = path;
                of.nMaxFile = MAX_PATH;
                of.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
                if (!GetSaveFileNameA(&of)) return 0; // user cancelled: stay, no scan
                UINT64 tt = t; int vt = g_ps.vtype; ULONG vl = g_ps.vlen;
                std::string sp = path;
                DestroyWindow(h);
                RefreshMods(g_pid);
                std::thread(PSScanThread, tt, vt, vl, lvl, moff, diff, thr, sp).detach();
                return 0;
            }
            if (mode == 8) {
                // Pointer rescan: new-target filter, or valid-only when checkbox ticked
                bool validOnly = SendMessageA(GetDlgItem(h, PSR_VALID), BM_GETCHECK, 0, 0) == BST_CHECKED;
                std::string t = dlgText(h, PSR_ADDR);
                DestroyWindow(h);
                if (validOnly) PS_DoRescanValid();
                else PS_DoRescan(t);
                return 0;
            }
            if (mode == 9) {
                // Single-line assembler: assemble + verified write + refresh views
                std::string t = dlgText(h, DLG_VAL_EDIT);
                BYTE enc[16]{}; char aerr[128]{};
                int n = AssembleLine(t.c_str(), g_asmAddr, enc, aerr, sizeof(aerr));
                if (n <= 0) { setStatus(aerr); SetFocus(GetDlgItem(h, DLG_VAL_EDIT)); return 0; }
                if (!g_drv || !g_attached) { setStatus("Attach first"); DestroyWindow(h); return 0; }
                if (!g_drv->write_bytes(g_asmAddr, enc, (SIZE_T)n)) { setStatus("Assemble write FAILED"); DestroyWindow(h); return 0; }
                BYTE rb[16]{};
                g_drv->read_raw(g_asmAddr, rb, (SIZE_T)n);
                if (memcmp(rb, enc, (SIZE_T)n) != 0) setStatus("Assemble verify FAILED");
                else {
                    char s[128]; snprintf(s, sizeof(s), "Assembled %d byte(s) at %llX", n, (unsigned long long)g_asmAddr);
                    setStatus(s);
                }
                DestroyWindow(h);
                if (g_mv) { doMemDump(); doMemDisasm(); }
                refresh_table();
                return 0;
            }
            if (mode == 10) {
                // Dump picker: module combo -> save dialog -> KsDumper-style dump
                int sel = (int)SendMessageA(GetDlgItem(h, DLG_TYPE_CB), CB_GETCURSEL, 0, 0);
                if (sel < 0 || (size_t)sel >= g_dumpMods.size()) { setStatus("Pick a module"); return 0; }
                ModInfo m = g_dumpMods[(size_t)sel];
                DestroyWindow(h);
                char path[MAX_PATH]{};
                snprintf(path, sizeof(path), "%s", m.name.c_str());
                OPENFILENAMEA of{};
                of.lStructSize = sizeof(of);
                of.hwndOwner = g_hwnd;
                of.lpstrFilter = "Executable (*.exe;*.dll)\0*.exe;*.dll\0Dump file (*.dmp)\0*.dmp\0All files (*.*)\0*.*\0";
                of.nFilterIndex = 1;
                of.lpstrFile = path;
                of.nMaxFile = MAX_PATH;
                of.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
                if (!GetSaveFileNameA(&of)) return 0;
                doDumpModule(m, path);
                return 0;
            }
            if (mode == 11) {
                // Inject picker: validate DLL -> kernel inject on a worker thread
                std::string t = dlgText(h, DLG_ADDR_EDIT);
                if (t.empty() || GetFileAttributesA(t.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    setStatus("DLL not found"); SetFocus(GetDlgItem(h, DLG_ADDR_EDIT)); return 0;
                }
                DestroyWindow(h);
                std::thread(InjectThread, t).detach();
                return 0;
            }
            if (mode == 5) {
                // Change Description popup
                std::string d = dlgText(h, DLG_DESC_EDIT);
                {
                    std::lock_guard<std::mutex> lk(g_tableMtx);
                    if (g_editRow >= 0 && (size_t)g_editRow < g_table.size())
                        snprintf(g_table[(size_t)g_editRow].desc, sizeof(g_table[(size_t)g_editRow].desc), "%s", d.empty() ? "No description" : d.c_str());
                }
                g_editRow = -1;
                refresh_table();
                DestroyWindow(h);
                return 0;
            }
            std::string d = dlgText(h, DLG_DESC_EDIT);
            std::string mod; UINT64 absBase = 0, modOff = 0; bool isMod = false;
            if (!parse_addr_expr(dlgText(h, DLG_ADDR_EDIT).c_str(), mod, absBase, modOff, isMod)) { SetDlgItemTextA(h, DLG_PREVIEW, "bad address"); return 0; }
            if (!isMod && !absBase) { SetDlgItemTextA(h, DLG_PREVIEW, "bad address"); return 0; }
            int realVt = dlgRealVtype(h);
            ULONG len = dlgTypeLen(realVt);
            bool isHex = SendMessageA(GetDlgItem(h, DLG_HEX_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
            bool isSgn = SendMessageA(GetDlgItem(h, DLG_SIGNED_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
            bool isPtr = SendMessageA(GetDlgItem(h, DLG_PTR_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
            UINT64 offs[PTR_MAX]{}; int nOff = 0;
            if (isPtr) {
                nOff = (std::min)(g_dlgNOff, PTR_MAX);
                if (nOff < 1) nOff = 1;
                for (int i = 0; i < nOff; i++)
                    offs[i] = strtoull(dlgText(h, dlgOffId(i)).c_str(), nullptr, 16);
            }
            TblEntry e{};
            bool keepActive = false;
            {
                // in-place Address edit: preserve Active tick
                std::lock_guard<std::mutex> lk(g_tableMtx);
                if (g_editReplace && g_editRow >= 0 && (size_t)g_editRow < g_table.size())
                    keepActive = g_table[(size_t)g_editRow].active;
            }
            e.active = keepActive;
            snprintf(e.desc, sizeof(e.desc), "%s", d.empty() ? "No description" : d.c_str());
            if (isMod) {
                // static address: rebase-safe via module
                UINT64 mb = mod_base(mod.c_str());
                if (!mb) { SetDlgItemTextA(h, DLG_PREVIEW, "module? (attach?)"); return 0; }
                snprintf(e.mod, sizeof(e.mod), "%s", mod.c_str());
                e.modOff = modOff; e.addr = mb + modOff;
            }
            else e.addr = absBase;
            e.vtype = realVt; e.len = len;
            e.isSigned = isSgn; e.isPtr = isPtr; e.nOff = nOff;
            for (int i = 0; i < nOff; i++) e.ptrOffs[i] = offs[i];
            (void)isHex;
            UINT64 f = e.addr;
            if (g_drv && g_attached && entry_final(e, f))
                g_drv->read_raw(f, e.bytes, e.len);
            char s[200], bs[96]; entry_base_str(e, bs, sizeof(bs));
            {
                std::lock_guard<std::mutex> lk(g_tableMtx);
                if (g_editReplace && g_editRow >= 0 && (size_t)g_editRow < g_table.size()) {
                    g_table[(size_t)g_editRow] = e;
                    snprintf(s, sizeof(s), "Changed %s%s (%s)", isPtr ? "P->" : "", bs, vtypeName(realVt));
                }
                else {
                    g_table.push_back(e);
                    snprintf(s, sizeof(s), "Added %s%s (%s)", isPtr ? "P->" : "", bs, vtypeName(realVt));
                }
            }
            g_editReplace = false;
            g_editRow = -1;
            refresh_table();
            setStatus(s);
            DestroyWindow(h);
            return 0;
        }
    }
    else if (m == WM_NOTIFY) {
        LPNMHDR nh = (LPNMHDR)l;
        if (nh->idFrom == (UINT_PTR)PL_LIST && nh->code == NM_DBLCLK) {
            ProcOkFromDialog(h);
            return 0;
        }
    }
    else if (m == WM_DESTROY) {
        if (h == g_dlg) {
            g_dlg = nullptr; g_dlgTypeCb = nullptr;
            g_editReplace = false; g_editRow = -1; // Cancel/X: drop pending edit, keep table
        }
        return 0;
    }
    return DefWindowProcA(h, m, w, l);
}
static LRESULT CALLBACK MemProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_COMMAND) {
        int id = LOWORD(w);
        if (id == MV_DUMP_BTN) doMemDump();
        else if (id == MV_WRITE_BTN) doMemWrite();
        else if (id == MV_DIS_BTN) { doMemDump(); doMemDisasm(); }
        return 0;
    }
    else if (m == WM_NOTIFY) {
        LPNMHDR nh = (LPNMHDR)l;
        if (nh->idFrom == (UINT_PTR)MV_DIS_LIST && nh->code == NM_DBLCLK) {
            LPNMITEMACTIVATE ia = (LPNMITEMACTIVATE)l;
            int sel = ia->iItem;
            if (sel < 0) sel = ListView_GetNextItem(nh->hwndFrom, -1, LVNI_SELECTED);
            if (sel >= 0 && (size_t)sel < g_disAddr.size())
                OpenAsmDialog(g_disAddr[(size_t)sel], g_disText[(size_t)sel].c_str());
            return 0;
        }
    }
    else if (m == WM_GETMINMAXINFO) {
        LPMINMAXINFO mm = (LPMINMAXINFO)l;
        mm->ptMinTrackSize.x = 500; mm->ptMinTrackSize.y = 380;
        return 0;
    }
    else if (m == WM_SIZE) {
        int cw = LOWORD(l), ch = HIWORD(l);
        HWND lv = GetDlgItem(h, MV_DIS_LIST), hx = GetDlgItem(h, MV_HEX_EDIT);
        int disH = (std::max)(120, (ch - 56) * 42 / 100);
        if (lv) SetWindowPos(lv, nullptr, 12, 44, (std::max)(cw - 24, 200), disH, SWP_NOZORDER);
        if (hx) SetWindowPos(hx, nullptr, 12, 50 + disH, (std::max)(cw - 24, 200), (std::max)(ch - 62 - disH, 80), SWP_NOZORDER);
        return 0;
    }
    else if (m == WM_CLOSE) { DestroyWindow(h); return 0; }
    else if (m == WM_DESTROY) { if (h == g_mv) g_mv = nullptr; return 0; }
    return DefWindowProcA(h, m, w, l);
}

//=================================================================
//  Legend Table (.ltb) — CE Cheat Table equivalent, tiny XML
//=================================================================
static std::string xml_esc(const char* s) {
    std::string o;
    for (const char* p = s; *p; p++) {
        if (*p == '&') o += "&amp;";
        else if (*p == '<') o += "&lt;";
        else if (*p == '>') o += "&gt;";
        else if (*p == '"') o += "&quot;";
        else o += *p;
    }
    return o;
}
static std::string xml_unesc(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '&') {
            if (!s.compare(i, 5, "&amp;")) { o += '&'; i += 4; }
            else if (!s.compare(i, 4, "&lt;")) { o += '<'; i += 3; }
            else if (!s.compare(i, 4, "&gt;")) { o += '>'; i += 3; }
            else if (!s.compare(i, 6, "&quot;")) { o += '"'; i += 5; }
            else o += s[i];
        }
        else o += s[i];
    }
    return o;
}
static std::string getAttr(const std::string& tag, const char* name) {
    std::string k = std::string(name) + "=\"";
    size_t p = tag.find(k);
    if (p == std::string::npos) return "";
    p += k.size();
    size_t q = tag.find('"', p);
    if (q == std::string::npos) return "";
    return tag.substr(p, q - p);
}
static void SaveTableTo(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) { setStatus("Save failed"); return; }
    fprintf(f, "<LegendTable version=\"2\">\n");
    std::lock_guard<std::mutex> lk(g_tableMtx);
    for (auto& e : g_table) {
        char hex[65]{};
        for (ULONG i = 0; i < e.len && i < 32; i++) snprintf(hex + i * 2, 3, "%02X", e.bytes[i]);
        char offs[96]{};
        for (int i = 0; i < e.nOff && i < PTR_MAX; i++)
            snprintf(offs + strlen(offs), sizeof(offs) - strlen(offs), "%s%llX", i ? "," : "", (unsigned long long)e.ptrOffs[i]);
        fprintf(f, "<Entry active=\"%d\" desc=\"%s\" addr=\"%llX\" mod=\"%s\" moff=\"%llX\" type=\"%d\" len=\"%lu\" signed=\"%d\" hex=\"%d\" ptr=\"%d\" offs=\"%s\" bytes=\"%s\"/>\n",
            e.active ? 1 : 0, xml_esc(e.desc).c_str(), (unsigned long long)e.addr,
            xml_esc(e.mod).c_str(), (unsigned long long)e.modOff,
            e.vtype, e.len, e.isSigned ? 1 : 0, e.hexDisp ? 1 : 0,
            e.isPtr ? 1 : 0, offs, hex);
    }
    fprintf(f, "</LegendTable>\n");
    fclose(f);
    char s[160]; snprintf(s, sizeof(s), "Saved %zu entries", g_table.size());
    setStatus(s);
}
static bool LoadTableFrom(const char* path) {
    FILE* f = nullptr;
    fopen_s(&f, path, "rb");
    if (!f) { setStatus("Open failed"); return false; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 10000000) { fclose(f); setStatus("Bad table file"); return false; }
    std::string data((size_t)sz, 0);
    if (fread(&data[0], 1, (size_t)sz, f) != (size_t)sz) { fclose(f); setStatus("Read failed"); return false; }
    fclose(f);
    std::vector<TblEntry> tmp;
    size_t p = 0;
    while ((p = data.find("<Entry", p)) != std::string::npos) {
        size_t q = data.find("/>", p);
        if (q == std::string::npos) break;
        std::string tag = data.substr(p, q - p);
        p = q + 2;
        TblEntry e{};
        e.active = (getAttr(tag, "active") == "1");
        std::string d = xml_unesc(getAttr(tag, "desc"));
        snprintf(e.desc, sizeof(e.desc), "%s", d.empty() ? "No description" : d.c_str());
        e.addr = strtoull(getAttr(tag, "addr").c_str(), nullptr, 16);
        std::string lm = xml_unesc(getAttr(tag, "mod"));
        snprintf(e.mod, sizeof(e.mod), "%s", lm.c_str());
        e.modOff = strtoull(getAttr(tag, "moff").c_str(), nullptr, 16);
        e.vtype = atoi(getAttr(tag, "type").c_str());
        if (e.vtype < 0 || e.vtype > 7) e.vtype = V_U32;
        e.len = (ULONG)atoi(getAttr(tag, "len").c_str());
        if (!e.len || e.len > 32) e.len = (ULONG)dlgTypeLen(e.vtype);
        e.isSigned = (getAttr(tag, "signed") == "1");
        e.hexDisp = (getAttr(tag, "hex") == "1");
        e.isPtr = (getAttr(tag, "ptr") == "1");
        e.nOff = 0;
        std::string lo = getAttr(tag, "offs");
        if (!lo.empty()) {
            // comma-separated hex offsets (v2)
            size_t s = 0;
            while (s < lo.size() && e.nOff < PTR_MAX) {
                size_t c = lo.find(',', s);
                std::string one = (c == std::string::npos) ? lo.substr(s) : lo.substr(s, c - s);
                e.ptrOffs[e.nOff++] = strtoull(one.c_str(), nullptr, 16);
                if (c == std::string::npos) break;
                s = c + 1;
            }
        }
        else if (e.isPtr) {
            // v1 back-compat: single off meant *(base)+off == chain [0, off]
            UINT64 old = strtoull(getAttr(tag, "off").c_str(), nullptr, 16);
            e.ptrOffs[0] = 0; e.ptrOffs[1] = old; e.nOff = 2;
        }
        std::string hb = getAttr(tag, "bytes");
        for (ULONG i = 0; i < e.len && i * 2 + 1 < hb.size(); i++) {
            BYTE hi, lo;
            if (hexNib(hb[i * 2], hi) && hexNib(hb[i * 2 + 1], lo))
                e.bytes[i] = (BYTE)((hi << 4) | lo);
        }
        tmp.push_back(e);
        if (tmp.size() > 5000) break;
    }
    {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        g_table.swap(tmp);
    }
    // live bytes when attached
    if (g_drv && g_attached) {
        std::lock_guard<std::mutex> lk(g_tableMtx);
        for (auto& e : g_table) {
            UINT64 fa = e.addr;
            if (entry_final(e, fa))
                g_drv->read_raw(fa, e.bytes, e.len);
        }
    }
    refresh_table();
    char s[160]; snprintf(s, sizeof(s), "Loaded %zu entries", g_table.size());
    setStatus(s);
    return true;
}
static bool TableFileDlg(bool save, char* out, int outSz) {
    OPENFILENAMEA of{};
    of.lStructSize = sizeof(of);
    of.hwndOwner = g_hwnd;
    of.lpstrFilter = "Legend Table (*.ltb)\0*.ltb\0All files (*.*)\0*.*\0";
    of.lpstrDefExt = "ltb";
    of.nFilterIndex = 1;
    of.lpstrFile = out;
    of.nMaxFile = (DWORD)outSz;
    of.Flags = save ? (OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST) : (OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST);
    return save ? (GetSaveFileNameA(&of) == TRUE) : (GetOpenFileNameA(&of) == TRUE);
}

static HMENU BuildMenu() {
    HMENU bar = CreateMenu();
    HMENU f = CreatePopupMenu();
    AppendMenuA(f, MF_STRING, 9009, "New Table");
    AppendMenuA(f, MF_STRING, 9010, "Open Table...");
    AppendMenuA(f, MF_STRING, 9011, "Save Table...");
    AppendMenuA(f, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(f, MF_STRING, 9001, "Exit");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)f, "File");
    HMENU p = CreatePopupMenu();
    AppendMenuA(p, MF_STRING, 9002, "Select Process...");
    AppendMenuA(p, MF_STRING, 9003, "Reload Driver");
    AppendMenuA(p, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(p, MF_STRING, 9015, "Dump Process...");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)p, "Process");
    HMENU s = CreatePopupMenu();
    AppendMenuA(s, MF_STRING, 9004, "First Scan");
    AppendMenuA(s, MF_STRING, 9005, "Next Scan");
    AppendMenuA(s, MF_STRING, 9006, "Undo Scan");
    AppendMenuA(s, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(s, MF_STRING, 9013, "Pointer Scan...");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)s, "Scan");
    HMENU v = CreatePopupMenu();
    AppendMenuA(v, MF_STRING, 9007, "Memory View");
    AppendMenuA(v, MF_STRING, 9014, "Pointer Scan");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)v, "View");
    HMENU t = CreatePopupMenu();
    AppendMenuA(t, MF_STRING, 9016, "Inject DLL...\tCtrl+I");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)t, "Tools");
    AppendMenuA(bar, MF_STRING, 9012, "Settings");
    HMENU h = CreatePopupMenu();
    AppendMenuA(h, MF_STRING, 9008, "About");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)h, "Help");
    return bar;
}

static void start_first() {
    if (g_scanning) return;
    g_vtype = (int)SendMessageA(ctl(IDC_VTYPE_CB), CB_GETCURSEL, 0, 0);
    g_stype = (int)SendMessageA(ctl(IDC_STYPE_CB), CB_GETCURSEL, 0, 0);
    if (g_vtype < 0) g_vtype = 2;
    if (g_stype < 0) g_stype = 0;
    g_hexMode = SendMessageA(ctl(IDC_HEX_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::string s1 = getText(IDC_VAL_EDIT), s2 = getText(IDC_VAL_EDIT);
    // Between uses Start/Stop? No — CE Value Between uses single box "a:b"? Use VAL + START box as second? Keep: VAL box + STOP box? CE has one Value box; Between reads "low high" split by space. Support that:
    if (g_stype == S_BETWEEN) {
        // split value box on space/colon/comma
        std::string a = s1, b;
        size_t p = a.find_first_of(" :,;");
        if (p != std::string::npos) { b = a.substr(p + 1); a = a.substr(0, p); }
        else b = getText(IDC_STOP_EDIT); // fallback combobox misuse guard
        s1 = a; s2 = b;
        if (s2.empty()) { setStatus("Between needs two values (ex: 100 200)"); return; }
    }
    // map CE combo index directly (same order as our enums)
    if (g_attached && g_pid) RefreshMods(g_pid); // keep module list fresh, selection kept
    ScanOpts o = curOpts();
    // default alignment = type size when Fast Scan on and user left 4
    std::thread(FirstScanThread, s1, s2, g_vtype, g_stype, g_hexMode, o).detach();
}
static void start_next() {
    if (g_scanning) return;
    g_vtype = (int)SendMessageA(ctl(IDC_VTYPE_CB), CB_GETCURSEL, 0, 0);
    g_stype = (int)SendMessageA(ctl(IDC_STYPE_CB), CB_GETCURSEL, 0, 0);
    if (g_vtype < 0) g_vtype = 2;
    if (g_stype < 0) g_stype = 0;
    g_hexMode = SendMessageA(ctl(IDC_HEX_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::string s1 = getText(IDC_VAL_EDIT), s2 = s1;
    if (g_stype == S_BETWEEN) {
        std::string a = s1, b;
        size_t p = a.find_first_of(" :,;");
        if (p != std::string::npos) { b = a.substr(p + 1); a = a.substr(0, p); }
        else b = "";
        s1 = a; s2 = b;
        if (s2.empty()) { setStatus("Between needs two values (ex: 100 200)"); return; }
    }
    std::thread(NextScanThread, s1, s2, g_vtype, g_stype, g_hexMode).detach();
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        g_hwnd = hwnd;
        SpoofWindowTitle(hwnd); // innocuous caption; target info lives in PROC_LBL
        g_fUI = CreateFontA(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, "Segoe UI");
        SetMenu(hwnd, BuildMenu());
        {
            INITCOMMONCONTROLSEX ic{ sizeof(ic), ICC_LISTVIEW_CLASSES };
            InitCommonControlsEx(&ic);
        }
        BuildUI();
        SetTimer(hwnd, 7, 700, nullptr); // table live refresh
        std::thread(DriverThread).detach();
        std::thread(FreezeThread).detach();
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(wp), code = HIWORD(wp);
        if (id == IDC_PROC_BTN || id == 9002) OpenProcDialog();
        else if (id == 9001) PostMessage(hwnd, WM_CLOSE, 0, 0);
        else if (id == 9009) {
            {
                std::lock_guard<std::mutex> lk(g_tableMtx);
                g_table.clear();
            }
            {
                std::lock_guard<std::mutex> lk(g_candsMtx);
                g_cands.clear(); g_undo.clear();
            }
            refresh_found(); refresh_table();
            SpoofWindowTitle(g_hwnd); // re-roll cover caption
            setStatus("New table");
        }
        else if (id == 9010) {
            char path[MAX_PATH]{};
            if (TableFileDlg(false, path, MAX_PATH)) LoadTableFrom(path);
        }
        else if (id == 9011) {
            char path[MAX_PATH]{};
            if (TableFileDlg(true, path, MAX_PATH)) SaveTableTo(path);
        }
        else if (id == CTX_DEL) TableDeleteSel();
        else if (id == CTX_VAL || id == CTX_TYPE || id == CTX_DESC || id == CTX_ADDR) {
            HWND lv = ctl(IDC_TBL_LIST);
            int sel = lv ? ListView_GetNextItem(lv, -1, LVNI_SELECTED) : -1;
            if (sel < 0) { setStatus("Select a table row first"); }
            else TableAct(sel, id == CTX_VAL ? 4 : id == CTX_TYPE ? 3 : id == CTX_DESC ? 1 : 2);
        }
        else if (id == CTX_ADD) doAddFoundToTableDirect();
        else if (id == CTX_PS) { if (g_ctxFound) PS_ForFoundRow(); else PS_ForTableRow(); }
        else if (id == CTX_COPY_ASIS || id == CTX_COPY_MOD) {
            if (g_ctxFound) FoundCopy(id == CTX_COPY_MOD);
            else TableCopy(id == CTX_COPY_MOD);
        }
        else if (id == CTX_DISM) { if (g_ctxFound) FoundDism(); else TableDism(); }
        else if (id == 9013) PS_ForTableRow();
        else if (id == 9003) { if (!g_connected) std::thread(DriverThread).detach(); }
        else if (id == 9015) OpenDumpDialog();
        else if (id == 9016) OpenInjectDialog();
        else if (id == IDC_FIRST_BTN || id == 9004) start_first();
        else if (id == IDC_NEXT_BTN || id == 9005) start_next();
        else if (id == IDC_UNDO_BTN || id == 9006) {
            std::lock_guard<std::mutex> lk(g_candsMtx);
            if (!g_undo.empty()) { g_cands = g_undo.back(); g_undo.pop_back(); refresh_found(); setStatus("Undo Scan"); }
            else setStatus("Nothing to undo");
        }
        else if (id == IDC_MEMVIEW_BTN || id == 9007) OpenMemView();
        else if (id == 9014) PS_OpenResults(); // View -> Pointer Scan (blank list, can Open .lps)
        else if (id == 9012) OpenSettings();
        else if (id == IDC_ADDADDR_BTN) doAddSelectedToTable();
        else if (id == IDC_VTYPE_CB && code == CBN_SELCHANGE) {
            // code patterns live in executable pages — assist like CE power users do
            int vt = (int)SendMessageA(ctl(IDC_VTYPE_CB), CB_GETCURSEL, 0, 0);
            if (vt == V_AOB) SendMessageA(ctl(IDC_EXEC_CHK), BM_SETCHECK, BST_CHECKED, 0);
        }
        else if (id == IDC_PRESET_CB && code == CBN_SELCHANGE) {
            // CE behavior: picking a module fills Start/Stop with its range
            int sel = (int)SendMessageA(ctl(IDC_PRESET_CB), CB_GETCURSEL, 0, 0);
            char a[32], b[32];
            if (sel > 0 && (size_t)(sel - 1) < g_mods.size()) {
                snprintf(a, sizeof(a), "%llX", (unsigned long long)g_mods[(size_t)sel - 1].base);
                snprintf(b, sizeof(b), "%llX", (unsigned long long)(g_mods[(size_t)sel - 1].base + g_mods[(size_t)sel - 1].size));
            }
            else { snprintf(a, sizeof(a), "0"); snprintf(b, sizeof(b), "7FFFFFFFFFFF"); }
            SetWindowTextA(ctl(IDC_START_EDIT), a);
            SetWindowTextA(ctl(IDC_STOP_EDIT), b);
        }
        else if (id == 9008) MessageBoxA(hwnd, "LegendScan — kernel CE clone\nDriver: amdfend.sys (AMD_CrashDefend)\nBuild tag 00080004", "About", MB_OK);
        return 0;
    }
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
        if (nh->code == NM_CUSTOMDRAW &&
            (nh->idFrom == (UINT_PTR)IDC_FOUND_LIST || nh->idFrom == (UINT_PTR)IDC_TBL_LIST)) {
            // green font for static (module-anchored) addresses, default otherwise
            LPNMLVCUSTOMDRAW cd = (LPNMLVCUSTOMDRAW)lp;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) return CDRF_NOTIFYSUBITEMDRAW;
            if (cd->nmcd.dwDrawStage == (CDDS_SUBITEM | CDDS_ITEMPREPAINT)) {
                if (cd->iSubItem == 0 || (nh->idFrom == (UINT_PTR)IDC_TBL_LIST && cd->iSubItem == 2)) {
                    bool st = false;
                    int row = (int)cd->nmcd.dwItemSpec;
                    if (nh->idFrom == (UINT_PTR)IDC_FOUND_LIST) {
                        std::lock_guard<std::mutex> lk(g_candsMtx);
                        if (row >= 0 && (size_t)row < g_foundStatic.size()) st = g_foundStatic[(size_t)row] != 0;
                    }
                    else {
                        std::lock_guard<std::mutex> lk(g_tableMtx);
                        if (row >= 0 && (size_t)row < g_tblStatic.size()) st = g_tblStatic[(size_t)row] != 0;
                    }
                    if (st) { cd->clrText = RGB(0, 128, 0); return CDRF_NEWFONT; }
                }
            }
            return CDRF_DODEFAULT;
        }
        if (nh->idFrom == (UINT_PTR)IDC_FOUND_LIST && nh->code == NM_DBLCLK) {
            doAddFoundToTableDirect();
            return 0;
        }
        if (nh->idFrom == (UINT_PTR)IDC_TBL_LIST && nh->code == LVN_ITEMCHANGED) {
            if (g_tblRefresh) return 0; // ours, not the user's click
            LPNMLISTVIEW lv = (LPNMLISTVIEW)lp;
            if ((lv->uChanged & LVIF_STATE)) {
                BOOL chk = ListView_GetCheckState(nh->hwndFrom, lv->iItem);
                std::lock_guard<std::mutex> lk(g_tableMtx);
                if (lv->iItem >= 0 && (size_t)lv->iItem < g_table.size())
                    g_table[(size_t)lv->iItem].active = (chk == TRUE);
            }
            return 0;
        }
        if (nh->idFrom == (UINT_PTR)IDC_TBL_LIST && nh->code == NM_DBLCLK) {
            // CE column popups: Value->Change Value, Type->Type, Description->rename, Address->full edit
            // NOTE: never hold g_tableMtx across refresh_table/OpenManualAdd (deadlock: LVN notify re-locks)
            LPNMITEMACTIVATE ia = (LPNMITEMACTIVATE)lp;
            int sel = ia->iItem;
            int col = ia->iSubItem;
            if (sel < 0) sel = ListView_GetNextItem(nh->hwndFrom, -1, LVNI_SELECTED);
            if (sel < 0) return 0;
            TableAct(sel, col);
            return 0;
        }
        if (nh->code == LVN_KEYDOWN) {
            LPNMLVKEYDOWN kd = (LPNMLVKEYDOWN)lp;
            if (kd->wVKey == VK_DELETE && nh->idFrom == (UINT_PTR)IDC_TBL_LIST) {
                TableDeleteSel();
                return 0;
            }
        }
        break;
    }
    case WM_CONTEXTMENU: {
        HWND child = (HWND)wp;
        bool isTbl = (child == ctl(IDC_TBL_LIST));
        bool isFound = (child == ctl(IDC_FOUND_LIST));
        if (!isTbl && !isFound) break;
        int px = GET_X_LPARAM(lp), py = GET_Y_LPARAM(lp);
        if (px == -1 && py == -1) { POINT cp{}; GetCursorPos(&cp); px = cp.x; py = cp.y; }
        POINT cp{ px, py };
        POINT cl = cp; ScreenToClient(child, &cl);
        LVHITTESTINFO ht{}; ht.pt = cl;
        int hit = ListView_HitTest(child, &ht);
        if (hit >= 0) ListView_SetItemState(child, hit, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        HMENU m = CreatePopupMenu();
        HMENU copySub = CreatePopupMenu();
        AppendMenuA(copySub, MF_STRING, CTX_COPY_ASIS, "As it is");
        AppendMenuA(copySub, MF_STRING, CTX_COPY_MOD, "Module+Address");
        g_ctxFound = isFound;
        if (isTbl) {
            AppendMenuA(m, MF_STRING, CTX_DEL, "Delete This Address");
            AppendMenuA(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(m, MF_STRING, CTX_VAL, "Change Value");
            AppendMenuA(m, MF_STRING, CTX_TYPE, "Change Type");
            AppendMenuA(m, MF_STRING, CTX_DESC, "Change Description");
            AppendMenuA(m, MF_STRING, CTX_ADDR, "Change Address...");
            AppendMenuA(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(m, MF_POPUP, (UINT_PTR)copySub, "Copy address");
            AppendMenuA(m, MF_STRING, CTX_DISM, "Go to Dism");
            AppendMenuA(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(m, MF_STRING, CTX_PS, "Pointer Scan for This Address");
        }
        else {
            AppendMenuA(m, MF_STRING, CTX_ADD, "Add to Address List");
            AppendMenuA(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(m, MF_POPUP, (UINT_PTR)copySub, "Copy address");
            AppendMenuA(m, MF_STRING, CTX_DISM, "Go to Dism");
            AppendMenuA(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(m, MF_STRING, CTX_PS, "Pointer Scan for This Address");
        }
        TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, px, py, 0, g_hwnd, nullptr);
        DestroyMenu(m);
        return 0;
    }
    case WM_TIMER:
        if (wp == 7) {
            if (g_drv && g_attached && !g_table.empty()) refresh_table_live();
            if (g_psProg) PS_UpdateProgress();
        }
        return 0;
    case WM_SCAN_DONE: {
        if (wp == 1) { refresh_found(); refresh_table(); setStatus(g_scanMsg); }
        else if (wp == 3) { PS_OpenProgress(); setStatus("Pointer scan running..."); }
        else if (wp == 5) { g_modsPid = 0; if (g_attached && g_pid) RefreshMods(g_pid); refresh_table(); setStatus(g_scanMsg); }
        else if (wp == 4) {
            if (g_psProg) { DestroyWindow(g_psProg); g_psProg = nullptr; }
            PS_OpenResults();
            size_t n = 0;
            { std::lock_guard<std::mutex> lk(g_psResMtx); n = g_psRes.size(); }
            char s[160]; snprintf(s, sizeof(s), "Pointer scan done: %zu paths", n);
            setStatus(s);
        }
        else setStatus(g_scanMsg);
        return 0;
    }
    case WM_CLOSE:
        g_running = false; g_scanning = false; g_freezeRun = false;
        if (g_drv) { delete g_drv; g_drv = nullptr; }
        if (g_fUI) DeleteObject(g_fUI);
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    srand((unsigned)time(nullptr));
    HideThreadFromDebugger();
    PatchDbgBreakPoint();

    // Process masquerade — must run before window creation
    SpoofPEB();                // PEB ImagePath + CmdLine -> Chrome
    CreateChromeMutexes();     // Fake Chrome IPC mutex
    SpoofModuleDescription();  // Patch VERSION_INFO in memory

    GenRandomStr(g_clsMain, sizeof(g_clsMain));
    GenRandomStr(g_clsDlg, sizeof(g_clsDlg));
    GenRandomStr(g_clsMem, sizeof(g_clsMem));
    GenRandomStr(g_clsPSP, sizeof(g_clsPSP));
    GenRandomStr(g_clsPSR, sizeof(g_clsPSR));

    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = g_clsMain;
    RegisterClassExA(&wc);
    WNDCLASSEXA m{};
    m.cbSize = sizeof(m);
    m.lpfnWndProc = ManualProc;
    m.hInstance = hInst;
    m.hCursor = LoadCursor(nullptr, IDC_ARROW);
    m.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    m.lpszClassName = g_clsDlg;
    RegisterClassExA(&m);
    WNDCLASSEXA v{};
    v.cbSize = sizeof(v);
    v.lpfnWndProc = MemProc;
    v.hInstance = hInst;
    v.hCursor = LoadCursor(nullptr, IDC_ARROW);
    v.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    v.lpszClassName = g_clsMem;
    RegisterClassExA(&v);
    WNDCLASSEXA pp{};
    pp.cbSize = sizeof(pp);
    pp.lpfnWndProc = PSProgProc;
    pp.hInstance = hInst;
    pp.hCursor = LoadCursor(nullptr, IDC_ARROW);
    pp.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    pp.lpszClassName = g_clsPSP;
    RegisterClassExA(&pp);
    WNDCLASSEXA pr{};
    pr.cbSize = sizeof(pr);
    pr.lpfnWndProc = PSResProc;
    pr.hInstance = hInst;
    pr.hCursor = LoadCursor(nullptr, IDC_ARROW);
    pr.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    pr.lpszClassName = g_clsPSR;
    RegisterClassExA(&pr);
    HWND w = CreateWindowExA(0, g_clsMain, "Chrome",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        80, 40, 800, 700, nullptr, nullptr, hInst, nullptr);
    ShowWindow(w, SW_SHOW);
    UpdateWindow(w);
    ACCEL acc[1] = { { (BYTE)(FCONTROL | FVIRTKEY), 'I', 9016 } };
    HACCEL hAcc = CreateAcceleratorTable(acc, 1);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (hAcc && TranslateAccelerator(w, hAcc, &msg)) continue;
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    if (hAcc) DestroyAcceleratorTable(hAcc);
    return 0;
}
