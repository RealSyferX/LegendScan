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
    DLG_CHAIN = 1035, DLG_ADD_OFF, DLG_REM_OFF,
    // process list dialog
    PL_LIST = 1010, PL_REFRESH, PL_EDIT,
    // table/found context menu
    CTX_DEL = 9110, CTX_VAL, CTX_TYPE, CTX_DESC, CTX_ADDR, CTX_ADD,
    // mem viewer popup
    MV_X = 1100, MV_ADDR_EDIT, MV_SIZE_EDIT, MV_DUMP_BTN, MV_WRITE_EDIT, MV_WRITE_BTN, MV_HEX_EDIT
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
static bool entry_final(const TblEntry& e, UINT64& out) {
    UINT64 base = e.addr;
    if (e.mod[0]) {
        base = mod_base(e.mod);
        if (!base) return false;
        base += e.modOff;
    }
    if (!e.isPtr || e.nOff <= 0) { out = base; return true; }
    if (!g_drv || !g_attached) return false;
    UINT64 p = base;
    for (int i = 0; i < e.nOff && i < PTR_MAX; i++) {
        UINT64 v = 0;
        g_drv->read_raw(p + e.ptrOffs[i], (BYTE*)&v, 8);
        if (!v) return false;
        p = v;
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
    char a[32], v[128], pv[128];
    size_t show = (std::min<size_t>)(g_cands.size(), 20000);
    for (size_t i = 0; i < show; i++) {
        BYTE cur[32]{};
        if (g_drv && g_attached) g_drv->read_raw(g_cands[i].addr, cur, g_valLen);
        snprintf(a, sizeof(a), "%016llX", (unsigned long long)g_cands[i].addr);
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
    char a[128], v[128];
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
        char bs[96]; entry_base_str(e, bs, sizeof(bs));
        if (e.isPtr) snprintf(a, sizeof(a), "P->%s", bs);
        else snprintf(a, sizeof(a), "%s", bs);
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
    char a[128], v[128];
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
        char bs[96]; entry_base_str(e, bs, sizeof(bs));
        if (e.isPtr) snprintf(a, sizeof(a), "P->%s", bs);
        else snprintf(a, sizeof(a), "%s", bs);
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
    if (ok) snprintf(g_scanMsg, sizeof(g_scanMsg), "First scan done: %zu regions", scanned);
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
        for (int i = 0; ok && i < n; i++) {
            UINT64 v = 0;
            g_drv->read_raw(p + offs[i], (BYTE*)&v, 8);
            char step[64]; snprintf(step, sizeof(step), "\r\n+%llX -> %llX", (unsigned long long)offs[i], (unsigned long long)v);
            chain += step;
            if (!v) ok = false; else p = v;
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
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "LSManualCls", titlePref ? titlePref : "Add address", WS_POPUP | WS_CAPTION | WS_SYSMENU, 300, 200, 300, 300, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
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
// --- CE column popups (modes 3/4/5) ---
static void OpenChangeValue(const TblEntry& e) {
    if (g_dlg) { SetForegroundWindow(g_dlg); return; }
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "LSManualCls", "Change Value", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 330, 150, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
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
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "LSManualCls", "Type", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 300, 200, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
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
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "LSManualCls", "Change Description", WS_POPUP | WS_CAPTION | WS_SYSMENU, 350, 250, 360, 140, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
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
// Memory viewer popup
static void OpenMemView() {
    if (g_mv) { SetForegroundWindow(g_mv); return; }
    g_mv = CreateWindowExA(WS_EX_DLGMODALFRAME, "LSMemCls", "LegendScan - Memory Viewer", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME, 200, 150, 640, 480, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
    HWND p = g_mv;
    auto c = [&](const char* cls, const char* t, DWORD st, int x, int y, int w, int h, int id) {
        HWND h2 = CreateWindowExA(0, cls, t, st | WS_CHILD | WS_VISIBLE, x, y, w, h, p, (HMENU)(INT_PTR)id, GetModuleHandleA(nullptr), nullptr);
        if (g_fUI) SendMessageA(h2, WM_SETFONT, (WPARAM)g_fUI, TRUE);
        return h2;
    };
    c("STATIC", "Address:", SS_LEFT, 12, 12, 60, 20, -1);
    c("EDIT", "0", WS_BORDER | ES_AUTOHSCROLL, 75, 10, 150, 24, MV_ADDR_EDIT);
    c("STATIC", "Size:", SS_LEFT, 235, 12, 35, 20, -1);
    c("EDIT", "256", WS_BORDER | ES_AUTOHSCROLL | ES_NUMBER, 275, 10, 60, 24, MV_SIZE_EDIT);
    c("BUTTON", "Dump", BS_PUSHBUTTON, 345, 9, 70, 26, MV_DUMP_BTN);
    c("EDIT", "90 90 90", WS_BORDER | ES_AUTOHSCROLL, 425, 10, 120, 24, MV_WRITE_EDIT);
    c("BUTTON", "Write", BS_PUSHBUTTON, 550, 9, 70, 26, MV_WRITE_BTN);
    HWND hex = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "Attach first, set address, Dump.", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY, 12, 44, 600, 390, p, (HMENU)(INT_PTR)MV_HEX_EDIT, GetModuleHandleA(nullptr), nullptr);
    (void)hex;
    ShowWindow(p, SW_SHOW);
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
    char ttl[200]; snprintf(ttl, sizeof(ttl), "LegendScan - %lX-%s (amdfend)", pid, pname);
    SetWindowTextA(g_hwnd, ttl);
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
    g_dlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "LSManualCls", "Process List", WS_POPUP | WS_CAPTION | WS_SYSMENU, 250, 150, 420, 480, g_hwnd, nullptr, GetModuleHandleA(nullptr), nullptr);
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
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)p, "Process");
    HMENU s = CreatePopupMenu();
    AppendMenuA(s, MF_STRING, 9004, "First Scan");
    AppendMenuA(s, MF_STRING, 9005, "Next Scan");
    AppendMenuA(s, MF_STRING, 9006, "Undo Scan");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)s, "Scan");
    HMENU v = CreatePopupMenu();
    AppendMenuA(v, MF_STRING, 9007, "Memory View");
    AppendMenuA(bar, MF_POPUP, (UINT_PTR)v, "View");
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
            SetWindowTextA(g_hwnd, "LegendScan - Kernel CE (amdfend)");
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
        else if (id == 9003) { if (!g_connected) std::thread(DriverThread).detach(); }
        else if (id == IDC_FIRST_BTN || id == 9004) start_first();
        else if (id == IDC_NEXT_BTN || id == 9005) start_next();
        else if (id == IDC_UNDO_BTN || id == 9006) {
            std::lock_guard<std::mutex> lk(g_candsMtx);
            if (!g_undo.empty()) { g_cands = g_undo.back(); g_undo.pop_back(); refresh_found(); setStatus("Undo Scan"); }
            else setStatus("Nothing to undo");
        }
        else if (id == IDC_MEMVIEW_BTN || id == 9007) OpenMemView();
        else if (id == IDC_ADDADDR_BTN) doAddSelectedToTable();
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
        else if (id == 9008) MessageBoxA(hwnd, "LegendScan — kernel CE clone\nDriver: amdfend.sys (AMD_CrashDefend)\nBuild tag 00080002", "About", MB_OK);
        return 0;
    }
    case WM_NOTIFY: {
        LPNMHDR nh = (LPNMHDR)lp;
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
        if (isTbl) {
            AppendMenuA(m, MF_STRING, CTX_DEL, "Delete This Address");
            AppendMenuA(m, MF_SEPARATOR, 0, nullptr);
            AppendMenuA(m, MF_STRING, CTX_VAL, "Change Value");
            AppendMenuA(m, MF_STRING, CTX_TYPE, "Change Type");
            AppendMenuA(m, MF_STRING, CTX_DESC, "Change Description");
            AppendMenuA(m, MF_STRING, CTX_ADDR, "Change Address...");
        }
        else {
            AppendMenuA(m, MF_STRING, CTX_ADD, "Add to Address List");
        }
        TrackPopupMenu(m, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON, px, py, 0, g_hwnd, nullptr);
        DestroyMenu(m);
        return 0;
    }
    case WM_TIMER:
        if (wp == 7) {
            if (g_drv && g_attached && !g_table.empty()) refresh_table_live();
        }
        return 0;
    case WM_SCAN_DONE: {
        if (wp == 1) { refresh_found(); refresh_table(); setStatus(g_scanMsg); }
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
    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "LegendScanCls";
    RegisterClassExA(&wc);
    WNDCLASSEXA m{};
    m.cbSize = sizeof(m);
    m.lpfnWndProc = ManualProc;
    m.hInstance = hInst;
    m.hCursor = LoadCursor(nullptr, IDC_ARROW);
    m.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    m.lpszClassName = "LSManualCls";
    RegisterClassExA(&m);
    WNDCLASSEXA v{};
    v.cbSize = sizeof(v);
    v.lpfnWndProc = MemProc;
    v.hInstance = hInst;
    v.hCursor = LoadCursor(nullptr, IDC_ARROW);
    v.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    v.lpszClassName = "LSMemCls";
    RegisterClassExA(&v);
    HWND w = CreateWindowExA(0, "LegendScanCls", "LegendScan - Kernel CE (amdfend)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        80, 40, 800, 700, nullptr, nullptr, hInst, nullptr);
    ShowWindow(w, SW_SHOW);
    UpdateWindow(w);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}
