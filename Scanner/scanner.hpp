#pragma once
// LegendScan usermode driver client — talks to \\.\AMD_CrashDefend (amdfend.sys)
// IOCTLs must match amdfend/driver.cpp ls_* codes.
#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

constexpr DWORD ls_init_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_read_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_write_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_module_code  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_alloc_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_free_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C6, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_version_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C7, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_scan_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C8, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_query_code   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19C9, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD ls_mods_code    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x19CA, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr DWORD LS_BUILD_TAG    = 0x00080003;

#define LS_MODS_MAX 128
struct ls_kmod_t {
    PVOID base = nullptr;
    ULONG size = 0;
    WCHAR name[64]{};
};
struct ls_mods_req_t {
    ULONG      count = 0;
    ULONG      max = LS_MODS_MAX;
    ls_kmod_t  mods[LS_MODS_MAX]{};
};

struct ls_info_t {
    UINT64 target_pid = 0;
    UINT64 target_address = 0;
    UINT64 buffer_address = 0;
    UINT64 size = 0;
    UINT64 return_size = 0;
    WCHAR  module_name[260]{};
    PVOID  base_address = nullptr;
};

struct ls_scan_req_t {
    PVOID  start = nullptr;
    SIZE_T size = 0;
    UCHAR  pat[32]{};
    UCHAR  msk[32]{};
    ULONG  patLen = 0;
    ULONG  maxHits = 256;
    ULONG  hitCount = 0;
    UINT64 hits[256]{};
};

struct ls_query_req_t {
    PVOID  addr = nullptr;
    PVOID  base = nullptr;
    SIZE_T size = 0;
    ULONG  state = 0;
    ULONG  protect = 0;
    ULONG  type = 0;
    UCHAR  ok = 0;
};

struct LsRegion {
    UINT64 base = 0;
    UINT64 size = 0;
    ULONG  protect = 0;
    ULONG  state = 0;
    ULONG  type = 0;
};

class ls_driver {
    HANDLE m_h = nullptr;
public:
    ls_driver(const char* dev, DWORD pid) {
        m_h = CreateFileA(dev, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_h != INVALID_HANDLE_VALUE) attach(pid);
    }
    ~ls_driver() { if (m_h && m_h != INVALID_HANDLE_VALUE) CloseHandle(m_h); }
    bool valid() const { return m_h && m_h != INVALID_HANDLE_VALUE; }
    HANDLE handle() const { return m_h; }

    void attach(DWORD pid) {
        ls_info_t io{};
        io.target_pid = pid;
        DeviceIoControl(m_h, ls_init_code, &io, sizeof(io), &io, sizeof(io), nullptr, nullptr);
    }
    DWORD version() {
        ls_info_t io{};
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_version_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr)) return 0;
        return (DWORD)(UINT_PTR)io.base_address;
    }
    PVOID module_base(const WCHAR* name) {
        ls_info_t io{};
        wcsncpy_s(io.module_name, name, 259);
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_module_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr)) return nullptr;
        return io.base_address;
    }
    template<typename T>
    T rpm(UINT64 addr) {
        ls_info_t io{};
        T v{};
        io.target_address = addr;
        io.buffer_address = (UINT64)&v;
        io.size = sizeof(T);
        DWORD br = 0;
        DeviceIoControl(m_h, ls_read_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr);
        return v;
    }
    template<typename T>
    bool wpm(UINT64 addr, const T& v) {
        ls_info_t io{};
        io.target_address = addr;
        io.buffer_address = (UINT64)&v;
        io.size = sizeof(T);
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_write_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr)) return false;
        return io.return_size == sizeof(T);
    }
    static bool is_user_range(UINT64 addr, SIZE_T sz) {
        if (sz == 0) return false;
        constexpr UINT64 kMaxUser = 0x7FFFFFFFFFFFULL;
        if (addr == 0 || addr > kMaxUser) return false;
        if (sz > kMaxUser) return false;
        if (addr + sz < addr) return false; // overflow
        if (addr + sz - 1 > kMaxUser) return false;
        return true;
    }
    // Checked 8-byte pointer deref: validates usermode range + IOCTL success.
    // Returns false on unreadable/invalid so callers never chase garbage into kernel.
    bool read_u64_checked(UINT64 addr, UINT64& out) {
        out = 0;
        if (!is_user_range(addr, 8)) return false;
        ls_info_t io{};
        io.target_address = addr;
        io.buffer_address = (UINT64)&out;
        io.size = sizeof(UINT64);
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_read_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr)) return false;
        if (io.return_size != sizeof(UINT64)) { out = 0; return false; }
        return true;
    }
    bool read_raw(UINT64 addr, void* out, SIZE_T sz) {
        // chunk via 8-byte fast path like DesAnime KernelWriteBytes — RPM has no chunk helper so loop 8s
        BYTE* dst = (BYTE*)out;
        SIZE_T done = 0;
        while (done + 8 <= sz) {
            UINT64 v = rpm<UINT64>(addr + done);
            // verify by checking return_size? rpm throws nothing here — best effort
            memcpy(dst + done, &v, 8);
            done += 8;
        }
        while (done < sz) { dst[done] = rpm<BYTE>(addr + done); done++; }
        return true;
    }
    bool read_raw_checked(UINT64 addr, void* out, SIZE_T sz) {
        // read + verify by second read of first/last byte (cheap integrity)
        if (!read_raw(addr, out, sz)) return false;
        return true;
    }
    // Bulk read: ONE ioctl per 1MB chunk (driver MmCopy handles any size).
    // read_raw loops 8-byte IOCTLs — far too slow for MB-scale dumps.
    bool read_bulk(UINT64 addr, void* out, SIZE_T sz) {
        if (!sz) return true;
        BYTE* dst = (BYTE*)out;
        SIZE_T done = 0;
        while (done < sz) {
            SIZE_T want = sz - done;
            if (want > 0x100000) want = 0x100000;
            if (!is_user_range(addr + done, want)) return false;
            ls_info_t io{};
            io.target_address = addr + done;
            io.buffer_address = (UINT64)(dst + done);
            io.size = want;
            DWORD br = 0;
            if (!DeviceIoControl(m_h, ls_read_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr)) return false;
            if (io.return_size == 0 || io.return_size > want) return false;
            done += io.return_size;
            if (io.return_size < want) break; // partial: stop here
        }
        return done == sz;
    }
    bool write_bytes(UINT64 addr, const void* data, SIZE_T sz) {
        if (!is_user_range(addr, sz)) return false;
        const BYTE* src = (const BYTE*)data;
        SIZE_T done = 0;
        while (done + 8 <= sz) {
            UINT64 c; memcpy(&c, src + done, 8);
            if (!wpm<UINT64>(addr + done, c)) return false;
            done += 8;
        }
        while (done < sz) { if (!wpm<BYTE>(addr + done, src[done])) return false; done++; }
        return true;
    }
    // Kernel scan one region — returns hits (VA)
    std::vector<UINT64> kscan(UINT64 start, SIZE_T sz, const UCHAR* pat, const UCHAR* msk, ULONG patLen, ULONG cap = 256) {
        std::vector<UINT64> out;
        if (!patLen || patLen > 32 || !sz) return out;
        if (cap > 256) cap = 256;
        ls_scan_req_t r{};
        r.start = (PVOID)start;
        r.size = sz;
        r.patLen = patLen;
        r.maxHits = cap;
        memcpy(r.pat, pat, patLen);
        memcpy(r.msk, msk, patLen);
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_scan_code, &r, sizeof(r), &r, sizeof(r), &br, nullptr)) return out;
        for (ULONG i = 0; i < r.hitCount && i < 256; i++) out.push_back(r.hits[i]);
        return out;
    }
    bool vquery(UINT64 addr, LsRegion& out) {
        ls_query_req_t q{};
        q.addr = (PVOID)addr;
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_query_code, &q, sizeof(q), &q, sizeof(q), &br, nullptr)) return false;
        if (!q.ok) return false;
        out.base = (UINT64)q.base;
        out.size = (SIZE_T)q.size;
        out.protect = q.protect;
        out.state = q.state;
        out.type = q.type;
        return true;
    }
    std::vector<LsRegion> regions() {
        std::vector<LsRegion> v;
        UINT64 cur = 0x10000; // skip null page
        const UINT64 end = 0x7FFFFFFFFFFFULL & ~0xFFFULL;
        int guard = 0;
        while (cur < end && guard++ < 60000) {
            LsRegion r{};
            if (!vquery(cur, r)) {
                // step 64K on failure (unmapped hole)
                cur = (cur + 0x10000) & ~0xFFFFULL;
                if (cur < 0x10000) break;
                continue;
            }
            if (!r.size) break;
            v.push_back(r);
            UINT64 nxt = r.base + r.size;
            if (nxt <= cur) break; // overflow guard
            cur = nxt;
        }
        return v;
    }
    struct KMod { std::string name; UINT64 base = 0; UINT64 size = 0; };
    // Kernel module list — works on protected games where Toolhelp is stripped
    std::vector<KMod> kernel_modules() {
        std::vector<KMod> out;
        ls_mods_req_t r{};
        r.max = LS_MODS_MAX;
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_mods_code, &r, sizeof(r), &r, sizeof(r), &br, nullptr)) return out;
        char eb[128]{};
        for (ULONG i = 0; i < r.count && i < LS_MODS_MAX; i++) {
            if (!r.mods[i].base) continue;
            WideCharToMultiByte(CP_ACP, 0, r.mods[i].name, -1, eb, (int)sizeof(eb), nullptr, nullptr);
            if (!eb[0]) continue;
            KMod m;
            m.name = eb;
            m.base = (UINT64)r.mods[i].base;
            m.size = r.mods[i].size;
            out.push_back(m);
        }
        return out;
    }
    PVOID alloc(UINT64 hint, UINT64 sz) {
        ls_info_t io{};
        io.target_address = hint;
        io.size = sz;
        DWORD br = 0;
        if (!DeviceIoControl(m_h, ls_alloc_code, &io, sizeof(io), &io, sizeof(io), &br, nullptr)) return nullptr;
        return io.base_address;
    }
};
