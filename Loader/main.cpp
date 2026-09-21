/*
 * LSLoader — LegendScan driver loader (EfiGuard edition, amdfend.sys)
 * Uses NtLoadDriver directly — no BYOVD, no KDMapper
 * Usage: Loader.exe amdfend.sys [--no-dsefix] [--keep|--persist|--no-unload] [--unload]
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <io.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Advapi32.lib")

typedef NTSTATUS(NTAPI* NtLoadDriver_t)(PUNICODE_STRING);
typedef NTSTATUS(NTAPI* NtUnloadDriver_t)(PUNICODE_STRING);

static NtLoadDriver_t   pNtLoad = nullptr;
static NtUnloadDriver_t pNtUnload = nullptr;

static void InitNtApis() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtLoad = (NtLoadDriver_t)GetProcAddress(ntdll, "NtLoadDriver");
    pNtUnload = (NtUnloadDriver_t)GetProcAddress(ntdll, "NtUnloadDriver");
}

static bool EnableLoadDriverPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueA(nullptr, "SeLoadDriverPrivilege", &tp.Privileges[0].Luid)) {
        printf("[-] LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return true;
}

static bool SetupRegKey(const wchar_t* imagePath, const wchar_t* svcName) {
    wchar_t keyPath[512];
    swprintf_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    HKEY hKey;
    LSTATUS st = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &hKey, nullptr);
    if (st != ERROR_SUCCESS) {
        printf("[-] RegCreateKeyEx failed: %ld\n", st);
        printf("    Are you running as Administrator?\n");
        return false;
    }
    DWORD type = 1, start = 3, err = 1;
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)imagePath, (DWORD)((wcslen(imagePath) + 1) * sizeof(wchar_t)));
    RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&type, 4);
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&start, 4);
    RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&err, 4);
    RegCloseKey(hKey);
    return true;
}

static void CleanupRegKey(const wchar_t* svcName) {
    wchar_t keyPath[512];
    swprintf_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, keyPath);
}

static void BuildRegPath(const wchar_t* svcName, wchar_t* out, size_t outLen) {
    swprintf_s(out, outLen, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
}

static void ToUnicodeString(wchar_t* buf, UNICODE_STRING* us) {
    us->Buffer = buf;
    us->Length = (USHORT)(wcslen(buf) * sizeof(wchar_t));
    us->MaximumLength = us->Length + sizeof(wchar_t);
}

static void GetSvcName(const wchar_t* fullPath, wchar_t* svcName, size_t len) {
    const wchar_t* fn = wcsrchr(fullPath, L'\\');
    fn = fn ? fn + 1 : fullPath;
    wcsncpy_s(svcName, len, fn, len - 1);
    wchar_t* dot = wcsrchr(svcName, L'.');
    if (dot) *dot = L'\0';
}

static bool CallEfiDSEFix(const wchar_t* exeDir) {
    wchar_t path[MAX_PATH];
    swprintf_s(path, L"%sEfiDSEFix.exe", exeDir);
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] EfiDSEFix.exe not found — assuming DSE already disabled\n");
        return true;
    }
    printf("[*] Running EfiDSEFix.exe -d to disable DSE...\n");
    wchar_t cmd[MAX_PATH + 16];
    swprintf_s(cmd, L"\"%s\" -d", path);
    STARTUPINFOW si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        printf("[-] Failed to run EfiDSEFix.exe: %lu\n", GetLastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    if (ec == 0) { printf("[+] DSE disabled via EfiDSEFix\n"); return true; }
    printf("[!] EfiDSEFix returned %lu — DSE may still be on\n", ec);
    return false;
}

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  LegendScan Loader (EfiGuard edition)\n");
    printf("  amdfend.sys | No BYOVD | No KDMapper\n");
    printf("==============================================\n\n");

    if (argc < 2) {
        printf("Usage:\n");
        printf("  Loader.exe <driver.sys>\n");
        printf("  Loader.exe <driver.sys> --no-dsefix\n");
        printf("  Loader.exe <driver.sys> --keep     (stay loaded)\n");
        printf("  Loader.exe <driver.sys> --unload   (unload after Enter)\n");
        printf("  Loader.exe <driver.sys> --unload-only (unload now, no load)\n");
        return 1;
    }
    bool noDseFix = false, unloadOnly = false;
    for (int i = 2; i < argc; i++) {
        if (_stricmp(argv[i], "--no-dsefix") == 0) noDseFix = true;
        if (_stricmp(argv[i], "--unload-only") == 0) unloadOnly = true;
    }

    wchar_t wideArg[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wideArg, MAX_PATH);
    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(wideArg, MAX_PATH, fullPath, nullptr)) {
        printf("[-] Cannot resolve path: %s\n", argv[1]);
        return 1;
    }
    if (GetFileAttributesW(fullPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Driver not found: %s\n", argv[1]);
        return 1;
    }
    wchar_t exeDir[MAX_PATH];
    GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(exeDir, L'\\');
    if (lastSlash) *(lastSlash + 1) = L'\0';

    printf("[*] Driver : %S\n", fullPath);
    wchar_t svcName[64];
    GetSvcName(fullPath, svcName, 64);
    printf("[*] Service: %S\n\n", svcName);

    InitNtApis();
    if (!pNtLoad || !pNtUnload) { printf("[-] NtLoadDriver not found\n"); return 1; }

    printf("[1] Enabling SeLoadDriverPrivilege...\n");
    if (!EnableLoadDriverPrivilege()) return 1;
    printf("[+] Privilege enabled\n");

    if (unloadOnly) {
        // Unload a resident driver WITHOUT loading first (for updates).
        // NtUnloadDriver needs the service key to exist — recreate minimal key.
        wchar_t ntPath0[MAX_PATH];
        swprintf_s(ntPath0, L"\\??\\%s", fullPath);
        SetupRegKey(ntPath0, svcName);
        wchar_t regPath0[512];
        BuildRegPath(svcName, regPath0, 512);
        UNICODE_STRING us0;
        ToUnicodeString(regPath0, &us0);
        printf("[*] Unloading %S...\n", svcName);
        NTSTATUS su = pNtUnload(&us0);
        CleanupRegKey(svcName);
        if (NT_SUCCESS(su)) { printf("[+] Driver unloaded.\n"); return 0; }
        printf("[-] Unload failed: 0x%08X (already unloaded?)\n", su);
        return 1;
    }

    if (!noDseFix) { printf("[2] Disabling DSE...\n"); CallEfiDSEFix(exeDir); }
    else printf("[2] DSE fix skipped (--no-dsefix)\n");

    CleanupRegKey(svcName);
    printf("[3] Setting up registry service key...\n");
    wchar_t ntPath[MAX_PATH];
    swprintf_s(ntPath, L"\\??\\%s", fullPath);
    if (!SetupRegKey(ntPath, svcName)) return 1;
    printf("[+] Registry key created\n");

    wchar_t regPath[512];
    BuildRegPath(svcName, regPath, 512);
    UNICODE_STRING usRegPath;
    ToUnicodeString(regPath, &usRegPath);

    printf("[4] Loading driver via NtLoadDriver...\n");
    NTSTATUS st = pNtLoad(&usRegPath);
    CleanupRegKey(svcName);

    if (!NT_SUCCESS(st)) {
        printf("[-] NtLoadDriver failed: 0x%08X\n", st);
        switch (st) {
        case 0xC0000034: printf("    Object not found — check path\n"); break;
        case 0xC000010E: printf("    DSE still enabled — EfiGuard active?\n"); break;
        case 0xC0000022: printf("    Access denied — run as Administrator\n"); break;
        default: printf("    Check EfiGuard + DSE\n"); break;
        }
        return 1;
    }
    printf("[+] Driver loaded successfully!\n");
    printf("[+] Device: \\\\.\\AMD_CrashDefend\n\n");

    bool keep = false, doUnload = false;
    for (int i = 2; i < argc; i++) {
        if (_stricmp(argv[i], "--keep") == 0 || _stricmp(argv[i], "--persist") == 0 || _stricmp(argv[i], "--no-unload") == 0) keep = true;
        if (_stricmp(argv[i], "--unload") == 0) doUnload = true;
    }
    if (keep) {
        printf("[*] --keep: driver stays loaded. Close window freely.\n");
        printf("[*] Unload later: Loader.exe <driver> --unload\n");
        return 0;
    }
    if (!doUnload && !_isatty(_fileno(stdin))) {
        printf("[*] Non-interactive launch: keeping driver loaded.\n");
        return 0;
    }
    printf("    Press Enter to unload and exit (or --keep to persist)...\n");
    getchar();
    printf("[5] Unloading driver...\n");
    SetupRegKey(ntPath, svcName);
    UNICODE_STRING usUnload;
    ToUnicodeString(regPath, &usUnload);
    NTSTATUS st2 = pNtUnload(&usUnload);
    CleanupRegKey(svcName);
    if (NT_SUCCESS(st2)) printf("[+] Driver unloaded.\n");
    else printf("[!] Unload returned 0x%08X (may still run)\n", st2);
    return 0;
}
