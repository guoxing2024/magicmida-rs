// XC-8-A: VEH probe host (minimal, no external deps).
// Loads a candidate DLL, calls GetAppVersion, and a Vectored Exception
// Handler prints RIP + registers on ACCESS_VIOLATION so we can attribute
// data-dependency vs VM-execution crashes.
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static uint64_t g_mod_base = 0;

// x64 CONTEXT layout offsets (from winnt.h, for manual register reads).
#define CTX_RSP  0x88
#define CTX_RAX  0x98
#define CTX_RCX  0xA0
#define CTX_RDX  0xA8
#define CTX_RBX  0xB0
#define CTX_RBP  0xB8
#define CTX_RSI  0xC0
#define CTX_RDI  0xC8
#define CTX_RIP  0xF8

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR rip = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;
        ULONG_PTR fault = ep->ExceptionRecord->ExceptionInformation[1];
        DWORD vtype = (DWORD)ep->ExceptionRecord->ExceptionInformation[0];
        fprintf(stderr, "[VEH] ACCESS_VIOLATION RIP=0x%llX rva=0x%llX type=%u fault=0x%llX\n",
                (unsigned long long)rip, (unsigned long long)(rip - g_mod_base),
                vtype, (unsigned long long)fault);
        if (ep->ContextRecord) {
            BYTE *c = (BYTE *)ep->ContextRecord;
            uint64_t rsp = *(uint64_t *)(c + CTX_RSP);
            uint64_t rax = *(uint64_t *)(c + CTX_RAX);
            uint64_t rcx = *(uint64_t *)(c + CTX_RCX);
            uint64_t rdx = *(uint64_t *)(c + CTX_RDX);
            uint64_t rbx = *(uint64_t *)(c + CTX_RBX);
            uint64_t rsi = *(uint64_t *)(c + CTX_RSI);
            uint64_t rdi = *(uint64_t *)(c + CTX_RDI);
            fprintf(stderr, "[VEH] Rsp=0x%llX Rax=0x%llX Rcx=0x%llX Rdx=0x%llX\n",
                    (unsigned long long)rsp, (unsigned long long)rax,
                    (unsigned long long)rcx, (unsigned long long)rdx);
            fprintf(stderr, "[VEH] Rbx=0x%llX Rsi=0x%llX Rdi=0x%llX\n",
                    (unsigned long long)rbx, (unsigned long long)rsi,
                    (unsigned long long)rdi);
        }
        // Dump instruction bytes at RIP.
        BYTE buf[16];
        SIZE_T r = 0;
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)rip, buf, 16, &r) || r) {
            fprintf(stderr, "[VEH] instr:");
            for (SIZE_T i = 0; i < r; i++) fprintf(stderr, " %02X", buf[i]);
            fprintf(stderr, "\n");
        }
        // Keep searching (let the crash proceed normally after logging).
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: veh_probe.exe <dll> [func]\n"); return 2; }
    const char *dll = argv[1];
    const char *func = argc > 2 ? argv[2] : "GetAppVersion";

    AddVectoredExceptionHandler(1, veh_handler);

    HMODULE h = LoadLibraryA(dll);
    if (!h) { fprintf(stderr, "LoadLibraryA failed: %lu\n", GetLastError()); return 1; }
    g_mod_base = (uint64_t)h;
    fprintf(stderr, "[probe] loaded %s hmod=0x%llX\n", dll, (unsigned long long)g_mod_base);

    FARPROC p = GetProcAddress(h, func);
    if (!p) { fprintf(stderr, "[probe] %s not found\n", func); return 1; }
    fprintf(stderr, "[probe] %s @ 0x%llX (rva 0x%llX)\n", func,
            (unsigned long long)p, (unsigned long long)((uint64_t)p - g_mod_base));

    typedef uint64_t (__stdcall *fn0_t)(void);
    fn0_t fn = (fn0_t)p;
    uint64_t ret = fn();
    fprintf(stderr, "[probe] %s returned 0x%llX (no crash)\n", func, (unsigned long long)ret);
    return 0;
}
