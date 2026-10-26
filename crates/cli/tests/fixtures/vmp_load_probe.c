/* vmp_load_probe.c — measure what the decoded VMProtect payload (a DLL) does
 * when a host loads it.
 *
 *   1. LoadLibraryW(argv[1]).
 *  2. If it fails, print the Win32 error and exit 1.
 *  3. If it loads, report exports found by ordinal/name count via the PEB is
 *     not portable — instead poll, for OBSERVE seconds:
 *       - threads of this process (DllMain work shows up here),
 *       - top-level windows of this process,
 *       - files created in the working directory.
 *  4. Exit 0 with LOADED=1.
 *
 * Output is KEY=VALUE lines, UTF-8, so a gate can scrape it:
 *   LOADED=1 | LOADED=0 REASON=Win32 error N
 *   THREADS=<n>            (max observed)
 *   WINDOW visible=... class='...' title='...'   (one line per new window)
 *   FILE <name>            (one line per new file in CWD)
 *
 * Build: gcc -O2 -o vmp_load_probe.exe vmp_load_probe.c
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static void emit_utf8(const char *key, const wchar_t *w) {
    char utf8[1024] = {0};
    WideCharToMultiByte(CP_UTF8, 0, w, -1, utf8, sizeof utf8 - 1, NULL, NULL);
    printf("%s %s\n", key, utf8);
    fflush(stdout);
}

struct snap {
    DWORD pid;
    int seen_win;
    char seen_key[256][512];
    int n_seen;
};

static BOOL CALLBACK obs(HWND h, LPARAM lp) {
    struct snap *s = (struct snap *)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != s->pid) return TRUE;
    BOOL vis = IsWindowVisible(h);
    char cls[256] = {0}, txt[512] = {0};
    GetClassNameA(h, cls, sizeof cls - 1);
    GetWindowTextA(h, txt, sizeof txt - 1);
    char key[1024];
    snprintf(key, sizeof key, "%p|%d|%s|%s", (void *)h, (int)vis, cls, txt);
    for (int i = 0; i < s->n_seen; i++)
        if (!strcmp(s->seen_key[i], key)) return TRUE;
    if (s->n_seen < 256) {
        snprintf(s->seen_key[s->n_seen++], 512, "%s", key);
        printf("WINDOW visible=%d class='%s' title='%s'\n", (int)vis, cls, txt);
        fflush(stdout);
    }
    s->seen_win++;
    return TRUE;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: vmp_load_probe.exe DLL [seconds]\n"); return 2; }
    int observe = argc >= 3 ? atoi(argv[2]) : 8;
    if (observe < 1) observe = 1;

    wchar_t wide[32768];
    if (MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wide,
                            (int)(sizeof wide / sizeof wide[0])) == 0) {
        printf("LOADED=0 REASON=path conversion failed\n");
        return 2;
    }

    struct snap s = {0};
    s.pid = GetCurrentProcessId();

    /* Snapshot the working directory before load. */
    char before[256][MAX_PATH];
    int n_before = 0;
    WIN32_FIND_DATAA fd;
    HANDLE f = FindFirstFileA("*", &fd);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                n_before < 256)
                snprintf(before[n_before++], MAX_PATH, "%s", fd.cFileName);
        } while (FindNextFileA(f, &fd));
        FindClose(f);
    }

    HMODULE h = LoadLibraryW(wide);
    if (!h) {
        printf("LOADED=0 REASON=LoadLibrary failed %lu\n", GetLastError());
        return 1;
    }
    printf("LOADED=1 base=%p\n", (void *)h);
    fflush(stdout);

    /* Walk the loaded image's export directory: authoritative, because any
     * runtime fix-up the protection applies has already happened.  Then
     * resolve the first exported function by ordinal (no code is run —
     * GetProcAddress only reads tables). */
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)h;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)h + dos->e_lfanew);
        DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exp_sz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (exp_rva && exp_sz) {
            IMAGE_EXPORT_DIRECTORY *exp =
                (IMAGE_EXPORT_DIRECTORY *)((BYTE *)h + exp_rva);
            DWORD *funcs = (DWORD *)((BYTE *)h + exp->AddressOfFunctions);
            DWORD first_slot = 0, nonzero = 0;
            for (DWORD i = 0; i < exp->NumberOfFunctions; i++) {
                if (funcs[i]) {
                    nonzero++;
                    if (!first_slot) first_slot = i;
                }
            }
            printf("EXPORT_SLOTS=%lu NAMES=%lu NONZERO=%lu BASE=%lu\n",
                   (unsigned long)exp->NumberOfFunctions,
                   (unsigned long)exp->NumberOfNames,
                   (unsigned long)nonzero,
                   (unsigned long)exp->Base);
            if (nonzero) {
                WORD ordinal = (WORD)(exp->Base + first_slot);
                FARPROC p = GetProcAddress(h, MAKEINTRESOURCEA(ordinal));
                printf("FIRST_EXPORT ordinal=%lu rva=%#lx resolves=%d\n",
                       (unsigned long)ordinal,
                       (unsigned long)funcs[first_slot],
                       p != NULL);
            }
        } else {
            printf("EXPORT_SLOTS=0 NAMES=0 NONZERO=0 BASE=0\n");
        }
        fflush(stdout);
    }

    int max_threads = 0;
    DWORD t0 = GetTickCount();
    while (GetTickCount() - t0 < (DWORD)observe * 1000) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { .dwSize = sizeof te };
            int mine = 0;
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID == s.pid) mine++;
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
            if (mine > max_threads) { max_threads = mine; }
        }
        EnumWindows(obs, (LPARAM)&s);
        Sleep(250);
    }

    int n_after = 0;
    f = FindFirstFileA("*", &fd);
    if (f != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                int known = 0;
                for (int i = 0; i < n_before; i++)
                    if (!strcmp(before[i], fd.cFileName)) { known = 1; break; }
                if (!known) printf("FILE %s\n", fd.cFileName);
            }
        } while (FindNextFileA(f, &fd));
        FindClose(f);
    }
    (void)n_after;

    printf("THREADS=%d\n", max_threads);
    fflush(stdout);
    FreeLibrary(h);
    return 0;
}
