/* dll_gate_harness.c — acceptance harness for the unpacked DLL case.
 *
 * The unpacked product is a DLL, so "did it work" cannot be answered by
 * launching it.  This harness answers it the way a real host application would:
 *
 *   1. LoadLibraryW the product.
 *   2. Call the exported `GetAppVersion()` and report the string.
 *   3. Call the exported `Run()` on a worker thread.  `Run()` installs hooks and
 *      then enters its own message loop, so it never returns on success.
 *   4. Poll for the window the product creates and report its class and title.
 *
 * Output is `KEY=VALUE` lines on stdout, UTF-8 encoded, so the Rust gate can
 * scrape it without depending on console code pages:
 *
 *   LOADED=1
 *   VERSION=1.1
 *   WINDOW_FOUND=1
 *   WINDOW_CLASS=PigToGoLicenseDialog
 *   WINDOW_TITLE=授权验证
 *   RUN_THREAD_ALIVE=1
 *
 * Exit code is 0 when every step succeeded, non-zero otherwise, but the gate
 * reads the keys rather than the code so a partial failure still reports why.
 *
 * Build (the gate does this itself):
 *   gcc -O2 -o dll_gate_harness.exe dll_gate_harness.c
 */
#include <windows.h>
#include <stdio.h>

static void emit_utf8(const char *key, const wchar_t *w) {
    char utf8[1024] = {0};
    WideCharToMultiByte(CP_UTF8, 0, w, -1, utf8, sizeof utf8 - 1, NULL, NULL);
    printf("%s=%s\n", key, utf8);
    fflush(stdout);
}

static DWORD WINAPI run_thread(LPVOID p) {
    typedef int (__cdecl *run_t)(void);
    run_t run = (run_t)p;
    run();
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: dll_gate_harness.dll DLL\n"); return 2; }

    /* argv[1] is ANSI; widen so non-ASCII paths survive. */
    wchar_t wide[32768];
    if (MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wide,
                            (int)(sizeof wide / sizeof wide[0])) == 0) {
        printf("LOADED=0\nREASON=path conversion failed\n");
        return 2;
    }

    HMODULE h = LoadLibraryW(wide);
    if (!h) {
        printf("LOADED=0\nREASON=LoadLibrary failed %lu\n", GetLastError());
        return 1;
    }
    printf("LOADED=1\n");

    /* ---- 1. the version string ------------------------------------------ */
    typedef const char *(__cdecl *gv_t)(void);
    gv_t gv = (gv_t)GetProcAddress(h, "GetAppVersion");
    if (!gv) {
        printf("REASON=GetAppVersion export missing\n");
        return 1;
    }
    const char *ver = gv();
    printf("VERSION=%s\n", ver ? ver : "(null)");
    fflush(stdout);

    /* ---- 2. drive Run() on a worker thread ------------------------------ */
    typedef int (__cdecl *run_t)(void);
    run_t run = (run_t)GetProcAddress(h, "Run");
    HANDLE th = NULL;
    if (run) {
        th = CreateThread(NULL, 0, run_thread, (LPVOID)run, 0, NULL);
    }

    /* ---- 3. wait for the window the product creates --------------------- */
    HWND win = NULL;
    for (int i = 0; i < 150; i++) {          /* up to 15 s */
        win = FindWindowA("PigToGoLicenseDialog", NULL);
        if (win) break;
        Sleep(100);
    }

    if (!win) {
        printf("WINDOW_FOUND=0\n");
        if (!run) printf("REASON=Run export missing\n");
        else      printf("REASON=no window within 15s\n");
        return 1;
    }

    printf("WINDOW_FOUND=1\n");
    printf("WINDOW_VISIBLE=%d\n", IsWindowVisible(win) ? 1 : 0);

    wchar_t cls[256] = {0};
    GetClassNameW(win, cls, 255);
    emit_utf8("WINDOW_CLASS", cls);

    wchar_t title[512] = {0};
    GetWindowTextW(win, title, 511);
    emit_utf8("WINDOW_TITLE", title);

    RECT r;
    if (GetWindowRect(win, &r))
        printf("WINDOW_RECT=%ld,%ld,%ld,%ld\n", r.left, r.top, r.right, r.bottom);

    /* A worker still parked in the message loop is the expected shape. */
    if (th) {
        DWORD st = WaitForSingleObject(th, 0);
        printf("RUN_THREAD_ALIVE=%d\n", st == WAIT_TIMEOUT ? 1 : 0);
    }
    fflush(stdout);
    return 0;
}
