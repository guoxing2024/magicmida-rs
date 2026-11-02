//! Path, address, and API resolution helpers for the unpacker.

use std::path::{Path, PathBuf};
use anyhow::anyhow;
use tracing::{debug, info, warn};
use windows::core::s;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use mida_core::{ContinueStatus, DebugEvent, DebuggerCore};
use mida_packers_themida::{install_code_section_guard, ThemidaState};
use super::session::{ResolvedApis, ProcessSession, ReadOnlyProcessDebugger};

// ---------------------------------------------------------------------------
// ScyllaHide paths
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
const SCYLLA_INJECTOR_NAME: &str = "InjectorCLIx64.exe";
#[cfg(target_arch = "x86")]
const SCYLLA_INJECTOR_NAME: &str = "InjectorCLIx86.exe";

#[cfg(target_arch = "x86_64")]
const SCYLLA_HOOK_NAME: &str = "HookLibraryx64.dll";
#[cfg(target_arch = "x86")]
const SCYLLA_HOOK_NAME: &str = "HookLibraryx86.dll";

/// Profile file name.  One file for all packers; the profile is selected by
/// the `CurrentProfile` key inside it, not by the file name.
const SCYLLA_INI_NAME: &str = "scylla_hide.ini";

/// Resolve the absolute path to the ScyllaHide injector binary.
pub(super) fn scylla_injector_path() -> PathBuf {
    exe_dir().join(SCYLLA_INJECTOR_NAME)
}

/// Resolve the absolute path to the ScyllaHide hook library DLL.
pub(super) fn scylla_hook_path() -> PathBuf {
    exe_dir().join(SCYLLA_HOOK_NAME)
}

/// Resolve the absolute path to the ScyllaHide profile file.
///
/// The injector takes **no ini argument** (measured: `InjectorCLIx64.exe
/// pid:<pid> <HookLibraryx64.dll> nowait`), so it reads `scylla_hide.ini` from
/// the directory it lives in — which is where the profile has to be rewritten
/// for per-packer selection.
pub(super) fn scylla_ini_path() -> PathBuf {
    exe_dir().join(SCYLLA_INI_NAME)
}

/// Directory containing the CLI executable.
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Output path
// ---------------------------------------------------------------------------

/// Compute the output path, using the Pascal "U" suffix convention.
///
/// Example: `test.exe` → `testU.exe`, `lib.dll` → `libU.dll`.
pub(super) fn resolve_output_path(input: &Path, output: Option<&Path>) -> PathBuf {
    if let Some(out) = output {
        return out.to_path_buf();
    }

    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("exe");

    let mut name = String::with_capacity(stem.len() + 1 + ext.len() + 1);
    name.push_str(stem);
    name.push('U');
    name.push('.');
    name.push_str(ext);

    input
        .parent()
        .unwrap_or(Path::new("."))
        .join(&name)
}

// ---------------------------------------------------------------------------
// API resolution
// ---------------------------------------------------------------------------

/// Resolve kernel32 API addresses **in the debugger's own process**.
///
/// On x64, kernel32.dll is loaded at the same base address in every process
/// (ASLR randomisation happens once per boot, not per-process).
pub(super) fn resolve_api_addrs() -> Result<ResolvedApis, anyhow::Error> {
    use windows::core::PCSTR;
    // SAFETY: GetModuleHandleW with a valid constant wide string never fails
    // for kernel32.dll / ntdll.dll (always loaded in every process).
    let k32 = unsafe { GetModuleHandleW(windows::core::w!("kernel32.dll")) }
        .map_err(|e| anyhow!("GetModuleHandleW(kernel32.dll) failed: {e}"))?;
    // SAFETY: ntdll.dll is always loaded in every Windows process; w!() yields a valid null-terminated wide string.
    let ntdll = unsafe { GetModuleHandleW(windows::core::w!("ntdll.dll")) }
        .map_err(|e| anyhow!("GetModuleHandleW(ntdll.dll) failed: {e}"))?;

    let resolve = |module: windows::Win32::Foundation::HMODULE, name: PCSTR| -> Result<usize, anyhow::Error> {
        // SAFETY: module is a valid HMODULE from GetModuleHandleW; name is a valid PCSTR constant from s!().
        let addr = unsafe { GetProcAddress(module, name) };
        match addr {
            Some(ptr) => Ok(ptr as usize),
            None => {
                // SAFETY: GetLastError is always safe to call — it reads the calling thread's last-error value.
                let err = unsafe { windows::Win32::Foundation::GetLastError() };
                Err(anyhow!("GetProcAddress failed: code {}", err.0))
            }
        }
    };

    let apis = ResolvedApis {
        close_handle: resolve(k32, s!("CloseHandle"))?,
        virtual_alloc: resolve(k32, s!("VirtualAlloc"))?,
        nt_close: resolve(ntdll, s!("NtClose"))?,
        nt_allocate_virtual_memory: resolve(ntdll, s!("NtAllocateVirtualMemory"))?,
        sleep: resolve(k32, s!("Sleep"))?,
        lstrlen: resolve(k32, s!("lstrlen"))?,
        exit_process: resolve(k32, s!("ExitProcess"))?,
        get_local_time: resolve(k32, s!("GetLocalTime"))?,
    };

    debug!(
        close_handle = %format!("{:#x}", apis.close_handle),
        virtual_alloc = %format!("{:#x}", apis.virtual_alloc),
        nt_close = %format!("{:#x}", apis.nt_close),
        nt_alloc = %format!("{:#x}", apis.nt_allocate_virtual_memory),
        sleep = %format!("{:#x}", apis.sleep),
        lstrlen = %format!("{:#x}", apis.lstrlen),
        "Resolved kernel32 and ntdll API addresses",
    );

    Ok(apis)
}

/// Resolve a host-process API address from a loaded DLL.
/// Returns 0 on failure.
pub(super) fn resolve_host_api(dll: &str, func: &str) -> usize {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    let to_pcstr = |s: &str| PCSTR::from_raw(s.as_ptr());
    // SAFETY: dll string is null-terminated UTF-8; GetModuleHandleA accepts a valid PCSTR.
    let Ok(module) = (unsafe { GetModuleHandleA(to_pcstr(&format!("{dll}\0"))) }) else {
        return 0;
    };
    // SAFETY: module is a valid HMODULE; func name is a null-terminated PCSTR.
    unsafe { GetProcAddress(module, to_pcstr(&format!("{func}\0"))) }
        .map(|f| f as usize)
        .unwrap_or(0)
}

/// V2 post-attach fake-time injection (x86 targets): patch the target's
/// kernelbase!GetLocalTime / GetSystemTime with a stub returning a fixed
/// date, so the WinLicense eval-expiry check passes and the shell proceeds
/// to the `.text` decryption instead of bailing with exit code 2.
///
/// Why the API layer: post-attach mode has no debug port, so the only
/// external levers are ReadProcessMemory / WriteProcessMemory.  The shell's
/// engine region churns (allocated, used, freed — measured 2026-10-29), so
/// code patches inside it don't stick; KUSER_SHARED_DATA is read-only.
/// System-DLL ASLR is per-boot rather than per-process, so the kernelbase
/// address resolved in this process (`resolve_host_api`) is valid in the
/// target.
///
/// Why `kernelbase` and not `kernel32`: kernel32!GetLocalTime is an export
/// *forwarder* — its "address" points at the ASCII forwarding string in
/// kernel32's export table, and writing code there corrupts the table the
/// shell's own resolver walks.
///
/// Date selection via `MAGICMIDA_V2_FAKE_TIME`: unset = don't patch,
/// `1` = 2000-06-15, otherwise `YYYY-MM-DD`.  2000 sits safely before the
/// expiry window of any 2005-2011 eval sample, so a `now > expiry` compare
/// keeps the trial "valid".
///
/// The stub preserves EDI (callee-saved — the earlier FAKE_WRITER trashed
/// it), points at the buffer through EAX, and returns with the stdcall
/// `ret 4`.  The earlier variant's `add esp,4; ret` popped the *argument
/// value* into EIP, sending the shell into the SYSTEMTIME buffer — the real
/// cause of the 1024-AV loop at 0x1075404 that was first misread as a
/// self-modifying check block (see POSTMORTEMS).
///
/// Returns true when at least one API was patched.
#[cfg(target_arch = "x86")]
pub(super) fn patch_v2_fake_time(dbg: &mut ProcessSession) -> bool {
    let var = match std::env::var("MAGICMIDA_V2_FAKE_TIME") {
        Ok(v) => v,
        Err(_) => return false,
    };
    let (year, month, day) = match var.trim() {
        "1" | "" => (2000u16, 6u16, 15u16),
        date => {
            let parts: Vec<u16> = date
                .split('-')
                .map(str::trim)
                .filter_map(|p| p.parse().ok())
                .collect();
            if parts.len() != 3 {
                warn!(value = %date, "MAGICMIDA_V2_FAKE_TIME: expected 1 or YYYY-MM-DD — not patching");
                return false;
            }
            (parts[0], parts[1], parts[2])
        }
    };

    let mut stub: [u8; 34] = [
        0x8B, 0x44, 0x24, 0x04,              // mov eax, [esp+4]   (lpSystemTime)
        0xC7, 0x00, 0, 0, 0, 0,              // mov dword [eax],   {wYear, wMonth}
        0xC7, 0x40, 0x04, 0, 0, 0, 0,        // mov dword [eax+4], {wDayOfWeek, wDay}
        0xC7, 0x40, 0x08, 0, 0, 0, 0,        // mov dword [eax+8], {wHour, wMinute}
        0xC7, 0x40, 0x0C, 0, 0, 0, 0,        // mov dword [eax+12],{wSecond, wMilliseconds}
        0xC2, 0x04, 0x00,                    // ret 4 (stdcall, one pointer arg)
    ];
    stub[6..8].copy_from_slice(&year.to_le_bytes());
    stub[8..10].copy_from_slice(&month.to_le_bytes());
    stub[13..15].copy_from_slice(&4u16.to_le_bytes()); // wDayOfWeek: date compares don't read it
    stub[15..17].copy_from_slice(&day.to_le_bytes());
    stub[19..21].copy_from_slice(&12u16.to_le_bytes()); // wHour
    // wMinute / wSecond / wMilliseconds stay zero.

    let mut patched = 0;
    for name in ["GetLocalTime", "GetSystemTime"] {
        let addr = resolve_host_api("kernelbase.dll", name);
        if addr == 0 {
            warn!(api = name, "fake-time: kernelbase export not resolved in host");
            continue;
        }
        // The target's loader maps kernelbase a moment after the main thread
        // resumes; poll until the API's first bytes are readable.  The
        // shell's first time call is seconds away (decode phase), so the
        // race is safe by a wide margin.
        let mut original = [0u8; 4];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut ready = false;
        while std::time::Instant::now() < deadline {
            if dbg.read_memory(addr, &mut original).is_ok()
                && original != *b"KERN"
                && original != [0u8; 4]
            {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !ready {
            warn!(
                api = name,
                addr = format!("{addr:#x}"),
                "fake-time: API never became readable in the target — not patched"
            );
            continue;
        }
        match dbg.write_memory(addr, &stub) {
            Ok(_) => {
                patched += 1;
                info!(
                    api = name,
                    addr = format!("{addr:#x}"),
                    date = format!("{year}-{month:02}-{day:02}"),
                    "fake-time: API patched to return the fixed date"
                );
            }
            Err(e) => warn!(api = name, error = %e, "fake-time: write failed"),
        }
    }
    patched > 0
}

/// V2 bail-scene diagnostics, part 1: trap the shell's exit path so the
/// bail moment can be frozen and inspected (x86 targets).
///
/// Post-attach mode has no debug port, so an exit is invisible from
/// outside: one poll tick the process is alive, the next the handle
/// reports an exit code — with zero visibility into *why*.  Overwriting
/// ExitProcess's first two bytes with `jmp $` turns the bail into an
/// infinite spin at a known address; the poll loop then suspends the
/// thread and dumps the full scene (registers, stack, check block) while
/// everything is still live.
///
/// Patched: kernelbase!ExitProcess and kernel32!ExitProcess (the latter
/// skipped when its prologue reads `KERN`, i.e. it is an export
/// forwarder).  The bailtrace previously confirmed the shell executes
/// kernel32!ExitProcess (exec-BP fired at its address), and kernel32's
/// stub jumps into kernelbase — both are covered.
///
/// Returns every armed trap address (empty when `MAGICMIDA_V2_TRAP_EXIT`
/// is unset or no candidate was patchable).  All of them must be checked —
/// measured 2026-10-29: the shell resolved ExitProcess straight from
/// kernelbase (it spun in the kernelbase trap while the checker compared
/// only kernel32's address and the run timed out).
#[cfg(target_arch = "x86")]
pub(super) fn arm_v2_exit_trap(dbg: &mut ProcessSession) -> Vec<usize> {
    use std::time::Duration;

    if std::env::var("MAGICMIDA_V2_TRAP_EXIT").is_err() {
        return Vec::new();
    }
    const JMP_SELF: [u8; 2] = [0xEB, 0xFE];
    let mut armed = Vec::new();
    for (dll, func) in [
        ("kernelbase.dll", "ExitProcess"),
        ("kernel32.dll", "ExitProcess"),
        ("ntdll.dll", "RtlExitUserProcess"),
    ] {
        let addr = resolve_host_api(dll, func);
        if addr == 0 {
            continue;
        }
        // The module maps a moment after the main thread resumes; poll
        // until the first bytes are readable (and not a forwarder string).
        let mut original = [0u8; 4];
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let mut ready = false;
        while std::time::Instant::now() < deadline {
            if dbg.read_memory(addr, &mut original).is_ok()
                && original != *b"KERN"
                && original != [0u8; 4]
            {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !ready {
            warn!(dll, "V2 bail trap: exit API never became readable — skipped");
            continue;
        }
        match dbg.write_memory(addr, &JMP_SELF) {
            Ok(_) => {
                armed.push(addr);
                info!(dll, func, addr = format!("{addr:#x}"), "V2 bail trap armed (jmp $)");
            }
            Err(e) => warn!(dll, error = %e, "V2 bail trap: write failed"),
        }
    }
    armed
}

/// Sample the main thread's RIP/ESP (plus 64 B of code at RIP and 256 B of
/// stack, both read while the thread is suspended) without a debug port
/// (post-attach V2): SuspendThread + GetThreadContext + ResumeThread,
/// microseconds of stall.  Invisible to the shell's integrity checks — no
/// byte of the target is modified, unlike the ExitProcess/time-API patches
/// it detects within seconds (measured 2026-10-29).
#[cfg(target_arch = "x86")]
/// All thread IDs of `pid` via a ToolHelp thread snapshot.
///
/// Post-attach mode never sees CREATE_THREAD debug events, so the debugger's
/// thread map only knows the main thread — the workers that actually run the
/// licence check (measured 2026-10-30: main thread leaves the image at
/// ~0.36 s, dialog at ~1 s) are invisible to it.  This walks the system
/// snapshot instead.
#[cfg(target_arch = "x86")]
pub(super) fn list_target_thread_ids(pid: u32) -> Vec<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    // SAFETY: pid 0 = system-wide thread snapshot; handle closed below.
    let Ok(h_snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }) else {
        return Vec::new();
    };
    let mut te = THREADENTRY32::default();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
    let mut out = Vec::new();
    // SAFETY: h_snap is a valid snapshot handle; te is sized.
    if unsafe { Thread32First(h_snap, &mut te) }.is_ok() {
        loop {
            if te.th32OwnerProcessID == pid {
                out.push(te.th32ThreadID);
            }
            // SAFETY: h_snap is a valid snapshot handle; te is sized.
            if unsafe { Thread32Next(h_snap, &mut te) }.is_err() {
                break;
            }
        }
    }
    // SAFETY: handle from CreateToolhelp32Snapshot.
    unsafe {
        let _ = CloseHandle(h_snap);
    }
    out
}

/// Sample one worker thread's RIP + 64 B of code at RIP, by raw `tid`
/// (OpenThread — the debugger's thread map does not know post-attach
/// workers).  Suspend → context → read → resume; microseconds of stall.
#[cfg(target_arch = "x86")]
pub(super) fn sample_worker_rip(dbg: &ProcessSession, tid: u32) -> Option<(usize, Vec<u8>)> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    // SAFETY: tid from the snapshot; handle closed below.
    let h = unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
    }
    .ok()?;
    // SAFETY: valid thread handle.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        // SAFETY: no-op when the open failed the suspend.
        unsafe {
            let _ = CloseHandle(h);
        }
        return None;
    }
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0001_0003);
    // SAFETY: valid handle and sized CONTEXT.
    let got = unsafe { GetThreadContext(h, &mut ctx) }.is_ok();
    let mut code = vec![0u8; 64];
    if got {
        let _ = dbg.read_memory(ctx.Eip as usize, &mut code);
    }
    // SAFETY: thread suspended above.
    unsafe {
        let _ = ResumeThread(h);
    }
    // SAFETY: handle from OpenThread.
    unsafe {
        let _ = CloseHandle(h);
    }
    if got {
        Some((ctx.Eip as usize, code))
    } else {
        None
    }
}

#[cfg(target_arch = "x86")]
pub(super) fn sample_main_rip(dbg: &mut ProcessSession) -> Option<(usize, usize, Vec<u8>, Vec<u8>)> {
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let tid = dbg.main_thread_id();
    let h = dbg.thread_handle(tid).ok()?;
    // SAFETY: thread handle from the debugger's own map.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        return None;
    }
    let ctx = dbg.get_thread_context_control(tid).ok();
    let mut code = vec![0u8; 64];
    let mut stack = vec![0u8; 256];
    if let Some(c) = ctx.as_ref() {
        let _ = dbg.read_memory(c.Eip as usize, &mut code);
        let _ = dbg.read_memory(c.Esp as usize, &mut stack);
    }
    // SAFETY: thread was suspended above.
    unsafe {
        let _ = ResumeThread(h);
    }
    let ctx = ctx?;
    Some((ctx.Eip as usize, ctx.Esp as usize, code, stack))
}

/// V2 post-attach freeze-on-RIP: sample the main thread; when RIP's RVA
/// falls inside `[lo, hi)` the thread is LEFT SUSPENDED and the full bail
/// scene is dumped (see [`dump_v2_bail_scene`]) — this is the unpatched
/// alternative to the ExitProcess trap, which the shell's integrity checks
/// detect.  `MAGICMIDA_V2_FREEZE_RVA=<lo>-<hi>` (RVA, hex ok).
///
/// Returns true when the freeze fired (scene dumped, process terminated —
/// the caller ends the run).
#[cfg(target_arch = "x86")]
pub(super) fn freeze_v2_on_rip(
    dbg: &mut ProcessSession,
    range: (usize, usize),
    output_path: &Path,
    image_base: usize,
) -> bool {
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread, TerminateProcess};

    let Some((rip, _esp, _code, _stack)) = sample_main_rip(dbg) else {
        return false;
    };
    // In range: re-suspend (sample_main_rip resumed) and hold while the
    // scene is dumped.  Range values >= 0x400_000 are ABSOLUTE addresses
    // (the image is 0x372000, so no RVA is that large) — used to freeze
    // inside late-loaded DLLs the shell runs through (measured: the exit
    // path enters 0x62f00000-0x63200000).
    let in_range = if range.0 >= 0x400_000 {
        rip >= range.0 && rip < range.1
    } else {
        rip >= image_base + range.0 && rip < image_base + range.1
    };
    if !in_range {
        return false;
    }
    // In range: re-suspend (sample_main_rip resumed) and hold while the
    // scene is dumped.
    let tid = dbg.main_thread_id();
    let Ok(h) = dbg.thread_handle(tid) else {
        return false;
    };
    // SAFETY: thread handle from the debugger's own map.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        return false;
    }
    let Ok(ctx) = dbg.get_thread_context_control(tid) else {
        // SAFETY: thread was suspended above.
        unsafe {
            let _ = ResumeThread(h);
        }
        return false;
    };
    info!(
        rip = format!("{rip:#x}"),
        rva = format!("{:#x}", rip - image_base),
        range = format!("{:#x}-{:#x}", range.0, range.1),
        "V2 FREEZE: main thread inside the target range — dumping scene"
    );
    dump_v2_bail_scene(dbg, &ctx, output_path, image_base);
    // SAFETY: live PROCESS_ALL_ACCESS handle.
    unsafe {
        let _ = TerminateProcess(dbg.process_handle(), 0x2B);
    }
    true
}

/// Dump the frozen-scene evidence shared by the ExitProcess-trap and the
/// freeze-on-RIP paths: full register log, 4 KB stack at Esp (+ image-range
/// values), 128 bytes of code at every image-range stack value (the live
/// caller frames are plaintext at freeze time — the engine re-encrypts
/// blocks only after they return), 2 KB centred on the topmost return
/// address, and 4 KB at each known check-site region.
#[cfg(target_arch = "x86")]
fn dump_v2_bail_scene(
    dbg: &mut ProcessSession,
    ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
    output_path: &Path,
    image_base: usize,
) {
    let out_dir = output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = output_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "v2bail".to_string());
    let dump = |suffix: &str, addr: usize, len: usize| -> Option<PathBuf> {
        let mut buf = vec![0u8; len];
        let n = dbg.read_memory(addr, &mut buf).ok()?;
        buf.truncate(n);
        let path = out_dir.join(format!("{stem}.{suffix}"));
        std::fs::write(&path, &buf).ok()?;
        Some(path)
    };
    let rip = ctx.Eip as usize;

    info!(
        eip = format!("{rip:#x}"),
        esp = format!("{:#x}", ctx.Esp),
        ebp = format!("{:#x}", ctx.Ebp),
        eax = format!("{:#x}", ctx.Eax),
        ebx = format!("{:#x}", ctx.Ebx),
        ecx = format!("{:#x}", ctx.Ecx),
        edx = format!("{:#x}", ctx.Edx),
        esi = format!("{:#x}", ctx.Esi),
        edi = format!("{:#x}", ctx.Edi),
        "V2 BAIL SCENE: thread frozen — dumping"
    );

    // Stack: 4 KB from Esp, plus every dword that points into the image
    // (candidate return addresses into the check code), plus 128 bytes of
    // CODE at each such address — the live caller frames are plaintext at
    // trap time by construction (the engine re-encrypts blocks only after
    // they return, and these frames have not returned), unlike the
    // encrypted-at-rest engine pages the watch snapshots see.
    let esp = ctx.Esp as usize;
    let mut image_sites: Vec<usize> = Vec::new();
    if let Some(path) = dump("v2bail_stack.bin", esp, 0x1000) {
        info!(path = %path.display(), "V2 BAIL SCENE: stack dumped");
        let mut stack = vec![0u8; 0x1000];
        if dbg.read_memory(esp, &mut stack).is_ok() {
            for (i, w) in stack.chunks_exact(4).enumerate() {
                let v = u32::from_le_bytes(w.try_into().unwrap()) as usize;
                if v >= image_base && v < image_base + 0x400_000 {
                    info!(
                        off = i * 4,
                        value = format!("{v:#x}"),
                        rva = format!("{:#x}", v - image_base),
                        "V2 BAIL SCENE: stack value inside image"
                    );
                    image_sites.push(v);
                }
            }
        }
    }
    image_sites.sort_unstable();
    image_sites.dedup();
    let mut code_blob = Vec::new();
    for &site in &image_sites {
        let mut bytes = [0u8; 128];
        if dbg.read_memory(site, &mut bytes).is_ok() {
            code_blob.extend_from_slice(&(site as u32).to_le_bytes());
            code_blob.extend_from_slice(&128u32.to_le_bytes());
            code_blob.extend_from_slice(&bytes);
            info!(
                addr = format!("{site:#x}"),
                rva = format!("{:#x}", site - image_base),
                head = format!("{:02x?}", &bytes[..16]),
                "V2 BAIL SCENE: code at return address"
            );
        }
    }
    if !code_blob.is_empty() {
        let path = out_dir.join(format!("{stem}.v2bail_code.bin"));
        match std::fs::write(&path, &code_blob) {
            Ok(()) => info!(path = %path.display(), "V2 BAIL SCENE: code at return addresses dumped"),
            Err(e) => warn!(error = %e, "V2 BAIL SCENE: code dump write failed"),
        }
    }
    // The direct caller of ExitProcess — 2 KB centred on the topmost
    // return address, whole-function context for offline disassembly.
    if let Some(&first) = image_sites.first() {
        let start = first.saturating_sub(0x400);
        if let Some(path) = dump("v2bail_caller.bin", start, 0x800) {
            info!(path = %path.display(), base = format!("{start:#x}"), "V2 BAIL SCENE: caller region dumped");
        }
    }
    for (name, rva) in [("v2bail_check1.bin", 0x75_000usize), ("v2bail_check2.bin", 0x102_000)] {
        match dump(name, image_base + rva, 0x1000) {
            Some(path) => info!(path = %path.display(), rva = format!("{rva:#x}"), "V2 BAIL SCENE: check-site region dumped"),
            None => warn!(rva = format!("{rva:#x}"), "V2 BAIL SCENE: check-site region unreadable"),
        }
    }

    // Module list at freeze time — identifies late-loaded DLLs the shell
    // executes through (the RIPSAMPLE trajectory showed the exit path
    // running inside 0x62f00000-0x63200000, a module no early scan sees).
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
            TH32CS_SNAPMODULE,
        };
        // SAFETY: pid is the live target's; handle closed below.
        if let Ok(h_snap) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dbg.pid()) } {
            let mut me = MODULEENTRY32W::default();
            me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
            // SAFETY: h_snap is a valid snapshot handle; me is sized.
            if unsafe { Module32FirstW(h_snap, &mut me) }.is_ok() {
                loop {
                    let name = String::from_utf16_lossy(&me.szModule)
                        .trim_end_matches('\0')
                        .to_string();
                    info!(
                        base = format!("{:#x}", me.modBaseAddr as usize),
                        size = me.modBaseSize,
                        name = %name,
                        "V2 BAIL SCENE: module"
                    );
                    // SAFETY: h_snap is a valid snapshot handle; me is sized.
                    if unsafe { Module32NextW(h_snap, &mut me) }.is_err() {
                        break;
                    }
                }
            }
            // SAFETY: handle from CreateToolhelp32Snapshot.
            unsafe {
                let _ = CloseHandle(h_snap);
            }
        }
    }

    // All-threads park map: the frozen main thread is often just the
    // *symptom* — the engine's wait typically depends on a worker's
    // completion.  Suspend every thread of the target and log where each
    // one is parked (RIP; match against the module list above offline).
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT};
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
            TH32CS_SNAPTHREAD,
        };
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
        };
        let pid = dbg.pid();
        // SAFETY: pid 0 = system-wide thread snapshot; handle closed below.
        if let Ok(h_snap) = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) } {
            let mut te = THREADENTRY32::default();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            // SAFETY: h_snap is a valid snapshot handle; te is sized.
            if unsafe { Thread32First(h_snap, &mut te) }.is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid {
                        // SAFETY: tid from the snapshot; handle closed below.
                        if let Ok(h) = unsafe {
                            OpenThread(
                                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                                false,
                                te.th32ThreadID,
                            )
                        } {
                            // SAFETY: valid thread handle.
                            let prev = unsafe { SuspendThread(h) };
                            if prev != u32::MAX {
                                let mut ctx = CONTEXT::default();
                                ctx.ContextFlags =
                                    windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(
                                        0x0001_0003,
                                    );
                                // SAFETY: valid handle and sized CONTEXT.
                                if unsafe { GetThreadContext(h, &mut ctx) }.is_ok() {
                                    info!(
                                        tid = te.th32ThreadID,
                                        is_main = te.th32ThreadID == dbg.main_thread_id(),
                                        eip = format!("{:#x}", ctx.Eip),
                                        esp = format!("{:#x}", ctx.Esp),
                                        "V2 BAIL SCENE: thread park"
                                    );
                                }
                                // SAFETY: thread suspended above.
                                unsafe {
                                    let _ = ResumeThread(h);
                                }
                            }
                            // SAFETY: handle from OpenThread.
                            unsafe {
                                let _ = CloseHandle(h);
                            }
                        }
                    }
                    // SAFETY: h_snap is a valid snapshot handle; te is sized.
                    if unsafe { Thread32Next(h_snap, &mut te) }.is_err() {
                        break;
                    }
                }
            }
            // SAFETY: handle from CreateToolhelp32Snapshot.
            unsafe {
                let _ = CloseHandle(h_snap);
            }
        }
    }
}

/// V2 bail-scene diagnostics via the ExitProcess trap: called on every
/// post-attach poll tick while a trap is armed.  Samples the main thread;
/// when RIP sits on a trap address the bail is in progress — the scene is
/// dumped while the thread stays suspended, the process is terminated, and
/// the caller ends the run.
#[cfg(target_arch = "x86")]
pub(super) fn check_v2_exit_trap(
    dbg: &mut ProcessSession,
    trap_addrs: &[usize],
    output_path: &Path,
    image_base: usize,
) -> bool {
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread, TerminateProcess};

    let tid = dbg.main_thread_id();
    let Ok(h) = dbg.thread_handle(tid) else {
        return false;
    };
    // SAFETY: thread handle from the debugger's own map.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        return false;
    }
    let ctx = match dbg.get_thread_context_control(tid) {
        Ok(c) => c,
        Err(_) => {
            // SAFETY: thread was suspended above.
            unsafe {
                let _ = ResumeThread(h);
            }
            return false;
        }
    };
    let rip = ctx.Eip as usize;
    if !trap_addrs.iter().any(|&t| rip >= t && rip <= t + 2) {
        // SAFETY: thread was suspended above.
        unsafe {
            let _ = ResumeThread(h);
        }
        return false;
    }
    dump_v2_bail_scene(dbg, &ctx, output_path, image_base);
    // The scene is on disk; the trapped process has nothing more to give.
    // SAFETY: live PROCESS_ALL_ACCESS handle.
    unsafe {
        let _ = TerminateProcess(dbg.process_handle(), 0x2B);
    }
    true
}

// ---------------------------------------------------------------------------
// Data section bounds
// ---------------------------------------------------------------------------



/// Spawn the dialog-killer thread: poll (50 ms) for a `#32770` dialog that
/// belongs to the target and terminate the target the moment one appears.
///
/// Why: on the interactive desktop the licence check ends by showing the
/// "CALC" hardware-lock dialog on the operator's screen.  The phase recorder
/// needs the interactive desktop to reach the check at all (the hidden
/// desktop parks the shell before the check), but the *check itself* runs
/// before the dialog — so the run is killed the instant the dialog exists.
/// Visible lifetime of the popup: one or two frames.
///
/// Gated by `MAGICMIDA_V2_DIALOG_KILL=1`.  Returns the join handle; the
/// thread self-terminates after killing, when the target dies first, or
/// after a 10-minute cap.
#[cfg(target_arch = "x86")]
pub(super) fn spawn_dialog_killer(
    pid: u32,
    h_process: HANDLE,
    image_base: usize,
    output_path: &Path,
    main_tid: u32,
) -> Option<std::thread::JoinHandle<()>> {

    let strpatch_arg = std::env::var("MAGICMIDA_V2_STRPATCH").ok();
    let sp_groups: Option<([u8; 4], [u8; 4])> = strpatch_arg.as_ref().and_then(|v| {
        let parts: Vec<&str> = v.split('|').collect();
        if parts.len() == 2 && parts[0].len() == 4 && parts[1].len() == 4 {
            let mut a = [0u8; 4];
            let mut b = [0u8; 4];
            for (i, ch) in parts[0].chars().enumerate() {
                a[i] = ch as u8;
            }
            for (i, ch) in parts[1].chars().enumerate() {
                b[i] = ch as u8;
            }
            Some((a, b))
        } else {
            None
        }
    });
    if strpatch_arg.is_some() && sp_groups.is_none() {
        info!("STRPATCH: bad argument, expected <4hex>|<4hex>");
        return None;
    }
    if std::env::var("MAGICMIDA_V2_DIALOG_KILL").is_err()
        && std::env::var("MAGICMIDA_V2_FAILFREEZE").is_err()
        && std::env::var("MAGICMIDA_V2_HASHPATCH").is_err()
        && std::env::var("MAGICMIDA_V2_PREFREEZE").is_err()
        && std::env::var("MAGICMIDA_V2_JNEPATCH").is_err()
        && std::env::var("MAGICMIDA_V2_REFTRACE").is_err()
        && std::env::var("MAGICMIDA_V2_REFHUNT").is_err()
        && std::env::var("MAGICMIDA_V2_SENTINEL").is_err()
        && std::env::var("MAGICMIDA_V2_NOWRITE").is_err()
        && std::env::var("MAGICMIDA_V2_VMDIFF").is_err()
        && std::env::var("MAGICMIDA_V2_LICPATCH").is_err()
        && std::env::var("MAGICMIDA_V2_SFREZE").is_err()
        && std::env::var("MAGICMIDA_V2_SFAKE").is_err()
        && sp_groups.is_none()
    {
        return None;
    }
    let handle_raw = h_process.0 as isize;
    let out_path = output_path.to_path_buf();
    let watch_t0 = std::time::Instant::now();
    let join = std::thread::spawn(move || {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::System::Threading::{SuspendThread, TerminateProcess};
        use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
        // The bail signature, measured 2026-10-31 (S1 snapshot 14, the
        // dialog-preceding state): the two fail-continuations written into
        // the state bank the moment the licence comparison fails.  The dialog
        // is created only AFTER the bail path runs, so killing on this
        // signature happens **before the window exists** — the operator sees
        // nothing, ever.
        //
        // 2026-11-01 (H6 banktrace + Y1test full-run banktrace): the 8-byte
        // pattern exists contiguously only for a 1-2 ms transient (H6 t=384);
        // the settled bail state scatters its halves (`ef e9 17 01` at +0x2e,
        // `22 25 18 01` at +0x36).  The stable marker across every
        // observation (H6 t=384/386, S1 snap_014, Y1test t=401) is
        // **contA == 0xFFFFA595** (bank+0x1E) — a negative counter the fail
        // write installs and nothing else produces.  Trigger on either.
        const BAIL_SIG: [u8; 8] = [0x19, 0x25, 0x18, 0x01, 0xef, 0xe9, 0x17, 0x01];
        const FAIL_MARK: u32 = 0xFFFF_A595;
        const BANK_RVA: usize = 0x28580;
        let bank_addr = image_base + BANK_RVA;
        let mut bank = [0u8; 64];
        let freeze_mode = std::env::var("MAGICMIDA_V2_FAILFREEZE").is_ok();
        // Licence-hash patch (`MAGICMIDA_V2_HASHPATCH=1`): the check's two
        // comparison operands, measured 2026-11-01 across independent runs
        // (S1 snapshot 14 vs Y2test failfreeze — byte-identical, i.e.
        // machine-derived and deterministic):
        //   computed fingerprint hash (this machine) = 50 fc 39 64 05 31 66 a5
        //     — written at the decision moment into the 0x9898-marked slot
        //     at RVA 0x224ED;
        //   stored licence hash = 2e 15 77 e5 1f ef 05 b3 ... (constant in
        //     every snapshot of every run) at RVA 0x2056F — the data pointer
        //     dwells exactly there (banktrace t=371) right before the
        //     compare.  Overwrite the stored value with the computed one the
        //     moment the blob materialises (post-decode, ~100 ms before the
        //     compare reads it) and the check passes on its own path.
        let hashpatch = std::env::var("MAGICMIDA_V2_HASHPATCH").is_ok();
        // JNE patch (`MAGICMIDA_V2_JNEPATCH=1`): the fingerprint checksum
        // comparison at rva 0x13ECF1 (`jne fail` = 75 0E) sits in a block
        // the engine decrypts just-in-time.  Poll the two bytes every tick;
        // the instant the block materialises, NOP the branch so the check
        // falls through to `mov eax, 1` (pass).  Race: decrypt→execute gap
        // unknown — measured by whether the bail marker still appears.
        let jnepatch = std::env::var("MAGICMIDA_V2_JNEPATCH").is_ok();
        // Reference trace (`MAGICMIDA_V2_REFTRACE=1`): tight-loop the
        // checksum-reference slot (rva 0x13ED07) and the formatted
        // fingerprint string buffer (rva 0x2056D — S1_009 caught the
        // formatter mid-write there, "1051-BCEC-14F2-0C18-", same buffer as
        // the 0x2056F blob) through the decision window.  Ring-records
        // every change; the bail-marker dump includes the ring.
        let reftrace = std::env::var("MAGICMIDA_V2_REFTRACE").is_ok();
        // String patch (`MAGICMIDA_V2_STRPATCH=<4hex>|<4hex>`): the licence
        // check's pass condition is rolchk(formatted fingerprint)[:16] == 0
        // (compare block 0x13ECC0-0x13ED06, cmp target measured 0).  The
        // argument holds two 4-char hex groups replacing groups 1 and 3 of
        // the fingerprint string, solved offline (numpy two-group search)
        // so the checksum's high word zeroes.  Patched into BOTH copies
        // (0x2056D display, 0x22899 checked); the formatter never revisits
        // early groups, so writing once the first four dashes show is
        // race-free (format completes ~1 ms after group 1).
        const JNE_RVA: usize = 0x13ECF1;
        let jne_addr = image_base + JNE_RVA;
        const JNE_SIG: [u8; 6] = [0x0f, 0x85, 0x0a, 0x00, 0x00, 0x00];
        let mut jne_buf = [0u8; 6];
        let mut jne_count = 0u32;
        // Ref hunt (`MAGICMIDA_V2_REFHUNT=1`): the licence compare block
        // (RVA 0x13ECC0, decrypted JIT) computes rol1-add over a dp-selected
        // buffer and compares high16 against a reference slot — but every
        // static address in it is disp+dp and the dp varies per VM op, so
        // offline models of "which buffer / which ref" keep failing (two
        // zero-hit solver sweeps, 2026-11-01).  Ground truth instead: the
        // path builder inside the callee appends a 4-char tail to the module
        // path at 0x22899 (~byte 100) — a REAL buffer change — right before
        // the compare.  Tight-loop the ref slots (0x13ED07..0F), the append
        // window (0x22899+96..+112) and the buffer head; on an append change
        // or a nonzero ref byte, suspend the main thread (~2 µs) and dump
        // the full scene — landing inside the callee tail / mid-compare with
        // the reference still resident.
        let refhunt = std::env::var("MAGICMIDA_V2_REFHUNT").is_ok();
        // Sentinel patch (`MAGICMIDA_V2_SENTINEL=1`): the three list-search
        // result slots (RVA 0x216F5 / 0x22D7D / 0x233FD, each {-1, ptr}) —
        // YS1 shows {-1,…} at bail, Y8 (2 ms pre-fail) shows {0,…}: the
        // searches run BETWEEN the rolchk compare and the fail write, and a
        // miss (-1) is what drives the fail continuation.  Tight-loop the
        // three slots; the instant a result dword turns 0xFFFFFFFF, write 0
        // (fake "found at index 0") to outrun the fail write.
        let sentinel = std::env::var("MAGICMIDA_V2_SENTINEL").is_ok();
        const SENT_RVAS: [usize; 3] = [0x216F5, 0x22D7D, 0x233FD];
        // Fail-write interception (`MAGICMIDA_V2_NOWRITE=1`): the fail
        // values (counter 0xFFFFA595 + the bail continuation pair) are not
        // static bytecode constants — they are prepared ON THE VM STACK at
        // 0xEFE70-0xEF000 (YJUtest scene) during the 1-2 ms window between
        // "compare done" (contA == 0x0102114D) and the fail write.  Rewrite
        // the prepared values to the bank's CURRENT contents so the write
        // becomes a no-op and the VM keeps its normal continuation.
        let nowrite = std::env::var("MAGICMIDA_V2_NOWRITE").is_ok();
        const STK_LO: usize = 0xEFD00;
        const STK_LEN: usize = 0xB00;
        let mut nowrite_patched = false;
        let mut nowrite_triggers = 0u32;
        // VM write-map (`MAGICMIDA_V2_VMDIFF=1`): the licence's fields are
        // decrypted into the VMCTX / private heap BEFORE the pre-decision
        // state (the E-string blob at 0x2056D is already resident at the
        // 331 ms freeze, YPF3test) — the patch window is ~100 ms wide, the
        // only unknown is WHERE the search lists land.  Snapshot both
        // regions every 10 ms, log (t, region, off, len) change runs, and
        // dump the log + the final images: the offline replay shows exactly
        // which ranges are written once and stable — the licence fields.
        let vmdiff = std::env::var("MAGICMIDA_V2_VMDIFF").is_ok();
        // Licence-field patch (`MAGICMIDA_V2_LICPATCH=1`): the VMDIFF map
        // (YVD2test) dated the licence decryption to t=208 ms and exposed
        // 19 hash-looking 4-byte fields scattered around the three sentinel
        // slots (0x216F5 / 0x22D7D / 0x233FD) — the search lists.  The
        // search keys are the post-search sentinel d1 values 0x7DC80DE6 /
        // 0x022869C8 (run-stable, machine-derived; slot 3's d1 varies per
        // run).  From t=280 ms (fields resident, searches ~410 ms) keep the
        // fields filled with both keys, alternating, so every scan hits.
        let licpatch = std::env::var("MAGICMIDA_V2_LICPATCH").is_ok();
        // Search-freeze (`MAGICMIDA_V2_SFREZE=1`): the black-box field
        // patches are exhausted (LICPATCH survives 19/19 and still fails),
        // so catch a search op LIVE: us-cadence poll of the bank + sentinel
        // slot 1's result dword; the moment it turns 0xFFFFFFFF (search 1
        // just wrote its miss) SuspendThread the main thread (~2 us) -- the
        // freeze lands inside the search handler or 1-2 ops after it, with
        // the registers / bank / VM stack holding the search's remnants.
        // Record the bank-state ring through the whole decision window.
        let sfreze = std::env::var("MAGICMIDA_V2_SFREZE").is_ok();
        // Search-fake (`MAGICMIDA_V2_SFAKE=1`): the debug-port route is
        // dead (the V2 attach gate withholds the .text decryption —
        // upstream C-8), so machine-precision intervention has to be
        // port-free: a NO-SLEEP loop that reads all three sentinel result
        // dwords every ~5 us and rewrites any 0xFFFFFFFF to 0 the moment
        // it appears.  The fail write lands ~60 us after the last search
        // (SFREZE ring), so a slot-based fail decision loses to this; a
        // register-based one does not — the run's outcome decides which.
        let sfake = std::env::var("MAGICMIDA_V2_SFAKE").is_ok();
        const SFAKE_SLOTS: [usize; 3] = [0x216F5, 0x22D7D, 0x233FD];
        const LIC_FIELDS: [usize; 19] = [
            0x20415, 0x20659, 0x21621, 0x21761, 0x21871, 0x2192D, 0x219C1,
            0x21CE5, 0x22C09, 0x22CF5, 0x22DC9, 0x22E85, 0x22ECD, 0x23001,
            0x23055, 0x230A5, 0x230D5, 0x23375, 0x235E5,
        ];
        const LIC_KEY1: u32 = 0x7DC8_0DE6;
        const LIC_KEY2: u32 = 0x0228_69C8;
        // Pre-freeze (`MAGICMIDA_V2_PREFREEZE=1`): freeze on the LAST
        // pre-decision bank state (Y1test banktrace t=399: contA=0x0102114d,
        // contB=0x0110344f) — the thread is then still inside the compare
        // op, registers/stack pointing at the live operands.  The fail
        // write follows ~1-2 ms later; the fail-marker branch below stays
        // as the fallback when this state is missed.
        let prefreeze = std::env::var("MAGICMIDA_V2_PREFREEZE").is_ok();
        const PRE_CONTA: u32 = 0x0102_114d;
        const PRE_CONTB: u32 = 0x0110_344f;
        const STORED_SIG: [u8; 8] = [0x2e, 0x15, 0x77, 0xe5, 0x1f, 0xef, 0x05, 0xb3];
        const COMPUTED: [u8; 8] = [0x50, 0xfc, 0x39, 0x64, 0x05, 0x31, 0x66, 0xa5];
        const STORED_RVA: usize = 0x2056F;
        let stored_addr = image_base + STORED_RVA;
        let mut stored = [0u8; 8];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        // Hot path: pre-open the main thread so a trigger suspends the VM
        // with ONE SuspendThread (~2 µs) before the ToolHelp walk for the
        // remaining threads (~300 µs) — the compare op lives 2-20 µs, so
        // freeze latency is the whole race (µs ring, 2026-11-01).
        let h_main = (|| {
            use windows::Win32::System::Threading::{
                OpenThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
                THREAD_SUSPEND_RESUME,
            };
            // SAFETY: tid from the debugger's own main-thread record.
            unsafe {
                OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                    false,
                    main_tid,
                )
            }
            .ok()
        })();
        loop {
            // VM write-map: snapshot-diff the VMCTX + private heap through
            // the licence-decryption window; the change log maps the fields.
            if vmdiff && watch_t0.elapsed().as_millis() >= 100 {
                use std::time::Instant;
                let t0 = Instant::now();
                let mut cont_buf = [0u8; 8];
                // (region id, base, len)
                const REGS: [(u8, usize, usize); 2] =
                    [(0, 0, 0x8000), (1, 0x1150000, 0x40000)];
                let mut last: Vec<Vec<u8>> = REGS.iter().map(|(_, _, l)| vec![0u8; *l]).collect();
                let mut cur = vec![0u8; 0x40000];
                let mut recs: Vec<(u32, u8, u32, u32, Vec<u8>)> = Vec::new();
                let mut primed = [false; 2];
                loop {
                    // Bail protection: on the fail marker dump the scene and
                    // the log (the searches have run by then — their lists
                    // are in the final images).
                    let ok_m = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cont_buf.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if !ok_m {
                        break;
                    }
                    let ca = u32::from_le_bytes(cont_buf[0..4].try_into().unwrap());
                    if ca == FAIL_MARK {
                        info!("VMDIFF: bail marker — dumping scene + write map");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_vmdiff(&out_path, &recs, &REGS);
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    let t_ms = watch_t0.elapsed().as_millis() as u32;
                    for (rid, base, len) in REGS {
                        let addr = if base == 0 { image_base + 0x20000 } else { base };
                        cur[..len].copy_from_slice(&last[rid as usize][..len]);
                        // SAFETY: live PROCESS_ALL_ACCESS handle.
                        let ok = unsafe {
                            let mut n = 0;
                            ReadProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                addr as *const core::ffi::c_void,
                                cur.as_mut_ptr() as *mut core::ffi::c_void,
                                len,
                                Some(&mut n),
                            )
                            .is_ok()
                                && n == len
                        };
                        if !ok {
                            continue;
                        }
                        if !primed[rid as usize] {
                            primed[rid as usize] = true;
                            recs.push((t_ms, rid, 0, len as u32, cur[..len].to_vec()));
                        } else {
                            let mut i = 0usize;
                            while i < len {
                                if cur[i] != last[rid as usize][i] {
                                    let start = i;
                                    while i < len && cur[i] != last[rid as usize][i] {
                                        i += 1;
                                    }
                                    recs.push((
                                        t_ms,
                                        rid,
                                        start as u32,
                                        (i - start) as u32,
                                        cur[start..i].to_vec(),
                                    ));
                                } else {
                                    i += 1;
                                }
                            }
                        }
                        last[rid as usize][..len].copy_from_slice(&cur[..len]);
                    }
                    if t0.elapsed().as_millis() > 350 {
                        info!(
                            records = recs.len(),
                            "VMDIFF: window over — writing map, switching to bail watch"
                        );
                        dump_vmdiff(&out_path, &recs, &REGS);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                // Light bail watch for the rest of the run (the dialog must
                // never reach the screen even after the map is written).
                loop {
                    let ok_m = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cont_buf.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if !ok_m {
                        break;
                    }
                    let ca = u32::from_le_bytes(cont_buf[0..4].try_into().unwrap());
                    if ca == FAIL_MARK {
                        info!("VMDIFF: bail marker (late) — dumping scene");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    if std::time::Instant::now() > deadline {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                return;
            }
            // Hash patch: fire once, the instant the stored blob appears.
            if hashpatch {
                // SAFETY: live PROCESS_ALL_ACCESS handle.
                let got = unsafe {
                    let mut read: usize = 0;
                    let ok = ReadProcessMemory(
                        HANDLE(handle_raw as *mut core::ffi::c_void),
                        stored_addr as *const core::ffi::c_void,
                        stored.as_mut_ptr() as *mut core::ffi::c_void,
                        8,
                        Some(&mut read),
                    );
                    ok.is_ok() && read == 8
                };
                if got && stored == STORED_SIG {
                    // SAFETY: live handle; the target region is the shell's
                    // own decoded data slot (RW in the VMCTX page).
                    let wok = unsafe {
                        let mut written: usize = 0;
                        let ok = WriteProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            stored_addr as *mut core::ffi::c_void,
                            COMPUTED.as_ptr() as *const core::ffi::c_void,
                            8,
                            Some(&mut written),
                        );
                        ok.is_ok() && written == 8
                    };
                    info!(
                        addr = format!("{stored_addr:#x}"),
                        ok = wok,
                        "HASHPATCH: stored licence hash replaced with this machine's computed hash"
                    );
                }
            }
            // SAFETY: live PROCESS_ALL_ACCESS handle captured at spawn.
            let got = unsafe {
                let mut read: usize = 0;
                let ok = ReadProcessMemory(
                    HANDLE(handle_raw as *mut core::ffi::c_void),
                    bank_addr as *const core::ffi::c_void,
                    bank.as_mut_ptr() as *mut core::ffi::c_void,
                    bank.len(),
                    Some(&mut read),
                );
                ok.is_ok() && read == bank.len()
            };
            let cont_a = u32::from_le_bytes(bank[0x1e..0x22].try_into().unwrap());
            let cont_b = u32::from_le_bytes(bank[0x22..0x26].try_into().unwrap());
            let pre_hit = prefreeze && got && cont_a == PRE_CONTA && cont_b == PRE_CONTB;
            let mark = got && (bank.windows(8).any(|w| w == BAIL_SIG) || cont_a == FAIL_MARK);
            if pre_hit {
                dump_failfreeze_scene(
                    pid,
                    HANDLE(handle_raw as *mut core::ffi::c_void),
                    image_base,
                    &out_path,
                );
                info!("PREFREEZE: compare-op scene dumped (thread still inside the check)");
                // Leave suspended; the outer timeout reaps the process.
                return;
            }
            if mark {
                if freeze_mode || prefreeze {
                    dump_failfreeze_scene(
                        pid,
                        HANDLE(handle_raw as *mut core::ffi::c_void),
                        image_base,
                        &out_path,
                    );
                }
                // SAFETY: live handle.
                unsafe {
                    let _ = TerminateProcess(
                        HANDLE(handle_raw as *mut core::ffi::c_void),
                        0x2C,
                    );
                }
                info!(
                    failfreeze = freeze_mode,
                    "BAIL-KILL: licence check failed (bank marker) — target handled before the dialog"
                );
                return;
            }
            // Licence-field patch: keep the search lists filled with the
            // machine's search keys through the decision window.
            if licpatch && watch_t0.elapsed().as_millis() >= 280 {
                let mut cont_buf_l = [0u8; 8];
                let mut writes = 0u32;
                loop {
                    // SAFETY: live PROCESS_ALL_ACCESS handle.
                    let ok_m = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cont_buf_l.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if !ok_m {
                        break;
                    }
                    let ca = u32::from_le_bytes(cont_buf_l[0..4].try_into().unwrap());
                    if ca == FAIL_MARK {
                        info!(writes, "LICPATCH: bail marker — dumping scene");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    for (i, rva) in LIC_FIELDS.iter().enumerate() {
                        let v = if i % 2 == 0 { LIC_KEY1 } else { LIC_KEY2 };
                        let vb = v.to_le_bytes();
                        // SAFETY: live handle; the licence's decrypted field.
                        let wok = unsafe {
                            let mut w = 0;
                            WriteProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                (image_base + rva) as *mut core::ffi::c_void,
                                vb.as_ptr() as *const core::ffi::c_void,
                                4,
                                Some(&mut w),
                            )
                            .is_ok()
                                && w == 4
                        };
                        if wok && i == 0 {
                            writes += 1;
                        }
                    }
                    if watch_t0.elapsed().as_millis() > 450 {
                        info!(writes, "LICPATCH: window over — check survived the patch");
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                return;
            }
            // JNE patch: re-poll for the whole lifetime.  YJPtest (2026-11-01)
            // proved the patch lands (`ok=true`) yet the bail still fired:
            // the check runs in TWO rounds and the block re-decrypts per
            // round, so a fire-once patch only covers round 1.  Keep the
            // NO-SLEEP tight poll alive (RPM of 6 bytes is ~1-2 µs) and
            // re-NOP the signature every time it reappears.
            //
            // 2026-11-01: the real branch is the 6-byte jne rel32
            // `0f 85 0a 00 00 00` at 0x13ECF1 (fail = mov eax,0), NOT the
            // 2-byte `75 0E` this mode originally polled for — that wrong
            // pattern is why JNEPATCH never fired (every failfreeze dump
            // shows the same decrypted block).  NOP all 6 bytes so every
            // instance of the generic rolchk block falls through to
            // `mov eax, 1` (pass).
            if jnepatch {
                use std::time::Instant;
                let mut s_patched = [false; 3];
                let mut s_vals = [[0u8; 8]; 3];
                let mut all_patched_at: Option<Instant> = None;
                loop {
                    // SAFETY: live PROCESS_ALL_ACCESS handle.
                    let got = unsafe {
                        let mut read: usize = 0;
                        let ok = ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            jne_addr as *const core::ffi::c_void,
                            jne_buf.as_mut_ptr() as *mut core::ffi::c_void,
                            6,
                            Some(&mut read),
                        );
                        ok.is_ok() && read == 6
                    };
                    if !got {
                        break; // process died
                    }
                    if jne_buf == JNE_SIG {
                        const NOP6: [u8; 6] = [0x90; 6];
                        // SAFETY: live handle; target = the engine's own
                        // decrypted handler block (RW while executing).
                        let wok = unsafe {
                            let mut written: usize = 0;
                            let ok = WriteProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                jne_addr as *mut core::ffi::c_void,
                                NOP6.as_ptr() as *const core::ffi::c_void,
                                6,
                                Some(&mut written),
                            );
                            ok.is_ok() && written == 6
                        };
                        jne_count += 1;
                        info!(
                            addr = format!("{jne_addr:#x}"),
                            ok = wok, count = jne_count,
                            "JNEPATCH: fingerprint-check jne nop'd (0f85 0a -> x6 90)"
                        );
                        // no break: keep watching for re-decrypts
                    }
                    // Sentinel checks ride in the SAME loop (YJTtest: a
                    // handover-based split missed the decision window — the
                    // searches run ~410 ms after watch_t0, before any
                    // handover deadline).  Fake every miss to index 0.
                    if sentinel {
                        for i in 0..3 {
                            if s_patched[i] {
                                continue;
                            }
                            let saddr = image_base + SENT_RVAS[i];
                            // SAFETY: live PROCESS_ALL_ACCESS handle.
                            let ok = unsafe {
                                let mut n = 0;
                                ReadProcessMemory(
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    saddr as *const core::ffi::c_void,
                                    s_vals[i].as_mut_ptr() as *mut core::ffi::c_void,
                                    8,
                                    Some(&mut n),
                                )
                                .is_ok()
                                    && n == 8
                            };
                            if ok && s_vals[i][0..4] == [0xff, 0xff, 0xff, 0xff] {
                                let zero = 0u32.to_le_bytes();
                                // SAFETY: live handle; VM data slot (RW).
                                let wok = unsafe {
                                    let mut w = 0;
                                    WriteProcessMemory(
                                        HANDLE(handle_raw as *mut core::ffi::c_void),
                                        saddr as *mut core::ffi::c_void,
                                        zero.as_ptr() as *const core::ffi::c_void,
                                        4,
                                        Some(&mut w),
                                    )
                                    .is_ok()
                                        && w == 4
                                };
                                s_patched[i] = wok;
                                info!(
                                    rva = format!("{:#x}", SENT_RVAS[i]),
                                    ok = wok,
                                    "SENTINEL: miss result faked to index 0"
                                );
                            }
                        }
                        if s_patched.iter().all(|&p| p) {
                            if let Some(t) = all_patched_at {
                                if t.elapsed().as_millis() > 80 {
                                    info!(
                                        "SENTINEL: no fail marker after patch — check survived"
                                    );
                                    return;
                                }
                            } else {
                                all_patched_at = Some(Instant::now());
                            }
                        }
                    }
                    // Bail protection inside the tight poll: the outer
                    // loop's BAIL-KILL never runs while this spins, and the
                    // dialog must never reach the screen.
                    let mut cb = [0u8; 8];
                    let okm = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cb.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if okm {
                        let ca = u32::from_le_bytes(cb[0..4].try_into().unwrap());
                        if ca == FAIL_MARK {
                            if freeze_mode {
                                dump_failfreeze_scene(
                                    pid,
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    image_base,
                                    &out_path,
                                );
                            }
                            unsafe {
                                let _ = TerminateProcess(
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    0x2C,
                                );
                            }
                            info!(
                                count = jne_count,
                                patched = ?s_patched,
                                "BAIL-KILL: licence check failed despite patches"
                            );
                            return;
                        }
                    }
                    if std::time::Instant::now() > deadline {
                        return;
                    }
                }
                // fall through to the rest of the outer loop (sentinel etc.)
            }
            // Fail-write interception: while the check sits in its pre-fail
            // window (contA == 0x0102114D, Y8/YJUtest), rewrite the prepared
            // fail values on the VM stack to the bank's current contents —
            // the fail write then re-installs what is already there.
            // Fail-write interception: scan the VM-stack window CONTINUOUSLY
            // (YNXtest: the prepared values are pushed AFTER the
            // contA==0x0102114D window ends, so the trigger must be the
            // pattern itself, not the bank state) and rewrite the prepared
            // fail values to the bank's current contents the moment they
            // materialise.
            if nowrite && got && watch_t0.elapsed().as_millis() >= 300 {
                nowrite_triggers += 1;
                if nowrite_triggers <= 3 {
                    info!(
                        t_ms = watch_t0.elapsed().as_millis() as u32,
                        triggers = nowrite_triggers,
                        "NOWRITE: scanning stack window"
                    );
                }
                let mut stk = [0u8; STK_LEN];
                // SAFETY: live PROCESS_ALL_ACCESS handle; absolute VM-stack
                // window (stable 0xEFD00-0xF0000 across every observation).
                let ok_r = unsafe {
                    let mut n = 0;
                    ReadProcessMemory(
                        HANDLE(handle_raw as *mut core::ffi::c_void),
                        STK_LO as *const core::ffi::c_void,
                        stk.as_mut_ptr() as *mut core::ffi::c_void,
                        stk.len(),
                        Some(&mut n),
                    )
                    .is_ok()
                        && n == stk.len()
                };
                if ok_r {
                    let v36: [u8; 4] = bank[0x36..0x3A].try_into().unwrap();
                    let v2e: [u8; 4] = bank[0x2E..0x32].try_into().unwrap();
                    let ca_b = cont_a.to_le_bytes();
                    let mut n_changes = 0usize;
                    let mut i = 0usize;
                    while i + 4 <= stk.len() {
                        let w = &stk[i..i + 4];
                        if w == [0x95, 0xa5, 0xff, 0xff] {
                            stk[i..i + 4].copy_from_slice(&ca_b);
                            n_changes += 1;
                        } else if w == [0x23, 0x25, 0x18, 0x01]
                            || w == [0x22, 0x25, 0x18, 0x01]
                            || w == [0x19, 0x25, 0x18, 0x01]
                        {
                            stk[i..i + 4].copy_from_slice(&v36);
                            n_changes += 1;
                        } else if w == [0xef, 0xe9, 0x17, 0x01] {
                            stk[i..i + 4].copy_from_slice(&v2e);
                            n_changes += 1;
                        }
                        i += 4;
                    }
                    if n_changes > 0 {
                        // SAFETY: live handle; the shell's prepared frame.
                        let wok = unsafe {
                            let mut w = 0;
                            WriteProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                STK_LO as *mut core::ffi::c_void,
                                stk.as_ptr() as *const core::ffi::c_void,
                                stk.len(),
                                Some(&mut w),
                            )
                            .is_ok()
                                && w == stk.len()
                        };
                        info!(
                            changes = n_changes,
                            ok = wok,
                            "NOWRITE: prepared fail values rewritten to current bank state"
                        );
                        nowrite_patched = true;
                    }
                }
            }
            if nowrite && nowrite_patched && watch_t0.elapsed().as_millis() > 500 {
                info!("NOWRITE: past the decision with no fail marker — check survived");
                return;
            }
            if sentinel && watch_t0.elapsed().as_millis() >= 250 {
                use std::time::Instant;
                let t0 = Instant::now();
                let mut patched = [false; 3];
                let mut all_patched_at: Option<Instant> = None;
                let mut vals = [[0u8; 8]; 3];
                let mut cont_buf = [0u8; 8];
                loop {
                    // Bail protection / attribution: the dialog must never
                    // reach the screen; if the fail write fires anyway the
                    // scene shows which gate rejected the fake hits.
                    let ok_m = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cont_buf.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if !ok_m {
                        break;
                    }
                    let ca = u32::from_le_bytes(cont_buf[0..4].try_into().unwrap());
                    if ca == FAIL_MARK {
                        info!("SENTINEL: bail marker fired — dumping scene");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    for i in 0..3 {
                        if patched[i] {
                            continue;
                        }
                        let addr = image_base + SENT_RVAS[i];
                        // SAFETY: live PROCESS_ALL_ACCESS handle.
                        let ok = unsafe {
                            let mut n = 0;
                            ReadProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                addr as *const core::ffi::c_void,
                                vals[i].as_mut_ptr() as *mut core::ffi::c_void,
                                8,
                                Some(&mut n),
                            )
                            .is_ok()
                                && n == 8
                        };
                        if ok && vals[i][0..4] == [0xff, 0xff, 0xff, 0xff] {
                            let zero = 0u32.to_le_bytes();
                            // SAFETY: live handle; VM data slot (RW).
                            let wok = unsafe {
                                let mut w = 0;
                                WriteProcessMemory(
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    addr as *mut core::ffi::c_void,
                                    zero.as_ptr() as *const core::ffi::c_void,
                                    4,
                                    Some(&mut w),
                                )
                                .is_ok()
                                    && w == 4
                            };
                            patched[i] = wok;
                            info!(
                                rva = format!("{:#x}", SENT_RVAS[i]),
                                ok = wok,
                                "SENTINEL: miss result faked to index 0"
                            );
                        }
                    }
                    if patched.iter().all(|&p| p) {
                        if all_patched_at.is_none() {
                            all_patched_at = Some(Instant::now());
                        }
                        // 80 ms without a fail marker = the shell accepted
                        // the fake hits and moved on; release the target.
                        if all_patched_at.unwrap().elapsed().as_millis() > 80 {
                            info!("SENTINEL: no fail marker after patch — check survived");
                            return;
                        }
                    }
                    if t0.elapsed().as_millis() > 600 {
                        info!(patched = ?patched, "SENTINEL: window over");
                        return;
                    }
                }
                return;
            }
            if std::time::Instant::now() > deadline {
                return;
            }
            if refhunt && watch_t0.elapsed().as_millis() >= 250 {
                use std::time::Instant;
                let t0 = Instant::now();
                let mut ring: Vec<(u32, u32, u32, [u8; 24])> = Vec::with_capacity(4096);
                let mut last_ref = [0u8; 8];
                let mut last_app = [0u8; 16];
                let mut last_buf = [0u8; 24];
                loop {
                    // Bail protection: the dialog must never reach the screen.
                    let mut cont_buf = [0u8; 8];
                    let ok_m = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cont_buf.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if !ok_m {
                        break;
                    }
                    let ca = u32::from_le_bytes(cont_buf[0..4].try_into().unwrap());
                    if ca == FAIL_MARK {
                        info!("REFHUNT: bail marker (no ref seen) — dumping scene");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_refhunt(&out_path, &ring);
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    // ref slots (two dp candidates), append window, buffer head
                    let mut r8 = [0u8; 8];
                    let mut ap = [0u8; 16];
                    let mut bf = [0u8; 24];
                    let ok1 = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (image_base + 0x13ED07) as *const core::ffi::c_void,
                            r8.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    let ok2 = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (image_base + 0x22899 + 96) as *const core::ffi::c_void,
                            ap.as_mut_ptr() as *mut core::ffi::c_void,
                            16,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 16
                    };
                    let ok3 = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (image_base + 0x22899) as *const core::ffi::c_void,
                            bf.as_mut_ptr() as *mut core::ffi::c_void,
                            24,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 24
                    };
                    if ok1 && r8 != last_ref {
                        let mut rec = [0u8; 24];
                        rec[..8].copy_from_slice(&r8);
                        ring.push((t0.elapsed().as_micros() as u32, 0x13ED07, 0, rec));
                        last_ref = r8;
                    }
                    if ok2 && ap != last_app {
                        let mut rec = [0u8; 24];
                        rec[..16].copy_from_slice(&ap);
                        ring.push((
                            t0.elapsed().as_micros() as u32,
                            0x22899 + 96,
                            0,
                            rec,
                        ));
                        last_app = ap;
                    }
                    if ok3 && bf != last_buf {
                        ring.push((t0.elapsed().as_micros() as u32, 0x22899, 0, bf));
                        last_buf = bf;
                    }
                    let ref_nonzero = ok1 && r8.iter().any(|&b| b != 0);
                    // Trigger: the append window just changed (the callee's
                    // tail write — the last buffer mutation before the
                    // compare) or the ref went nonzero.
                    let app_just_changed = ring
                        .last()
                        .map(|(_, tg, _, _)| *tg == 0x22899 + 96)
                        .unwrap_or(false);
                    if ref_nonzero || app_just_changed {
                        info!(
                            t_us = t0.elapsed().as_micros() as u32,
                            ref_nonzero, append = app_just_changed,
                            "REFHUNT: trigger — freezing mid-check"
                        );
                        if let Some(h) = h_main {
                            unsafe {
                                let _ = SuspendThread(h);
                            }
                        }
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_refhunt(&out_path, &ring);
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    if t0.elapsed().as_millis() > 350 {
                        info!(records = ring.len(), "REFHUNT: window over without trigger");
                        if !ring.is_empty() {
                            dump_refhunt(&out_path, &ring);
                        }
                        return;
                    }
                }
                return;
            }
            if let Some((sp_g1, sp_g2)) = sp_groups {
                // Wait out the 300 ms gate.  The first version entered here
                // at thread start (elapsed ≈ 0), saw the gate unmet and fell
                // into the `return` below — the watch thread died silently
                // and all 10 STRPATCH runs never wrote a byte
                // (strpatch_bg_status.txt, 2026-11-01).  The bail marker
                // cannot fire before ~400 ms (decision t≈412 ms after
                // watch_t0, reftrace YCtest), so a sleep-wait needs no
                // marker polling.
                while watch_t0.elapsed().as_millis() < 300 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                {
                    // Tight loop: watch both string buffers; the moment the
                    // formatted fingerprint shows its first four dashes,
                    // write the solved groups.  Keep the bail-marker check
                    // alive so popup protection never stalls (YAtest).
                    // Load matters: the heavy 130-byte-per-iteration loops
                    // (YAtest/YFtest) pushed the shell into its park path;
                    // the light reftrace loops never did.  Read contA only
                    // (8 B) for the marker and alternate 24 B string reads.
                    let targets = [0x2056Dusize, 0x22899usize];
                    let mut buf = [0u8; 24];
                    let mut cont_buf = [0u8; 8];
                    let mut flip = 0usize;
                    // Diagnostics (`MAGICMIDA_V2_STRDIAG=1`, with STRPATCH):
                    // ring-record every buffer change and RPM failure at both
                    // targets through the window.  Flags: 1 = RPM failed,
                    // 2 = our written bytes were no longer visible on a later
                    // read (shell restored/re-encrypted).  Answers directly:
                    // does the checked copy (0x22899) ever hold the dash
                    // pattern, and do writes stick.
                    let strdiag = std::env::var("MAGICMIDA_V2_STRDIAG").is_ok();
                    let mut diag_ring: Vec<(u32, u32, u32, [u8; 24])> =
                        Vec::with_capacity(8192);
                    let mut diag_last = [[0u8; 24]; 2];
                    let mut diag_pend = [false; 2];
                    let mut diag_fails = [0u32; 2];
                    let mut diag_writes = [0u32; 2];
                    let diag_t0 = std::time::Instant::now();
                    loop {
                        // SAFETY: live PROCESS_ALL_ACCESS handle.
                        let ok_bank = unsafe {
                            let mut read: usize = 0;
                            let ok = ReadProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                (bank_addr + 0x1E) as *const core::ffi::c_void,
                                cont_buf.as_mut_ptr() as *mut core::ffi::c_void,
                                8,
                                Some(&mut read),
                            );
                            ok.is_ok() && read == 8
                        };
                        if !ok_bank {
                            if strdiag {
                                dump_strdiag(&out_path, &diag_ring, diag_fails, diag_writes);
                            }
                            break;
                        }
                        flip ^= 1;
                        let tgt = targets[flip];
                        // SAFETY: live handle.
                        let ok = unsafe {
                            let mut n = 0;
                            ReadProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                (image_base + tgt) as *const core::ffi::c_void,
                                buf.as_mut_ptr() as *mut core::ffi::c_void,
                                buf.len(),
                                Some(&mut n),
                            )
                            .is_ok()
                                && n == buf.len()
                        };
                        if ok {
                            let dashes = buf[4] == b'-' && buf[9] == b'-'
                                && buf[14] == b'-' && buf[19] == b'-';
                            let already = buf[0..4] == sp_g1 && buf[10..14] == sp_g2;
                            if dashes && !already {
                                // SAFETY: live handle; shell string scratch.
                                let wok = unsafe {
                                    let mut w1 = 0usize;
                                    let ok1 = WriteProcessMemory(
                                        HANDLE(handle_raw as *mut core::ffi::c_void),
                                        (image_base + tgt) as *mut core::ffi::c_void,
                                        sp_g1.as_ptr() as *const core::ffi::c_void,
                                        4,
                                        Some(&mut w1),
                                    );
                                    let mut w2 = 0usize;
                                    let ok2 = WriteProcessMemory(
                                        HANDLE(handle_raw as *mut core::ffi::c_void),
                                        (image_base + tgt + 10) as *mut core::ffi::c_void,
                                        sp_g2.as_ptr() as *const core::ffi::c_void,
                                        4,
                                        Some(&mut w2),
                                    );
                                    ok1.is_ok() && w1 == 4 && ok2.is_ok() && w2 == 4
                                };
                                info!(
                                    addr = format!("{:#x}", image_base + tgt),
                                    ok = wok,
                                    "STRPATCH: solved groups written"
                                );
                                if strdiag {
                                    diag_writes[flip] =
                                        diag_writes[flip].saturating_add(1);
                                    diag_pend[flip] = true;
                                }
                            }
                        }
                        if strdiag {
                            let t_us = diag_t0.elapsed().as_micros() as u32;
                            if !ok {
                                diag_fails[flip] = diag_fails[flip].saturating_add(1);
                                if diag_ring.len() < 16384 {
                                    diag_ring.push((t_us, tgt as u32, 1, [0u8; 24]));
                                }
                            } else if diag_pend[flip] {
                                diag_pend[flip] = false;
                                if buf[0..4] != sp_g1 && diag_ring.len() < 16384 {
                                    diag_ring.push((t_us, tgt as u32, 2, buf));
                                    diag_last[flip] = buf;
                                }
                            } else if buf != diag_last[flip] && diag_ring.len() < 16384 {
                                diag_ring.push((t_us, tgt as u32, 0, buf));
                                diag_last[flip] = buf;
                            }
                        }
                        let ca = u32::from_le_bytes(cont_buf[0..4].try_into().unwrap());
                        if ca == FAIL_MARK {
                            info!("STRPATCH: bail marker still fired — dumping scene");
                            if strdiag {
                                dump_strdiag(&out_path, &diag_ring, diag_fails, diag_writes);
                            }
                            dump_failfreeze_scene(
                                pid,
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                image_base,
                                &out_path,
                            );
                            // SAFETY: live handle.
                            unsafe {
                                let _ = TerminateProcess(
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    0x2C,
                                );
                            }
                            return;
                        }
                        if watch_t0.elapsed().as_millis() > 600 {
                            info!("STRPATCH: window over (no marker) — shell survived the check");
                            if strdiag {
                                dump_strdiag(&out_path, &diag_ring, diag_fails, diag_writes);
                            }
                            return;
                        }
                    }
                }
                return;
            }
            if reftrace && watch_t0.elapsed().as_millis() >= 300 {
                use std::time::Instant;
                let t0 = Instant::now();
                let mut ring: Vec<(u32, [u8; 8], [u8; 48])> = Vec::with_capacity(512);
                let mut last_ref = [0u8; 8];
                let last_str = [0u8; 48];
                loop {
                    // SAFETY: live PROCESS_ALL_ACCESS handle.
                    let ok_bank = unsafe {
                        let mut read: usize = 0;
                        let ok = ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            bank_addr as *const core::ffi::c_void,
                            bank.as_mut_ptr() as *mut core::ffi::c_void,
                            bank.len(),
                            Some(&mut read),
                        );
                        ok.is_ok() && read == bank.len()
                    };
                    if !ok_bank {
                        break;
                    }
                    // v4: the string read tripled the loop period and the
                    // reference transient slipped between samples — but the
                    // string-completion moment IS the compare window (264µs
                    // wide, YCtest): when the 39-char string is complete,
                    // freeze immediately.  The scene then holds the run's
                    // own mutated compare block (plaintext) + the reference
                    // in a register or its per-run slot.
                    let mut r = [0u8; 8];
                    let mut st = [0u8; 48];
                    // SAFETY: live handle.
                    let ok_str = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (image_base + 0x2056D) as *const core::ffi::c_void,
                            st.as_mut_ptr() as *mut core::ffi::c_void,
                            48,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 48
                    };
                    if ok_str
                        && st[0..4] == *b"1051"
                        && st[35..39] == *b"2536"
                    {
                        info!(
                            t_us = t0.elapsed().as_micros() as u32,
                            "REFTRACE: fingerprint string complete — freezing mid-compare"
                        );
                        // SAFETY: pre-opened main-thread handle.
                        if let Some(h) = h_main {
                            unsafe {
                                let _ = SuspendThread(h);
                            }
                        }
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_reftrace(&out_path, &ring);
                        // Leave suspended; the outer timeout reaps.
                        return;
                    }
                    // SAFETY: live handle.
                    let ok1 = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (image_base + 0x13ED07) as *const core::ffi::c_void,
                            r.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if ok1 && r != last_ref {
                        ring.push((t0.elapsed().as_micros() as u32, r, last_str));
                        last_ref = r;
                        if ring.len() >= 4096 {
                            ring.remove(0);
                        }
                    }
                    let ca = u32::from_le_bytes(bank[0x1e..0x22].try_into().unwrap());
                    if ca == FAIL_MARK || bank.windows(8).any(|w| w == BAIL_SIG) {
                        info!(
                            t_us = t0.elapsed().as_micros() as u32,
                            records = ring.len(),
                            "REFTRACE: decision reached"
                        );
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_reftrace(&out_path, &ring);
                        // SAFETY: live handle.
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    if t0.elapsed().as_millis() > 500 {
                        info!(
                            records = ring.len(),
                            "REFTRACE: window ended without marker (run parked?)"
                        );
                        if !ring.is_empty() {
                            dump_reftrace(&out_path, &ring);
                        }
                        return;
                    }
                }
                return;
            }
            if sfreze && watch_t0.elapsed().as_millis() >= 280 {
                use std::time::Instant;
                let t0 = Instant::now();
                let mut cont_buf = [0u8; 8];
                let mut ring: Vec<(u32, u32, u32, u16)> = Vec::with_capacity(8192);
                let mut last_ca = 0u32;
                let mut last_cb = 0u32;
                let mut last_oi = 0u16;
                let mut s1 = [0u8; 4];
                loop {
                    // SAFETY: live PROCESS_ALL_ACCESS handle.
                    let ok_b = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            bank_addr as *const core::ffi::c_void,
                            bank.as_mut_ptr() as *mut core::ffi::c_void,
                            bank.len(),
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == bank.len()
                    };
                    if !ok_b {
                        break;
                    }
                    let ca = u32::from_le_bytes(bank[0x1e..0x22].try_into().unwrap());
                    let cb = u32::from_le_bytes(bank[0x22..0x26].try_into().unwrap());
                    let oi = u16::from_le_bytes(bank[0x3a..0x3c].try_into().unwrap());
                    if ca != last_ca || cb != last_cb || oi != last_oi {
                        ring.push((t0.elapsed().as_micros() as u32, ca, cb, oi));
                        if ring.len() >= 8192 {
                            ring.remove(0);
                        }
                        last_ca = ca;
                        last_cb = cb;
                        last_oi = oi;
                    }
                    if ca == FAIL_MARK {
                        info!(
                            ring = ring.len(),
                            "SFREZE: fail marker before the sentinel fired - dumping"
                        );
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_state_ring(&out_path, &ring);
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    // sentinel slot 1 (RVA 0x216F5) result dword
                    // SAFETY: live handle.
                    let ok_s = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (image_base + 0x216F5) as *const core::ffi::c_void,
                            s1.as_mut_ptr() as *mut core::ffi::c_void,
                            4,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 4
                    };
                    if ok_s && s1 == [0xff, 0xff, 0xff, 0xff] {
                        info!(
                            t_us = t0.elapsed().as_micros() as u32,
                            ring = ring.len(),
                            "SFREZE: sentinel miss written - freezing mid-search"
                        );
                        if let Some(h) = h_main {
                            unsafe {
                                let _ = SuspendThread(h);
                            }
                        }
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_state_ring(&out_path, &ring);
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    if t0.elapsed().as_millis() > 200 {
                        info!(ring = ring.len(), "SFREZE: window over without trigger");
                        dump_state_ring(&out_path, &ring);
                        // keep the bail watch alive (the dialog must never
                        // reach the screen even after the window)
                        loop {
                            // SAFETY: live handle.
                            let ok_m = unsafe {
                                let mut n = 0;
                                ReadProcessMemory(
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    (bank_addr + 0x1E) as *const core::ffi::c_void,
                                    cont_buf.as_mut_ptr() as *mut core::ffi::c_void,
                                    8,
                                    Some(&mut n),
                                )
                                .is_ok()
                                    && n == 8
                            };
                            if !ok_m {
                                break;
                            }
                            let ca2 =
                                u32::from_le_bytes(cont_buf[0..4].try_into().unwrap());
                            if ca2 == FAIL_MARK {
                                info!("SFREZE: late bail marker - dumping scene");
                                dump_failfreeze_scene(
                                    pid,
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    image_base,
                                    &out_path,
                                );
                                unsafe {
                                    let _ = TerminateProcess(
                                        HANDLE(handle_raw as *mut core::ffi::c_void),
                                        0x2C,
                                    );
                                }
                                return;
                            }
                            if std::time::Instant::now() > deadline {
                                return;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        return;
                    }
                }
                return;
            }
            if sfake && watch_t0.elapsed().as_millis() >= 280 {
                let mut fakes = 0u32;
                let mut sval = [0u8; 4];
                let zero = 0u32.to_le_bytes();
                let mut cont_buf_s = [0u8; 8];
                loop {
                    // Fail-marker check every ~50 us: heavier bank read.
                    let ok_m = unsafe {
                        let mut n = 0;
                        ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            (bank_addr + 0x1E) as *const core::ffi::c_void,
                            cont_buf_s.as_mut_ptr() as *mut core::ffi::c_void,
                            8,
                            Some(&mut n),
                        )
                        .is_ok()
                            && n == 8
                    };
                    if !ok_m {
                        break;
                    }
                    let ca = u32::from_le_bytes(cont_buf_s[0..4].try_into().unwrap());
                    if ca == FAIL_MARK {
                        info!(fakes, "SFAKE: bail marker - dumping scene");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    for rva in SFAKE_SLOTS {
                        // SAFETY: live PROCESS_ALL_ACCESS handle.
                        let ok = unsafe {
                            let mut n = 0;
                            ReadProcessMemory(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                (image_base + rva) as *const core::ffi::c_void,
                                sval.as_mut_ptr() as *mut core::ffi::c_void,
                                4,
                                Some(&mut n),
                            )
                            .is_ok()
                                && n == 4
                        };
                        if ok && sval == [0xff, 0xff, 0xff, 0xff] {
                            // SAFETY: live handle; the licence's result slot.
                            let wok = unsafe {
                                let mut w = 0;
                                WriteProcessMemory(
                                    HANDLE(handle_raw as *mut core::ffi::c_void),
                                    (image_base + rva) as *mut core::ffi::c_void,
                                    zero.as_ptr() as *const core::ffi::c_void,
                                    4,
                                    Some(&mut w),
                                )
                                .is_ok()
                                    && w == 4
                            };
                            if wok {
                                fakes += 1;
                            }
                        }
                    }
                    if watch_t0.elapsed().as_millis() > 450 {
                        info!(
                            fakes,
                            "SFAKE: past the decision with no fail marker - check survived"
                        );
                        return;
                    }
                }
            }
            if prefreeze {
                // µs-resolution state recorder: no sleep — the pre-decision
                // window is shorter than the 1 ms poll (Y6test missed it).
                // Ring of (t_us, contA, contB, opidx) is dumped with the
                // scene so the state sequence around the compare is ground
                // truth either way.
                use std::time::Instant;
                let t0 = Instant::now();
                let mut ring: Vec<(u32, u32, u32, u16)> = Vec::with_capacity(4096);
                loop {
                    // SAFETY: live PROCESS_ALL_ACCESS handle.
                    let got = unsafe {
                        let mut read: usize = 0;
                        let ok = ReadProcessMemory(
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            bank_addr as *const core::ffi::c_void,
                            bank.as_mut_ptr() as *mut core::ffi::c_void,
                            bank.len(),
                            Some(&mut read),
                        );
                        ok.is_ok() && read == bank.len()
                    };
                    if !got {
                        break; // process died
                    }
                    let ca = u32::from_le_bytes(bank[0x1e..0x22].try_into().unwrap());
                    let cb = u32::from_le_bytes(bank[0x22..0x26].try_into().unwrap());
                    let oi = u16::from_le_bytes(bank[0x3a..0x3c].try_into().unwrap());
                    let t_us = t0.elapsed().as_micros() as u32;
                    if ring.last().map(|r| (r.1, r.2, r.3)) != Some((ca, cb, oi)) {
                        ring.push((t_us, ca, cb, oi));
                        if ring.len() > 8192 {
                            ring.remove(0);
                        }
                    }
                    if ca == PRE_CONTA && cb == PRE_CONTB {
                        info!(t_us, "PREFREEZE: pre-decision state hit");
                        // SAFETY: pre-opened main-thread handle.
                        if let Some(h) = h_main {
                            unsafe {
                                let _ = SuspendThread(h);
                            }
                        }
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_state_ring(&out_path, &ring);
                        // Leave suspended; the outer timeout reaps the process.
                        return;
                    }
                    if bank.windows(8).any(|w| w == BAIL_SIG) || ca == FAIL_MARK {
                        info!(t_us, "PREFREEZE: fail marker first (pre-state missed) — dumping with ring");
                        dump_failfreeze_scene(
                            pid,
                            HANDLE(handle_raw as *mut core::ffi::c_void),
                            image_base,
                            &out_path,
                        );
                        dump_state_ring(&out_path, &ring);
                        // SAFETY: live handle.
                        unsafe {
                            let _ = TerminateProcess(
                                HANDLE(handle_raw as *mut core::ffi::c_void),
                                0x2C,
                            );
                        }
                        return;
                    }
                    if t0.elapsed().as_secs() > 120 {
                        return;
                    }
                }
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });
    Some(join)
}

/// VM write-map (`MAGICMIDA_V2_VMDIFF`): `VMD1` header + region table +
/// (t_ms, region, off, len, bytes) change records.  The offline replay
/// (zeros → records in order) reconstructs each region's state at any time;
/// ranges written once and stable = licence fields.
#[cfg(target_arch = "x86")]
fn dump_vmdiff(
    output_path: &Path,
    recs: &[(u32, u8, u32, u32, Vec<u8>)],
    regs: &[(u8, usize, usize)],
) {
    let stem = output_path.with_extension("v2vmdiff");
    let mut name = match stem.file_name() {
        Some(n) => n.to_os_string(),
        None => return,
    };
    name.push(".bin");
    let path = stem.with_file_name(name);
    let mut blob = Vec::with_capacity(16 + recs.iter().map(|r| r.4.len() + 11).sum::<usize>());
    blob.extend_from_slice(b"VMD1");
    blob.extend_from_slice(&(regs.len() as u32).to_le_bytes());
    for (rid, base, len) in regs {
        blob.extend_from_slice(&(*rid as u32).to_le_bytes());
        blob.extend_from_slice(&(*base as u32).to_le_bytes());
        blob.extend_from_slice(&(*len as u32).to_le_bytes());
    }
    for (t, rid, off, len, bytes) in recs {
        blob.extend_from_slice(&t.to_le_bytes());
        blob.push(*rid);
        blob.extend_from_slice(&off.to_le_bytes());
        blob.extend_from_slice(&len.to_le_bytes());
        blob.extend_from_slice(bytes);
    }
    match std::fs::write(&path, &blob) {
        Ok(()) => info!(path = %path.display(), records = recs.len(), "VMDIFF: map written"),
        Err(e) => warn!(error = %e, "VMDIFF: map write failed"),
    }
}

/// REFHUNT ring (`MAGICMIDA_V2_REFHUNT`): (t_us, tag, 0, 24 B) changes at
/// the ref slots (tag 0x13ED07), the append window (tag 0x22899+96) and the
/// buffer head (tag 0x22899) through the check window.
#[cfg(target_arch = "x86")]
fn dump_refhunt(output_path: &Path, ring: &[(u32, u32, u32, [u8; 24])]) {
    let stem = output_path.with_extension("v2refhunt");
    let mut name = match stem.file_name() {
        Some(n) => n.to_os_string(),
        None => return,
    };
    name.push(".bin");
    let path = stem.with_file_name(name);
    let mut blob = Vec::with_capacity(8 + ring.len() * 36);
    blob.extend_from_slice(b"RFG1");
    blob.extend_from_slice(&(ring.len() as u32).to_le_bytes());
    for (t, tag, fl, buf) in ring {
        blob.extend_from_slice(&t.to_le_bytes());
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&fl.to_le_bytes());
        blob.extend_from_slice(buf);
    }
    match std::fs::write(&path, &blob) {
        Ok(()) => info!(path = %path.display(), records = ring.len(), "REFHUNT: ring written"),
        Err(e) => warn!(error = %e, "REFHUNT: ring write failed"),
    }
}

/// STRDIAG ring (`MAGICMIDA_V2_STRDIAG`): buffer activity at the two
/// STRPATCH targets through the decision window.  Header `SDG1` +
/// (rpm_fail[2], writes[2], count) then (t_us, tgt, flags, 24 B) records;
/// flags 1 = RPM failed, 2 = written bytes no longer visible on a later
/// read, 0 = ordinary change.
#[cfg(target_arch = "x86")]
fn dump_strdiag(
    output_path: &Path,
    ring: &[(u32, u32, u32, [u8; 24])],
    fails: [u32; 2],
    writes: [u32; 2],
) {
    let stem = output_path.with_extension("v2strdiag");
    let mut name = match stem.file_name() {
        Some(n) => n.to_os_string(),
        None => return,
    };
    name.push(".bin");
    let path = stem.with_file_name(name);
    let mut blob = Vec::with_capacity(24 + ring.len() * 36);
    blob.extend_from_slice(b"SDG1");
    blob.extend_from_slice(&fails[0].to_le_bytes());
    blob.extend_from_slice(&fails[1].to_le_bytes());
    blob.extend_from_slice(&writes[0].to_le_bytes());
    blob.extend_from_slice(&writes[1].to_le_bytes());
    blob.extend_from_slice(&(ring.len() as u32).to_le_bytes());
    for (t, tgt, fl, buf) in ring {
        blob.extend_from_slice(&t.to_le_bytes());
        blob.extend_from_slice(&(*tgt as u32).to_le_bytes());
        blob.extend_from_slice(&fl.to_le_bytes());
        blob.extend_from_slice(buf);
    }
    match std::fs::write(&path, &blob) {
        Ok(()) => info!(path = %path.display(), records = ring.len(), "STRDIAG: ring written"),
        Err(e) => warn!(error = %e, "STRDIAG: ring write failed"),
    }
}

/// Reference-trace ring (`MAGICMIDA_V2_REFTRACE`): (t_us, ref@0x13ED07,
/// string@0x22899) changes through the decision window.
#[cfg(target_arch = "x86")]
fn dump_reftrace(output_path: &Path, ring: &[(u32, [u8; 8], [u8; 48])]) {
    let stem = output_path.with_extension("v2reftrace");
    let mut name = match stem.file_name() {
        Some(n) => n.to_os_string(),
        None => return,
    };
    name.push(".bin");
    let path = stem.with_file_name(name);
    let mut blob = Vec::with_capacity(ring.len() * 60);
    for (t, r, st) in ring {
        blob.extend_from_slice(&t.to_le_bytes());
        blob.extend_from_slice(r);
        blob.extend_from_slice(st);
    }
    match std::fs::write(&path, &blob) {
        Ok(()) => info!(path = %path.display(), records = ring.len(), "REFTRACE: ring written"),
        Err(e) => warn!(error = %e, "REFTRACE: ring write failed"),
    }
}

/// µs-resolution state ring (`MAGICMIDA_V2_PREFREEZE`): the observed bank
/// continuation sequence around the licence decision — the ground truth
/// for picking a freeze point the next round.
#[cfg(target_arch = "x86")]
fn dump_state_ring(output_path: &Path, ring: &[(u32, u32, u32, u16)]) {
    let stem = output_path.with_extension("v2statering");
    let mut name = match stem.file_name() {
        Some(n) => n.to_os_string(),
        None => return,
    };
    name.push(".bin");
    let path = stem.with_file_name(name);
    let mut blob = Vec::with_capacity(ring.len() * 14);
    for (t, ca, cb, oi) in ring {
        blob.extend_from_slice(&t.to_le_bytes());
        blob.extend_from_slice(&ca.to_le_bytes());
        blob.extend_from_slice(&cb.to_le_bytes());
        blob.extend_from_slice(&oi.to_le_bytes());
    }
    match std::fs::write(&path, &blob) {
        Ok(()) => info!(path = %path.display(), records = ring.len(), "PREFREEZE: state ring written"),
        Err(e) => warn!(error = %e, "PREFREEZE: ring write failed"),
    }
}

/// Fail-freeze scene dump (`MAGICMIDA_V2_FAILFREEZE=1`): the licence
/// comparison's two operands (computed fingerprint hash vs the hash stored
/// in the licence key) are materialised on the VM stack / VMCTX in the
/// 2 ms window around the fail-continuation write (banktrace 2026-11-01:
/// decision at t=399→401 ms in EVERY run, parked or not).  The watcher
/// thread catches the marker at 1 ms, suspends every target thread, and
/// this dumps everything the offline analysis needs — full image, state
/// bank, the VM stack region, VMCTX, and every thread's CONTEXT — then the
/// caller terminates.  Popup-free by construction (the dialog is seconds
/// away and the process never gets there).
#[cfg(target_arch = "x86")]
fn dump_failfreeze_scene(
    pid: u32,
    h_process: HANDLE,
    image_base: usize,
    output_path: &Path,
) -> Option<()> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT, ReadProcessMemory};
    use windows::Win32::System::Threading::{
        OpenThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
        THREAD_SUSPEND_RESUME,
    };
    use std::io::Write;

    let rpm = |addr: usize, buf: &mut [u8]| -> bool {
        // SAFETY: live PROCESS_ALL_ACCESS handle.
        unsafe {
            let mut read: usize = 0;
            let ok = ReadProcessMemory(
                h_process,
                addr as *const core::ffi::c_void,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len(),
                Some(&mut read),
            );
            ok.is_ok() && read == buf.len()
        }
    };

    // Suspend every thread of the target first (ToolHelp snapshot; the
    // debugger's thread map does not know post-attach workers).
    let mut handles = Vec::new();
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        if let Ok(h_snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut te = THREADENTRY32::default();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if Thread32First(h_snap, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid {
                        if let Ok(h) = OpenThread(
                            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                            false,
                            te.th32ThreadID,
                        ) {
                            let _ = SuspendThread(h);
                            handles.push((te.th32ThreadID, h));
                        }
                    }
                    if Thread32Next(h_snap, &mut te).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(h_snap);
        }
    }
    info!(threads = handles.len(), "FAILFREEZE: threads suspended");
    if handles.is_empty() {
        return None;
    }

    let stem = output_path.with_extension("v2failfreeze");
    let mut name = match stem.file_name() {
        Some(n) => n.to_os_string(),
        None => {
            warn!("FAILFREEZE: no file name in output path");
            return None;
        }
    };
    name.push(".bin");
    let snap = stem.with_file_name(name);
    let mut file = match std::fs::File::create(&snap) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, path = %snap.display(), "FAILFREEZE: create failed");
            return None;
        }
    };
    let sec = |f: &mut std::fs::File, tag: &[u8; 4], addr: usize, data: &[u8]| {
        let _ = f.write_all(tag);
        let _ = f.write_all(&(addr as u32).to_le_bytes());
        let _ = f.write_all(&(data.len() as u32).to_le_bytes());
        let _ = f.write_all(data);
    };

    // Thread contexts (raw, tagged per tid).
    for (tid, h) in &handles {
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0001_0003);
        // SAFETY: suspended thread handle opened above.
        if unsafe { GetThreadContext(*h, &mut ctx) }.is_ok() {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&ctx as *const CONTEXT) as *const u8,
                    std::mem::size_of::<CONTEXT>(),
                )
            };
            let _ = file.write_all(b"CTX ");
            let _ = file.write_all(&tid.to_le_bytes());
            let _ = file.write_all(&(bytes.len() as u32).to_le_bytes());
            let _ = file.write_all(bytes);
        }
    }

    // State bank.
    let mut bank = [0u8; 64];
    if rpm(image_base + 0x28580, &mut bank) {
        sec(&mut file, b"BANK", image_base + 0x28580, &bank);
    }
    // VM stack region (bank vmsp is corrupted post-write; the region is
    // stable at 0xefd00-0xf0000 across every observation).  2026-11-01
    // (Y7test): the real thread stack reaches BELOW 0xEFD00 — the main
    // thread's esp at freeze was 0xEFB34, and the compare frame's deeper
    // part sits at 0xEFC00-0xEFD00.  Widen to [0xEF800, 0xF7800).
    let mut vmstk = vec![0u8; 0x8000];
    if rpm(0xef800, &mut vmstk) {
        sec(&mut file, b"STCK", 0xef800, &vmstk);
    } else {
        // 0xEF800 is not always mapped (Y9test: RPM failed and the section
        // was silently skipped).  Fall back to the known-good window.
        let mut vmstk2 = vec![0u8; 0x3000];
        if rpm(0xefd00, &mut vmstk2) {
            sec(&mut file, b"STCK", 0xefd00, &vmstk2);
        }
    }
    // VMCTX / VM register file.
    let mut vmctx = vec![0u8; 0x8000];
    if rpm(image_base + 0x20000, &mut vmctx) {
        sec(&mut file, b"CTXM", image_base + 0x20000, &vmctx);
    }
    // Shell private heap (2026-11-01): the fail-handler / verdict code lives
    // OUTSIDE the image at ~0x1170000-0x118xxxx (the fail continuations
    // 0x1182519 / 0x117e9ef point here) — every scene so far missed it,
    // which is why the verdict block was never disassembled.
    // 2026-11-02 (YPF2test): the VM stack (vmsp=0x01163803) and the search
    // data pointer (bank+0x36 = 0x0115D00C) live at 0x115xxxx-0x116xxxx —
    // widen the window to cover the whole heap span.
    let mut priv_heap = vec![0u8; 0x40000];
    if rpm(0x1150000, &mut priv_heap) {
        sec(&mut file, b"PRIV", 0x1150000, &priv_heap);
    }
    // Full image.
    let mut img = vec![0u8; 0x371_000];
    if rpm(image_base + 0x1000, &mut img) {
        sec(&mut file, b"IMAG", image_base + 0x1000, &img);
    }
    // Dynamic high-heap regions (2026-11-02, 续 12): the VM's op blocks
    // (contA+dp) and stack (vmsp) live in the LargeAddressAware high heap
    // (0xE-0xFxxxxxxx) — never dumped before, which is why every op block
    // read looked like garbage.  Compute the ranges from the LIVE bank
    // (all threads are suspended: stable), read page-wise with a present
    // bitmap (a single RPM over a range with one unmapped page fails
    // whole).  Sections: b"HIHE" = the op block ±0x20000, b"HIST" = the
    // VM stack ±0x80000.
    const DP_BASE: u32 = 0xEEDC_0014; // 0x01028892 - 0x1226887E, dispatcher-derived
    let cont_a_hi = u32::from_le_bytes(bank[0x1e..0x22].try_into().unwrap());
    let vmsp = u32::from_le_bytes(bank[0x2a..0x2e].try_into().unwrap());
    let sparse = |f: &mut std::fs::File, tag: &[u8; 4], base: u32, span: u32| {
        let page = 0x1000u32;
        let npages = (span / page) as usize;
        let mut bitmap = vec![0u8; npages / 8 + 1];
        let mut data = Vec::with_capacity(span as usize);
        let mut present = 0usize;
        for p in 0..npages {
            let mut pbuf = [0u8; 0x1000];
            // SAFETY: live handle; each 4 KB page is probed independently.
            let ok = unsafe {
                let mut n = 0;
                ReadProcessMemory(
                    h_process,
                    (base.wrapping_add((p as u32).wrapping_mul(page))) as *const core::ffi::c_void,
                    pbuf.as_mut_ptr() as *mut core::ffi::c_void,
                    page as usize,
                    Some(&mut n),
                )
                .is_ok()
                    && n == page as usize
            };
            if ok {
                bitmap[p / 8] |= 1 << (p % 8);
                data.extend_from_slice(&pbuf);
                present += 1;
            }
        }
        let _ = f.write_all(tag);
        let _ = f.write_all(&base.to_le_bytes());
        let _ = f.write_all(&span.to_le_bytes());
        let _ = f.write_all(&(present as u32).to_le_bytes());
        let _ = f.write_all(&bitmap);
        let _ = f.write_all(&data);
    };
    let block_va = cont_a_hi.wrapping_add(DP_BASE);
    // Recon: query the two targets so a zero-present dump is attributable
    // (state/protection/region size) instead of a silent all-fail.
    {
        use windows::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
        for (label, va) in [("block", block_va), ("vmsp", vmsp)] {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: live handle; valid MBI.
            let q = unsafe {
                VirtualQueryEx(
                    h_process,
                    Some(va as *const core::ffi::c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            info!(
                label,
                va = format!("{va:08x}"),
                queried = q,
                state = format!("{:x}", mbi.State.0),
                protect = format!("{:x}", mbi.Protect.0),
                region = format!("{:x}", mbi.RegionSize),
                "SFREZE-SCENE: high-heap recon"
            );
        }
    }
    sparse(&mut file, b"HIHE", block_va.wrapping_sub(0x2_0000), 0x4_0000);
    sparse(&mut file, b"HIST", vmsp.wrapping_sub(0x8_0000), 0x10_0000);

    info!(path = %snap.display(), threads = handles.len(), "FAILFREEZE: scene dumped");
    // SAFETY: handles opened above.
    unsafe {
        for (_, h) in &handles {
            let _ = CloseHandle(*h);
        }
    }
    Some(())
}

/// .dat decrypt-routine hunt (`MAGICMIDA_V2_DATSCAN=1`, 2026-11-02 续 14):
/// the black-box patch routes are exhausted (the fail decision is
/// register-level), so the remaining path is licence FORGERY — recover the
/// .dat cipher.  Multi-needle full-space scan (the range runs to
/// 0xFFF00000: the LargeAddressAware high heap included; only MEM_PRIVATE
/// regions are scanned — the system DLLs are MEM_IMAGE and would blow the
/// budget).  Needles: the raw file head (81f8f14e…, the first 16 B of the
/// 480-byte licence file), the dashless fingerprint string, the registered
/// name.  When the file copy lands, its 480 B are SNAPSHOT-TRACKED every
/// tick — an in-place decrypt shows up as the snapshot morphing from the
/// raw form to the plaintext licence, which is the cipher's output (diff
/// vs the raw = the keystream).  Events are appended to
/// <stem>.v2datscan.bin: (tag u8, t_ms u32, addr u32, len u32, data).
#[cfg(target_arch = "x86")]
pub(super) struct DatScanState {
    pub file_addr: Option<usize>,
    pub file_raw: Option<Vec<u8>>,
    pub snaps: u32,
    pub seen_name: bool,
    pub seen_str: bool,
    pub clean_dumped: bool,
    pub log: Vec<u8>,
}

#[cfg(target_arch = "x86")]
impl Default for DatScanState {
    fn default() -> Self {
        Self {
            file_addr: None,
            file_raw: None,
            snaps: 0,
            seen_name: false,
            seen_str: false,
            clean_dumped: false,
            log: Vec::new(),
        }
    }
}

#[cfg(target_arch = "x86")]
pub(super) fn dat_scan_tick(
    dbg: &mut ProcessSession,
    st: &mut DatScanState,
    output_path: &Path,
    t_ms: u32,
) {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_NOACCESS,
    };

    // The first 16 bytes of CISC-1.dat (the campaign's fixed sample).
    const FILE_HEAD: &[u8] = &[
        0x81, 0xf8, 0xf1, 0x4e, 0xc7, 0x66, 0x56, 0x78, 0x67, 0x57, 0xed,
        0x71, 0xe0, 0xd7, 0xbd, 0x4c,
    ];
    const STR_DASHLESS: &[u8] = b"1051BCEC14F20C1837455E665E6D2536";
    const NAME: &[u8] = b"This application has been registered";
    const SCAN_CAP: usize = 256 << 20;
    const CHUNK: usize = 1 << 20;

    let h_process = dbg.process_handle();
    let log_event = |st: &mut DatScanState, tag: u8, addr: usize, data: &[u8]| {
        st.log.extend_from_slice(&[tag]);
        st.log.extend_from_slice(&t_ms.to_le_bytes());
        st.log.extend_from_slice(&(addr as u32).to_le_bytes());
        st.log.extend_from_slice(&(data.len() as u32).to_le_bytes());
        st.log.extend_from_slice(data);
    };

    // The file copy: found → snapshot-track it every tick (cheap: 480 B).
    if let Some(fa) = st.file_addr {
        let mut snap = vec![0u8; 480];
        // SAFETY: live PROCESS_ALL_ACCESS handle.
        let got = unsafe {
            let mut n = 0;
            ReadProcessMemory(
                h_process,
                fa as *const core::ffi::c_void,
                snap.as_mut_ptr() as *mut core::ffi::c_void,
                480,
                Some(&mut n),
            )
            .is_ok()
                && n == 480
        };
        if got {
            st.snaps += 1;
            let changed = st.file_raw.as_ref().map(|r| *r != snap).unwrap_or(true);
            if changed {
                log_event(st, 2, fa, &snap);
                st.file_raw = Some(snap);
            }
        }
        // The needle scans continue until both fields are seen.
        if st.seen_name && st.seen_str {
            return;
        }
    }

    // Full-space multi-needle scan (MEM_PRIVATE, committed, readable).
    let mut buf = vec![0u8; CHUNK];
    let mut scanned = 0usize;
    let mut addr = 0x1_0000usize;
    let mut found_file = st.file_addr;
    while addr < 0xFFF0_0000 && scanned < SCAN_CAP {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: valid process handle and sized MBI.
        let ok = unsafe {
            VirtualQueryEx(
                h_process,
                Some(addr as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ok == 0 {
            break;
        }
        let region = mbi.RegionSize as usize;
        let base = mbi.BaseAddress as usize;
        let committed = mbi.State == MEM_COMMIT;
        let private = mbi.Type == MEM_PRIVATE;
        let readable = mbi.Protect != PAGE_NOACCESS && mbi.Protect.0 != 0;
        if committed && private && readable && region >= 16 {
            let mut roff = 0usize;
            while roff < region && scanned < SCAN_CAP {
                let len = CHUNK.min(region - roff);
                let got = dbg.read_memory(base + roff, &mut buf[..len]).unwrap_or(0);
                if got >= 16 {
                    let slice = &buf[..got];
                    if found_file.is_none() {
                        if let Some(p) = slice.windows(FILE_HEAD.len()).position(|w| w == FILE_HEAD)
                        {
                            let hit = base + roff + p;
                            found_file = Some(hit);
                            st.file_addr = Some(hit);
                            info!(t_ms, addr = format!("{hit:#x}"), "DATSCAN: raw .dat copy found");
                            let mut snap = vec![0u8; 480];
                            // SAFETY: live handle.
                            let okr = unsafe {
                                let mut n = 0;
                                ReadProcessMemory(
                                    h_process,
                                    hit as *const core::ffi::c_void,
                                    snap.as_mut_ptr() as *mut core::ffi::c_void,
                                    480,
                                    Some(&mut n),
                                )
                                .is_ok()
                                    && n == 480
                            };
                            if okr {
                                st.file_raw = Some(snap.clone());
                                log_event(st, 1, hit, &snap);
                            }
                        }
                    }
                    if !st.seen_str {
                        if let Some(p) =
                            slice.windows(STR_DASHLESS.len()).position(|w| w == STR_DASHLESS)
                        {
                            let hit = base + roff + p;
                            st.seen_str = true;
                            info!(t_ms, addr = format!("{hit:#x}"), "DATSCAN: dashless fingerprint (raw) found");
                            let ctx = slice[p.saturating_sub(64)..(p + 128).min(got)].to_vec();
                            log_event(st, 4, hit.saturating_sub(64), &ctx);
                        }
                    }
                    if !st.seen_name {
                        if let Some(p) = slice.windows(NAME.len()).position(|w| w == NAME) {
                            let hit = base + roff + p;
                            st.seen_name = true;
                            info!(t_ms, addr = format!("{hit:#x}"), "DATSCAN: registered name (raw) found");
                            let ctx = slice[p.saturating_sub(64)..(p + 128).min(got)].to_vec();
                            log_event(st, 3, hit.saturating_sub(64), &ctx);
                        }
                    }
                }
                scanned += got;
                roff += CHUNK;
            }
        }
        addr = base.saturating_add(region);
    }
    if found_file.is_none() && st.file_addr.is_none() && t_ms > 0 && t_ms % 200 == 0 {
        info!(t_ms, scanned_mb = scanned >> 20, "DATSCAN: file copy not found yet");
    }
    // One-shot: dump the region containing the CLEAN (unobfuscated) shell
    // module.  The DATRIP capture found compiler-style code (ebp frames,
    // plain calls) at 0x00AA42BA — the same worker thread that runs the
    // licence work — while everything VM-side is obfuscated.  The module
    // is static code: dumping it once = the licence logic readable
    // offline.
    if !st.clean_dumped {
        use windows::Win32::System::Memory::VirtualQueryEx;
        let probe = 0x00AA42BAusize;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: live handle; valid MBI.
        let q = unsafe {
            VirtualQueryEx(
                h_process,
                Some(probe as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if q > 0
            && mbi.State == MEM_COMMIT
            && mbi.Protect != PAGE_NOACCESS
            && mbi.Protect.0 != 0
        {
            let rbase = mbi.BaseAddress as usize;
            let rlen = (mbi.RegionSize as usize).min(0x10_0000);
            let mut mod_buf = vec![0u8; rlen];
            // SAFETY: live handle; committed region.
            let okm = unsafe {
                let mut n = 0;
                ReadProcessMemory(
                    h_process,
                    rbase as *const core::ffi::c_void,
                    mod_buf.as_mut_ptr() as *mut core::ffi::c_void,
                    rlen,
                    Some(&mut n),
                )
                .is_ok()
                    && n == rlen
            };
            if okm {
                log_event(st, 5, rbase, &mod_buf);
                st.clean_dumped = true;
                info!(
                    t_ms,
                    base = format!("{rbase:#x}"),
                    len = rlen,
                    "DATSCAN: clean shell module dumped"
                );
            }
        } else {
            // Not mapped yet — retry on later ticks.
        }
    }

    // Flush the event log every tick (cheap, robust against a hard kill).
    let stem = output_path.with_extension("v2datscan");
    if let Some(name) = stem.file_name() {
        let mut n = name.to_os_string();
        n.push(".bin");
        let path = stem.with_file_name(n);
        let _ = std::fs::write(&path, &st.log);
    }
}

/// All-thread RIP sampling inside the .dat transform window
/// (`MAGICMIDA_V2_DATRIP=1`, 2026-11-02 续 15): the licence decryption
/// (t=182-208 ms) runs on a WORKER thread — the main-thread-only
/// RIPSAMPLE is blind here.  Every call samples up to 8 threads
/// (round-robin via a ToolHelp walk) with Suspend/GetContext/Resume and
/// records (t, tid, rip, esi, ebp, 64 B code at rip) to
/// <stem>.v2datrip.bin.  The decrypt routine's RIPs cluster in the
/// window; the code bytes at rip ARE its instructions.
#[cfg(target_arch = "x86")]
pub(super) struct DatRipState {
    pub threads: Vec<u32>,
    pub idx: usize,
    pub refreshed_at: Option<std::time::Instant>,
    pub clean_dumped: bool,
    pub written: std::io::BufWriter<std::fs::File>,
}

#[cfg(target_arch = "x86")]
pub(super) fn dat_rip_tick(dbg: &mut ProcessSession, st: &mut DatRipState, t_ms: u32) {
    use std::io::Write;
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, CONTEXT, ReadProcessMemory,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    if !(150..=260).contains(&t_ms) {
        if t_ms > 260 {
            // Window over: flush the samples to disk before the run ends.
            let _ = st.written.flush();
        }
        return;
    }
    let pid = dbg.pid();
    let h_process = dbg.process_handle();
    // Refresh the thread list every ~40 ms (the workers spawn continuously).
    let refresh = st
        .refreshed_at
        .map(|r| r.elapsed().as_millis() >= 40)
        .unwrap_or(true);
    if refresh {
        st.threads.clear();
        // SAFETY: standard ToolHelp snapshot walk.
        unsafe {
            if let Ok(h_snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
                let mut te = THREADENTRY32::default();
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                // SAFETY: fresh snapshot.
                if Thread32First(h_snap, &mut te).is_ok() {
                    loop {
                        if te.th32OwnerProcessID == pid {
                            st.threads.push(te.th32ThreadID);
                        }
                        if Thread32Next(h_snap, &mut te).is_err() {
                            break;
                        }
                    }
                }
                let _ = windows::Win32::Foundation::CloseHandle(h_snap);
            }
        }
        st.refreshed_at = Some(std::time::Instant::now());
    }
    // Every thread per tick (the clean-module bursts are short; 8 per tick
    // missed them in YTR8test — a full sweep is ~27 threads x ~100 us).
    let n = st.threads.len();
    if n == 0 {
        return;
    }
    for k in 0..n {
        let tid = st.threads[(st.idx + k) % n];
        // The workers are NOT in the debugger's thread map (post-attach =
        // no debug events) — OpenThread directly, close after each sample.
        use windows::Win32::System::Threading::{
            OpenThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
            THREAD_SUSPEND_RESUME,
        };
        // SAFETY: tid from the ToolHelp walk of the target's own threads.
        let Ok(h) = (unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                false,
                tid,
            )
        }) else {
            continue;
        };
        // SAFETY: freshly opened handle.
        let prev = unsafe { SuspendThread(h) };
        if prev == u32::MAX {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(h);
            }
            continue;
        }
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags =
            windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0001_0003);
        // SAFETY: suspended thread handle.
        let okc = unsafe { GetThreadContext(h, &mut ctx) }.is_ok();
        // SAFETY: thread was suspended above.
        unsafe {
            let _ = ResumeThread(h);
        }
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(h);
        }
        if !okc {
            continue;
        }
        let bytes = unsafe {
            std::slice::from_raw_parts((&ctx as *const CONTEXT) as *const u8, std::mem::size_of::<CONTEXT>())
        };
        let rd = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let (eip, esi, ebp) = (rd(0xB8), rd(0xA0), rd(0xB4));
        let mut code = vec![0u8; 64];
        let _ = dbg.read_memory(eip as usize, &mut code);
        // A sampled RIP outside the image and the system DLLs = the
        // shell's OWN native module (the clean licence code found at
        // 0x00AA42BA in YTR5test, compiler-style, same worker thread as
        // the licence work).  Dump its region once — static code = the
        // licence logic readable offline.
        let in_image = (0x1000000..0x1372000).contains(&(eip as usize));
        let in_sys = (0x77000000..0x78000000).contains(&(eip as usize));
        if !in_image && !in_sys && !st.clean_dumped {
            use windows::Win32::System::Memory::{
                VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
            };
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: live handle; valid MBI.
            let q = unsafe {
                VirtualQueryEx(
                    h_process,
                    Some(eip as *const core::ffi::c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if q > 0 && mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS {
                let rbase = mbi.BaseAddress as usize;
                let rlen = (mbi.RegionSize as usize).min(0x10_0000);
                let mut mod_buf = vec![0u8; rlen];
                // SAFETY: live handle; committed region.
                let okm = unsafe {
                    let mut n = 0;
                    ReadProcessMemory(
                        h_process,
                        rbase as *const core::ffi::c_void,
                        mod_buf.as_mut_ptr() as *mut core::ffi::c_void,
                        rlen,
                        Some(&mut n),
                    )
                    .is_ok()
                        && n == rlen
                };
                if okm {
                    let _ = st.written.write_all(&5u8.to_le_bytes());
                    let _ = st.written.write_all(&t_ms.to_le_bytes());
                    let _ = st.written.write_all(&(rbase as u32).to_le_bytes());
                    let _ = st.written.write_all(&(rlen as u32).to_le_bytes());
                    let _ = st.written.write_all(&mod_buf);
                    let _ = st.written.flush();
                    st.clean_dumped = true;
                    info!(
                        t_ms,
                        rip = format!("{eip:08x}"),
                        base = format!("{rbase:#x}"),
                        len = rlen,
                        "DATRIP: clean shell module region dumped"
                    );
                }
            }
        }
        // Record: (t, tid, rip, esi, ebp, code[64]).
        let _ = st.written.write_all(&t_ms.to_le_bytes());
        let _ = st.written.write_all(&tid.to_le_bytes());
        let _ = st.written.write_all(&eip.to_le_bytes());
        let _ = st.written.write_all(&esi.to_le_bytes());
        let _ = st.written.write_all(&ebp.to_le_bytes());
        let _ = st.written.write_all(&code);
    }
    st.idx = (st.idx + n) % n.max(1);
}

/// DR write-breakpoint arming (`MAGICMIDA_V2_DRBP=1`, 2026-11-02 续 13):/// DR write-breakpoint arming (`MAGICMIDA_V2_DRBP=1`, 2026-11-02 续 13):/// DR write-breakpoint arming (`MAGICMIDA_V2_DRBP=1`, 2026-11-02 续 13):/// DR write-breakpoint arming (`MAGICMIDA_V2_DRBP=1`, 2026-11-02 续 13):
/// suspend the main thread and point DR1-DR3 (NOT DR0 — the shell checks
/// DR0) at the three sentinel-slot result dwords, enabled as WRITE
/// breakpoints of 4 bytes (DR7 = 0xDDD00054: L1|L2|L3 + R/W=01 + LEN=11
/// per slot).  A search's miss store then traps at the instruction
/// boundary inside the search handler, and the debug loop's SingleStep
/// branch captures the handler's live registers.
#[cfg(target_arch = "x86")]
pub(super) fn arm_v2_dr_breakpoints(dbg: &mut ProcessSession, image_base: usize) {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let tid = dbg.main_thread_id();
    let h = match dbg.thread_handle(tid) {
        Ok(h) => h,
        Err(_) => return,
    };
    // SAFETY: thread handle from the debugger's own map.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        return;
    }
    let mut ctx = CONTEXT::default();
    // CONTEXT_DEBUG_REGISTERS on i386.
    ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0001_0010);
    // SAFETY: suspended thread handle.
    unsafe {
        let _ = GetThreadContext(h, &mut ctx);
    }
    let bytes = unsafe {
        std::slice::from_raw_parts_mut((&mut ctx as *mut CONTEXT) as *mut u8, std::mem::size_of::<CONTEXT>())
    };
    bytes[0x08..0x0C].copy_from_slice(&((image_base + 0x216F5) as u32).to_le_bytes()); // Dr1
    bytes[0x0C..0x10].copy_from_slice(&((image_base + 0x22D7D) as u32).to_le_bytes()); // Dr2
    bytes[0x10..0x14].copy_from_slice(&((image_base + 0x233FD) as u32).to_le_bytes()); // Dr3
    bytes[0x14..0x18].copy_from_slice(&0u32.to_le_bytes()); // Dr6: clear stale
    bytes[0x18..0x1C].copy_from_slice(&0xDDD0_0054u32.to_le_bytes()); // Dr7
    // SAFETY: suspended thread handle.
    unsafe {
        let _ = SetThreadContext(h, &ctx);
    }
    // SAFETY: thread was suspended above.
    unsafe {
        let _ = ResumeThread(h);
    }
    info!(
        dr1 = format!("{:#x}", image_base + 0x216F5),
        dr2 = format!("{:#x}", image_base + 0x22D7D),
        dr3 = format!("{:#x}", image_base + 0x233FD),
        "DRBP: DR1-3 write breakpoints armed on the sentinel slots"
    );
}

/// DR write-breakpoint hit (`MAGICMIDA_V2_DRBP`): called from the debug
/// loop on a SingleStep while armed.  Captures the search handler's live
/// registers to <stem>.v2drhit.bin, rewrites the triggered sentinel dword
/// to 0 (fake "hit at index 0" — machine precision, still inside the
/// handler before the fail continuation is queued), and clears the sticky
/// DR6 so the next trigger is attributable.
#[cfg(target_arch = "x86")]
pub(super) fn handle_v2_dr_hit(
    dbg: &mut ProcessSession,
    tid: u32,
    image_base: usize,
    output_path: &Path,
    hits: u32,
) {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT};

    let h = match dbg.thread_handle(tid) {
        Ok(h) => h,
        Err(_) => return,
    };
    let mut ctx = CONTEXT::default();
    // CONTROL | INTEGER | DEBUG_REGISTERS on i386.
    ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0001_0013);
    // SAFETY: stopped thread handle (the debug exception holds it).
    unsafe {
        let _ = GetThreadContext(h, &mut ctx);
    }
    let bytes = unsafe {
        std::slice::from_raw_parts((&ctx as *const CONTEXT) as *const u8, std::mem::size_of::<CONTEXT>())
    };
    let rd = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let (eip, eax, ecx, edx, ebx, esp, ebp, esi, edi) =
        (rd(0xB8), rd(0xB0), rd(0xAC), rd(0xA8), rd(0xA4), rd(0xC4), rd(0xB4), rd(0xA0), rd(0x9C));
    let dr6 = rd(0x14);
    let slot_rva: usize = if dr6 & 0x2 != 0 {
        0x216F5
    } else if dr6 & 0x4 != 0 {
        0x22D7D
    } else if dr6 & 0x8 != 0 {
        0x233FD
    } else {
        0
    };
    info!(
        hits,
        eip = format!("{eip:08x}"),
        eax = format!("{eax:08x}"),
        ecx = format!("{ecx:08x}"),
        edx = format!("{edx:08x}"),
        ebx = format!("{ebx:08x}"),
        esp = format!("{esp:08x}"),
        ebp = format!("{ebp:08x}"),
        esi = format!("{esi:08x}"),
        edi = format!("{edi:08x}"),
        dr6 = format!("{dr6:08x}"),
        slot = format!("{slot_rva:x}"),
        "DRBP: search-handler hit - registers captured, result faked to 0"
    );
    // Append the register record for offline semantics analysis.
    let stem = output_path.with_extension("v2drhit");
    if let Some(name) = stem.file_name() {
        let mut n = name.to_os_string();
        n.push(".bin");
        let path = stem.with_file_name(n);
        let mut rec = Vec::with_capacity(13 * 4);
        for v in [
            hits, tid, eip, eax, ecx, edx, ebx, esp, ebp, esi, edi, dr6,
            slot_rva as u32,
        ] {
            rec.extend_from_slice(&v.to_le_bytes());
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            use std::io::Write;
            let _ = f.write_all(&rec);
        }
    }
    // Machine-precision intervention: the miss (-1) is already stored (a
    // write BP traps after the store) — rewrite it to 0 = "found at index
    // 0" while the handler is still parked at the instruction boundary.
    if slot_rva != 0 {
        let _ = dbg.write_memory(image_base + slot_rva, &0u32.to_le_bytes());
    }
    // Clear the sticky DR6 so the next trigger is attributable.
    let mut c2 = CONTEXT::default();
    c2.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_FLAGS(0x0001_0010);
    let b2 = unsafe {
        std::slice::from_raw_parts_mut((&mut c2 as *mut CONTEXT) as *mut u8, std::mem::size_of::<CONTEXT>())
    };
    b2[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
    // SAFETY: stopped thread handle.
    unsafe {
        let _ = SetThreadContext(h, &c2);
    }
}

/// Fingerprint hunt (`MAGICMIDA_V2_FPHUNT=1`): scan the target image for
/// the hardware-fingerprint string the licence dialog prints ("BCEC-14F2…").
///
/// The check must materialise that string in memory while it runs, so the
/// first tick the scan finds it is a tick the check (or its data stage) is
/// live.  On a hit: the main thread is frozen (left suspended), the 256 KiB
/// around the hit plus the full bail scene are dumped, and the process is
/// terminated — all before the dialog can be created, so nothing reaches the
/// operator's screen.
///
/// Returns `true` when a hit was processed (caller ends the run).
#[cfg(target_arch = "x86")]
pub(super) fn fingerprint_hunt_tick(
    dbg: &mut ProcessSession,
    image_base: usize,
    output_path: &Path,
) -> bool {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
    };
    use windows::Win32::System::Threading::{SuspendThread, TerminateProcess};

    const NEEDLE: &[u8] = b"BCEC-14F2";
    // The same fingerprint in UTF-16 (dialogs are usually built wide).
    const NEEDLE_W: &[u8] = &[
        b'B', 0x00, b'C', 0x00, b'E', 0x00, b'C', 0x00, b'-', 0x00,
        b'1', 0x00, b'4', 0x00, b'F', 0x00, b'2', 0x00,
    ];
    // The fingerprint as raw little-endian WORDs (BCEC-14F2-0C16 …) — the
    // form the *check* most likely compares.  The dialog string is formatted
    // only at dialog time, which is why the ASCII scan never caught the
    // check itself.
    const NEEDLE_BIN: &[u8] = &[0xec, 0xbc, 0xf2, 0x14, 0x16, 0x0c];
    const SCAN_CAP: usize = 64 << 20; // 64 MiB per scan — bounds the RPM cost
    const CHUNK: usize = 1 << 20;

    let h_process = dbg.process_handle();
    let mut buf = vec![0u8; CHUNK];
    let mut scanned = 0usize;
    let mut hit_addr: Option<usize> = None;
    let mut hit_is_wide = false;
    let mut addr = 0x1_0000usize;
    while addr < 0x7FFF_0000 && hit_addr.is_none() && scanned < SCAN_CAP {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: valid process handle and sized MBI.
        let ok = unsafe {
            VirtualQueryEx(
                h_process,
                Some(addr as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ok == 0 {
            break;
        }
        let region = mbi.RegionSize as usize;
        let base = mbi.BaseAddress as usize;
        let committed = mbi.State == MEM_COMMIT;
        let readable = mbi.Protect != PAGE_NOACCESS && mbi.Protect.0 != 0;
        if committed && readable && region >= NEEDLE.len() {
            let mut roff = 0usize;
            while roff + NEEDLE.len() <= region && hit_addr.is_none() && scanned < SCAN_CAP {
                let len = CHUNK.min(region - roff);
                let got = dbg
                    .read_memory(base + roff, &mut buf[..len])
                    .unwrap_or(0);
                if got >= NEEDLE.len() {
                    let slice = &buf[..got];
                    let pos_a = slice.windows(NEEDLE.len()).position(|w| w == NEEDLE);
                    let pos_w = slice.windows(NEEDLE_W.len()).position(|w| w == NEEDLE_W);
                    let pos_b = slice.windows(NEEDLE_BIN.len()).position(|w| w == NEEDLE_BIN);
                    if let Some(pos) = pos_a.or(pos_w).or(pos_b) {
                        hit_addr = Some(base + roff + pos);
                        hit_is_wide = pos_w.is_some() && pos_a.is_none();
                    }
                }
                scanned += got;
                roff += CHUNK;
            }
        }
        addr = base.saturating_add(region);
    }
    let _ = image_base;
    let Some(hit_addr) = hit_addr else {
        return false;
    };
    info!(
        addr = format!("{hit_addr:#x}"),
        wide = hit_is_wide,
        scanned_mb = scanned >> 20,
        "FP-HUNT: fingerprint string materialised — freezing and dumping"
    );

    // Freeze the main thread and keep it suspended for the scene dump.
    let tid = dbg.main_thread_id();
    let Ok(h) = dbg.thread_handle(tid) else {
        return false;
    };
    // SAFETY: thread handle from the debugger's own map.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        return false;
    }
    let ctx = dbg.get_thread_context_control(tid).ok();

    // 256 KiB around the hit — the check code and its data stage.
    let dump_lo = hit_addr.saturating_sub(0x2_0000);
    let mut blob = vec![0u8; 0x4_0000];
    let got = dbg.read_memory(dump_lo, &mut blob).unwrap_or(0);
    blob.truncate(got);
    let out_dir = output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = output_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "v2fp".to_string());
    let path = out_dir.join(format!("{stem}.v2fphunt.bin"));
    match std::fs::write(&path, &blob) {
        Ok(()) => info!(
            path = %path.display(),
            base = format!("{dump_lo:#x}"),
            bytes = got,
            "FP-HUNT: check neighbourhood dumped"
        ),
        Err(e) => warn!(error = %e, "FP-HUNT: dump write failed"),
    }
    if let Some(ctx) = &ctx {
        dump_v2_bail_scene(dbg, ctx, output_path, image_base);
    }
    // SAFETY: live PROCESS_ALL_ACCESS handle.
    unsafe {
        let _ = TerminateProcess(dbg.process_handle(), 0x2D);
    }
    true
}

/// VM state snapshot (`MAGICMIDA_V2_VMSNAP[=<ms>]`): the mini-devirt data
/// collector.  Called from the recorder when a sample lands in the engine
/// pool at t ≥ gate (default 250 ms — the measured licence-check window is
/// ~298-371 ms).  Freezes the main thread **leaving it suspended**, dumps
/// everything the VM can plausibly be using, terminates the process, and
/// returns `true` (caller ends the run).
///
/// Dump layout (`<stem>.v2vmsnap.bin`), sequential tagged sections:
///   `REGS`  — the full x86 CONTEXT
///   `STACK` — 16 KiB at Esp
///   `EBP`   — 256 KiB at Ebp (the VM context base candidate)
///   `ESI`   — 64 KiB at Esi
///   `EDI`   — 64 KiB at Edi
///   `WS`    — 128 KiB at the known workspace 0x12200000
/// Each section: 4-byte tag, 4-byte address, 4-byte length, bytes.
///
/// One run = one slice of the check.  Several runs at different depths give
/// the diffs that locate the bytecode PC and the register bank.
#[cfg(target_arch = "x86")]
pub(super) fn vm_snapshot_tick(
    dbg: &mut ProcessSession,
    image_base: usize,
    output_path: &Path,
    snap_idx: usize,
) -> Option<Vec<u8>> {
    use windows::Win32::System::Threading::SuspendThread;

    const WS_BASE: usize = 0x1220_0000;
    const WS_LEN: usize = 0x2_0000;

    // Freeze and hold.
    let tid = dbg.main_thread_id();
    let Ok(h) = dbg.thread_handle(tid) else {
        return None;
    };
    // SAFETY: thread handle from the debugger's own map.
    let prev = unsafe { SuspendThread(h) };
    if prev == u32::MAX {
        return None;
    }
    let Ok(ctx) = dbg.get_thread_context_control(tid) else {
        // SAFETY: thread suspended above.
        unsafe {
            let _ = windows::Win32::System::Threading::ResumeThread(h);
        }
        return None;
    };

    let out_dir = output_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = output_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "v2vm".to_string());
    let path = out_dir.join(format!("{stem}.v2vmsnap_{snap_idx:03}.bin"));

    let mut file = match std::fs::File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "VMSNAP: create failed");
            // SAFETY: thread suspended above.
            unsafe {
                let _ = windows::Win32::System::Threading::ResumeThread(h);
            }
            return None;
        }
    };
    use std::io::Write;
    let sec = |f: &mut std::fs::File, tag: &[u8; 4], addr: usize, data: &[u8]| {
        let _ = f.write_all(tag);
        let _ = f.write_all(&(addr as u32).to_le_bytes());
        let _ = f.write_all(&(data.len() as u32).to_le_bytes());
        let _ = f.write_all(data);
    };

    // The check-phase code bytes at EIP — the caller records them.
    let mut code_at_eip = vec![0u8; 64];
    let _ = dbg.read_memory(ctx.Eip as usize, &mut code_at_eip);

    // REGS: the raw CONTEXT is the fastest honest capture.
    let regs_bytes = unsafe {
        std::slice::from_raw_parts(
            (&ctx as *const windows::Win32::System::Diagnostics::Debug::CONTEXT)
                as *const u8,
            std::mem::size_of::<windows::Win32::System::Diagnostics::Debug::CONTEXT>(),
        )
    };
    let _ = file.write_all(b"VMSN");
    let _ = file.write_all(&(regs_bytes.len() as u32).to_le_bytes());
    let _ = file.write_all(regs_bytes);

    // Stack window straddles esp: [esp-0x4000, esp+0x4000).  The VM pops
    // values and re-references them below the current esp (measured
    // 2026-11-01: every emulation of a freeze state diverged on exactly
    // those bytes — the above-esp-only capture left popped-but-alive data
    // uncaptured).  The STCK section address records where the read began.
    let esp = ctx.Esp as usize;
    let stk_base = esp.saturating_sub(0x4000);
    let mut stack = vec![0u8; 0x8000];
    let got = dbg.read_memory(stk_base, &mut stack).unwrap_or(0);
    stack.truncate(got);
    sec(&mut file, b"STCK", stk_base, &stack);

    // Full image dump.  The VM addressing is EBP-relative with wrap-around:
    // EBP = 0xEEDC0014 (measured) and displacements like 0x122624E5 sum back
    // into the image (0xEEDC0014 + 0x122624E5 mod 2^32 = 0x010224F9) — the
    // VM context/workspace lives at low image RVAs, so one image dump covers
    // the register bank, the bytecode, and the data stage in one file.
    let mut img = vec![0u8; 0x371_000];
    let got = dbg.read_memory(image_base + 0x1000, &mut img).unwrap_or(0);
    if got > 0 {
        img.truncate(got);
        sec(&mut file, b"IMAG", image_base + 0x1000, &img);
    }

    let mut ws = vec![0u8; WS_LEN];
    let got = dbg.read_memory(WS_BASE, &mut ws).unwrap_or(0);
    if got > 0 {
        ws.truncate(got);
        sec(&mut file, b"WKSP", WS_BASE, &ws);
    }

    drop(file);
    info!(
        path = %path.display(),
        idx = snap_idx,
        ebp = format!("{:#x}", ctx.Ebp),
        eip = format!("{:#x}", ctx.Eip),
        esp = format!("{:#x}", ctx.Esp),
        "VMSNAP: VM state captured (thread resumed)"
    );
    // Resume — one run yields a *sequence* of slices on one timeline, which
    // is what makes the diffs clean (cross-run diffs are time-skewed).
    // SAFETY: thread suspended above.
    unsafe {
        let _ = windows::Win32::System::Threading::ResumeThread(h);
    }
    Some(code_at_eip)
}

/// Message waker (`MAGICMIDA_V2_WAKE=1`): the V2 main thread parks in
/// `win32u!NtUserWaitMessage` (syscall 0x1100a — verified 2026-10-31 by
/// reading the stub's syscall number; earlier misread as 0x110a) — the
/// "wait for a thread message" API.  Posting **thread** messages (not
/// window messages — park runs have no window) should wake it and, if the
/// shell's engine is message-driven, let it continue.  WM_TIMER and WM_NULL
/// alternate; both are harmless to a dispatcher that ignores them.
///
/// Runs for the session lifetime (600 s cap); posts every 200 ms.
#[cfg(target_arch = "x86")]
pub(super) fn spawn_message_waker(main_tid: u32) -> Option<std::thread::JoinHandle<()>> {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::PostThreadMessageW;

    if std::env::var("MAGICMIDA_V2_WAKE").is_err() {
        return None;
    }
    let join = std::thread::spawn(move || {
        const WM_NULL: u32 = 0x0000;
        const WM_TIMER: u32 = 0x0113;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        let mut tick = 0u64;
        while std::time::Instant::now() < deadline {
            let msg = if tick % 2 == 0 { WM_TIMER } else { WM_NULL };
            // SAFETY: valid thread id captured at spawn; the call fails
            // harmlessly (ERROR_INVALID_THREAD_ID) once the thread is gone.
            let ok = unsafe { PostThreadMessageW(main_tid, msg, WPARAM(0), LPARAM(0)) };
            if tick % 25 == 0 {
                debug!(
                    tick,
                    msg = format!("{msg:#x}"),
                    posted = ok.is_ok(),
                    "message waker"
                );
            }
            tick += 1;
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    });
    Some(join)
}

/// Compute the data-section boundaries for the IAT guard-address fallback.
pub(super) fn compute_data_section_bounds(
    image_base: usize,
    base_of_data: usize,
    sections: &[mida_pe::PeSection],
) -> (usize, usize) {
    for section in sections {
        let section_start = section.virtual_address as usize;
        let section_end = section_start + section.virtual_size as usize;
        if base_of_data < section_end {
            let data_start = image_base + base_of_data;
            let data_size = section_end.saturating_sub(base_of_data);
            return (data_start, data_size);
        }
    }
    (0, 0)
}

/// Flatten the PE section table into `(rva, virtual_size, is_executable)`
/// triples, the shape the IAT locator consumes.
///
/// The locator needs this to tell a real data section from the unmapped-looking
/// gap between two sections: gaps are mapped and readable at run time, so
/// `read_memory` on one succeeds and returns zeroes.  Memory content cannot
/// distinguish them; the section table can.
pub(super) fn section_table(sections: &[mida_pe::PeSection]) -> Vec<(u32, u32, bool)> {
    sections
        .iter()
        .map(|s| {
            (
                s.virtual_address,
                s.virtual_size,
                s.characteristics & 0x2000_0000 != 0,
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PE header helper
// ---------------------------------------------------------------------------

/// Compute the RVA of the first byte of section `idx`'s name field within the
/// PE header of a remote process.
pub(super) fn pe_section_name_remote_rva(
    h_process: HANDLE,
    image_base: usize,
    idx: usize,
) -> Option<usize> {
    use mida_core::DebuggerCore;
    let mut buf4 = [0u8; 4];
    let ro = ReadOnlyProcessDebugger { h_process, image_base: image_base as u64 };
    ro.read_memory(image_base + 0x3C, &mut buf4).ok()?;
    let e_lfanew = u32::from_le_bytes(buf4) as usize;
    let nt = image_base + e_lfanew;

    let mut buf2 = [0u8; 2];
    ro.read_memory(nt + 4 + 16, &mut buf2).ok()?;
    let opt_hdr_size = u16::from_le_bytes(buf2) as usize;

    let sections_start = nt + 24 + opt_hdr_size;
    let name_addr = sections_start + idx * 40;
    let rva = name_addr.saturating_sub(image_base);
    Some(rva)
}

// ---------------------------------------------------------------------------
// .NET dump
// ---------------------------------------------------------------------------

/// Dump a .NET + Themida binary via raw memory dump at the _CorExeMain
/// breakpoint.
pub(super) fn dotnet_dump_and_dump_output(
    dbg: &mut ProcessSession,
    image_base: usize,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
    let mut header_buf = vec![0u8; 0x1000];
    let read = dbg
        .read_memory(image_base, &mut header_buf)
        .map_err(|e| anyhow!("Failed to read .NET header: {e}"))?;
    if read < 0x1000 {
        return Err(anyhow!("Short read on .NET header: got {read} bytes"));
    }

    let live_pe = mida_pe::PeHeader::from_bytes(&header_buf)?;
    let entry_point = live_pe.entry_point;

    mida_pe::dump_dotnet(dbg, image_base as u64, entry_point, output_path)
        .map_err(|e| anyhow!(".NET dump failed: {e}"))
}

// ---------------------------------------------------------------------------
// Packed-DLL detection
// ---------------------------------------------------------------------------

/// Themida v3 x64 section that only exists in a packed image, never in a
/// normal host EXE.  Eight bytes, space-padded, exactly as it appears in the
/// section table.
const WINLICE_SECTION: &[u8; 8] = b".winlice";

/// Return the base address of `candidate` if it is the packed DLL.
///
/// Called for every `LOAD_DLL` event.  The debuggee is our loader host, so the
/// first thing the loader reports is the host EXE and then the system DLLs; the
/// packed DLL is identified by its `.winlice` section rather than by path,
/// because the path in `LOAD_DLL` is ANSI and may be non-ASCII.
///
/// `expected_text_rva` is the `.text` RVA parsed from the file on disk.  A
/// matching `.winlice` is enough on its own, but requiring the section table to
/// agree with the file rules out a stray `ntdll` copy that happens to contain
/// the string.
pub(super) fn detect_packed_dll(
    dbg: &ProcessSession,
    candidate: usize,
    expected_text_rva: u32,
) -> Option<usize> {
    let sections = read_remote_sections(dbg, candidate)?;

    let has_winlice = sections.iter().any(|s| &s.name == WINLICE_SECTION);
    if !has_winlice {
        return None;
    }

    // The image we care about must agree with the on-disk section 0 RVA.
    let text_rva = sections.first()?.virtual_address;
    if text_rva != expected_text_rva {
        return None;
    }

    Some(candidate)
}

/// A section header read out of a remote process.
struct RemoteSection {
    name: [u8; 8],
    virtual_address: u32,
}

/// Parse the section table of the PE mapped at `base` in the debuggee.
fn read_remote_sections(dbg: &ProcessSession, base: usize) -> Option<Vec<RemoteSection>> {
    let mut dos = [0u8; 0x40];
    dbg.read_memory(base, &mut dos).ok()?;
    if &dos[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as usize;
    let nt = base.checked_add(e_lfanew)?;

    let mut sig = [0u8; 4];
    dbg.read_memory(nt, &mut sig).ok()?;
    if &sig != b"PE\0\0" {
        return None;
    }

    let mut fh = [0u8; 20];
    dbg.read_memory(nt + 4, &mut fh).ok()?;
    let num_sections = u16::from_le_bytes(fh[2..4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(fh[16..18].try_into().ok()?) as usize;
    // A sane PE has a handful of sections; bail on a corrupt header rather than
    // trying to read a million headers out of the target.
    if num_sections == 0 || num_sections > 96 {
        return None;
    }

    let sec_start = nt + 4 + 20 + opt_size;
    let mut out = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let mut sh = [0u8; 40];
        dbg.read_memory(sec_start + i * 40, &mut sh).ok()?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&sh[0..8]);
        out.push(RemoteSection {
            name,
            virtual_address: u32::from_le_bytes(sh[12..16].try_into().ok()?),
        });
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Hardware breakpoint handler
// ---------------------------------------------------------------------------

/// Handle a hardware breakpoint event (CloseHandle / VirtualAlloc / .text+0x1000).
pub(super) fn handle_hw_breakpoint(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    guard_installed: &mut bool,
    address: u64,
    _thread_id: u32,
    image_base_usize: usize,
    _image_boundary: usize,
    h_process: HANDLE,
    guard_protection: u32,
    output_path: &std::path::Path,
) -> Result<(), anyhow::Error> {
    let rip = address as usize;

    let text_write_bp_addr = (image_base_usize + 0x1000) as u64;
    let slot0_is_text_write = dbg
        .hw_breakpoint_addr(0) == Some(text_write_bp_addr);

    // V2 bailtrace hit: the ExitProcess execute BP (armed by the CloseHandle
    // V2 branch when MAGICMIDA_V2_BAILTRACE is set) fired.  The shell has
    // decided to bail (exit code 2 — same bare and debugged, so it is the
    // license/environment check, not anti-debug) and its stack still holds
    // the check-site return chain.  Walk the stack, log every return
    // address inside the shell image with surrounding code bytes, clear the
    // slot, and let ExitProcess run.
    let bail_hit = dbg
        .apis
        .as_ref()
        .map(|a| a.exit_process)
        .filter(|&ep| {
            rip == ep as usize && dbg.hw_breakpoint_addr(3) == Some(ep as u64)
        });
    if bail_hit.is_some() {
            let ctx = dbg
                .get_thread_context_control(_thread_id)
                .map_err(|e| anyhow!("bailtrace: get_thread_context_control: {e}"))?;
            info!(
                esp = format!("{:#x}", mida_core::debugger::ctx_sp(&ctx)),
                eip = format!("{:#x}", mida_core::debugger::ctx_ip(&ctx)),
                "V2 BAILTRACE: shell reached ExitProcess — walking the stack for the check site"
            );
            // Bail-time image dump: the shell re-encrypts its code during
            // teardown (measured: the exit-snapshot bytes at the captured
            // return sites differ from the live bytes read at this same
            // hit), so the only stable view of the decoded check site is
            // NOW — the process is suspended at ExitProcess's first
            // instruction.
            {
                let total = state
                    .pe_info
                    .pe_sections
                    .iter()
                    .map(|s| s.virtual_address as usize + s.virtual_size as usize)
                    .max()
                    .unwrap_or(0);
                if total > 0 {
                    let mut buf = vec![0u8; total];
                    for off in (0..total).step_by(0x1000) {
                        let len = std::cmp::min(0x1000, total - off);
                        let _ =
                            dbg.read_memory(image_base_usize + off, &mut buf[off..off + len]);
                    }
                    let stem = output_path.with_extension("v2image_bail");
                    let mut name =
                        stem.file_name().expect("output path has a file name").to_os_string();
                    name.push(".bin");
                    let snap = stem.with_file_name(name);
                    if let Err(e) = std::fs::write(&snap, &buf) {
                        warn!(error = %e, "V2 BAILTRACE: bail-time image dump failed");
                    } else {
                        info!(path = %snap.display(), total = format!("{total:#x}"), "V2 BAILTRACE: bail-time image written (shell code decoded, pre-teardown)");
                    }                }
            }
            // Workspace dump: the shell's runtime engine + API name table
            // live in VirtualAlloc regions at absolute addresses
            // 0x122bxxxx-0x1235xxxx (measured from the resolver trace
            // this boot: 127/129 call continuations land there).  The
            // image carries zero API names — the name table is in the
            // workspace — and the workspace is encoded until execution,
            // so the decoded, name-readable view exists only while the
            // shell is running: i.e. at this exact frozen moment.
            {
                const WS_BASE: u64 = 0x1220_0000;
                const WS_SIZE: u64 = 0x200_000;
                let mut ws = vec![0u8; WS_SIZE as usize];
                let mut ws_ok = 0usize;
                for off in (0..WS_SIZE).step_by(0x1000) {
                    let off = off as usize;
                    let len = std::cmp::min(0x1000, WS_SIZE - off as u64) as usize;
                    if dbg
                        .read_memory(WS_BASE as usize + off, &mut ws[off..off + len])
                        .is_ok()
                    {
                        ws_ok += 1;
                    }
                }
                let stem = output_path.with_extension("v2ws_bail");
                let mut name =
                    stem.file_name().expect("output path has a file name").to_os_string();
                name.push(".bin");
                let ws_path = stem.with_file_name(name);
                if std::fs::write(&ws_path, &ws).is_ok() {
                    info!(
                        path = %ws_path.display(),
                        pages_ok = ws_ok,
                        "V2 BAILTRACE: shell workspace dumped at bail (engine + name table)"
                    );
                } else {
                    warn!("V2 BAILTRACE: workspace dump write failed");
                }
            }
            let mut stack = [0u8; 0x800];
            if dbg
                .read_memory(mida_core::debugger::ctx_sp(&ctx), &mut stack)
                .is_ok()
            {
                let lo = image_base_usize;
                let hi = image_base_usize
                    + state
                        .pe_info
                        .pe_sections
                        .iter()
                        .map(|s| s.virtual_address as usize + s.virtual_size as usize)
                        .max()
                        .unwrap_or(0);
                for off in (0..stack.len() - 4).step_by(4) {
                    let v = u32::from_le_bytes([
                        stack[off],
                        stack[off + 1],
                        stack[off + 2],
                        stack[off + 3],
                    ]) as usize;
                    if v >= lo && v < hi {
                        let mut code = [0u8; 48];
                        let from = v.saturating_sub(24);
                        if dbg.read_memory(from, &mut code).is_ok() {
                            info!(
                                stack_off = format!("{off:#x}"),
                                ret = format!("{v:#x}"),
                                code = ?&code,
                                "V2 BAILTRACE: return address into the shell image"
                            );
                        }
                    }
                }
            } else {
                warn!("V2 BAILTRACE: stack read at ExitProcess failed");
            }
            // Raw stack head + registers: [esp] tells call (return address)
            // vs jmp-after-push (exit code) — the bail image has no static
            // ExitProcess reference, so the call shape is only observable
            // here.  Measured: none of the 13 image-range stack values has
            // a call opcode ending at it — the stack is stale junk and the
            // real call came through a register after runtime resolution.
            let mut head = [0u8; 64];
            if dbg
                .read_memory(mida_core::debugger::ctx_sp(&ctx), &mut head)
                .is_ok()
            {
                let dwords: Vec<String> = head
                    .chunks_exact(4)
                    .map(|c| format!("{:#x}", u32::from_le_bytes(c.try_into().unwrap())))
                    .collect();
                info!(stack_head = ?dwords, "V2 BAILTRACE: raw stack head at ExitProcess");
            }
            #[cfg(target_arch = "x86")]
            info!(
                eax = format!("{:#x}", ctx.Eax),
                ecx = format!("{:#x}", ctx.Ecx),
                edx = format!("{:#x}", ctx.Edx),
                ebx = format!("{:#x}", ctx.Ebx),
                esi = format!("{:#x}", ctx.Esi),
                edi = format!("{:#x}", ctx.Edi),
                ebp = format!("{:#x}", ctx.Ebp),
                "V2 BAILTRACE: registers at ExitProcess"
            );
            dbg.clear_hw_breakpoint(3)?;
            return Ok(());
    }

    // V2 bailtrace: time-API observation hits (slots 2/3).  Log the caller
    // and how close to the bail the shell reads the clock, then RF-continue
    // with the BP still armed.  If a time API is the LAST outside call
    // before the bail, the expiry check is date-based and the fix is a time
    // shim, not a code patch.
    let time_hit = dbg
        .apis
        .as_ref()
        .map(|a| {
            if rip == a.get_local_time
                && dbg.hw_breakpoint_addr(1) == Some(a.get_local_time as u64)
            {
                Some((1usize, "GetLocalTime"))
            } else if dbg.hw_breakpoint_addr(2) == Some(0x102888a) {
                Some((2usize, "api-resolver"))
            } else {
                None
            }
        })
        .unwrap_or(None);
    if let Some((slot, label)) = time_hit {
        // Image size (max section end) — used by both dump sites below.
        let img_total = state
            .pe_info
            .pe_sections
            .iter()
            .map(|s| s.virtual_address as usize + s.virtual_size as usize)
            .max()
            .unwrap_or(0);
        if let Ok(ctx) = dbg.get_thread_context_control(_thread_id) {
            let sp = mida_core::debugger::ctx_sp(&ctx);
            let mut stack = [0u8; 8];
            if dbg.read_memory(sp, &mut stack).is_ok() {
                let ret =
                    u32::from_le_bytes(stack[0..4].try_into().unwrap()) as usize;
                let mut raw = [0u8; 0x40];
                let _ = dbg.read_memory(sp, &mut raw);
                // Multi-slot name probe: the resolver's entry-time
                // stack layout is not pinned (its own prologue shifts
                // esp before it reads the name).  Dump the raw stack as
                // HEX plus every 4-byte slot's readable string, so the
                // offline analysis can map slot -> name without another
                // live run.  Name-looking = ASCII letters/digits/_ 4-32
                // chars (the shell's API names are plain ASCII).
                let mut name_hits: Vec<(usize, String)> = Vec::new();
                for (slot_off, chunk) in raw.chunks_exact(4).enumerate() {
                    let name_ptr =
                        u32::from_le_bytes(chunk.try_into().unwrap()) as usize;
                    if name_ptr < 0x10000 {
                        continue;
                    }
                    let mut nb = [0u8; 64];
                    if dbg.read_memory(name_ptr, &mut nb).is_ok() {
                        let end = nb.iter().position(|&b| b == 0).unwrap_or(nb.len());
                        let str = String::from_utf8_lossy(&nb[..end]).into_owned();
                        let looks_like_name = !str.is_empty()
                            && str.len() <= 32
                            && str.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
                            });
                        if looks_like_name {
                            name_hits.push((slot_off * 4, str));
                        }
                    }
                }
                info!(
                    api = label,
                    slot,
                    ret = format!("{ret:#x}"),
                    esp = format!("{sp:#x}"),
                    names = ?name_hits,
                    "V2 BAILTRACE: resolver hit (multi-slot name probe)"
                );                #[cfg(target_arch = "x86")]
                info!(
                    eax = format!("{:#x}", ctx.Eax),
                    ecx = format!("{:#x}", ctx.Ecx),
                    edx = format!("{:#x}", ctx.Edx),
                    ebx = format!("{:#x}", ctx.Ebx),
                    esi = format!("{:#x}", ctx.Esi),
                    edi = format!("{:#x}", ctx.Edi),
                    "V2 BAILTRACE: resolver hit (registers)"
                );
                // Continuation-memory dump: the API name strings live in
                // the shell's workspace region next to the continuation
                // code (the image carries zero API names — measured).
                // 0x200 bytes at the continuation address, logged at debug
                // so offline scanning can find the name offsets.
                {
                    let mut cont = [0u8; 0x200];
                    if dbg.read_memory(ret, &mut cont).is_ok() {
                        debug!(
                            ret = format!("{ret:#x}"),
                            cont = ?String::from_utf8_lossy(&cont),
                            "V2 BAILTRACE: resolver continuation memory"
                        );
                    }
                }
                // Image dump at the GetLocalTime hit: the shell's engine
                // code blocks are decoded only while executing and are
                // re-encrypted after use (measured: the bail-time snapshot
                // has the whole engine back at entropy ~7.9), so the check
                // site's code (the continuation RVA 0x7547e + the
                // comparison/conditional right after it) is readable ONLY
                // at this exact frozen moment.  One full-image dump.
                if slot == 1 {
                    let total = img_total;
                    if total > 0 {
                        let mut buf = vec![0u8; total];
                        for off in (0..total).step_by(0x1000) {
                            let len = std::cmp::min(0x1000, total - off);
                            let _ = dbg.read_memory(image_base_usize + off, &mut buf[off..off + len]);
                        }
                        let stem = output_path.with_extension("v2image_getlocaltime");
                        let mut name = stem
                            .file_name()
                            .expect("output path has a file name")
                            .to_os_string();
                        name.push(".bin");
                        let snap = stem.with_file_name(name);
                        if std::fs::write(&snap, &buf).is_ok() {
                            info!(
                                path = %snap.display(),
                                total = format!("{total:#x}"),
                                ret = format!("{ret:#x}"),
                                "V2 BAILTRACE: image dumped at GetLocalTime hit (check site decoded)"
                            );
                        }
                    }
                }
                // Workspace dump at the GetLocalTime hit: the engine's
                // check code is NOT in the packed image — the call chain
                // is `engine (workspace) -> thunk (image, push <续址>;
                // jmp resolver) -> API`, so the continuation after the
                // GetLocalTime call (measured: ret 0x107547e is the
                // thunk's next push; the true continuation 0x122b6057 is
                // in the workspace) carries the comparison and the
                // conditional jump.  The workspace is zeroed before bail
                // (measured: all v2ws_* dumps are empty), so this hit is
                // the only capture point for the decoded check code.
                if slot == 1 {
                    const WS_BASE: u64 = 0x1220_0000;
                    const WS_SIZE: u64 = 0x200_000;
                    let mut ws = vec![0u8; WS_SIZE as usize];
                    let mut ws_ok = 0usize;
                    for off in (0..WS_SIZE).step_by(0x1000) {
                        let off = off as usize;
                        let len = std::cmp::min(0x1000, WS_SIZE - off as u64) as usize;
                        if dbg
                            .read_memory(WS_BASE as usize + off, &mut ws[off..off + len])
                            .is_ok()
                        {
                            ws_ok += 1;
                        }
                    }
                    let stem = output_path.with_extension("v2ws_getlocaltime");
                    let mut name = stem
                        .file_name()
                        .expect("output path has a file name")
                        .to_os_string();
                    name.push(".bin");
                    let ws_path = stem.with_file_name(name);
                    if std::fs::write(&ws_path, &ws).is_ok() {
                        info!(
                            path = %ws_path.display(),
                            pages_ok = ws_ok,
                            ret = format!("{ret:#x}"),
                            "V2 BAILTRACE: workspace dumped at GetLocalTime hit (check code decoded)"
                        );
                    }
                }
                // Workspace region diagnostic: the full 2 MB dump above
                // read pages_ok=0 — every page failed.  Query the region
                // states and probe direct reads at the continuation
                // addresses to see whether the engine region is
                // uncommitted, PAGE_NOACCESS, or moved elsewhere.
                {
                    use windows::Win32::System::Memory::{
                        MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, VirtualQueryEx,
                    };
                    let h_proc = dbg.process_handle();
                    for probe in [0x1220_0000u64, 0x122b_0000, 0x1230_0000, 0x123b_0000] {
                        let mut mbi = MEMORY_BASIC_INFORMATION::default();
                        let rc = unsafe {
                            VirtualQueryEx(
                                h_proc,
                                Some(probe as *const _),
                                &mut mbi,
                                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                            )
                        };
                        if rc == std::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
                            info!(
                                probe = format!("{probe:#x}"),
                                state = ?mbi.State,
                                r#type = ?mbi.Type,
                                protect = ?mbi.Protect,
                                region_size = format!("{:#x}", mbi.RegionSize),
                                "V2 BAILTRACE: workspace region state"
                            );
                        } else {
                            info!(
                                probe = format!("{probe:#x}"),
                                "V2 BAILTRACE: workspace region query failed (unmapped?)"
                            );
                        }
                    }
                    // Direct probe reads: the engine continuations (the
                    // check code lives there — the violation site is the
                    // IMAGE's RVA 0x75404, the engine code is in the
                    // workspace) and the check block in the image.
                    for (label, addr) in [
                        ("engine-cont", 0x122b_6057u64),
                        ("engine-cont2", 0x122b_5474u64),
                        ("check-block", 0x1075_404u64),
                    ] {
                        let mut buf = [0u8; 0x200];
                        match dbg.read_memory(addr as usize, &mut buf) {
                            Ok(n) => info!(
                                label,
                                addr = format!("{addr:#x}"),
                                read = n,
                                head = ?String::from_utf8_lossy(&buf[..16]),
                                "V2 BAILTRACE: probe read OK"
                            ),
                            Err(e) => info!(
                                label,
                                addr = format!("{addr:#x}"),
                                error = %e,
                                "V2 BAILTRACE: probe read FAILED"
                            ),
                        }
                    }
                    let _ = (MEM_COMMIT, MEM_PRIVATE); // keep the imports honest
                }
                // Per-hit engine code capture: at resolver hits whose
                // continuation lies inside the packed image, the engine
                // block there is decoded (it is executing) — dump 0x400 B
                // per hit, numbered in call order, so the ordered API
                // sequence maps to code offline (the names stay encoded;
                // the code itself carries the comparison constants).
                if slot == 2
                    && ret >= image_base_usize
                    && ret < image_base_usize + img_total
                    && state.v2_cont_dumps < 200
                {
                    state.v2_cont_dumps += 1;
                    let mut cont = [0u8; 0x400];
                    if dbg.read_memory(ret, &mut cont).is_ok() {
                        let stem = output_path.with_extension(format!(
                            "v2cont_{:03}",
                            state.v2_cont_dumps
                        ));
                        let mut name = stem
                            .file_name()
                            .expect("output path has a file name")
                            .to_os_string();
                        name.push(".bin");
                        let path = stem.with_file_name(name);
                        if std::fs::write(&path, &cont).is_ok() {
                            debug!(
                                ret = format!("{ret:#x}"),
                                path = %path.display(),
                                "V2 BAILTRACE: engine block dumped at resolver continuation"
                            );
                        }
                    }
                }
            }
            // Time shim (bailtrace, x86): the shell reads the clock exactly
            // once during the decode phase (measured: one GetLocalTime
            // call, ret=0x107547e; registers all zero — the SYSTEMTIME
            // pointer is the stdcall stack arg at [esp+4]) and bails
            // when the date is past the license expiry — the bare run
            // exits 2, same as debugged, so it is the license/environment
            // check, not anti-debug.  Write a fake SYSTEMTIME into the
            // caller's buffer and skip the real call: pop the return
            // address + the stack arg, return to the caller.  The check
            // then compares the fake date against the expiry — a date
            // inside the 2008 eval window passes.  MAGICMIDA_V2_NO_SHIM=1
            // keeps the plain RF-continue (the observation-only mode).
            // CORRECTED (2026-10-30): the earlier "self-modifying check
            // block" reading was wrong.  The 1024-hit AccessViolation loop
            // at 0x1075404 was the first FAKE_WRITER draft's own return
            // path: `add esp,4; ret` popped the ARGUMENT VALUE into EIP,
            // so the shell executed the SYSTEMTIME buffer (address
            // 0x1075404).  The current stub uses the stdcall `ret 4` and
            // points at the buffer through EAX instead of callee-saved EDI.
            // The API-level injection below patches GetLocalTime's entry
            // into a fake-writer: the API itself writes the fake SYSTEMTIME
            // into the buffer, which is the exact flow the shell expects.
            #[cfg(target_arch = "x86")]
            if slot == 1 && std::env::var("MAGICMIDA_V2_NO_SHIM").is_err() {
                // The fake-writer patch (34 B): reads the stdcall arg
                // from [esp+4] into EAX (volatile — the first draft used
                // EDI, a callee-saved register, and corrupted the shell's
                // state), writes the fake SYSTEMTIME
                // (2008-06-15 12:00:00.000 — the first draft had the year
                // immediate byte-swapped: 0xD007 = 53255, not 2008), and
                // returns with the stdcall `ret 4`.  The first draft's
                // `add esp,4; ret` popped the *argument value* into EIP —
                // the shell "executed" the SYSTEMTIME buffer, producing the
                // 1024-AV loop at 0x1075404 that was first misread as a
                // self-modifying check block.
                const FAKE_WRITER: [u8; 34] = [
                    0x8B, 0x44, 0x24, 0x04,                   // mov eax, [esp+4]
                    0xC7, 0x00, 0xD8, 0x07, 0x06, 0x00,       // mov [eax], {wYear=2008, wMonth=6}
                    0xC7, 0x40, 0x04, 0x00, 0x00, 0x0F, 0x00, // mov [eax+4], {wDayOfWeek=0, wDay=15}
                    0xC7, 0x40, 0x08, 0x00, 0x00, 0x0C, 0x00, // mov [eax+8], {wHour=0, wMinute=12}
                    0xC7, 0x40, 0x0C, 0x00, 0x00, 0x00, 0x00, // mov [eax+12], {wSecond=0, wMilliseconds=0}
                    0xC2, 0x04, 0x00,                         // ret 4
                ];
                if dbg.write_memory(rip, &FAKE_WRITER).is_ok() {
                    info!(
                        api = format!("{rip:#x}"),
                        "V2 BAILTRACE: GetLocalTime entry patched to fake-writer (API writes the fake SYSTEMTIME itself)"
                    );
                }
                let mut ctx2 = ctx;
                ctx2.EFlags |= 0x0001_0000;
                super::session::set_thread_context_control(dbg, _thread_id, &ctx2)?;
                info!(
                    "V2 BAILTRACE: GetLocalTime API-injected — fake SYSTEMTIME (2008-06-15) written by the API"
                );
                return Ok(());
            }
            let mut ctx2 = ctx;
            ctx2.EFlags |= 0x0001_0000;
            super::session::set_thread_context_control(dbg, _thread_id, &ctx2)?;
        }
        return Ok(());
    }

    if let Some(ref apis) = dbg.apis {
        let at_close = rip == apis.close_handle || rip == apis.nt_close;
        let at_virtual_alloc = rip == apis.virtual_alloc || rip == apis.nt_allocate_virtual_memory;

        if at_close {
            // ---- classic (v1-generation) stubs: guard immediately ------------
            //
            // Measured on Themida 1.1.1.0 (`OUT\v1v2\unpack_t111.log`,
            // 2026-10-26): the v1 shell's first CloseHandle lands **after**
            // decompression is already complete — 13.5 s of silence, then the
            // hit, then the original program running to exit 100 ms later.
            // The v3 staging (`.text` write BP → VirtualAlloc BP → guard)
            // therefore never advances past this point for v1: the write BP at
            // `.text+0x1000` never fires because there are no more `.text`
            // writes.  The right move is the era-script move: the shell is
            // done, so protect `.text` right now — the stub's jump to the OEP
            // becomes an execute fault and the OEP falls out of the
            // first-fault rule.
            let classic_stub = matches!(
                state.pe_info.themida_version,
                mida_packers_themida::ThemidaVersion::V1
                    | mida_packers_themida::ThemidaVersion::Ancient
            );
            if classic_stub {
                info!(
                    rip = %format_args!("{rip:#x}"),
                    version = ?state.pe_info.themida_version,
                    "CloseHandle/NtClose hit — classic (v1-generation) stub: \
                     installing the .text guard directly",
                );
                dbg.clear_hw_breakpoint(0)?;
                install_code_section_guard(
                    h_process,
                    image_base_usize
                        + state.pe_info.pe_sections[0].virtual_address as usize,
                    state.pe_info.base_of_data as usize
                        - state.pe_info.pe_sections[0].virtual_address as usize,
                    guard_protection,
                )?;
                *guard_installed = true;

                // Themida 1.1.1-shape: the shell materialised the original
                // program as a file-mapped image the `.text` guard cannot
                // see (no in-place decompression — the program simply runs
                // and exits, measured: hit at 13.5 s, exit 67 ms later).
                // At this point the decompression is complete, so scan the
                // address space for the materialised image and hand it to
                // the pipeline's mapped-dump path.
                if let Ok(images) = mida_pe::dumper::scan_mapped_images(dbg, false) {
                    for img in &images {
                        debug!(
                            base = format!("{:#x}", img.base),
                            region = format!("{:#x}", img.region_size),
                            size_img = format!("{:#x}", img.size_of_image),
                            ep = format!("{:#x}", img.entry_point),
                            imp = format!("{:#x}/{:#x}", img.import_rva, img.import_size),
                            secs = img.sections.len(),
                            mapped = img.is_mapped,
                            "Mapped image found in target",
                        );
                    }
                    // Candidate: a file-mapped image, not the packed image
                    // itself, not a system DLL, big enough to be a program.
                    let packed_base = image_base_usize as u64;
                    let candidate = images
                        .iter()
                        .filter(|img| {
                            img.is_mapped
                                && img.base != packed_base
                                && img.base < 0x7C00_0000
                                && img.size_of_image >= 0x10000
                        })
                        .max_by_key(|img| img.size_of_image);
                    if let Some(img) = candidate {
                        info!(
                            base = format!("{:#x}", img.base),
                            size_img = format!("{:#x}", img.size_of_image),
                            ep = format!("{:#x}", img.entry_point),
                            "Classic file-mapping shape: materialised image found,                              stepping to its OEP",
                        );
                        state.pending_mapped_dump = Some(img.clone());
                    }
                }
            } else {
                info!(
                    rip = %format_args!("{rip:#x}"),
                    is_nt_close = rip == apis.nt_close,
                    "CloseHandle/NtClose hit",
                );
                // V2 (SecureEngine 2.x) 分管道：保留 .text 写 BP（实测：
                // 不设 BP 时壳在 CloseHandle 后 ~38s 内 bail exit_code=2，
                // 载荷线程永不创建；设了 BP 壳正常解码，载荷线程在
                // 0x64035dc0 等壳 VirtualAlloc 区域启动——BP 虽不触发，
                // 但其存在防止壳反调试 bail）。同时武装 v2_watch，
                // CreateThread handler 会在载荷线程启动时 dump 载荷区。
                if state.pe_info.themida_version
                    == mida_packers_themida::ThemidaVersion::V2
                {
                    state.v2_watch = true;
                    dbg.clear_hw_breakpoint(0)?;
                    dbg.set_hw_breakpoint(
                        0,
                        image_base_usize + 0x1000,
                        mida_core::HwbpType::Write,
                    )?;
                    info!(
                        "V2 pipeline: CloseHandle BP cleared, .text write BP set (anti-bail), watch armed"
                    );
                    // Bailtrace observation slots 1-3 were armed at process
                    // start (the check may run during the decode phase);
                    // only slot 0 changes here (CloseHandle BP → .text
                    // write BP).
                } else {
                    info!("switching to .text write BP");
                    dbg.clear_hw_breakpoint(0)?;
                    dbg.set_hw_breakpoint(
                        0,
                        image_base_usize + 0x1000,
                        mida_core::HwbpType::Write,
                    )?;
                }
            }
        } else if at_virtual_alloc {
            info!(
                rip = %format_args!("{rip:#x}"),
                is_nt_alloc = rip == apis.nt_allocate_virtual_memory,
                "VirtualAlloc/NtAllocateVirtualMemory hit — installing code section guard",
            );
            dbg.clear_hw_breakpoint(0)?;
            install_code_section_guard(
                h_process,
                image_base_usize + state.pe_info.pe_sections[0].virtual_address as usize,
                state.pe_info.base_of_data as usize - state.pe_info.pe_sections[0].virtual_address as usize,
                guard_protection,
            )?;
            *guard_installed = true;
        } else if slot0_is_text_write {
            info!(
                rip = %format_args!("{rip:#x}"),
                "Write to .text base — switching to VirtualAlloc execute BP",
            );
            dbg.clear_hw_breakpoint(0)?;
            let va_addr = dbg.apis.as_ref().map(|a| a.virtual_alloc);
            if let Some(va) = va_addr {
                dbg.set_hw_breakpoint(0, va, mida_core::HwbpType::Execute)?;
                info!(
                    virtual_alloc = %format!("{va:#x}"),
                    "VirtualAlloc HW breakpoint set (slot 0)",
                );
            }
        } else if !*guard_installed {
            debug!(
                rip = %format_args!("{rip:#x}"),
                exception = %format!("{address:#x}"),
                "Unexpected breakpoint with no guard installed"
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// read_tls_callback_oep
// ---------------------------------------------------------------------------

/// Read a packed DLL's real entry point out of the shell's own TLS callback
/// array.
///
/// # Why this exists
///
/// An EXE target's OEP is found by arming a `PAGE_NOACCESS` guard over `.text`
/// and taking the first execute fault.  A packed DLL cannot use that mechanism:
/// at the moment the guard would be armed the shell is still inside its own
/// `DllMain`, and the guard's fault/retry cycle derails it.  Measured with an
/// identical debugger and ScyllaHide injection:
///
/// | `.text` guard | `.bss` non-zero | `hinstDLL` global |
/// |---|---|---|
/// | armed   | 0   | 0        |
/// | not armed | 177 | set    |
///
/// The guard is also unnecessary.  Themida's DLL shell publishes the real
/// `DllMain` into its TLS callback array during startup: measured on the
/// reference `core.dll` after a full boot, `[image_base + 0x170010]` holds
/// `image_base + 0x2BB10`, which is exactly the OEP the guarded path discovers.
///
/// # Returns
///
/// The first callback address that lies inside the image and is non-zero, or
/// `None` while the array is still empty (the caller retries).
pub(super) fn read_tls_callback_oep(
    dbg: &ProcessSession,
    image_base: usize,
    image_boundary: usize,
) -> Option<usize> {
    const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

    // Locate the TLS directory from the live headers rather than from the
    // in-memory `ThemidaPeInfo`, which does not carry the data directories.
    let mut headers = vec![0u8; 0x1000];
    if dbg.read_memory(image_base, &mut headers).is_err() {
        return None;
    }
    let pe = mida_pe::PeHeader::from_bytes(&headers).ok()?;
    let tls_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_dir.virtual_address == 0 || tls_dir.size == 0 {
        return None;
    }

    // The callback array is a pointer-sized slot at the end of the TLS
    // directory: StartRawData, EndRawData, AddressOfIndex, AddressOfCallbacks.
    // The directory is itself an address, not an RVA, so read it live rather
    // than mapping it through the file.
    let ptr = std::mem::size_of::<usize>();
    let dir_addr = image_base + tls_dir.virtual_address as usize;
    let mut dir = vec![0u8; ptr * 4];
    if dbg.read_memory(dir_addr, &mut dir).is_err() {
        return None;
    }
    let read_ptr = |off: usize| -> usize {
        if ptr == 8 {
            u64::from_le_bytes(dir[off..off + 8].try_into().unwrap_or([0u8; 8])) as usize
        } else {
            u32::from_le_bytes(dir[off..off + 4].try_into().unwrap_or([0u8; 4])) as usize
        }
    };

    let callbacks = read_ptr(ptr * 3);
    if callbacks == 0 {
        return None;
    }

    // Walk the array: it is a NULL-terminated list of absolute addresses.
    for i in 0..8 {
        let mut slot = vec![0u8; ptr];
        if dbg.read_memory(callbacks + i * ptr, &mut slot).is_err() {
            return None;
        }
        let addr = if ptr == 8 {
            u64::from_le_bytes(slot[..8].try_into().unwrap_or([0u8; 8])) as usize
        } else {
            u32::from_le_bytes(slot[..4].try_into().unwrap_or([0u8; 4])) as usize
        };
        if addr == 0 {
            return None; // end of list; nothing published yet
        }
        // Only accept an address that lies inside the image: the shell also
        // publishes its own internal callbacks, which are not the entry point.
        let rva = addr.wrapping_sub(image_base);
        if rva < image_boundary.wrapping_sub(image_base) {
            return Some(addr);
        }
    }
    None
}



// ---------------------------------------------------------------------------
// live_bss_activity
// ---------------------------------------------------------------------------

/// Count non-zero bytes in the image's writable data sections.
///
/// # Why this is the right "initialisation finished" signal
///
/// A packed DLL's shell writes its state into uninitialised/writable sections
/// (`.bss`, `.data`) during `DllMain`.  Measured on the reference `core.dll`,
/// injected with ScyllaHide and running under this debugger, the shell goes from
/// 0 to 177 non-zero bytes in one step around 300 ms and then stops changing.
///
/// The TLS callback array becomes non-zero at that same moment, so "the OEP is
/// published" alone is not a safe stop condition — sampling finer than the
/// 50 ms resolution used for that measurement shows the callback landing a few
/// instructions before the rest of the state.  Waiting for the *activity* to
/// settle is sample-independent: it does not name any RVA or any particular
/// global, so it works for any packed DLL rather than just this one.
pub(super) fn live_data_nonzero(dbg: &ProcessSession, image_base: usize, pe_sections: &[mida_pe::PeSection]) -> usize {
    let mut total = 0;
    for sec in pe_sections {
        // Only writable data sections carry runtime state; skip code and
        // read-only sections, which are static from the file.
        let ch = sec.characteristics;
        let writable = ch & 0x8000_0000 != 0;
        let executable = ch & 0x2000_0000 != 0;
        if !writable || executable {
            continue;
        }
        let va = sec.virtual_address as usize;
        let size = (sec.virtual_size as usize).min(0x100_000);
        if size == 0 {
            continue;
        }
        let mut buf = vec![0u8; size];
        if dbg.read_memory(image_base + va, &mut buf).is_ok() {
            total += buf.iter().filter(|b| **b != 0).count();
        }
    }
    total
}

/// Single-step `thread_id` until its instruction pointer lands inside
/// `[start, end)` — the shell's jump into the materialised image, which is
/// the original program's OEP.  Returns the OEP address, or `None` after
/// `max_steps` steps.
///
/// Events from other threads are resumed immediately; only the target
/// thread's `SingleStep` traps are inspected.
pub(super) fn step_until_in_image(
    dbg: &mut ProcessSession,
    thread_id: u32,
    start: u64,
    end: u64,
    max_steps: u32,
) -> Result<Option<u64>, anyhow::Error> {
    use tracing::warn;

    let mut ctx = dbg
        .get_thread_context_control(thread_id)
        .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
    ctx.EFlags |= 0x100; // TF
    super::session::set_thread_context_control(dbg, thread_id, &ctx)?;
    dbg.continue_event(thread_id, ContinueStatus::Continue)?;

    for _ in 0..max_steps {
        // Timeout-guarded wait: the shell's main thread may spin on
        // `pause`/`rep` while waiting for the decompression, and TF never
        // fires on a paused thread — a blocking wait would hang forever.
        // On timeout, re-arm TF and keep stepping.
        let ev = match dbg.wait_event_timeout(10000) {
            Ok(ev) => ev,
            Err(mida_core::CoreError::Timeout) => {
                let mut ctx = dbg
                    .get_thread_context_control(thread_id)
                    .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                ctx.EFlags |= 0x100;
                super::session::set_thread_context_control(dbg, thread_id, &ctx)?;
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                continue;
            }
            Err(e) => return Err(anyhow!("wait_event: {e}")),
        };
        match ev {
            DebugEvent::SingleStep { thread_id: tid, address } if tid == thread_id => {
                if address >= start && address < end {
                    return Ok(Some(address));
                }
                // keep stepping
                let mut ctx = dbg
                    .get_thread_context_control(thread_id)
                    .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                ctx.EFlags |= 0x100;
                super::session::set_thread_context_control(dbg, thread_id, &ctx)?;
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }
            _ => {
                // Another thread's event (or the target's own fault): resume
                // it and keep the target stepping.
                if let DebugEvent::AccessViolation {
                    thread_id: tid,
                    address,
                    ..
                } = ev
                {
                    if tid == thread_id {
                        warn!(address, "Shell faulted during OEP stepping — aborting mapped dump");
                        return Ok(None);
                    }
                }
                if let DebugEvent::Breakpoint { thread_id: tid, .. }
                | DebugEvent::SingleStep { thread_id: tid, .. }
                | DebugEvent::AccessViolation { thread_id: tid, .. } = ev
                {
                    dbg.continue_event(tid, ContinueStatus::Continue)?;
                }
                // keep the target stepping regardless
                let mut ctx = dbg
                    .get_thread_context_control(thread_id)
                    .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                ctx.EFlags |= 0x100;
                super::session::set_thread_context_control(dbg, thread_id, &ctx)?;
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }
        }
    }
    Ok(None)
}
