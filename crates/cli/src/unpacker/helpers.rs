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

/// Cheap non-suspending probe of the main thread's RIP: GetThreadContext
/// on a RUNNING thread returns whatever context the kernel last saved —
/// stale by up to one scheduler quantum, but it costs zero disruption
/// (no SuspendThread), which matters because sustained suspension during
/// the decode phase stalls the shell's timing-sensitive engine (measured
/// 2026-10-30: flat sampling from t=5 hung three runs that otherwise exit
/// in 9-26 s).  Used purely as the trigger for the real suspending burst.
#[cfg(target_arch = "x86")]
pub(super) fn probe_main_rip_nosuspend(dbg: &mut ProcessSession) -> Option<usize> {
    let tid = dbg.main_thread_id();
    let ctx = dbg.get_thread_context_control(tid).ok()?;
    Some(ctx.Eip as usize)
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
