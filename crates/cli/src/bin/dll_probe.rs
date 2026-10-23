//! Probe: host a packed DLL through the **real Windows loader**, watch its
//! `.text` with a re-arming `PAGE_NOACCESS` guard, and capture the real OEP.
//!
//! ## Why the loader path
//!
//! The stub-EXE trick (`clear IMAGE_FILE_DLL`, jump straight to `DllMain`) does
//! not work for a Themida-packed DLL: it bypasses the loader's
//! `DLL_PROCESS_ATTACH` sequencing and the shell dies at `.winlice+0x33E22E`
//! dereferencing a null pointer.  Loading the same DLL with `LoadLibraryW`
//! works — `DllMain` completes, the exports return real values, and the mapped
//! `.text` differs from the file by 99.6% (i.e. it is fully decrypted).
//!
//! So the unpack path is: let the loader map and initialise the DLL, then dump
//! the module.  The one thing missing is the **real OEP** — the dumped image's
//! `AddressOfEntryPoint` still points into the shell.
//!
//! ## How the OEP is found
//!
//! `.text` is set to `PAGE_NOACCESS` as soon as the loader reports the DLL,
//! before `DllMain` runs.  Every access then faults:
//!
//! * A **read or write** fault means the shell is still touching `.text`
//!   (decrypting it, or probing it).  We temporarily restore
//!   `PAGE_EXECUTE_READWRITE`, arm the trap flag so exactly one instruction
//!   runs, and re-arm `PAGE_NOACCESS` on the resulting single-step.  This is
//!   the same re-arm cycle as `mida_packers_themida::guard`.
//! * An **execute** fault (`ExceptionInformation[0] == 8`) means control has
//!   finally reached decrypted code.  That address is the real `DllMain`, i.e.
//!   the OEP.
//!
//! A plain `PAGE_GUARD` page cannot be used here: it is one-shot — the OS
//! clears the guard bit on the first access — and the shell then calls
//! `VirtualProtect` on `.text`, so only a single hit is ever delivered.
//!
//! ## Continue status
//!
//! Faults we deliberately observe are continued with `DBG_CONTINUE`.  Everything
//! else is continued with `DBG_EXCEPTION_NOT_HANDLED` so the target's own SEH
//! chain sees it.  Themida's FPU divide-by-zero anti-debug probe
//! (`STATUS_FLOAT_DIVIDE_BY_ZERO`) stalls the shell forever if swallowed, which
//! is why ScyllaHide is injected before the debuggee is resumed.
//!
//! Run:
//!   cargo run --release --bin dll_probe -- <dll-path> [host-exe]

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WaitForDebugEvent, CONTEXT, CONTEXT_CONTROL_AMD64, DEBUG_EVENT,
    CREATE_PROCESS_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenThread, PROCESS_INFORMATION, STARTUPINFOW,
    CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

/// Themida v3 x64 DLLs all carry a `.winlice` section; the host EXE does not.
const WINLICE: &[u8; 8] = b".winlice";
const DEFAULT_HOST: &str = r"D:\Projects\Magicmida-RS\OUT\dllhost.exe";

const STATUS_BREAKPOINT: u32 = 0x8000_0003;
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// Give up after this many re-arm cycles so a pathological sample cannot spin
/// forever.  A healthy run needs a few dozen.
const MAX_REARM: u32 = 20_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let dll = args
        .get(1)
        .map(String::as_str)
        .unwrap_or(r"D:\Projects\shiguang\core.dll");
    let host = args.get(2).map(String::as_str).unwrap_or(DEFAULT_HOST);

    println!("host exe = {host}");
    println!("dll      = {dll}");

    let cmd = format!("\"{host}\" \"{dll}\"");
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let mut si = STARTUPINFOW::default();
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            windows::core::PWSTR::from_raw(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )?;
    }
    println!("debuggee pid = {}", pi.dwProcessId);
    let h = pi.hProcess;

    let mut dll_base: u64 = 0;
    let mut text: Option<(u64, u64)> = None; // (start, size)
    let mut armed = false;
    let mut stepping = false;
    let mut oep: Option<u64> = None;
    let mut rearm_count: u32 = 0;
    let mut write_faults: u32 = 0;
    let mut read_faults: u32 = 0;
    let mut av_other: u32 = 0;

    loop {
        let mut ev = DEBUG_EVENT::default();
        if unsafe { WaitForDebugEvent(&mut ev, 30_000) }.is_err() {
            println!("WaitForDebugEvent timed out — process idle or gone");
            break;
        }
        let mut status = DBG_EXCEPTION_NOT_HANDLED;

        match ev.dwDebugEventCode {
            x if x == CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { ev.u.CreateProcessInfo };
                println!(
                    "CREATE_PROCESS base = {:#x} (the host EXE)",
                    info.lpBaseOfImage as u64
                );
                if !info.hFile.is_invalid() {
                    let _ = unsafe { CloseHandle(info.hFile) };
                }

                // Themida probes for a debugger immediately.  Without ScyllaHide
                // it trips STATUS_FLOAT_DIVIDE_BY_ZERO and stalls.
                //
                // Order matters: the injector hijacks the target's main thread,
                // so it must be spawned only after this event has been answered
                // and the thread is running.  See `scyllahide.rs` for the
                // measurement.
                let exe_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.to_path_buf()))
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                let cfg = mida_packers_themida::ScyllaHideConfig {
                    injector_cli_path: exe_dir
                        .join("InjectorCLIx64.exe")
                        .display()
                        .to_string(),
                    hook_library_path: exe_dir
                        .join("HookLibraryx64.dll")
                        .display()
                        .to_string(),
                    ini_path: None,
                };
                // Spawn the injector and get straight back to WaitForDebugEvent:
                // blocking here would freeze the target (pending debug event)
                // and the injector would wait on it forever.
                match mida_packers_themida::inject_scylla_hide(ev.dwProcessId, &cfg) {
                    Ok(()) => println!("ScyllaHide injector spawned"),
                    Err(e) => println!("ScyllaHide injection FAILED: {e}"),
                }
            }

            x if x == LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { ev.u.LoadDll };
                let base = info.lpBaseOfDll as u64;

                if dll_base == 0 && find_section(h, base, WINLICE).is_some() {
                    dll_base = base;
                    let (text_va, text_vsz) =
                        section_by_index(h, base, 0).expect("section 0 must exist");
                    let start = base + text_va;
                    if let Err(e) = protect(h, start, text_vsz, PAGE_NOACCESS.0) {
                        println!("    arm failed: {e}");
                    } else {
                        armed = true;
                        text = Some((start, text_vsz));
                        println!(
                            ">>> packed DLL at {base:#x}; .winlice present; \
                             PAGE_NOACCESS armed on .text {start:#x} (+{text_vsz:#x})"
                        );
                    }
                }
                if !info.hFile.is_invalid() {
                    let _ = unsafe { CloseHandle(info.hFile) };
                }
            }

            x if x == EXCEPTION_DEBUG_EVENT => {
                let rec = unsafe { ev.u.Exception.ExceptionRecord };
                let code = rec.ExceptionCode.0 as u32;
                let addr = rec.ExceptionAddress as u64;
                let info0 = rec.ExceptionInformation[0] as u64;
                let info1 = rec.ExceptionInformation[1] as u64;

                match code {
                    STATUS_SINGLE_STEP if stepping => {
                        stepping = false;
                        if let Some((s, sz)) = text {
                            let _ = protect(h, s, sz, PAGE_NOACCESS.0);
                            armed = true;
                        }
                        status = DBG_CONTINUE;
                    }

                    STATUS_ACCESS_VIOLATION => {
                        let in_text = text
                            .map(|(s, sz)| addr >= s && addr < s + sz)
                            .unwrap_or(false);
                        let target_in_text = text
                            .map(|(s, sz)| info1 >= s && info1 < s + sz)
                            .unwrap_or(false);

                        if in_text && info0 == 8 {
                            // Execute into decrypted .text = the real DllMain.
                            let rva = addr.wrapping_sub(dll_base);
                            println!(
                                "\n*** REAL OEP ***\n\
                                 \x20   rip = {addr:#x}\n\
                                 \x20   rva = {rva:#x}\n\
                                 \x20   dll = {dll_base:#x}\n\
                                 \x20   rearm cycles = {rearm_count}"
                            );
                            dump_around(h, addr, 48);
                            oep = Some(addr);
                            if let Some((s, sz)) = text {
                                let _ = protect(h, s, sz, PAGE_EXECUTE_READ.0);
                            }
                            armed = false;
                            status = DBG_CONTINUE;
                            break;
                        }

                        if target_in_text && armed && rearm_count < MAX_REARM {
                            // The shell is touching .text.  Let exactly one
                            // instruction through, then re-arm.
                            if info0 == 1 {
                                write_faults += 1;
                            } else {
                                read_faults += 1;
                            }
                            if let Some((s, sz)) = text {
                                let _ = protect(h, s, sz, PAGE_EXECUTE_READWRITE.0);
                            }
                            armed = false;
                            match set_trap_flag(ev.dwThreadId) {
                                Ok(()) => {
                                    stepping = true;
                                    rearm_count += 1;
                                    status = DBG_CONTINUE;
                                }
                                Err(e) => {
                                    println!("set TF failed: {e}");
                                    status = DBG_EXCEPTION_NOT_HANDLED;
                                }
                            }
                            if rearm_count <= 20 || rearm_count % 500 == 0 {
                                println!(
                                    "  rearm#{rearm_count}: {kind} fault at {addr:#x} \
                                     target={info1:#x} (w={write_faults} r={read_faults})",
                                    kind = if info0 == 1 { "write" } else { "read" }
                                );
                            }
                        } else {
                            av_other += 1;
                            if av_other <= 10 {
                                println!(
                                    "AV at {addr:#x} (rva {:#x}) access={info0} \
                                     target={info1:#x} — not ours",
                                    addr.wrapping_sub(dll_base.max(1))
                                );
                            }
                            status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }

                    STATUS_BREAKPOINT => status = DBG_CONTINUE,
                    _ => status = DBG_EXCEPTION_NOT_HANDLED,
                }
            }

            x if x == EXIT_PROCESS_DEBUG_EVENT => {
                let code = unsafe { ev.u.ExitProcess.dwExitCode };
                println!("EXIT_PROCESS code={code:#x}");
                break;
            }
            _ => {}
        }

        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)? };
    }

    println!(
        "\n--- summary ---\n\
         dll base          = {dll_base:#x}\n\
         oep               = {}\n\
         oep rva           = {}\n\
         rearm cycles      = {rearm_count}\n\
         text write faults = {write_faults}\n\
         text read faults  = {read_faults}\n\
         other AVs         = {av_other}",
        oep.map(|a| format!("{a:#x}")).unwrap_or_else(|| "(none)".into()),
        oep.map(|a| format!("{:#x}", a.wrapping_sub(dll_base)))
            .unwrap_or_else(|| "(none)".into()),
    );

    unsafe {
        let _ = CloseHandle(h);
        let _ = CloseHandle(pi.hThread);
    }
    Ok(())
}

fn protect(h: HANDLE, start: u64, size: u64, prot: u32) -> Result<(), windows::core::Error> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            h,
            start as *const _,
            size as usize,
            PAGE_PROTECTION_FLAGS(prot),
            &mut old,
        )
    }
}

/// Arm the trap flag on `thread_id` so exactly one instruction executes before
/// the next `STATUS_SINGLE_STEP`.
fn set_trap_flag(thread_id: u32) -> Result<(), windows::core::Error> {
    unsafe {
        let ht = OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            thread_id,
        )?;
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
        GetThreadContext(ht, &mut ctx)?;
        ctx.EFlags |= 0x100; // TF
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
        let r = SetThreadContext(ht, &ctx);
        let _ = CloseHandle(ht);
        r
    }
}

fn find_section(h: HANDLE, base: u64, name: &[u8; 8]) -> Option<(u64, u64)> {
    read_sections(h, base)?
        .into_iter()
        .find(|(n, _, _)| n == name)
        .map(|(_, va, vsz)| (va, vsz))
}

fn section_by_index(h: HANDLE, base: u64, idx: usize) -> Option<(u64, u64)> {
    read_sections(h, base)?
        .get(idx)
        .map(|&(_, va, vsz)| (va, vsz))
}

fn read_sections(h: HANDLE, base: u64) -> Option<Vec<([u8; 8], u64, u64)>> {
    let mut dos = [0u8; 0x40];
    read_exact(h, base, &mut dos)?;
    if &dos[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().ok()?) as u64;
    let nt = base + e_lfanew;

    let mut sig = [0u8; 4];
    read_exact(h, nt, &mut sig)?;
    if &sig != b"PE\0\0" {
        return None;
    }
    let mut fh = [0u8; 20];
    read_exact(h, nt + 4, &mut fh)?;
    let num_sections = u16::from_le_bytes(fh[2..4].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(fh[16..18].try_into().ok()?) as u64;

    let sec_start = nt + 4 + 20 + opt_size;
    let mut out = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let mut sh = [0u8; 40];
        read_exact(h, sec_start + i as u64 * 40, &mut sh)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&sh[0..8]);
        let vsz = u32::from_le_bytes(sh[8..12].try_into().ok()?) as u64;
        let va = u32::from_le_bytes(sh[12..16].try_into().ok()?) as u64;
        out.push((name, va, vsz));
    }
    Some(out)
}

fn read_exact(h: HANDLE, addr: u64, buf: &mut [u8]) -> Option<()> {
    let mut got = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            h,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            Some(&mut got),
        )
    };
    (ok.is_ok() && got == buf.len()).then_some(())
}

fn dump_around(h: HANDLE, addr: u64, len: usize) {
    let start = addr.saturating_sub(16);
    let mut buf = vec![0u8; len + 16];
    if read_exact(h, start, &mut buf).is_none() {
        println!("    (could not read around {addr:#x})");
        return;
    }
    for (i, chunk) in buf.chunks(16).enumerate() {
        let at = start + i as u64 * 16;
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let mark = if at <= addr && addr < at + 16 { " <<<" } else { "" };
        println!("    {at:012x}  {}{mark}", hex.join(" "));
    }
}
