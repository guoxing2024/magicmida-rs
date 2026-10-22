//! Probe: launch the DLL stub under a debugger and dump the bytes at the
//! faulting address, to understand what the packer is executing there.
//!
//! Standalone tool, not part of the pipeline.  Run:
//!   cargo run --release --bin dll_probe -- <dll-path>

use std::path::Path;

use windows::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, ReadProcessMemory, WaitForDebugEvent, DEBUG_EVENT,
    EXCEPTION_DEBUG_EVENT,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION,
};
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

/// The faulting RVA we are investigating inside `.winlice`.
const TARGET_RVA: u64 = 0x0033_E22E;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let dll = args.get(1).map(String::as_str).unwrap_or(
        r"D:\Projects\shiguang\core.dll",
    );

    // Reuse the core crate's stub generator so this probe sees exactly what the
    // pipeline produces.
    let stub = mida_core::create_debug_process(&mida_core::CreateProcessOptions {
        executable: Path::new(dll).to_path_buf(),
        command_line: None,
        is_dll: true,
        suspended: false,
    })?;

    println!("debuggee pid = {}", stub.pid);
    // image_base is filled from the PEB during CREATE_PROCESS; it is zero until
    // the first event has been consumed.
    let mut image_base = stub.image_base;

    let h = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            stub.pid,
        )?
    };

    // Let it run until the first access violation, then dump around the fault.
    let mut events = 0;
    loop {
        let mut ev = DEBUG_EVENT::default();
        if unsafe { WaitForDebugEvent(&mut ev, 5000) }.is_err() {
            println!("no more events");
            break;
        }
        events += 1;

        // Pick up the real image base once the loader has reported it.
        if image_base == 0 && ev.dwDebugEventCode == windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT {
            let base = unsafe { ev.u.CreateProcessInfo.lpBaseOfImage } as u64;
            image_base = base;
            println!("image base   = {:#x} (from CREATE_PROCESS)", image_base);
        }

        if ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let rec = unsafe { ev.u.Exception.ExceptionRecord };
            let code = rec.ExceptionCode.0 as u32;
            // 0x80000003 = breakpoint, 0xC0000005 = access violation
            if code == 0xC000_0005_u32 {
                let fault = rec.ExceptionAddress as u64;
                let rva = fault.wrapping_sub(image_base);
                println!(
                    "AV #{}: fault={:#x} rva={:#x} info0={:?} info1={:?}",
                    events, fault, rva, rec.ExceptionInformation[0], rec.ExceptionInformation[1]
                );

                if (rva as i64 - TARGET_RVA as i64).abs() < 0x1000 {
                    dump_around(h, image_base, fault, 96)?;
                    break;
                }
            } else if code == 0x8000_0003_u32 {
                println!("breakpoint at {:#x}", rec.ExceptionAddress as u64);
            }
        }

        // Continue, ignoring exceptions so the packer keeps going.
        // Always swallow exceptions: this probe wants to observe the packer
        // running, not to judge it.  DBG_EXCEPTION_NOT_HANDLED would let the
        // first fault terminate the process.
        let _ = DBG_EXCEPTION_NOT_HANDLED;
        let status = DBG_CONTINUE;
        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)? };

        if events > 5000 {
            println!("event budget exhausted");
            break;
        }
    }

    unsafe { let _ = CloseHandle(h); }
    Ok(())
}

fn dump_around(h: HANDLE, image_base: u64, addr: u64, len: usize) -> Result<(), Box<dyn std::error::Error>> {
    let start = addr - 0x40;
    let mut buf = vec![0u8; len + 0x40];

    // `.winlice` is PAGE_NOACCESS until the packer decrypts it; make it readable
    // for the duration of the read.
    let mut old = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        let _ = VirtualProtectEx(
            h,
            start as *const _,
            buf.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
    }

    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            h,
            start as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            Some(&mut read),
        )
    };

    println!("\n=== memory around {:#x} (rva {:#x}) ===", addr, addr - image_base);
    if ok.is_err() {
        println!("ReadProcessMemory failed (read {read} bytes)");
        return Ok(());
    }
    for (i, chunk) in buf.chunks(16).enumerate() {
        let at = start as usize + i * 16;
        let marker = if at <= addr as usize && (addr as usize) < at + 16 { " <<<" } else { "" };
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!("{at:012x}  {}{}", hex.join(" "), marker);
    }

    unsafe {
        let _ = VirtualProtectEx(h, start as *const _, buf.len(), old, &mut old);
    }
    Ok(())
}
