//! Probe: dump a **naturally bootstrapped** packed DLL.
//!
//! ## Why this exists
//!
//! Attaching a debugger to the loader host and hijacking `Rip` to the OEP breaks
//! the shell's own state machine: the IAT window then re-detects only 357 of
//! 3282 slots and `.bss` never receives the initialised data.  The shell is
//! perfectly happy when nobody interferes — `LoadLibraryW` returns, exports work,
//! `GetAppVersion()` answers `"1.1"`.
//!
//! So the correct shape for a DLL is: **let it bootstrap undisturbed, then read
//! the finished image out of memory.**
//!
//! ## How
//!
//! 1. Launch the loader host normally (not under a debugger) and wait for its
//!    `.host.log` to report `ok=1`, i.e. `DllMain` returned.
//! 2. Attach as a debugger *after* the fact (`DebugActiveProcess`).  Attaching
//!    stops every thread, so the image is stable while we read it.
//! 3. Locate the module by base, then dump it with the project's own
//!    `dump_process`, which rebuilds the import table from the live IAT.
//!
//! Run:
//!   cargo run --release --bin dll_dump -- <dll-path> <out-path>

use std::path::Path;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop,
    WaitForDebugEvent, DEBUG_EVENT,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_VM_OPERATION,
    PROCESS_VM_WRITE,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let dll = args
        .get(1)
        .map(String::as_str)
        .unwrap_or(r"D:\Projects\shiguang\core.dll");
    let out = args
        .get(2)
        .map(String::as_str)
        .unwrap_or(r"D:\Projects\shiguang\coreUD.dll");

    println!("dll = {dll}");
    println!("out = {out}");

    // ---- 1: launch the host and wait for DllMain to finish -------------------
    let host = mida_core::ensure_loader_host(Path::new(dll))?;
    let mut child = std::process::Command::new(&host)
        .arg(dll)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id();
    println!("host pid = {pid}");

    let log_path = format!("{dll}.host.log");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut bootstrapped = false;
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&log_path) {
            if text.contains("ok=1") {
                bootstrapped = true;
                println!("bootstrap confirmed: {}", text.lines().next().unwrap_or(""));
                break;
            }
            if text.contains("ok=0") {
                return Err("LoadLibraryW failed — see the host log".into());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !bootstrapped {
        return Err("Timed out waiting for the DLL to bootstrap".into());
    }

    // Give the shell a moment to finish any post-DllMain writes (the version
    // string lands in .bss after the import table is complete).
    std::thread::sleep(Duration::from_millis(500));

    // ---- 2: attach so every thread stops and the image is stable ------------
    unsafe { DebugActiveProcess(pid) }
        .map_err(|e| format!("DebugActiveProcess({pid}) failed: {e}"))?;
    println!("attached");

    let h = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            false,
            pid,
        )?
    };

    // Drain the attach-time events (they are all informational); each one must
    // be continued or the target stays frozen.
    let mut dll_base = 0u64;
    let drain_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < drain_deadline {
        let mut ev = DEBUG_EVENT::default();
        if unsafe { WaitForDebugEvent(&mut ev, 500) }.is_err() {
            break;
        }
        // Nothing to do with the events; just keep the target moving.
        unsafe { ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, windows::Win32::Foundation::DBG_CONTINUE)? };
        if dll_base == 0 {
            dll_base = find_module_by_winlice(h, pid);
        }
        if dll_base != 0 {
            break;
        }
    }

    if dll_base == 0 {
        dll_base = find_module_by_winlice(h, pid);
    }
    if dll_base == 0 {
        return Err("Could not locate the packed DLL in the target".into());
    }
    println!("dll base = {dll_base:#x}");

    // ---- 3: dump with the project's own pipeline ----------------------------
    let oep_rva = find_oep_rva(h, dll_base)?;
    println!("oep rva  = {oep_rva:#x}");

    // The packed image's own IAT directory is empty (the shell never fills it
    // in — it keeps the import descriptors in a private `.winlice` region and
    // patches them at runtime).  The real descriptors are at the IMPORT
    // directory the shell wrote into the live header, and they point at a
    // fragmented set of thunk arrays.  Hand `dump_process` the first block and
    // let it walk the descriptors.
    let (iat_rva, iat_size) = real_iat_location(h, dll_base)?;
    println!("iat rva  = {iat_rva:#x} size = {iat_size:#x}");

    let mut ro = ReadOnly { h, image_base: dll_base };
    let opts = mida_pe::DumpOptions {
        image_base: dll_base,
        entry_point: oep_rva,
        fix_imports: true,
        create_data_sections: false,
        shrink: true,
        output_path: out.into(),
        executable_path: Some(dll.into()),
        iat_location: Some((dll_base as usize + iat_rva as usize, iat_size as usize)),
        additional_iat_locations: Vec::new(),
    };
    mida_pe::dump_process(&mut ro, &opts)?;
    println!("dumped to {out}");

    unsafe {
        let _ = DebugActiveProcessStop(pid);
        let _ = CloseHandle(h);
    }
    let _ = child.kill();
    Ok(())
}

/// Minimal read-only `DebuggerCore` over an `OpenProcess` handle.
struct ReadOnly {
    h: HANDLE,
    image_base: u64,
}

impl std::fmt::Debug for ReadOnly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadOnly").finish()
    }
}

impl mida_core::DebuggerCore for ReadOnly {
    fn process_handle(&self) -> HANDLE { self.h }
    fn pid(&self) -> u32 { 0 }
    fn image_base(&self) -> u64 { self.image_base }
    fn wait_event(&mut self) -> Result<mida_core::DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn wait_event_timeout(&mut self, _ms: u32) -> Result<mida_core::DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn continue_event(&mut self, _tid: u32, _s: mida_core::ContinueStatus) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, mida_core::CoreError> {
        let mut got = 0usize;
        unsafe {
            windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                self.h,
                address as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                Some(&mut got),
            )
        }
        .map_err(|_| mida_core::CoreError::MemoryRead { address: address as u64, requested: buf.len() })?;
        Ok(got)
    }
    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, mida_core::CoreError> {
        let mut wrote = 0usize;
        unsafe {
            windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                self.h,
                address as *const _,
                data.as_ptr() as *const _,
                data.len(),
                Some(&mut wrote),
            )
        }
        .map_err(|_| mida_core::CoreError::MemoryWrite { address: address as u64, requested: data.len() })?;
        Ok(wrote)
    }
    fn get_thread_context(&self, _tid: u32) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context_control(&self, _tid: u32) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context_control_integer(&self, _tid: u32) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn set_thread_context(&self, _tid: u32, _ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
}

/// Walk the target's module list and return the base of the one that carries a
/// `.winlice` section.
fn find_module_by_winlice(h: HANDLE, pid: u32) -> u64 {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) } {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let mut me = MODULEENTRY32W::default();
    me.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let mut ok = unsafe { Module32FirstW(snap, &mut me) }.is_ok();
    while ok {
        let base = me.modBaseAddr as u64;
        if has_winlice(h, base) {
            let _ = unsafe { CloseHandle(snap) };
            return base;
        }
        ok = unsafe { Module32NextW(snap, &mut me) }.is_ok();
    }
    let _ = unsafe { CloseHandle(snap) };
    0
}

fn has_winlice(h: HANDLE, base: u64) -> bool {
    let mut dos = [0u8; 0x40];
    if read(h, base, &mut dos).is_none() || &dos[0..2] != b"MZ" {
        return false;
    }
    let e = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as u64;
    let mut fh = [0u8; 20];
    if read(h, base + e + 4, &mut fh).is_none() {
        return false;
    }
    let n = u16::from_le_bytes(fh[2..4].try_into().unwrap()) as u64;
    let opt = u16::from_le_bytes(fh[16..18].try_into().unwrap()) as u64;
    let start = base + e + 4 + 20 + opt;
    for i in 0..n.min(96) {
        let mut sh = [0u8; 40];
        if read(h, start + i * 40, &mut sh).is_none() {
            return false;
        }
        if &sh[0..8] == b".winlice" {
            return true;
        }
    }
    false
}

/// Find the real `DllMain` RVA by scanning the decrypted `.text` for the
/// characteristic `cmp edx, 1` / `cmp edx, 2` dispatch that every DllMain has.
///
/// This is only used to set `AddressOfEntryPoint` in the dumped image; the
/// caller passes it straight into `DumpOptions`.
fn find_oep_rva(h: HANDLE, base: u64) -> Result<u32, Box<dyn std::error::Error>> {
    let mut dos = [0u8; 0x40];
    read(h, base, &mut dos).ok_or("cannot read DOS header")?;
    let e = u32::from_le_bytes(dos[0x3C..0x40].try_into()?) as u64;
    let mut fh = [0u8; 20];
    read(h, base + e + 4, &mut fh).ok_or("cannot read file header")?;
    let _n = u16::from_le_bytes(fh[2..4].try_into()?) as u64;
    let opt = u16::from_le_bytes(fh[16..18].try_into()?) as u64;
    let start = base + e + 4 + 20 + opt;

    let mut sh = [0u8; 40];
    read(h, start, &mut sh).ok_or("cannot read section 0")?;
    let text_va = u32::from_le_bytes(sh[12..16].try_into()?) as u64;
    let text_vsz = u32::from_le_bytes(sh[8..12].try_into()?) as u64;

    let mut text = vec![0u8; text_vsz as usize];
    read(h, base + text_va, &mut text).ok_or("cannot read .text")?;

    // A `DllMain` compares its second argument (`edx` on x64) against
    // `DLL_PROCESS_ATTACH` (1) and `DLL_PROCESS_DETACH` (2):
    //     83 FA 01   cmp edx, 1
    //     83 FA 02   cmp edx, 2
    //
    // Two conditions must hold, and neither is sufficient alone:
    //
    // 1. The candidate is preceded by inter-function padding.  MSVC emits
    //    `0f 1f 84 00 00 00 00 00` (8-byte NOP) or a run of `cc`/`90` between
    //    functions.  Without this test the scan matches `0x48 0x89` anywhere —
    //    on the reference DLL it returned rva 0x1088, which is the middle of a
    //    `mov` sequence, not a function start.
    //
    // 2. A `cmp edx, 1|2` appears within the first 64 bytes.  That is the
    //    `fdwReason` dispatch, which every `DllMain` has and ordinary code does
    //    not.
    for i in 8..text.len().saturating_sub(64) {
        if !at_function_boundary(&text, i) || !is_prologue(&text, i) {
            continue;
        }
        for j in i..(i + 64).min(text.len().saturating_sub(3)) {
            if text[j] == 0x83 && text[j + 1] == 0xFA && (text[j + 2] == 0x01 || text[j + 2] == 0x02) {
                return Ok(text_va as u32 + i as u32);
            }
        }
    }

    Err("no DllMain signature found in .text".into())
}

/// True when `text[i]` starts a function, judged by the padding that the
/// compiler emits between functions.
///
/// Recognises the 8-byte NOP (`0f 1f 84 00 00 00 00 00`), the 2-byte NOP
/// (`66 90`), and runs of `int3` / `nop` bytes.
fn at_function_boundary(text: &[u8], i: usize) -> bool {
    if i < 8 {
        return false;
    }
    let prev = &text[i - 8..i];
    // 8-byte NOP: 0f 1f 84 00 00 00 00 00
    if prev == [0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00] {
        return true;
    }
    // 2-byte NOP: 66 90
    if prev[6..8] == [0x66, 0x90] {
        return true;
    }
    // Run of int3 / nop padding right before the candidate.
    text[i - 4..i].iter().all(|&b| b == 0xCC || b == 0x90)
}

/// True when `text[i..]` looks like the first instruction of an x64 function.
fn is_prologue(text: &[u8], i: usize) -> bool {
    match text[i] {
        0x55 | 0x53 | 0x56 | 0x57 => true,                 // push rbp/rbx/rsi/rdi
        0x48 => matches!(text[i + 1], 0x83 | 0x81 | 0x89), // sub rsp,imm / mov [rsp+x],reg
        0x41 => matches!(text[i + 1], 0x54..=0x57),        // push r12..r15
        _ => false,
    }
}

/// Read the live import descriptors and return the `(rva, size)` of the
/// **contiguous block** that covers the most thunks.
///
/// The shell leaves the original import table in place as a decoy — on the
/// reference DLL it sits at rva `0x16f280` inside `.idata` and gives each module
/// exactly one thunk.  Those slots hold *pointers into the shell's own
/// dispatcher*, not real API addresses, so a rebuild that trusts them produces
/// an import table that resolves to nothing.
///
/// The genuine table is the one the shell builds at runtime: 115 descriptors
/// with thunk arrays scattered across the image, each slot holding a real
/// `0x7fff...` API address.  We walk every descriptor and pick the widest
/// contiguous run of non-zero slots, ignoring runs of length 1 (the decoy's
/// shape).
fn real_iat_location(h: HANDLE, base: u64) -> Result<(u32, u32), Box<dyn std::error::Error>> {
    let mut dos = [0u8; 0x40];
    read(h, base, &mut dos).ok_or("cannot read DOS header")?;
    let e = u32::from_le_bytes(dos[0x3C..0x40].try_into()?) as u64;
    let mut fh = [0u8; 20];
    read(h, base + e + 4, &mut fh).ok_or("cannot read file header")?;

    // IMPORT directory entry = index 1, at optional_header + 0x70 + 1*8
    // (the data directories start at 0x70 in PE32+).
    let dd = base + e + 4 + 20 + 0x70;
    let mut imp = [0u8; 8];
    read(h, dd + 8, &mut imp).ok_or("cannot read IMPORT directory entry")?;
    let imp_rva = u32::from_le_bytes(imp[0..4].try_into()?) as u64;

    if imp_rva == 0 {
        return Err("live IMPORT directory is empty".into());
    }

    // Walk the descriptors and pick the widest thunk run.
    let mut best = (0u32, 0u32);
    let mut descriptor_count = 0u32;
    for i in 0..256u64 {
        let mut ent = [0u8; 20];
        if read(h, base + imp_rva + i * 20, &mut ent).is_none() {
            break;
        }
        let oft = u32::from_le_bytes(ent[0..4].try_into()?) as u64;
        let name = u32::from_le_bytes(ent[12..16].try_into()?) as u64;
        let ft = u32::from_le_bytes(ent[16..20].try_into()?) as u64;
        if oft == 0 && ft == 0 && name == 0 {
            break;
        }
        descriptor_count += 1;
        if ft == 0 {
            continue;
        }
        // Count the slots in this array, tolerating interleaved zeros.
        //
        // The shell does not lay thunk arrays out as a dense run: on the
        // reference DLL the array at rva 0x1032e0 reads
        //   0x7fffe3f83f90, 0, 0x7fff2cebe120, 0, ...
        // i.e. every second slot is a zero.  Stopping at the first zero finds
        // nothing, which is why this used to report "only single-slot decoys".
        // Instead scan up to the next descriptor boundary and keep the furthest
        // non-zero slot, so a sparse array still yields its full extent.
        let mut n = 0u64;
        let mut last_nonzero = 0u64;
        while n < 4096 {
            let mut slot = [0u8; 8];
            if read(h, base + ft + n * 8, &mut slot).is_none() {
                break;
            }
            if u64::from_le_bytes(slot) != 0 {
                last_nonzero = n + 1;
            } else if n > last_nonzero.saturating_add(64) {
                // A long zero run means the array ended.
                break;
            }
            n += 1;
        }
        let extent = last_nonzero * 8;
        // Runs of 1 are the decoy's signature; require at least 2 slots.
        if last_nonzero >= 2 && extent as u32 > best.1 {
            best = (ft as u32, extent as u32);
        }
    }

    if best.1 == 0 {
        return Err("no resolved thunk arrays found (only single-slot decoys)".into());
    }
    println!("descriptors = {descriptor_count}");
    Ok(best)
}

fn read(h: HANDLE, addr: u64, buf: &mut [u8]) -> Option<()> {    let mut got = 0usize;
    unsafe {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            h,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            Some(&mut got),
        )
    }
    .ok()?;
    (got == buf.len()).then_some(())
}
