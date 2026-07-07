//! IAT repair for Themida v1/v2/v3, plus the helper functions used by all
//! repair strategies.
//!
//! The v1/v2 strategies are `pub(super)` (internal); `fix_iat_v3` is `pub`
//! because it is part of the crate's public API surface (referenced by tests
//! and documentation).

use tracing::{debug, error, info, warn};

use mida_core::DebuggerCore;
use mida_disasm::Disassembler;

use crate::common::ThemidaState;
use crate::error::ThemidaError;
use super::{IatLocation, MAX_IAT_SIZE};

// ===========================================================================
// IAT repair — V1
// ===========================================================================

/// Repair the IAT for Themida v1.
///
/// Themida v1 wraps each IAT entry with a simple jumper: the IAT slot points
/// to a small stub in the Themida section, and that stub jumps to the real
/// API.  The strategy is:
///
/// 1. Read each IAT slot.
/// 2. If the slot points into the Themida section, follow the jump(er) to
///    get the real API address.
/// 3. Write the real API address back into the IAT slot.
pub(super) fn fix_iat_v1(
    debugger: &mut dyn DebuggerCore,
    iat: &IatLocation,
) -> Result<(), ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();
    let slot_count = iat.size / ptr_size;
    let mut iat_data = vec![0usize; slot_count];

    let bytes_read = debugger
        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
        .read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * ptr_size,
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v1 read: {e}")))?;

    let actual_slots = bytes_read / ptr_size;
    let mut fix_count: usize = 0;

    for i in 0..actual_slots {
        let slot_va = iat.address + i * ptr_size;
        let current = iat_data[i];

        if current == 0 {
            continue;
        }

        // In v1, each IAT slot points to a jumper stub that looks like:
        //   jmp [real_api]   or   mov eax, real_api; jmp eax
        // We read 8 bytes from the current value and try to resolve the
        // real API.
        if let Some(real_api) =
            resolve_v1_jumper(debugger, current)?
        {
            if real_api != current && real_api != 0 {
                iat_data[i] = real_api;
                fix_count += 1;
                debug!("IAT[{i}] {slot_va:#x}: {current:#x} → {real_api:#x}");
            }
        }
    }

    // Write the repaired IAT back.
    if fix_count > 0 {
        let write_size = actual_slots * ptr_size;
        let bytes_written = debugger
            // SAFETY: iat_data is a Vec<usize>; the aliasing immutable slice covers exactly write_size bytes and is discarded after write_memory returns.
            .write_memory(iat.address, unsafe {
                std::slice::from_raw_parts(
                    iat_data.as_ptr() as *const u8,
                    write_size,
                )
            })
            .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v1 write: {e}")))?;

        if bytes_written < write_size {
            warn!(
                "fix_iat_v1: short write ({bytes_written} of {write_size} bytes)"
            );
        }
    }

    info!("fix_iat_v1: repaired {fix_count} IAT entries");
    Ok(())
}

/// Try to resolve a v1 jumper stub to the real API address.
///
/// Reads 8 bytes at `jumper_addr` and looks for common patterns:
/// - `jmp [addr]` (FF 25 ...)
/// - `mov reg, addr; jmp reg`
pub(super) fn resolve_v1_jumper(
    debugger: &dyn DebuggerCore,
    jumper_addr: usize,
) -> Result<Option<usize>, ThemidaError> {
    let mut code = [0u8; 8];
    let n = debugger
        .read_memory(jumper_addr, &mut code)
        .map_err(|e| ThemidaError::Debugger(format!("resolve_v1_jumper read: {e}")))?;

    if n < 2 {
        return Ok(None);
    }

    // Pattern 1: jmp [addr] — FF 25 xx xx xx xx
    if code[0] == 0xFF && code[1] == 0x25 && n >= 6 {
        let disp = i32::from_le_bytes([code[2], code[3], code[4], code[5]]);
        let target = if std::mem::size_of::<usize>() == 8 {
            // x64: RIP-relative
            (jumper_addr as i64 + 6 + disp as i64) as usize
        } else {
            // x86: absolute
            disp as usize
        };
        // Read the pointer at the target.
        let mut ptr: usize = 0;
        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                &mut ptr as *mut usize as *mut u8,
                std::mem::size_of::<usize>(),
            )
        };
        if debugger.read_memory(target, buf).is_ok() && ptr != 0 {
            return Ok(Some(ptr));
        }
    }

    // Pattern 2: jmp rel32 — E9 xx xx xx xx — the target *is* the API.
    if code[0] == 0xE9 && n >= 5 {
        let rel32 = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
        let target = (jumper_addr as i64 + 5 + rel32 as i64) as usize;
        if is_likely_api_address(target) {
            return Ok(Some(target));
        }
    }

    // Pattern 3: mov eax, imm32; jmp eax — B8 xx xx xx xx FF E0
    if code[0] == 0xB8 && n >= 7 && code[5] == 0xFF && code[6] == 0xE0 {
        let imm = usize::from_le_bytes([
            code[1], code[2], code[3], code[4], 0, 0, 0, 0,
        ]);
        if is_likely_api_address(imm) {
            return Ok(Some(imm));
        }
    }

    Ok(None)
}

// ===========================================================================
// IAT repair — V2
// ===========================================================================

/// Repair the IAT for Themida v2.
///
/// Themida v2 uses a more complex IAT redirection. Each IAT slot points to a
/// stub inside the Themida section. We need to:
///
/// 1. Read each IAT slot.
/// 2. If the slot points into the Themida section, try to resolve the real
///    API by following the jump chain (the stub eventually jumps to the
///    real API or loads it from a table).
/// 3. Write the real API address back into the IAT slot.
///
/// If we can't resolve a slot (e.g. because it requires single-stepping
/// through obfuscated code), we leave it as-is — the follow-up v3 tracer
/// step will handle those.
pub(super) fn fix_iat_v2(
    debugger: &mut dyn DebuggerCore,
    iat: &IatLocation,
    themida_section_start: usize,
    themida_section_end: usize,
) -> Result<(), ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();
    let slot_count = iat.size / ptr_size;

    // Allocate buffer.
    let mut iat_data = vec![0usize; slot_count.min(MAX_IAT_SIZE / ptr_size)];

    let bytes_read = debugger
        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
        .read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * ptr_size,
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v2 read: {e}")))?;

    let actual_slots = bytes_read / ptr_size;
    let mut fix_count: usize = 0;

    for i in 0..actual_slots {
        let slot_va = iat.address + i * ptr_size;
        let current = iat_data[i];

        if current == 0 {
            continue;
        }

        // If the slot points into the Themida section, try to follow the
        // jump chain.
        if current >= themida_section_start && current < themida_section_end {
            if let Some(real_api) = resolve_v2_stub(debugger, current, themida_section_start, themida_section_end)? {
                if real_api != current && real_api != 0 {
                    iat_data[i] = real_api;
                    fix_count += 1;
                    debug!("IAT[{i}] {slot_va:#x}: {current:#x} → {real_api:#x}");
                }
            }
        }
        // If the slot already points to a valid API, leave it alone.
    }

    if fix_count > 0 {
        let write_size = actual_slots * ptr_size;
        let bytes_written = debugger
            // SAFETY: iat_data is a Vec<usize>; the aliasing immutable slice covers exactly write_size bytes and is discarded after write_memory returns.
            .write_memory(iat.address, unsafe {
                std::slice::from_raw_parts(
                    iat_data.as_ptr() as *const u8,
                    write_size,
                )
            })
            .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v2 write: {e}")))?;

        if bytes_written < write_size {
            warn!("fix_iat_v2: short write ({bytes_written} of {write_size} bytes)");
        }
    }

    info!("fix_iat_v2: repaired {fix_count} IAT entries");
    Ok(())
}

/// Try to resolve a Themida v2 stub to the real API address by following
/// the jump chain.
///
/// Many v2 stubs end with a `jmp [rip+disp]` or `jmp rel32` that ultimately
/// reaches the real API.  We read a small window of code at `stub_addr` and
/// disassemble it, looking for these patterns.
pub(super) fn resolve_v2_stub(
    debugger: &dyn DebuggerCore,
    stub_addr: usize,
    _tm_start: usize,
    _tm_end: usize,
) -> Result<Option<usize>, ThemidaError> {
    let mut code = [0u8; 32];
    let n = debugger
        .read_memory(stub_addr, &mut code)
        .map_err(|e| ThemidaError::Debugger(format!("resolve_v2_stub read: {e}")))?;

    let bitness = if std::mem::size_of::<usize>() == 8 {
        64
    } else {
        32
    };
    let disasm = Disassembler::new(bitness, stub_addr as u64);

    // Scan the code window for:
    // - jmp [mem] → follow the memory operand → read the pointer
    // - jmp rel32 → if target looks like an API, return it
    // - mov rax/eax, imm; jmp rax/eax → return the imm
    for insn in disasm.decode_all(&code[..n]) {
        let ip = insn.ip() as usize;
        let _insn_bytes = &code[(ip - stub_addr)..];

        match insn.mnemonic() {
            iced_x86::Mnemonic::Jmp => {
                match insn.op0_kind() {
                    iced_x86::OpKind::Memory => {
                        // jmp [mem] — follow the memory operand.
                        let target_ptr = if bitness == 64 {
                            ip + insn.len() + insn.memory_displacement64() as usize
                        } else {
                            insn.memory_displacement64() as usize
                        };
                        let mut ptr: usize = 0;
                        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
                        let buf = unsafe {
                            std::slice::from_raw_parts_mut(
                                &mut ptr as *mut usize as *mut u8,
                                std::mem::size_of::<usize>(),
                            )
                        };
                        if debugger.read_memory(target_ptr, buf).is_ok()
                            && is_likely_api_address(ptr)
                        {
                            return Ok(Some(ptr));
                        }
                    }
                    iced_x86::OpKind::NearBranch64 => {
                        let target = insn.near_branch_target() as usize;
                        if is_likely_api_address(target) {
                            return Ok(Some(target));
                        }
                    }
                    _ => {}
                }
            }
            iced_x86::Mnemonic::Mov => {
                // mov rax/eax, imm → if next is jmp rax/eax, return imm.
                if insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Immediate64
                {
                    let imm = insn.immediate64() as usize;
                    // Check if the next instruction is jmp reg.
                    let next_offset = (ip - stub_addr) + insn.len();
                    if next_offset + 2 <= n
                        && code[next_offset] == 0xFF
                    {
                        // It's a jmp reg (FF Ex). The immediate is likely the API.
                        if is_likely_api_address(imm) {
                            return Ok(Some(imm));
                        }
                    }
                }
            }
            iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Retf => {
                // ret — end of the stub; stop scanning.
                break;
            }
            _ => {}
        }
    }

    Ok(None)
}

// ===========================================================================
// IAT repair — V3 (via single-step VM tracing)
// ===========================================================================

/// Repair the IAT for Themida v3 using single-step VM tracing.
///
/// Themida v3 obfuscates each import address so that the IAT slot does not
/// point to a simple jumper stub but into the Themida VM.  Resolving the
/// real API requires single-stepping through the VM until it reaches a known
/// API function.
///
/// This is the Rust equivalent of `ThemidaCommon.pas` `TraceImports`.  The
/// actual tracing logic lives in [`trace_imports::trace_imports`]; here we
/// set up the anti-trace API addresses in `state` (the disassembler host-
/// process addresses are valid in the target because kernel32 is loaded at
/// a per-system ASLR base shared by all processes) and delegate.
pub fn fix_iat_v3(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    iat: &IatLocation,
    main_thread_id: u32,
) -> Result<(), ThemidaError> {
    use crate::trace_imports::trace_imports;
    use mida_tracer::LogMsgType;

    // Resolve anti-trace API addresses in the host process (valid in the
    // target because kernel32 is loaded at a per-system ASLR base).
    if state.sleep_api == 0 || state.lstrlen_api == 0 {
        resolve_anti_trace_apis(state);
    }

    // Capture trace start SP if not already set.
    if state.trace_start_sp == 0 {
        match debugger.get_thread_context(main_thread_id) {
            Ok(ctx) => {
                #[cfg(target_arch = "x86")]
                {
                    state.trace_start_sp = ctx.Esp as usize;
                }
                #[cfg(target_arch = "x86_64")]
                {
                    state.trace_start_sp = ctx.Rsp as usize;
                }
            }
            Err(e) => {
                warn!("fix_iat_v3: cannot get thread context: {e}");
            }
        }
    }

    if state.trace_start_sp == 0 {
        warn!("fix_iat_v3: trace_start_sp is 0 - cannot trace");
        return Ok(());
    }

    let log = |msg_type: LogMsgType, msg: &str| {
        match msg_type {
            LogMsgType::Info => info!("[v3-trace] {msg}"),
            LogMsgType::Good => info!("[v3-trace] OK {msg}"),
            LogMsgType::Fatal => error!("[v3-trace] {msg}"),
        }
    };

    let result = trace_imports(debugger, state, iat, main_thread_id, &log)?;

    info!(
        "fix_iat_v3: {} resolved, {} failed ({} slots total)",
        result.resolved_count,
        result.failed_count,
        iat.size / std::mem::size_of::<usize>(),
    );

    if !result.failed_slots.is_empty() {
        warn!(
            "fix_iat_v3: failed slots: {:?}",
            &result.failed_slots[..result.failed_slots.len().min(10)]
        );
    }

    Ok(())
}

/// Resolve the host-process addresses of the anti-trace APIs (Sleep and
/// lstrlenA) and store them in `state`. Valid in the target because kernel32
/// is loaded at a per-system ASLR base shared by all processes.
pub(super) fn resolve_anti_trace_apis(state: &mut ThemidaState) {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let to_pcstr = |s: &str| PCSTR::from_raw(s.as_ptr());

    // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
    let Ok(k32) = (unsafe { GetModuleHandleA(to_pcstr("kernel32.dll\0")) }) else {
        warn!("resolve_anti_trace_apis: GetModuleHandleA(kernel32) failed");
        return;
    };

    if state.sleep_api == 0 {
        // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
        state.sleep_api = unsafe { GetProcAddress(k32, to_pcstr("Sleep\0")) }
            .map(|f| f as usize)
            .unwrap_or(0);
    }
    if state.lstrlen_api == 0 {
        // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
        state.lstrlen_api = unsafe { GetProcAddress(k32, to_pcstr("lstrlenA\0")) }
            .map(|f| f as usize)
            .unwrap_or(0);
    }
}

// ===========================================================================
// Internal — helpers
// ===========================================================================

/// Extract the Themida section bounds from the PE info in `state`.
pub(super) fn get_themida_section_bounds(state: &ThemidaState) -> (usize, usize) {
    let image_base = state.pe_info.image_base as usize;

    if let Some(idx) = state.pe_info.themida_section {
        if let Some(section) = state.pe_info.pe_sections.get(idx) {
            let start = image_base + section.virtual_address as usize;
            let end = start + section.virtual_size as usize;
            return (start, end);
        }
    }

    // Fallback: use the entire image boundary.
    (image_base, state.pe_info.image_boundary as usize)
}

/// Heuristic: does `addr` look like a valid API address?
///
/// API addresses are typically:
/// - Above `0x10000` (no low-memory code).
/// - Outside the image boundaries (for most DLLs; can be inside the image
///   for forwarded exports, but that's rare).
/// - Not obviously a kernel address (for user-mode targets).
pub(super) fn is_likely_api_address(addr: usize) -> bool {
    // Must be above the low-memory region.
    if addr < 0x10000 {
        return false;
    }

    // On 64-bit Windows, user-mode DLLs load in the 0x0000_7FF6_xxxx_xxxx
    // to 0x0000_7FFF_xxxx_xxxx range (high user space).  API addresses
    // are typically in this range.  Small values (< 0x7fff_0000_0000)
    // are likely RVAs or data pointers, not resolved API addresses.
    //
    // This mirrors Pascal's `IsAPIAddress` which checks module export
    // tables — resolved API addresses live inside loaded DLLs, not in
    // the protected image's data sections.
    #[cfg(target_arch = "x86_64")]
    {
        (0x7ff0_0000_0000..0x0000_7FFF_FFFF_0000).contains(&addr)
    }
    #[cfg(target_arch = "x86")]
    {
        // 32-bit: DLLs load in the 0x60000000-0x7FFF0000 range typically.
        addr >= 0x6000_0000 && addr < 0x7FFF_0000
    }
}

/// Heuristic: is `addr` within the image being unpacked?
///
/// Used during IAT boundary scanning to identify Themida-stub pointers
/// (resolved API addresses that land inside the protector's VM section).
/// We only accept addresses that look like user-mode VAs above 0x10000;
/// small RVAs (like `0x1383bc`) are rejected because they are data
/// pointers, not resolved API addresses.
pub(super) fn is_within_image(addr: usize, _iat_base: usize, _slot_count: usize) -> bool {
    // Resolved API addresses and Themida-stub pointers are always above
    // 0x7ff0_0000_0000 on x64.  Small values (< 0x7fff_0000_0000) are
    // RVAs or data pointers, not API addresses.
    #[cfg(target_arch = "x86_64")]
    {
        (0x7ff0_0000_0000..0x0000_7FFF_FFFF_0000).contains(&addr)
    }
    #[cfg(target_arch = "x86")]
    {
        addr >= 0x6000_0000 && addr < 0x7FFF_0000
    }
}
