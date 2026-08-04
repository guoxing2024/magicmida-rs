//! Global variable detection and snapshot module
//!
//! This module provides functionality to detect and capture non-container global variables
//! that are initialized at runtime by the unpacker.

use tracing::{debug, info, warn};

use crate::header::PeHeader;

/// Snapshot of a non-container global variable that needs runtime initialization.
///
/// These are regular variables (not SecurityCookie-encoded containers) that are
/// decrypted/initialized by the unpacker at runtime.
#[derive(Debug, Clone)]
#[allow(dead_code)] // legacy global-var capture; TLS/global restoration pending
pub struct GlobalVarSnapshot {
    /// RVA in `.data` where the variable is stored.
    pub rva: u32,
    /// Size of the variable in bytes.
    pub size: usize,
    /// Runtime value from live process.
    pub value: Vec<u8>,
}

/// Detect critical global variables by analyzing OEP code for immediate memory references.
///
/// This function disassembles the first N instructions at OEP and extracts all RIP-relative
/// memory references to .data section. These variables are likely runtime-initialized and
/// need to be captured from the live process.
#[allow(dead_code)] // legacy OEP-reference analysis
pub fn detect_critical_vars_from_oep(
    pe: &PeHeader,
    dump_buf: &[u8],
    oep_rva: u32,
    max_instructions: usize,
) -> Vec<u32> {
    let mut critical_rvas = Vec::new();

    // Find .data section bounds
    let data_section = match pe.sections.iter().find(|s| s.name == ".data") {
        Some(s) => s,
        None => return critical_rvas,
    };

    let data_start = data_section.virtual_address;
    let data_end = data_start + data_section.virtual_size;

    // Get OEP code
    let oep_offset = oep_rva as usize;
    if oep_offset + 512 > dump_buf.len() {
        return critical_rvas;
    }

    let code = &dump_buf[oep_offset..oep_offset + 512];

    // Simple x64 RIP-relative instruction pattern detection
    // Look for: 48/4C [8B/89/8D/C7] [ModR/M with RIP-relative] [disp32]
    let mut i = 0;
    let mut instr_count = 0;

    while i < code.len() - 7 && instr_count < max_instructions {
        // REX.W prefix (48) or REX.WR (4C)
        if code[i] == 0x48 || code[i] == 0x4C {
            let opcode = code[i + 1];

            // mov/lea/mov_imm with potential RIP-relative
            if opcode == 0x8B || opcode == 0x89 || opcode == 0x8D || opcode == 0xC7 {
                let modrm = code[i + 2];

                // Check for RIP-relative (mod=00, r/m=101)
                // ModR/M format: [mod:2][reg:3][r/m:3]
                // RIP-relative: mod=00 (0b00), r/m=101 (0b101)
                // This gives us x05, x0D, x15, x1D, x25, x2D, x35, x3D
                if (modrm & 0xC7) == 0x05
                    || (modrm & 0xC7) == 0x0D
                    || (modrm & 0xC7) == 0x15
                    || (modrm & 0xC7) == 0x1D
                    || (modrm & 0xC7) == 0x25
                    || (modrm & 0xC7) == 0x2D
                    || (modrm & 0xC7) == 0x35
                    || (modrm & 0xC7) == 0x3D
                {
                    // Read 32-bit displacement
                    let disp =
                        i32::from_le_bytes([code[i + 3], code[i + 4], code[i + 5], code[i + 6]]);

                    // Calculate target RVA: next_instruction_rva + displacement
                    let instr_len = 7; // REX + opcode + ModR/M + disp32
                    let next_rip = oep_rva + (i as u32) + instr_len;
                    let target_rva = (next_rip as i64 + disp as i64) as u32;

                    // Check if target is in .data section
                    if target_rva >= data_start && target_rva < data_end {
                        if !critical_rvas.contains(&target_rva) {
                            critical_rvas.push(target_rva);

                            debug!(
                                target_rva = format_args!("{:#x}", target_rva),
                                oep_offset = format_args!("{:#x}", i),
                                "Detected critical var referenced from OEP"
                            );
                        }
                    }
                }
            }

            instr_count += 1;
        }

        i += 1;
    }

    if !critical_rvas.is_empty() {
        info!(
            count = critical_rvas.len(),
            "Detected critical global variables from OEP analysis"
        );
    }

    critical_rvas
}

/// Detect and capture critical global variables from the live process.
///
/// This function reads the runtime values of variables identified by OEP analysis
/// or explicitly provided RVAs.
#[allow(dead_code)] // legacy global-var capture
pub fn detect_global_vars(
    pe: &PeHeader,
    debugger: &mut dyn mida_core::DebuggerCore,
    critical_rvas: &[u32],
    var_size: usize,
) -> Vec<GlobalVarSnapshot> {
    let mut vars = Vec::new();
    let image_base = pe.nt_headers.optional_header.image_base;

    // Cap per-variable read; critical_rvas come from analysis of untrusted PE.
    const MAX_GLOBAL_VAR_BYTES: usize = 64 * 1024;
    if var_size == 0 || var_size > MAX_GLOBAL_VAR_BYTES {
        warn!(
            var_size,
            max = MAX_GLOBAL_VAR_BYTES,
            "Global variable size rejected"
        );
        return vars;
    }

    for &rva in critical_rvas {
        let va = (image_base + rva as u64) as usize;

        // Read runtime value
        let mut buffer =
            match super::helpers::alloc_capped(var_size, MAX_GLOBAL_VAR_BYTES, "global variable") {
                Ok(buf) => buf,
                Err(e) => {
                    warn!(error = %e, rva = format_args!("{rva:#x}"), "Skipped global var alloc");
                    continue;
                }
            };
        match debugger.read_memory(va, &mut buffer) {
            Ok(_bytes_read) => {
                info!(
                    rva = format_args!("{:#x}", rva),
                    size = var_size,
                    "Captured global variable runtime value"
                );

                vars.push(GlobalVarSnapshot {
                    rva,
                    size: var_size,
                    value: buffer,
                });
            }
            Err(_) => {
                warn!(
                    rva = format_args!("{:#x}", rva),
                    "Failed to read global variable from live process"
                );
            }
        }
    }

    if !vars.is_empty() {
        info!(
            count = vars.len(),
            "Captured global variables requiring runtime values"
        );
    }

    vars
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_detect_critical_vars_empty() {
        // Test with minimal setup - should not crash
        // Real testing would require a full PE structure
    }
}
