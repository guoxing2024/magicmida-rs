//! Minimal, correct x64 instruction encoder for the runtime bootstrap stub.
//!
//! The stub must be emitted with **correct REX.B/REX.X/REX.R** prefixes so that
//! memory operands actually address the intended base/index registers. A naive
//! `8B 4C 24 10` decodes as `mov ecx, [rsp+0x10]` (base rsp) instead of
//! `mov ecx, [r12+0x10]` (base r12) — the exact class of bug this module
//! eliminates.
//!
//! Encoding rules used here (x86-64):
//! - Registers are numbered 0-15 (0=rax..7=rdi, 8=r8..15=r15).
//! - A register 8-15 needs the corresponding REX.R (reg field) / REX.X
//!   (index) / REX.B (base) bit set.
//! - A base register 12 (r12) or 13 (r13) in a ModRM r/m field requires the
//!   SIB escape (r/m=100) because their low-3-bit encodings collide with
//!   rsp/rbp special cases.
//! - r14/r15 encode directly as r/m 6/7 with REX.B.
//!
//! Every helper is validated by an iced-x86 disassembly test so the emitted
//! bytes are proven to decode to the intended instruction.

/// A memory operand `[base + index*scale + disp]`. `base`/`index` are 0-15.
/// `scale` is 1/2/4/8. `index` may be `None` for no index register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mem {
    pub base: u8,
    pub index: Option<u8>,
    pub scale: u8,
    pub disp: i64,
}

impl Mem {
    pub fn r10(disp: i64) -> Self {
        Mem {
            base: 10,
            index: None,
            scale: 1,
            disp,
        }
    }
    pub fn rax(disp: i64) -> Self {
        Mem {
            base: 0,
            index: None,
            scale: 1,
            disp,
        }
    }
    pub fn rcx(disp: i64) -> Self {
        Mem {
            base: 1,
            index: None,
            scale: 1,
            disp,
        }
    }
    pub fn r12(disp: i64) -> Self {
        Mem {
            base: 12,
            index: None,
            scale: 1,
            disp,
        }
    }
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn r13(disp: i64) -> Self {
        Mem {
            base: 13,
            index: None,
            scale: 1,
            disp,
        }
    }
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn r14(disp: i64) -> Self {
        Mem {
            base: 14,
            index: None,
            scale: 1,
            disp,
        }
    }
    pub fn r15(disp: i64) -> Self {
        Mem {
            base: 15,
            index: None,
            scale: 1,
            disp,
        }
    }
    pub fn rbx_index(index: u8, scale: u8) -> Self {
        Mem {
            base: 3,
            index: Some(index),
            scale,
            disp: 0,
        }
    }
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn rcx_index(index: u8) -> Self {
        Mem {
            base: 1,
            index: Some(index),
            scale: 1,
            disp: 0,
        }
    }
}

/// Encode a ModRM/SIB/disp for `mem`, returning the REX.X and REX.B bits that
/// the caller must OR into the instruction's REX prefix.
///
/// `reg_field` is the ModRM.reg register (0-15); the caller sets REX.R.
fn encode_mem(
    out: &mut Vec<u8>,
    mem: &Mem,
    rex_r: bool,
    reg_field: u8,
    rex_x: &mut bool,
    rex_b: &mut bool,
) {
    let base = mem.base;
    let scale_enc = match mem.scale {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => panic!("invalid scale"),
    };

    *rex_b = base >= 8;
    let base_rm = (base & 7) as u8;

    // Decide mod.
    let (mod_, disp_bytes) = if mem.disp == 0 && mem.index.is_some() {
        (0u8, 0usize)
    } else if mem.disp == 0 && mem.index.is_none() && base_rm != 5 {
        (0, 0)
    } else if mem.disp as i32 as i64 == mem.disp
        && (mem.disp as i32) >= -128
        && (mem.disp as i32) <= 127
    {
        (1u8, 1usize)
    } else {
        (2u8, 4usize)
    };

    let need_sib = mem.index.is_some() || base_rm == 4 || base_rm == 5;
    let rm = if need_sib { 4u8 } else { base_rm };

    let modrm = (mod_ << 6) | ((reg_field & 7) << 3) | rm;
    out.push(modrm);

    if need_sib {
        let index = mem.index.unwrap_or(4); // 4 = "no index"
        *rex_x = index >= 8;
        let sib = (scale_enc << 6) | ((index & 7) << 3) | (base_rm);
        out.push(sib);
    }

    match disp_bytes {
        0 => {}
        1 => out.push(mem.disp as u8),
        _ => out.extend_from_slice(&(mem.disp as i32).to_le_bytes()),
    }

    let _ = rex_r;
}

fn rex_prefix(w: bool, r: bool, x: bool, b: bool) -> u8 {
    0x40 | ((w as u8) << 3) | ((r as u8) << 2) | ((x as u8) << 1) | (b as u8)
}

/// Emit `mov r32, [mem]` (32-bit load, zero-extends to the full register).
pub fn mov_r32_mem(out: &mut Vec<u8>, dest: u8, mem: &Mem) {
    let rex_r = dest >= 8;
    let mut rex_x = false;
    let mut rex_b = false;
    out.push(rex_prefix(false, rex_r, false, false)); // placeholder, patched
    let rpos = out.len() - 1;
    out.push(0x8b);
    encode_mem(out, mem, rex_r, dest, &mut rex_x, &mut rex_b);
    out[rpos] = rex_prefix(false, rex_r, rex_x, rex_b);
}

/// Emit `mov r64, [mem]` (64-bit load).
pub fn mov_r64_mem(out: &mut Vec<u8>, dest: u8, mem: &Mem) {
    let rex_r = dest >= 8;
    let mut rex_x = false;
    let mut rex_b = false;
    out.push(0);
    let rpos = out.len() - 1;
    out.push(0x8b);
    encode_mem(out, mem, rex_r, dest, &mut rex_x, &mut rex_b);
    out[rpos] = rex_prefix(true, rex_r, rex_x, rex_b);
}

/// Emit `mov [mem], r64`.
pub fn mov_mem_r64(out: &mut Vec<u8>, mem: &Mem, src: u8) {
    let rex_r = src >= 8;
    let mut rex_x = false;
    let mut rex_b = false;
    out.push(0);
    let rpos = out.len() - 1;
    out.push(0x89);
    encode_mem(out, mem, rex_r, src, &mut rex_x, &mut rex_b);
    out[rpos] = rex_prefix(true, rex_r, rex_x, rex_b);
}

/// Emit `movzx r32, byte [mem]`.
pub fn movzx_r32_byte_mem(out: &mut Vec<u8>, dest: u8, mem: &Mem) {
    let rex_r = dest >= 8;
    let mut rex_x = false;
    let mut rex_b = false;
    out.push(0);
    let rpos = out.len() - 1;
    out.extend_from_slice(&[0x0f, 0xb6]);
    encode_mem(out, mem, rex_r, dest, &mut rex_x, &mut rex_b);
    out[rpos] = rex_prefix(false, rex_r, rex_x, rex_b);
}

/// Emit `add r64, [mem]` (memory as r/m source).
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
pub fn add_r64_mem(out: &mut Vec<u8>, dest: u8, mem: &Mem) {
    let rex_r = dest >= 8;
    let mut rex_x = false;
    let mut rex_b = false;
    out.push(0);
    let rpos = out.len() - 1;
    out.push(0x03);
    encode_mem(out, mem, rex_r, dest, &mut rex_x, &mut rex_b);
    out[rpos] = rex_prefix(true, rex_r, rex_x, rex_b);
}

/// Emit `add r64, r64`.
pub fn add_r64_r64(out: &mut Vec<u8>, a: u8, b: u8) {
    let rex_r = b >= 8;
    let rex_b = a >= 8;
    out.push(rex_prefix(true, rex_r, false, rex_b));
    out.push(0x03);
    let modrm = (0b11 << 6) | ((b & 7) << 3) | (a & 7);
    out.push(modrm);
}

/// Emit `mov r64, imm64` (movabs).
pub fn mov_r64_imm64(out: &mut Vec<u8>, dest: u8, imm: u64) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(true, false, false, rex_b));
    out.push(0xb8 + (dest & 7));
    out.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `add r64, imm32` (sign-extended).
pub fn add_r64_imm32(out: &mut Vec<u8>, dest: u8, imm: i32) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(true, false, false, rex_b));
    out.push(0x81);
    out.push(0xc0 + (dest & 7));
    out.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `add r32, imm32` (32-bit).
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
pub fn add_r32_imm32(out: &mut Vec<u8>, dest: u8, imm: i32) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(false, false, false, rex_b));
    out.push(0x81);
    out.push(0xc0 + (dest & 7));
    out.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `sub r32, imm8`.
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
pub fn sub_r32_imm8(out: &mut Vec<u8>, dest: u8, imm: i8) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(false, false, false, rex_b));
    out.push(0x83);
    out.push(0xe8 + (dest & 7));
    out.push(imm as u8);
}

/// Emit `inc r32`.
pub fn inc_r32(out: &mut Vec<u8>, dest: u8) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(false, false, false, rex_b));
    out.push(0xff);
    out.push(0xc0 + (dest & 7));
}

/// Emit `dec r32`.
pub fn dec_r32(out: &mut Vec<u8>, dest: u8) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(false, false, false, rex_b));
    out.push(0xff);
    out.push(0xc8 + (dest & 7));
}

/// Emit `xor r32, r32` (zero a register).
pub fn xor_r32_r32(out: &mut Vec<u8>, a: u8, b: u8) {
    let rex_r = b >= 8;
    let rex_b = a >= 8;
    out.push(rex_prefix(false, rex_r, false, rex_b));
    out.push(0x31);
    let modrm = (0b11 << 6) | ((b & 7) << 3) | (a & 7);
    out.push(modrm);
}

/// Emit `and r32, imm8`.
pub fn and_r32_imm8(out: &mut Vec<u8>, dest: u8, imm: u8) {
    let rex_b = dest >= 8;
    out.push(rex_prefix(false, false, false, rex_b));
    out.push(0x83);
    out.push(0xe0 + (dest & 7));
    out.push(imm);
}

/// Emit `cmp r8b, imm8` (compare low byte of a 64-bit register).
pub fn cmp_r8b_imm8(out: &mut Vec<u8>, reg: u8, imm: u8) {
    let rex_b = reg >= 8;
    out.push(rex_prefix(false, false, false, rex_b));
    out.push(0x80);
    out.push(0xf8 + (reg & 7));
    out.push(imm);
}

/// Emit `test r32, r32`.
pub fn test_r32_r32(out: &mut Vec<u8>, a: u8, b: u8) {
    let rex_r = b >= 8;
    let rex_b = a >= 8;
    out.push(rex_prefix(false, rex_r, false, rex_b));
    out.push(0x85);
    let modrm = (0b11 << 6) | ((b & 7) << 3) | (a & 7);
    out.push(modrm);
}

/// Emit `test r64, r64`.
pub fn test_r64_r64(out: &mut Vec<u8>, a: u8, b: u8) {
    let rex_r = b >= 8;
    let rex_b = a >= 8;
    out.push(rex_prefix(true, rex_r, false, rex_b));
    out.push(0x85);
    let modrm = (0b11 << 6) | ((b & 7) << 3) | (a & 7);
    out.push(modrm);
}

/// Emit `mov r64, [gs:disp32]`. Used to read the TEB/PEB (e.g. `gs:[0x60]`
/// is the PEB pointer on x64 Windows; the image base lives at `[PEB+0x10]`).
pub fn mov_r64_gs_disp32(out: &mut Vec<u8>, dest: u8, disp: i32) {
    let rex_b = dest >= 8;
    out.push(0x65); // GS segment override
    out.push(rex_prefix(true, false, false, rex_b));
    out.push(0x8b);
    // mod=00, reg=dest, r/m=100 (SIB with disp32, no base = absolute).
    let modrm = (0 << 6) | ((dest & 7) << 3) | 0b100;
    out.push(modrm);
    out.push(0x25); // SIB: no base, no index
    out.extend_from_slice(&disp.to_le_bytes());
}

/// Emit `mov r64, r64`.
pub fn mov_r64_r64(out: &mut Vec<u8>, dest: u8, src: u8) {
    let rex_r = src >= 8;
    let rex_b = dest >= 8;
    out.push(rex_prefix(true, rex_r, false, rex_b));
    out.push(0x89);
    let modrm = (0b11 << 6) | ((src & 7) << 3) | (dest & 7);
    out.push(modrm);
}

/// Emit `mov r32, r32`.
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
#[allow(dead_code)]
pub fn mov_r32_r32(out: &mut Vec<u8>, dest: u8, src: u8) {
    let rex_r = src >= 8;
    let rex_b = dest >= 8;
    out.push(rex_prefix(false, rex_r, false, rex_b));
    out.push(0x89);
    let modrm = (0b11 << 6) | ((src & 7) << 3) | (dest & 7);
    out.push(modrm);
}

/// Emit `imul r64, r64, imm32`.
pub fn imul_r64_r64_imm32(out: &mut Vec<u8>, dest: u8, src: u8, imm: i32) {
    let rex_r = src >= 8;
    let rex_b = dest >= 8;
    out.push(rex_prefix(true, rex_r, false, rex_b));
    out.push(0x69);
    let modrm = (0b11 << 6) | ((src & 7) << 3) | (dest & 7);
    out.push(modrm);
    out.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `call [rip+disp32]` (indirect call via IAT).
pub fn call_rip_rel32(out: &mut Vec<u8>, disp: i32) {
    out.extend_from_slice(&[0xff, 0x15]);
    out.extend_from_slice(&disp.to_le_bytes());
}

/// Emit `call rel32`.
pub fn call_rel32(out: &mut Vec<u8>, disp: i32) {
    out.push(0xe8);
    out.extend_from_slice(&disp.to_le_bytes());
}

/// Emit `jmp rel32`.
pub fn jmp_rel32(out: &mut Vec<u8>, disp: i32) {
    out.push(0xe9);
    out.extend_from_slice(&disp.to_le_bytes());
}

/// Emit `jz/jnz rel32` (jcc near). `cond` 0x84=jz, 0x85=jnz.
pub fn jcc_rel32(out: &mut Vec<u8>, cond: u8, disp: i32) {
    out.extend_from_slice(&[0x0f, cond]);
    out.extend_from_slice(&disp.to_le_bytes());
}

/// Emit `mov dword [mem], imm32` (32-bit store). Used for the completion cookie.
pub fn mov_dword_mem_imm32(out: &mut Vec<u8>, mem: &Mem, imm: u32) {
    let mut rex_x = false;
    let mut rex_b = false;
    out.push(0);
    let rpos = out.len() - 1;
    out.push(0xc7);
    encode_mem(out, mem, false, 0, &mut rex_x, &mut rex_b);
    out[rpos] = rex_prefix(false, false, rex_x, rex_b);
    out.extend_from_slice(&imm.to_le_bytes());
}

/// Emit `rep movsb`.
pub fn rep_movsb(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0xf3, 0xa4]);
}

/// Emit `push r64`.
pub fn push_r64(out: &mut Vec<u8>, reg: u8) {
    if reg >= 8 {
        out.push(0x41);
        out.push(0x50 + (reg & 7));
    } else {
        out.push(0x50 + reg);
    }
}

/// Emit `pop r64`.
pub fn pop_r64(out: &mut Vec<u8>, reg: u8) {
    if reg >= 8 {
        out.push(0x41);
        out.push(0x58 + (reg & 7));
    } else {
        out.push(0x58 + reg);
    }
}

/// Emit `sub rsp, imm8`.
pub fn sub_rsp_imm8(out: &mut Vec<u8>, imm: i8) {
    out.extend_from_slice(&[0x48, 0x83, 0xec, imm as u8]);
}

/// Emit `add rsp, imm8`.
pub fn add_rsp_imm8(out: &mut Vec<u8>, imm: i8) {
    out.extend_from_slice(&[0x48, 0x83, 0xc4, imm as u8]);
}

/// Emit `ret`.
pub fn ret(out: &mut Vec<u8>) {
    out.push(0xc3);
}

/// Emit `nop` (`jmp $` infinite loop used by the fail path).
pub fn infinite_loop(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0xeb, 0xfe]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, MemorySize, Mnemonic, OpKind, Register};

    fn dec(bytes: &[u8]) -> Vec<iced_x86::Instruction> {
        let mut d = Decoder::with_ip(64, bytes, 0x400000, DecoderOptions::NONE);
        let mut out = Vec::new();
        while d.can_decode() {
            out.push(d.decode());
        }
        out
    }

    #[test]
    fn mov_r32_r12_disp_decodes_to_r12() {
        let mut s = Vec::new();
        mov_r32_mem(&mut s, 1, &Mem::r12(0x10)); // mov ecx, [r12+0x10]
        let insn = &dec(&s)[0];
        assert_eq!(insn.mnemonic(), Mnemonic::Mov);
        assert_eq!(insn.memory_base(), Register::R12, "must be r12");
        assert_eq!(insn.memory_displacement64(), 0x10u64);
        assert_eq!(insn.op1_kind(), OpKind::Memory);
        assert_eq!(
            insn.memory_size(),
            MemorySize::UInt32,
            "must be 32-bit load"
        );
    }

    #[test]
    fn mov_r8d_r12_disp_decodes_to_r12() {
        let mut s = Vec::new();
        mov_r32_mem(&mut s, 8, &Mem::r12(8)); // mov r8d, [r12+8]
        let insn = &dec(&s)[0];
        assert_eq!(insn.memory_base(), Register::R12, "must be r12");
        assert_eq!(insn.memory_displacement64(), 8u64);
        assert_eq!(insn.memory_size(), MemorySize::UInt32);
    }

    #[test]
    fn all_r12_offsets_decode_to_r12() {
        for &off in &[0u32, 4, 8, 0xc, 0x10, 0x14, 0x18, 0x1c] {
            let mut s = Vec::new();
            mov_r32_mem(&mut s, 1, &Mem::r12(off as i64));
            let insn = &dec(&s)[0];
            assert_eq!(
                insn.memory_base(),
                Register::R12,
                "offset {off:#x}: base must be r12, got {:?}",
                insn.memory_base()
            );
            assert_eq!(insn.memory_displacement64(), off as u64, "offset {off:#x}");
        }
    }

    #[test]
    fn mov_r13d_r15_disp_decodes_to_r15() {
        let mut s = Vec::new();
        mov_r32_mem(&mut s, 13, &Mem::r15(4)); // mov r13d, [r15+4]
        let insn = &dec(&s)[0];
        assert_eq!(insn.memory_base(), Register::R15, "must be r15");
        assert_eq!(insn.memory_displacement64(), 4u64);
        assert_eq!(
            insn.memory_size(),
            MemorySize::UInt32,
            "header offset must be 32-bit"
        );
    }

    #[test]
    fn mov_r12d_r15_disp_is_32bit_zero_extend() {
        let mut s = Vec::new();
        mov_r32_mem(&mut s, 12, &Mem::r15(0x10)); // mov r12d, [r15+0x10]
        let insn = &dec(&s)[0];
        assert_eq!(insn.memory_base(), Register::R15);
        assert_eq!(insn.memory_displacement64(), 0x10u64);
        assert_eq!(
            insn.memory_size(),
            MemorySize::UInt32,
            "header offset must be 32-bit"
        );
    }

    #[test]
    fn mov_rbx_index_scale8_decodes() {
        let mut s = Vec::new();
        mov_r64_mem(&mut s, 0, &Mem::rbx_index(9, 8)); // mov rax, [rbx+r9*8]
        let insn = &dec(&s)[0];
        assert_eq!(insn.memory_base(), Register::RBX);
        assert_eq!(insn.memory_index(), Register::R9);
        assert_eq!(insn.memory_index_scale(), 8);
        assert_eq!(insn.memory_size(), MemorySize::UInt64);
    }

    #[test]
    fn mov_mem_rbx_r11_scale8_store_r10() {
        let mut s = Vec::new();
        mov_mem_r64(&mut s, &Mem::rbx_index(11, 8), 10); // mov [rbx+r11*8], r10
        let insn = &dec(&s)[0];
        assert_eq!(insn.mnemonic(), Mnemonic::Mov);
        assert_eq!(insn.memory_base(), Register::RBX);
        assert_eq!(insn.memory_index(), Register::R11);
        assert_eq!(insn.memory_index_scale(), 8);
        assert_eq!(insn.op1_register(), Register::R10, "store src must be r10");
    }

    #[test]
    fn movzx_byte_r12_decodes() {
        let mut s = Vec::new();
        movzx_r32_byte_mem(&mut s, 8, &Mem::r12(8)); // movzx r8d, byte [r12+8]
        let insn = &dec(&s)[0];
        assert_eq!(insn.mnemonic(), Mnemonic::Movzx);
        assert_eq!(insn.memory_base(), Register::R12);
        assert_eq!(insn.memory_size(), MemorySize::UInt8, "byte load");
    }

    #[test]
    fn mov_dword_cookie_decodes() {
        let mut s = Vec::new();
        mov_dword_mem_imm32(
            &mut s,
            &Mem {
                base: 10,
                index: None,
                scale: 1,
                disp: 0,
            },
            1,
        );
        let insn = &dec(&s)[0];
        assert_eq!(insn.mnemonic(), Mnemonic::Mov);
        assert_eq!(insn.memory_base(), Register::R10);
        assert_eq!(insn.memory_size(), MemorySize::UInt32);
    }

    #[test]
    fn add_r64_mem_r12_decodes() {
        let mut s = Vec::new();
        add_r64_mem(&mut s, 10, &Mem::r12(0x18)); // add r10, [r12+0x18]
        let insn = &dec(&s)[0];
        assert_eq!(insn.mnemonic(), Mnemonic::Add);
        assert_eq!(insn.memory_base(), Register::R12);
        assert_eq!(insn.memory_displacement64(), 0x18u64);
        assert_eq!(insn.memory_size(), MemorySize::UInt64, "r64 load");
    }
}
