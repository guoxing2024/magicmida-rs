//! iced-x86 disassembly wrapper providing high-level instruction iteration
//! and pattern-matching over decoded instructions.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};

/// High-level wrapper around `iced_x86::Decoder`.
///
/// Provides convenience methods for batch decoding, single-instruction
/// decoding, and predicate-based instruction search.
pub struct Disassembler {
    bitness: u32,
    base_address: u64,
}

impl Disassembler {
    /// Create a new disassembler for the given CPU bitness and base address.
    ///
    /// # Panics
    ///
    /// Panics if `bitness` is not 16, 32, or 64.
    pub fn new(bitness: u32, base_address: u64) -> Self {
        assert!(
            matches!(bitness, 16 | 32 | 64),
            "bitness must be 16, 32, or 64, got {}",
            bitness
        );
        Self {
            bitness,
            base_address,
        }
    }

    /// Decode every instruction in `code`, returning a lazy iterator.
    ///
    /// Instructions are decoded sequentially starting from `base_address`.
    pub fn decode_all<'a>(
        &'a self,
        code: &'a [u8],
    ) -> impl Iterator<Item = Instruction> + 'a {
        let mut decoder = Decoder::with_ip(self.bitness, code, self.base_address, DecoderOptions::NONE);
        std::iter::from_fn(move || {
            if decoder.can_decode() {
                Some(decoder.decode())
            } else {
                None
            }
        })
    }

    /// Decode a single instruction at the given `code` slice with IP = `ip`.
    ///
    /// Returns `None` if there are not enough bytes.
    pub fn decode_one(&self, code: &[u8], ip: u64) -> Option<Instruction> {
        let mut decoder = Decoder::with_ip(self.bitness, code, ip, DecoderOptions::NONE);
        if decoder.can_decode() {
            Some(decoder.decode())
        } else {
            None
        }
    }

    /// Decode sequentially from `base_ip` and return the first instruction that
    /// satisfies `predicate`, together with its byte offset from `base_ip`.
    ///
    /// Returns `None` if no matching instruction is found.
    pub fn find_instruction(
        &self,
        code: &[u8],
        base_ip: u64,
        predicate: impl Fn(&Instruction) -> bool,
    ) -> Option<(usize, Instruction)> {
        let mut decoder = Decoder::with_ip(self.bitness, code, base_ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let insn = decoder.decode();
            if predicate(&insn) {
                let offset = (insn.ip() - base_ip) as usize;
                return Some((offset, insn));
            }
        }
        None
    }
}

/// Returns `true` if the instruction is an indirect call through memory
/// (e.g. `call dword ptr [0x12345678]` or `call qword ptr [rip + 0x1234]`).
///
/// Used to locate IAT entries during import-table reconstruction.
pub fn is_indirect_call(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Call && insn.op_kind(0) == OpKind::Memory
}

/// Returns `true` if the instruction is an indirect jump through memory
/// (e.g. `jmp dword ptr [0x12345678]` or `jmp qword ptr [rip + 0x1234]`).
///
/// Used to locate IAT entries during import-table reconstruction.
pub fn is_indirect_jmp(insn: &Instruction) -> bool {
    insn.mnemonic() == Mnemonic::Jmp && insn.op_kind(0) == OpKind::Memory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_disassembler_valid_bitness() {
        let d = Disassembler::new(64, 0x400000);
        assert_eq!(d.bitness, 64);
        assert_eq!(d.base_address, 0x400000);
    }

    #[test]
    #[should_panic(expected = "bitness")]
    fn new_disassembler_invalid_bitness() {
        Disassembler::new(128, 0);
    }

    #[test]
    fn decode_one_x64() {
        let code = [0x90u8]; // nop
        let d = Disassembler::new(64, 0x401000);
        let insn = d.decode_one(&code, 0x401000).unwrap();
        assert_eq!(insn.mnemonic(), Mnemonic::Nop);
    }

    #[test]
    fn decode_one_x86() {
        let code = [0xC3u8]; // ret
        let d = Disassembler::new(32, 0x401000);
        let insn = d.decode_one(&code, 0x401000).unwrap();
        assert_eq!(insn.mnemonic(), Mnemonic::Ret);
    }

    #[test]
    fn decode_all_iterates() {
        // nop; nop; ret
        let code = [0x90u8, 0x90, 0xC3];
        let d = Disassembler::new(64, 0x401000);
        let insns: Vec<_> = d.decode_all(&code).collect();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].mnemonic(), Mnemonic::Nop);
        assert_eq!(insns[1].mnemonic(), Mnemonic::Nop);
        assert_eq!(insns[2].mnemonic(), Mnemonic::Ret);
    }

    #[test]
    fn decode_all_empty() {
        let d = Disassembler::new(64, 0x401000);
        let insns: Vec<_> = d.decode_all(&[]).collect();
        assert!(insns.is_empty());
    }

    #[test]
    fn find_instruction_x64() {
        // nop; nop; ret
        let code = [0x90u8, 0x90, 0xC3];
        let d = Disassembler::new(64, 0x401000);
        let (offset, insn) = d
            .find_instruction(&code, 0x401000, |i| i.mnemonic() == Mnemonic::Ret)
            .unwrap();
        assert_eq!(offset, 2);
        assert_eq!(insn.mnemonic(), Mnemonic::Ret);
    }

    #[test]
    fn find_instruction_not_found() {
        let code = [0x90u8, 0x90];
        let d = Disassembler::new(64, 0x401000);
        let result = d.find_instruction(&code, 0x401000, |i| i.mnemonic() == Mnemonic::Call);
        assert!(result.is_none());
    }

    #[test]
    fn indirect_call_detected() {
        // call qword ptr [rip + 0x1234] — FF 15 34 12 00 00
        let code = [0xFFu8, 0x15, 0x34, 0x12, 0x00, 0x00];
        let d = Disassembler::new(64, 0x401000);
        let insn = d.decode_one(&code, 0x401000).unwrap();
        assert!(is_indirect_call(&insn));
        assert!(!is_indirect_jmp(&insn));
    }

    #[test]
    fn indirect_jmp_detected() {
        // jmp qword ptr [rip + 0x1234] — FF 25 34 12 00 00
        let code = [0xFFu8, 0x25, 0x34, 0x12, 0x00, 0x00];
        let d = Disassembler::new(64, 0x401000);
        let insn = d.decode_one(&code, 0x401000).unwrap();
        assert!(is_indirect_jmp(&insn));
        assert!(!is_indirect_call(&insn));
    }

    #[test]
    fn direct_call_is_not_indirect() {
        // call rel32 — E8 xx xx xx xx
        let code = [0xE8u8, 0x00, 0x00, 0x00, 0x00];
        let d = Disassembler::new(64, 0x401000);
        let insn = d.decode_one(&code, 0x401000).unwrap();
        assert!(!is_indirect_call(&insn));
    }
}
