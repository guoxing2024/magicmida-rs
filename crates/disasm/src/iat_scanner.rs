/// Scan `.text` for `mov reg,[rip+disp]; call reg` patterns and collect
/// all IAT locations they reference.
///
/// This handles cases where code uses indirect calls via registers instead
/// of direct `call [mem]` instructions. Returns a list of unique IAT addresses.
///
/// # Example pattern
/// ```asm
/// mov rax, [rip+0x1038f5]  ; Load API address from IAT
/// call rax                 ; Call it
/// ```
pub fn find_all_iat_references(
    text: &[u8],
    text_base: usize,
) -> Vec<usize> {
    use std::collections::HashSet;
    let mut iat_refs = HashSet::new();

    // Scan for mov reg,[rip+disp32] patterns (REX.W + 0x8B + ModRM)
    // Common patterns:
    //   48 8B 05 xx xx xx xx  = mov rax,[rip+disp32]
    //   48 8B 0D xx xx xx xx  = mov rcx,[rip+disp32]
    //   48 8B 15 xx xx xx xx  = mov rdx,[rip+disp32]
    //   etc.

    for i in 0..text.len().saturating_sub(7) {
        // Check for REX.W prefix (0x48-0x4F)
        if (text[i] & 0xF8) == 0x48 {
            // Check for MOV opcode (0x8B)
            if text[i + 1] == 0x8B {
                let modrm = text[i + 2];
                // Check if it's [rip+disp32] addressing (ModR/M = 0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D)
                if (modrm & 0xC7) == 0x05 {
                    let ip = text_base + i;
                    let disp32 = i32::from_le_bytes([
                        text[i + 3],
                        text[i + 4],
                        text[i + 5],
                        text[i + 6],
                    ]);
                    // Calculate effective address: RIP after instruction + displacement
                    let iat_addr = (ip as i64 + 7 + disp32 as i64) as usize;

                    // Only collect addresses outside .text section
                    if iat_addr < text_base || iat_addr >= text_base + text.len() {
                        iat_refs.insert(iat_addr);
                    }
                }
            }
        }
    }

    // Also scan for FF 15/25 (call/jmp [rip+disp])
    for i in 0..text.len().saturating_sub(6) {
        if text[i] == 0xFF && (text[i + 1] == 0x15 || text[i + 1] == 0x25) {
            let ip = text_base + i;
            let disp32 = i32::from_le_bytes([
                text[i + 2],
                text[i + 3],
                text[i + 4],
                text[i + 5],
            ]);
            let iat_addr = (ip as i64 + 6 + disp32 as i64) as usize;

            if iat_addr < text_base || iat_addr >= text_base + text.len() {
                iat_refs.insert(iat_addr);
            }
        }
    }

    let mut result: Vec<usize> = iat_refs.into_iter().collect();
    result.sort();
    result
}
