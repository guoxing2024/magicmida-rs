//! Undo for UPX's call-trick filters, ported from `src/filter/{cto,ctok}.h`
//! at tag v5.2.1 (the `U` / unfilter half — the filter half runs at pack time
//! only).
//!
//! Both variants rewrite the 4 bytes after an `E8`/`E9` opcode from a
//! relative displacement into a big-endian "absolute" form
//! (`set_be32(b+ic+1, jc + addvalue + cto<<24)`, where `jc` is the target's
//! offset in the region); unfiltering is the exact inverse:
//! `disp = get_be32(b+ic+1) - ic - 1 - addvalue - cto<<24`, taken modulo
//! 2³² like the C unsigned arithmetic.
//!
//! - id `0x26` (`cto32_e8e9_bswap_le`): the condition is simply
//!   `b[x] == 0xe8 || b[x] == 0xe9` (`filter_impl.cpp` line 73).
//! - id `0x49` (`ctok32_e8e9_bswap_le`): additionally treats a `0F 8x`
//!   jcc-with-rel32 as a call site when `id & 0xf >= 9` (it is, for 0x49),
//!   guarded by `lastcall != x` — and `lastcall` is advanced by the rewrite
//!   itself, which is why the two loops below are spelled out separately
//!   instead of sharing one generic walker.
//!
//! Region and `addvalue` come from `pefile.cpp` `unpack0` (lines 3114-3119):
//! the unfilter runs over `obuf + (oh.codebase - rvamin)`, `oh.codesize`
//! bytes, with `addvalue = oh.codebase - rvamin`.
//!
//! The x86 corpus sample uses 0x26, both x64 samples 0x49; both verified
//! byte-exact against `upx -d`.

use super::error::UpxUnpackError;

/// Undo the filter over `region` (the code region carved out of the decoded
/// image).  `pre` is the byte preceding the region in the image — the ctok
/// condition reads `b[x-1]` and `x == 0` would otherwise index out of bounds
/// (UB in the C; measured never to matter on the corpus, pinned here as 0).
pub fn unfilter(
    id: u8,
    cto: u8,
    addvalue: u32,
    region: &mut [u8],
    pre: u8,
) -> Result<(), UpxUnpackError> {
    match id {
        0x26 => {
            unfilter_cto(region, cto, addvalue);
            Ok(())
        }
        0x49 => {
            unfilter_ctok(region, cto, addvalue, pre);
            Ok(())
        }
        other => Err(UpxUnpackError::UnsupportedFilter(other)),
    }
}

/// `cto.h`, `U`: condition is `b[x] == 0xe8 || b[x] == 0xe9`.
fn unfilter_cto(region: &mut [u8], cto: u8, addvalue: u32) {
    let cto32 = (cto as u32) << 24;
    let size5 = region.len().saturating_sub(5);
    let mut ic = 0usize;
    while ic < size5 {
        if region[ic] == 0xE8 || region[ic] == 0xE9 {
            if rewrite_if_marked(region, ic, cto, addvalue, cto32) {
                ic += 4;
            }
        }
        ic += 1;
    }
}

/// `ctok.h`, `U`: condition is
/// `COND1(b,x) || ((9 <= id & 0xf) && COND2(b,x,lastcall))` with
/// `COND2 = lastcall != x && 0xf == b[x-1] && 0x80 <= b[x] <= 0x8f`.
fn unfilter_ctok(region: &mut [u8], cto: u8, addvalue: u32, pre: u8) {
    let cto32 = (cto as u32) << 24;
    let size5 = region.len().saturating_sub(5);
    let mut lastcall: usize = 0;
    let mut ic = 0usize;
    while ic < size5 {
        let hit = region[ic] == 0xE8
            || region[ic] == 0xE9
            || (lastcall != ic
                && match ic {
                    0 => pre == 0x0F,
                    _ => region[ic - 1] == 0x0F,
                }
                && (0x80..=0x8F).contains(&region[ic]));
        if hit && region[ic + 1] == cto {
            rewrite(region, ic, cto, addvalue, cto32);
            ic += 4;
            lastcall = ic + 1;
        }
        ic += 1;
    }
}

/// The shared rewrite, `set_le32(b+ic+1, jc - ic - 1 - addvalue - cto)`.
/// (`cto` is folded into `cto32` already; the parameter keeps the port
/// shaped like the C signature.)
fn rewrite(region: &mut [u8], ic: usize, _cto: u8, addvalue: u32, cto32: u32) {
    let stored = u32::from_be_bytes([
        region[ic + 1],
        region[ic + 2],
        region[ic + 3],
        region[ic + 4],
    ]);
    let disp = stored
        .wrapping_sub(ic as u32 + 1)
        .wrapping_sub(addvalue)
        .wrapping_sub(cto32);
    region[ic + 1..ic + 5].copy_from_slice(&disp.to_le_bytes());
}

/// Rewrite only when the dword is marked with the cto byte (a "real" call);
/// returns whether it was.
fn rewrite_if_marked(region: &mut [u8], ic: usize, cto: u8, addvalue: u32, cto32: u32) -> bool {
    if region[ic + 1] == cto {
        rewrite(region, ic, cto, addvalue, cto32);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forward filter's rule, applied by hand: stored be32
    /// `= disp + ic + 1 + addvalue + cto<<24`.  Region with one real `E8`
    /// call at ic=0 (addvalue 0, cto 0xAB).
    #[test]
    fn undoes_what_the_filter_does_for_a_real_call() {
        // the filter only fires when jc + addvalue < 1<<24 (the high byte is
        // reserved for the cto mark), so the displacement fits 24 bits
        let disp: u32 = 0x0034_5678;
        let stored: u32 = disp.wrapping_add(0 + 1) | (0xABu32 << 24);
        let mut region = vec![0xE8];
        region.extend_from_slice(&stored.to_be_bytes());
        region.extend_from_slice(&[0x90, 0x90, 0x90]);
        unfilter(0x26, 0xAB, 0, &mut region, 0).expect("supported filter");
        assert_eq!(region[0], 0xE8, "the opcode byte is untouched");
        assert_eq!(&region[1..5], &disp.to_le_bytes());
        assert_eq!(&region[5..], &[0x90, 0x90, 0x90]);
    }

    /// A call whose second byte is not the cto is a "noncall": untouched.
    #[test]
    fn a_noncall_site_is_left_alone() {
        let mut region = vec![0xE8, 0x11, 0x22, 0x33, 0x44, 0x90];
        unfilter(0x26, 0xAB, 0, &mut region, 0).expect("supported filter");
        assert_eq!(region, vec![0xE8, 0x11, 0x22, 0x33, 0x44, 0x90]);
    }

    /// ctok 0x49 also rewrites `0F 8x <be32>` (jcc rel32) — the
    /// `id & 0xf >= 9` arm — where the cto byte marks the rewritten dword.
    #[test]
    fn ctok_rewrites_jcc_sites_with_the_cto_mark() {
        let disp: u32 = 0x0000_1000;
        let stored: u32 = disp.wrapping_add(5 + 1) | (0x55u32 << 24); // ic=5
        let mut region = vec![0x90, 0x90, 0x90, 0x90, 0x0F, 0x85];
        region.extend_from_slice(&stored.to_be_bytes());
        region.extend_from_slice(&[0x90, 0x90]);
        unfilter(0x49, 0x55, 0, &mut region, 0).expect("supported filter");
        assert_eq!(&region[6..10], &disp.to_le_bytes());
    }

    /// An unsupported filter id is an error, never a silent pass-through.
    #[test]
    fn unknown_filter_ids_are_rejected() {
        let mut region = vec![0xE8, 0, 0, 0, 0, 0x90];
        assert!(matches!(
            unfilter(0x80, 0, 0, &mut region, 0),
            Err(UpxUnpackError::UnsupportedFilter(0x80))
        ));
    }
}
