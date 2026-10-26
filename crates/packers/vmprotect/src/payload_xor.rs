//! Payload transforms that are *not* VMProtect features but are needed to turn
//! a carved container into something usable.
//!
//! # Why this is a separate, explicitly named table
//!
//! VMProtect's own output stops at the encrypted container: measured on the
//! `Packed` sample, the resource region freezes at `14596cbd…` and never changes
//! again before the process exits, and no region anywhere in the address space
//! becomes an `MZ` image.  The step that produces a runnable PE is the
//! application's own, so it cannot be derived from the packer's behaviour — it
//! has to be recorded per family.
//!
//! # How the key was obtained (so it can be re-derived, not just believed)
//!
//! Two files of identical length were available: the container as it appears in
//! the image (`14596cbd…`) and the decoded PE the sample itself writes out
//! (`e7004e89…`).  XOR-ing them yields a keystream whose structure is unambiguous:
//!
//! * `K[i] == K[i - 32]` holds for **12,782,080 consecutive bytes** — the entire
//!   file, one unbroken run, so there is no segment boundary to find;
//! * grouping the file into 32-byte blocks produces exactly **one** distinct
//!   block value across all 399,440 blocks;
//! * `K` contains only **31 distinct byte values**, which is what a fixed
//!   32-byte key looks like — a real stream cipher would be near-uniform.
//!
//! Recovered key, and the verification that it is complete:
//!
//! ```text
//! key     8f2bf1f6d282c02613e7bc85c5c9a599abf0ea376ed4227e8165f7d23296562f
//! input   14596cbdb54542a9bc33f955b92002b6f7029609f73753bfe9f384c6a2e5f21f
//! output  e7004e8901a640e9e1f254582df3ecbfc9300a7c2df3e46094922d86e8d64710  (exact)
//! ```
//!
//! Confirmed on three independently produced copies of the container (the
//! resource dump, the launcher's own `ID131`, and a live capture made by
//! `/dump-image`), all decoding to the same `e7004e89…`.

/// A transform that recovers a usable payload from a carved container.
pub struct PayloadTransform {
    /// Resource type this applies to (`RT_RCDATA` is 10).
    pub type_id: u32,
    /// Resource id.
    pub name_id: u32,
    /// Repeating XOR key, applied at `i % key.len()`.
    pub xor_key: &'static [u8],
    /// Where the key came from, in one line, for the log.
    pub provenance: &'static str,
}

/// Known transforms, keyed by resource identity.
///
/// Only entries whose key was measured from two independent artefacts belong
/// here.  A guessed key is worse than no entry: it produces plausible garbage.
pub const KNOWN_TRANSFORMS: &[PayloadTransform] = &[PayloadTransform {
    type_id: 10,
    name_id: 131,
    xor_key: &[
        0x8f, 0x2b, 0xf1, 0xf6, 0xd2, 0x82, 0xc0, 0x26, 0x13, 0xe7, 0xbc, 0x85, 0xc5, 0xc9, 0xa5,
        0x99, 0xab, 0xf0, 0xea, 0x37, 0x6e, 0xd4, 0x22, 0x7e, 0x81, 0x65, 0xf7, 0xd2, 0x32, 0x96,
        0x56, 0x2f,
    ],
    provenance: "measured from 14596cbd… and e7004e89…, a single 32-byte period across all \
                 12,782,080 bytes",
}];

impl PayloadTransform {
    /// Apply the transform.  Never fails; the caller must validate the result.
    pub fn apply(&self, input: &[u8]) -> Vec<u8> {
        input
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.xor_key[i % self.xor_key.len()])
            .collect()
    }
}

/// The transform for `(type_id, name_id)`, if one is known.
pub fn transform_for(type_id: Option<u32>, name_id: Option<u32>) -> Option<&'static PayloadTransform> {
    let (t, n) = (type_id?, name_id?);
    KNOWN_TRANSFORMS
        .iter()
        .find(|x| x.type_id == t && x.name_id == n)
}

/// `true` when `bytes` starts with a DOS header and a PE signature at
/// `e_lfanew`.
///
/// This is the acceptance test for a transform: a correct key must produce a
/// structurally valid image, so a wrong key is rejected by the data rather than
/// by trusting the table above.
pub fn looks_like_pe_image(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let e = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    e >= 0x40 && e.checked_add(4).is_some_and(|end| end <= bytes.len()) && &bytes[e..e + 4] == b"PE\0\0"
}

/// `true` when the decoded image declares itself a DLL in its file header.
///
/// This decides the *file name* of the decoded product, not just cosmetics: the
/// measured payload of the `Packed` launcher family carries
/// `IMAGE_FILE_DLL`, and `CreateProcess` refuses such an image with
/// "is not a valid application for this OS platform" — a user handed a
/// `.decoded.exe` double-clicks it and gets exactly that error.  Naming it
/// `.decoded.dll` states the fact the bytes carry.
///
/// Returns `false` for anything that does not parse down to the file-header
/// characteristics; the caller is expected to have accepted the image as a PE
/// already.
pub fn is_dll_image(bytes: &[u8]) -> bool {
    if !looks_like_pe_image(bytes) {
        return false;
    }
    let e = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let machine_and_more = e + 4;
    // COFF File Header: Machine (2) + NumberOfSections (2) + TimeDateStamp (4)
    // + PointerToSymbolTable (4) + NumberOfSymbols (4) + SizeOfOptionalHeader
    // (2) + Characteristics (2) → offset 18 from the PE signature.
    let chars_at = machine_and_more + 18;
    let Some(chars) = bytes.get(chars_at..chars_at + 2) else {
        return false;
    };
    u16::from_le_bytes([chars[0], chars[1]]) & 0x2000 != 0 // IMAGE_FILE_DLL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_key_has_the_expected_shape() {
        let t = &KNOWN_TRANSFORMS[0];
        assert_eq!(t.type_id, 10);
        assert_eq!(t.name_id, 131);
        assert_eq!(t.xor_key.len(), 32, "the measured period is 32 bytes");
        // 31 distinct values is what was measured; a uniform key would be a
        // different (and probably wrong) finding.
        let mut seen: Vec<u8> = t.xor_key.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 31);
    }

    #[test]
    fn applying_the_key_twice_is_the_identity() {
        let t = &KNOWN_TRANSFORMS[0];
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 13) as u8).collect();
        assert_eq!(t.apply(&t.apply(&data)), data);
    }

    #[test]
    fn a_real_pe_head_is_recognised_and_a_bad_one_is_not() {
        // The measured plaintext head, with e_lfanew 0x80 and a PE signature.
        let mut buf = vec![0u8; 0x100];
        buf[0..4].copy_from_slice(b"MZ\x90\x00");
        buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(looks_like_pe_image(&buf));

        // Same bytes with the signature removed.
        let mut bad = buf.clone();
        bad[0x80] = b'X';
        assert!(!looks_like_pe_image(&bad));

        // e_lfanew pointing outside the buffer must not panic.
        let mut bad = buf.clone();
        bad[0x3c..0x40].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(!looks_like_pe_image(&bad));

        assert!(!looks_like_pe_image(b"MZ"));
        assert!(!looks_like_pe_image(b""));
    }

    #[test]
    fn lookup_is_by_resource_identity_and_misses_cleanly() {
        assert!(transform_for(Some(10), Some(131)).is_some());
        assert!(transform_for(Some(10), Some(132)).is_none());
        assert!(transform_for(Some(3), Some(131)).is_none());
        assert!(transform_for(None, Some(131)).is_none());
    }

    /// A minimal but field-exact PE head: DOS header with `e_lfanew 0x80`,
    /// PE signature, and a COFF file header whose Characteristics the caller
    /// sets.  Mirrors how the real payload head is shaped (`e_lfanew 0x80`).
    /// Characteristics sit at `e_lfanew + 4 (signature) + 18 (COFF offset)`.
    fn pe_head(characteristics: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0xa0];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x96..0x98].copy_from_slice(&characteristics.to_le_bytes());
        b
    }

    #[test]
    fn the_dll_bit_decides_the_extension() {
        // The measured payload is an EXE-shaped head plus IMAGE_FILE_DLL.
        assert!(is_dll_image(&pe_head(0x2022)), "0x2022 carries IMAGE_FILE_DLL");
        assert!(is_dll_image(&pe_head(0x2100 | 0x2000 | 0x0002)));
        // An ordinary EXE image must not be renamed.
        assert!(!is_dll_image(&pe_head(0x0022)));
        assert!(!is_dll_image(&pe_head(0x0106 | 0x0002)));
    }

    #[test]
    fn is_dll_image_never_panics_on_truncated_input() {
        assert!(!is_dll_image(b""));
        assert!(!is_dll_image(b"MZ"));
        // `looks_like_pe_image` accepts a head truncated inside the COFF
        // header (it only reads the signature), so the DLL check must survive
        // that shape on its own.
        assert!(!is_dll_image(&pe_head(0x2022)[..0x96])); // cut before Characteristics
        assert!(!is_dll_image(&pe_head(0x2022)[..0x97])); // one Characteristics byte
        assert!(!is_dll_image(&pe_head(0x2022)[..0x80])); // cut before the signature
    }
}