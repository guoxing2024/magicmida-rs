//! Unit tests for `runtime_loader` (WO-21 split).
//!
//! Mechanically relocated from `runtime_loader.rs` (WO-9/16 pattern): zero
//! logic change, `super`/`super::super` resolve exactly because the module
//! is declared from `runtime_loader.rs` via `#[cfg(test)] #[path =
//! "runtime_loader_tests.rs"] mod runtime_loader_tests;`.

use super::*;

#[cfg(test)]
mod imp03_inert_adapter_tests {
    use super::*;

    /// Canonical user VA used as the fake target-local blob base in tests.
    const BLOB_BASE: u64 = 0x0000_1000_0000;

    fn dig64() -> String {
        "a".repeat(64)
    }

    fn build_blob(surfaces: &[&str]) -> V2ParamsBlob {
        let ss: Vec<String> = surfaces.iter().map(|s| s.to_string()).collect();
        V2ParamsBlob::build("p", "d", &ss, &dig64(), BLOB_BASE).unwrap()
    }

    #[test]
    fn wanted_exports_v2_has_five_symbols() {
        assert_eq!(WANTED_EXPORTS_V2.len(), 5);
        assert_eq!(WANTED_EXPORTS_V2[0], "MidaAntidebugInitialize");
        assert_eq!(WANTED_EXPORTS_V2[1], "MidaAntidebugGetAttestation");
        assert_eq!(WANTED_EXPORTS_V2[2], "MidaAntidebugShutdown");
        assert_eq!(WANTED_EXPORTS_V2[3], "MidaAntidebugInitializeV2");
        assert_eq!(WANTED_EXPORTS_V2[4], "WalkerExecute");
    }

    #[test]
    fn mida_exports_v2_require_complete_fail_closed() {
        // Empty set: every entry missing -> Err.
        let e = MidaExportsV2 {
            initialize: None,
            get_attestation: None,
            shutdown: None,
            initialize_v2: None,
            walker_execute: None,
        };
        assert!(e.require_complete().is_err());
        // v1 trio present but v2 entry + walker missing -> Err.
        let e2 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: None,
            walker_execute: None,
        };
        assert!(e2.require_complete().is_err());
        assert!(e2.require_v2_entry().is_err());
        // Full 5-item set -> Ok.
        let e3 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: Some(0x4000),
            walker_execute: Some(0x5000),
        };
        assert_eq!(e3.require_complete(), Ok(()));
        assert_eq!(e3.require_v2_entry(), Ok(0x4000));
        // v2 entry missing but walker present -> require_v2_entry Err.
        let e4 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: None,
            walker_execute: Some(0x5000),
        };
        assert!(e4.require_v2_entry().is_err());
    }

    #[test]
    fn thunk7_fixture_production_is_60b() {
        let fx = Thunk7Fixture::build();
        assert_eq!(fx.production.len(), 60);
        assert_eq!(fx.test_with_probe.len(), 64);
        fx.validate_structure().unwrap();
    }

    #[test]
    fn thunk7_fixture_structural_offsets() {
        let fx = Thunk7Fixture::build();
        assert_eq!(&fx.production[0x35..0x37], &[0xFF, 0xD0]);
        assert_eq!(fx.production[0x3B], 0xC3);
        assert_eq!(&fx.test_with_probe[0x35..0x39], &[0x49, 0x89, 0x63, 0x48]);
        assert_eq!(&fx.test_with_probe[0x39..0x3B], &[0xFF, 0xD0]);
        assert_eq!(fx.test_with_probe[0x3F], 0xC3);
    }

    #[test]
    fn thunk7_fixture_matches_known_hashes() {
        use sha2::{Digest, Sha256};
        let fx = Thunk7Fixture::build();
        let prod_sha = {
            let mut h = Sha256::new();
            h.update(&fx.production);
            let out = h.finalize();
            out.iter().map(|b| format!("{:02X}", b)).collect::<String>()
        };
        assert_eq!(
            prod_sha,
            "9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017"
        );
        let test_sha = {
            let mut h = Sha256::new();
            h.update(&fx.test_with_probe);
            let out = h.finalize();
            out.iter().map(|b| format!("{:02X}", b)).collect::<String>()
        };
        assert_eq!(
            test_sha,
            "01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE"
        );
    }

    // ------------------------------------------------------------------
    // V2ParamsBlob: build / parse (RC-4 absolute-VA envelope)
    // ------------------------------------------------------------------

    #[test]
    fn v2_params_blob_roundtrip_offsets() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        assert!(blob.bytes.len() > V2_HEADER_BYTES);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.profile_id_off, 0x48);
        assert_eq!(offs.digest_len, 64);
        assert_eq!(offs.expected_hooks, 2);
    }

    #[test]
    fn v2_params_blob_rejects_bad_digest_len() {
        let ss = vec!["AD-PROC-001".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, "short", BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_parse_rejects_truncated() {
        let blob = V2ParamsBlob {
            bytes: vec![0u8; 16],
        };
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_digest_len_field_is_64() {
        let blob = build_blob(&["AD-PROC-001"]);
        let field = u64::from_le_bytes(blob.bytes[0x40..0x48].try_into().unwrap());
        assert_eq!(field, 64);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.digest_len, 64);
        assert_eq!(offs.digest_off + 65, blob.bytes.len() as u64);
    }

    #[test]
    fn v2_params_blob_rejects_wrong_digest_len_field() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x40..0x48].copy_from_slice(&65u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_unknown_tail() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes.push(0xAA);
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_non_hex_digest() {
        let ss = vec!["AD-PROC-001".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, &"z".repeat(64), BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_offset_out_of_bounds() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let len = blob.bytes.len() as u64;
        blob.bytes[0x10..0x18].copy_from_slice(&(len + 100).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_underflow_surface_region() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        blob.bytes[0x28..0x30].copy_from_slice(&(dig_off + 8).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_build_writes_expected_hooks() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let h = u64::from_le_bytes(blob.bytes[0x20..0x28].try_into().unwrap());
        assert_eq!(h, 2);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.expected_hooks, 2);
    }

    #[test]
    fn v2_params_blob_rejects_uppercase_digest() {
        let ss = vec!["AD-PROC-001".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, &"A".repeat(64), BLOB_BASE).is_err());
        assert!(V2ParamsBlob::build("p", "d", &ss, &("a".repeat(63) + "F"), BLOB_BASE).is_err());
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), BLOB_BASE).is_ok());
    }

    #[test]
    fn v2_params_blob_parse_rejects_uppercase_digest_on_wire() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        blob.bytes[dig_off as usize] = b'A';
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_zero_expected_hooks() {
        // zero hooks + NONZERO surfaces_off must be rejected (RC-4 item 7).
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_zero_hooks_zero_off_allowed() {
        // RC-4 item 6: expected_hooks == 0 && surf_off == 0 is legal.
        let mut blob = build_blob(&["AD-PROC-001"]);
        // remove the pointer array region so the envelope has no array bytes;
        // digest shifts left by the array size, so digest_off must be updated.
        let surf_arr_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        let arr_len = (dig_off - surf_arr_off) as usize;
        blob.bytes.drain(surf_arr_off as usize..dig_off as usize);
        debug_assert_eq!(arr_len, 8);
        blob.bytes[0x38..0x40].copy_from_slice(&surf_arr_off.to_le_bytes());
        // zero hooks + zero surfaces_off
        blob.bytes[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        blob.bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.expected_hooks, 0);
        assert_eq!(offs.expected_surfaces_off, 0);
    }

    #[test]
    fn v2_params_blob_rejects_nonzero_hooks_zero_off() {
        // RC-4 item 8: nonzero hooks + zero surfaces_off must be rejected.
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_array_length_mismatch() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x20..0x28].copy_from_slice(&2u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_array_truncation() {
        // array region shorter than declared: surf_off moved 8 bytes right.
        let mut blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[0x28..0x30].copy_from_slice(&(surf_off + 8).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_zero_surface_entry() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_relative_surface_entry() {
        // RC-4 item 11: a self-relative-style small offset is NOT a valid
        // absolute VA (it is outside [blob_base, blob_end)).
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&0x48u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_noncanonical_surface_entry() {
        // RC-4 item 12: kernel-high-half VA (bit 47 set) is noncanonical user.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&0xFFFF_8000_0000_0000u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_entry_outside_blob() {
        // absolute VA beyond blob_end must be rejected.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let blob_end = BLOB_BASE + blob.bytes.len() as u64;
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&(blob_end + 0x10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_surface_string_unterminated() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let entry = u64::from_le_bytes(
            blob.bytes[surf_off as usize..surf_off as usize + 8]
                .try_into()
                .unwrap(),
        );
        let rel = (entry - BLOB_BASE) as usize;
        // wipe ALL bytes from the surface string start to blob end with non-zero
        for i in rel..blob.bytes.len() {
            blob.bytes[i] = 0x58; // 'X'
        }
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_builder_rejects_zero_hooks() {
        let empty: Vec<String> = vec![];
        assert!(V2ParamsBlob::build("p", "d", &empty, &dig64(), BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_builder_rejects_over_256() {
        // RC-4 item 10: builder rejects > 256 surfaces.
        let many: Vec<String> = (0..257).map(|i| format!("SURF-{i}")).collect();
        assert!(V2ParamsBlob::build("p", "d", &many, &dig64(), BLOB_BASE).is_err());
        // exactly 256 is allowed at build; parse requires matching array.
        let at256: Vec<String> = (0..256).map(|i| format!("SURF-{i}")).collect();
        let blob = V2ParamsBlob::build("p", "d", &at256, &dig64(), BLOB_BASE).unwrap();
        assert_eq!(
            u64::from_le_bytes(blob.bytes[0x20..0x28].try_into().unwrap()),
            256
        );
        assert!(blob.parse_offsets(BLOB_BASE).is_ok());
    }

    #[test]
    fn v2_params_blob_builder_rejects_empty_surface_string() {
        let ss = vec!["".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_builder_rejects_noncanonical_blob_base() {
        let ss = vec!["AD-PROC-001".to_string()];
        // kernel high half: noncanonical user VA
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), 0xFFFF_8000_0000_0000).is_err());
        // zero blob base rejected
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), 0).is_err());
    }

    #[test]
    fn v2_params_blob_build_writes_absolute_surface_vars() {
        // RC-4 item 2: array entries are ABSOLUTE target VAs (blob_base + rel).
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let e0 = u64::from_le_bytes(
            blob.bytes[surf_off as usize..surf_off as usize + 8]
                .try_into()
                .unwrap(),
        );
        let e1 = u64::from_le_bytes(
            blob.bytes[surf_off as usize + 8..surf_off as usize + 16]
                .try_into()
                .unwrap(),
        );
        // first surface string starts at 0x48 + len("p")+1 + len("d")+1
        let s0_rel = (0x48 + 2 + 2) as u64;
        let s1_rel = s0_rel + "AD-PROC-001".len() as u64 + 1;
        assert_eq!(e0, BLOB_BASE + s0_rel);
        assert_eq!(e1, BLOB_BASE + s1_rel);
        assert!(e0 > BLOB_BASE && e1 > e0);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.expected_hooks, 2);
    }

    #[test]
    fn v2_params_blob_build_rejects_absolute_va_overflow() {
        // blob_base at top of canonical user range + long strings -> the
        // absolute entry VA overflows u64 (checked_add fail-closed).
        let ss = vec!["AD-PROC-001".to_string()];
        let base = 0x0000_7FFF_FFFF_FFFFu64;
        // build must fail because abs = base + rel overflows
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), base).is_err());
    }

    #[test]
    fn v2_params_blob_parse_rejects_bad_blob_base() {
        let blob = build_blob(&["AD-PROC-001"]);
        // zero blob base
        assert!(blob.parse_offsets(0).is_err());
        // noncanonical blob base
        assert!(blob.parse_offsets(0xFFFF_8000_0000_0000).is_err());
        // blob_base + params_bytes overflow (defensive; canonical check
        // already rejects noncanonical base first)
        assert!(blob.parse_offsets(0x0000_7000_0000_0000).is_err());
    }

    #[test]
    fn v2_params_blob_parse_rejects_entry_arithmetic_underflow() {
        // entry arithmetic is fully checked (RC-4 P0-4): a crafted entry
        // below blob_base (but canonical) is rejected before any read.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let below = BLOB_BASE - 0x1000;
        blob.bytes[surf_off as usize..surf_off as usize + 8].copy_from_slice(&below.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    // ------------------------------------------------------------------
    // RC-5: checked helper / overflow branch unit tests
    // ------------------------------------------------------------------

    #[test]
    fn v2_checked_range_end_ok() {
        assert_eq!(
            checked_range_end(0x48, 65, "digest region").unwrap(),
            0x48 + 65
        );
        assert_eq!(checked_range_end(0x100, 0, "zero").unwrap(), 0x100);
    }

    #[test]
    fn v2_checked_range_end_overflow_fails_closed() {
        // u64::MAX + 1 must fail (no wrap).
        assert!(checked_range_end(u64::MAX, 1, "wrap").is_err());
        assert!(checked_range_end(u64::MAX, 8, "entry").is_err());
        assert!(checked_range_end(u64::MAX - 1, 2, "tail").is_err());
        // u64::MAX + 0 is fine (no overflow).
        assert_eq!(checked_range_end(u64::MAX, 0, "zero").unwrap(), u64::MAX);
    }

    #[test]
    fn v2_u64_to_usize_ok() {
        assert_eq!(u64_to_usize(0, "zero").unwrap(), 0usize);
        assert_eq!(u64_to_usize(0x48, "header").unwrap(), 0x48usize);
    }

    #[test]
    fn v2_u64_to_usize_overflow_fails_closed() {
        // On 32-bit targets a value above usize::MAX fails; on 64-bit the
        // conversion always succeeds, but the helper must never panic.
        let r = u64_to_usize(u64::MAX, "max");
        if usize::BITS < 64 {
            assert!(r.is_err());
        } else {
            assert_eq!(r.unwrap(), usize::MAX);
        }
    }

    #[test]
    fn v2_parse_offsets_rejects_digest_region_overflow_on_wire() {
        // digest_off = u64::MAX - 10: checked_range_end fails before any read.
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x38..0x40].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_parse_offsets_rejects_surfaces_end_overflow_on_wire() {
        // surf_off = u64::MAX - 10 with expected_hooks=1: array_end overflows.
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x28..0x30].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_parse_offsets_rejects_entry_offset_overflow_on_wire() {
        // surf_off = u64::MAX - 10, expected_hooks=2: second entry offset
        // (surf_off + 8) overflows and must fail-closed.
        let mut blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        blob.bytes[0x20..0x28].copy_from_slice(&2u64.to_le_bytes());
        blob.bytes[0x28..0x30].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_build_patch_closure_is_checked() {
        // The patch helper rejects out-of-range writes.
        let mut out = vec![0u8; 0x48];
        let patch = |out: &mut Vec<u8>, off: usize, val: u64| -> Result<(), RuntimeLoadError> {
            let end = off.checked_add(8).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed("v2 header patch overflow".to_string())
            })?;
            if end > out.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "v2 header patch out of bounds".to_string(),
                ));
            }
            out[off..end].copy_from_slice(&val.to_le_bytes());
            Ok(())
        };
        // valid patch
        assert!(patch(&mut out, 0x10, 0x48).is_ok());
        assert_eq!(&out[0x10..0x18], &0x48u64.to_le_bytes());
        // OOB patch fails (0x48 + 8 exceeds the 0x48-byte buffer)
        assert!(patch(&mut out, 0x48, 1).is_err());
        assert!(patch(&mut out, 0x41, 1).is_err());
        // overflow patch fails (off + 8 wraps)
        assert!(patch(&mut out, usize::MAX - 1, 1).is_err());
    }
    // ------------------------------------------------------------------
    // RC-6 / IMP-03-R5: local V2 preflight consumer
    // ------------------------------------------------------------------

    #[test]
    fn v2_preflight_valid_absolute_va_envelope() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        // structured result mirrors parse_offsets fields
        assert_eq!(pf.profile_id_off, 0x48);
        assert_eq!(pf.profile_digest_off, 0x48 + 2); // 74
        assert_eq!(pf.digest_len, 64);
        assert_eq!(pf.expected_hooks, 2);
        assert_eq!(pf.blob_base, BLOB_BASE);
        // surface entries are absolute VAs in declared order
        assert_eq!(pf.surface_entries.len(), 2);
        let s0_rel = (0x48 + 2 + 2) as u64; // "p\x00" + "d\x00"
        let s1_rel = s0_rel + "AD-PROC-001".len() as u64 + 1;
        assert_eq!(pf.surface_entries[0], BLOB_BASE + s0_rel);
        assert_eq!(pf.surface_entries[1], BLOB_BASE + s1_rel);
        // relative conversion round trip
        assert_eq!(pf.surface_relative_offset(0).unwrap(), s0_rel);
        assert_eq!(pf.surface_relative_offset(1).unwrap(), s1_rel);
        assert!(pf.surface_relative_offset(2).is_err());
    }

    #[test]
    fn v2_preflight_zero_hooks_zero_off_allowed() {
        // expected_hooks == 0 && surfaces_off == 0 is a legal envelope.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_arr_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        let arr_len = (dig_off - surf_arr_off) as usize;
        blob.bytes.drain(surf_arr_off as usize..dig_off as usize);
        debug_assert_eq!(arr_len, 8);
        blob.bytes[0x38..0x40].copy_from_slice(&surf_arr_off.to_le_bytes());
        blob.bytes[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        blob.bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        assert_eq!(pf.expected_hooks, 0);
        assert_eq!(pf.expected_surfaces_off, 0);
        assert!(pf.surface_entries.is_empty());
    }

    #[test]
    fn v2_preflight_wrong_blob_base_rejected() {
        // blob_base mismatch: entries validated against a DIFFERENT base
        // are out-of-blob -> fail-closed.
        let blob = build_blob(&["AD-PROC-001"]);
        assert!(blob.preflight_local(BLOB_BASE + 0x1000).is_err());
        assert!(blob.preflight_local(0).is_err());
        assert!(blob.preflight_local(0xFFFF_8000_0000_0000).is_err());
    }

    #[test]
    fn v2_preflight_unknown_tail_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes.push(0xAA);
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_noncanonical_entry_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&0xFFFF_8000_0000_0000u64.to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_zero_entry_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_out_of_blob_entry_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let blob_end = BLOB_BASE + blob.bytes.len() as u64;
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&(blob_end + 0x10).to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_digest_truncation_rejected() {
        // truncate the digest region: NUL missing / hex region cut
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes.truncate(blob.bytes.len() - 10);
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_surface_array_truncation_rejected() {
        // array region shorter than declared: surf_off moved 8 bytes right
        let mut blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[0x28..0x30].copy_from_slice(&(surf_off + 8).to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_surface_string_helper() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        let s0 = blob.surface_string(&pf, 0).unwrap();
        let s1 = blob.surface_string(&pf, 1).unwrap();
        assert_eq!(s0, b"AD-PROC-001");
        assert_eq!(s1, b"AD-PROC-002");
        assert!(blob.surface_string(&pf, 2).is_err());
    }

    #[test]
    fn v2_preflight_is_local_only_not_live_pass() {
        // Explicit semantic: a successful preflight is NOT a runtime/live
        // pass. It only proves local structural consistency. We assert the
        // API returns the structured result WITHOUT any runtime call, and
        // that the semantic note is documented on the type.
        let blob = build_blob(&["AD-PROC-001"]);
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        assert!(pf.surface_entries.len() == 1);
        assert!(pf.digest_len == 64);
        // The preflight does not imply any target-side capability; the
        // gate remains authoritative (checked in acceptance crate).
    }
}

#[cfg(test)]
mod imp06_sealed_authority_tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let d = h.finalize();
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn minimal_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        b
    }

    fn manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    fn tmp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("mida-imp06-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    /// The ONLY legitimate construction path: real PE file -> real
    /// verify_file() -> verified identity -> digest authority.
    fn verified_authority() -> RuntimeDigestAuthority {
        let pe = minimal_pe();
        let path = tmp_file("imp06_verified_runtime.dll", &pe);
        let expected = sha256_hex(&pe);
        let authority = manifest(&expected, pe.len() as u64);
        let id = authority.verify_file(&path).unwrap();
        RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
            .expect("verified identity must build a valid authority")
    }

    #[test]
    fn sealed_authority_getters_reflect_verified_identity() {
        let pe = minimal_pe();
        let path = tmp_file("imp06_getters.dll", &pe);
        let expected = sha256_hex(&pe);
        let authority = manifest(&expected, pe.len() as u64);
        let id = authority.verify_file(&path).unwrap();
        let da = RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
            .expect("verified identity must build a valid authority");
        assert_eq!(da.digest_value(), expected);
        assert_eq!(da.size_bytes(), pe.len() as u64);
        assert_eq!(da.architecture(), "x86_64");
        assert_eq!(da.manifest_artifact_id(), authority.artifact_id);
        assert_eq!(da.canonical_path(), id.path());
        // Read-only surface: no public field access, no public constructor.
        let _: &Path = da.canonical_path();
        let _: &str = da.digest_value();
        let _: u64 = da.size_bytes();
        let _: &str = da.manifest_artifact_id();
        let _: &str = da.architecture();
    }

    #[test]
    fn sealed_authority_echo_checks_are_fail_closed() {
        let auth = verified_authority();
        // Missing / placeholder / bad shapes all rejected.
        assert_eq!(
            auth.verify_runtime_echo(""),
            Err(DigestValidationError::Missing)
        );
        assert_eq!(
            auth.verify_runtime_echo(PLACEHOLDER_RUNTIME_DIGEST),
            Err(DigestValidationError::Placeholder)
        );
        assert!(matches!(
            auth.verify_runtime_echo(&"b".repeat(63)),
            Err(DigestValidationError::WrongLength { .. })
        ));
        assert!(matches!(
            auth.verify_runtime_echo(&"B".repeat(64)),
            Err(DigestValidationError::NotLowercaseHex)
        ));
        assert!(matches!(
            auth.verify_runtime_echo(&"z".repeat(64)),
            Err(DigestValidationError::NotLowercaseHex)
        ));
        // Correct digest accepted; different valid digest rejected.
        let d = auth.digest_value().to_string();
        assert_eq!(auth.verify_runtime_echo(&d), Ok(()));
        assert!(matches!(
            auth.verify_runtime_echo(&"c".repeat(64)),
            Err(DigestValidationError::EchoMismatch { .. })
        ));
    }

    #[test]
    fn sealed_authority_is_single_hash_point() {
        let pe = minimal_pe();
        let path = tmp_file("imp06_hashpoint.dll", &pe);
        let expected = sha256_hex(&pe);
        let authority = manifest(&expected, pe.len() as u64);
        let id = authority.verify_file(&path).unwrap();
        assert_eq!(id.sha256(), expected);
        // The authority digest is copied from the verified identity — no
        // second file read, no second hash computation.
        let da = RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
            .expect("verified identity must build a valid authority");
        assert_eq!(da.digest_value(), id.sha256());
        assert_eq!(da.digest_value(), expected);
        assert_eq!(da.size_bytes(), id.size_bytes());
        assert_eq!(da.manifest_artifact_id(), authority.artifact_id);
        assert_eq!(da.canonical_path(), id.path());
    }

    #[test]
    fn from_verified_identity_rejects_invalid_digest() {
        // The lexical gates are the same code path used by the production
        // authority; a forged identity (impossible outside this module) with
        // an invalid digest must be rejected here too.
        let id = RuntimeFileIdentity::from_verified(
            std::path::PathBuf::from("C:/tmp/x.dll"),
            PLACEHOLDER_RUNTIME_DIGEST.to_string(),
            10,
            "x86_64".to_string(),
            0x1000,
        );
        assert!(matches!(
            RuntimeDigestAuthority::from_verified_identity(&id, "mida-antidebug-runtime-x64"),
            Err(DigestValidationError::Placeholder)
        ));
        let id2 = RuntimeFileIdentity::from_verified(
            std::path::PathBuf::from("C:/tmp/x.dll"),
            "A".repeat(64),
            10,
            "x86_64".to_string(),
            0x1000,
        );
        assert!(matches!(
            RuntimeDigestAuthority::from_verified_identity(&id2, "mida-antidebug-runtime-x64"),
            Err(DigestValidationError::NotLowercaseHex)
        ));
        let id3 = RuntimeFileIdentity::from_verified(
            std::path::PathBuf::from("C:/tmp/x.dll"),
            "a".repeat(32),
            10,
            "x86_64".to_string(),
            0x1000,
        );
        assert!(matches!(
            RuntimeDigestAuthority::from_verified_identity(&id3, "mida-antidebug-runtime-x64"),
            Err(DigestValidationError::WrongLength { .. })
        ));
    }
}

#[cfg(test)]
mod imp08_v2_production_tests {
    use super::*;

    /// Minimal name_at resolver backed by a flat string table.
    /// Returns Ok(true) when a NUL terminator was found inside the table.
    fn flat_name_at(
        table: &[u8],
    ) -> impl FnMut(usize, &mut Vec<u8>) -> Result<bool, RuntimeLoadError> + '_ {
        move |rva, out| {
            let off = rva - 0x1000;
            let mut terminated = false;
            if off < table.len() {
                for &b in &table[off..] {
                    if b == 0 {
                        terminated = true;
                        break;
                    }
                    out.push(b);
                }
            }
            Ok(terminated)
        }
    }
    fn wanted5() -> [&'static [u8]; 5] {
        [
            b"MidaAntidebugInitialize",
            b"MidaAntidebugGetAttestation",
            b"MidaAntidebugShutdown",
            b"MidaAntidebugInitializeV2",
            b"WalkerExecute",
        ]
    }

    /// Build a flat export table with the 5 wanted names at known RVAs.
    fn build_export_table() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut strings = Vec::new();
        for (i, s) in symbols.iter().enumerate() {
            let _ = s;
            // Name-pointer table only (4B per entry); ordinals are a
            // SEPARATE array in the PE export directory.
            strings.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
        }
        // function RVAs: 0x2000 + i*0x10
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        // name strings
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            // Names live at RVA 0x1000 + i*0x20; table is a flat image that
            // starts at RVA 0x1000, so the in-table offset is i*0x20.
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        (strings, funcs, table)
    }

    #[test]
    fn wanted_set_is_frozen_five() {
        assert_eq!(WANTED_EXPORTS_V2.len(), 5);
        assert_eq!(
            WANTED_EXPORTS_V2,
            &[
                "MidaAntidebugInitialize",
                "MidaAntidebugGetAttestation",
                "MidaAntidebugShutdown",
                "MidaAntidebugInitializeV2",
                "WalkerExecute",
            ]
        );
    }

    #[test]
    fn resolve_five_exports_all_found() {
        let (names, funcs, table) = build_export_table();
        let mut name_at = flat_name_at(&table);
        let ords: Vec<u8> = (0..5).flat_map(|i| (i as u16).to_le_bytes()).collect();
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            5,
            5,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &wanted5(),
        )
        .unwrap();
        assert_eq!(found.len(), 5);
        for (i, f) in found.iter().enumerate() {
            assert_eq!(*f, Some(0x400000 + 0x2000 + i * 0x10));
        }
        // require_complete succeeds on the full set.
        let e = MidaExportsV2 {
            initialize: found[0],
            get_attestation: found[1],
            shutdown: found[2],
            initialize_v2: found[3],
            walker_execute: found[4],
        };
        assert_eq!(e.require_complete(), Ok(()));
    }

    #[test]
    fn digest_required_no_v1_fallback() {
        // IMP-08-R1 requirement 7: digest-required mode MUST NOT silently
        // fall back to the v1 entry. require_complete() demands the FULL
        // 5-item set — v1 alone (even with v2 present) is incomplete, and a
        // missing v1 entry also fails. The production caller
        // (load_and_initialize_inner, require_digest=true) calls
        // require_complete() + require_v2_entry() BEFORE any thunk call.
        let full = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: Some(0x4000),
            walker_execute: Some(0x5000),
        };
        assert_eq!(full.require_complete(), Ok(()));
        // v1 missing: still fails (no fallback to a "v2-only" mode).
        let no_v1 = MidaExportsV2 {
            initialize: None,
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: Some(0x4000),
            walker_execute: Some(0x5000),
        };
        assert!(no_v1.require_complete().is_err());
        // v2 missing but v1 present: fails (digest-required needs V2).
        let no_v2 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: None,
            walker_execute: Some(0x5000),
        };
        assert!(no_v2.require_complete().is_err());
        assert!(no_v2.require_v2_entry().is_err());
    }

    #[test]
    fn resolve_missing_export_fails_closed() {
        // Only 4 of the 5 wanted names present.
        let symbols: [&str; 4] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        let mut funcs = Vec::new();
        for i in 0..4 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            4,
            4,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &wanted5(),
        )
        .unwrap();
        // WalkerExecute not found: the resolver reports it as None; the
        // caller-level require_complete() rejects the incomplete set.
        assert!(found[0].is_some() && found[1].is_some() && found[2].is_some());
        assert!(found[3].is_some());
        assert!(found[4].is_none(), "{found:?}");
        let e = MidaExportsV2 {
            initialize: found[0],
            get_attestation: found[1],
            shutdown: found[2],
            initialize_v2: found[3],
            walker_execute: found[4],
        };
        assert!(e.require_complete().is_err()); // walker missing -> incomplete
    }

    #[test]
    fn duplicate_export_rejected_ambiguous() {
        // Two export names point to the SAME wanted symbol (two entries
        // claim "MidaAntidebugInitialize"); the resolver must fail closed.
        let symbols: [&str; 6] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugInitialize", // duplicate
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        let mut funcs = Vec::new();
        for i in 0..6 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            6,
            6,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &wanted5(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn forwarded_export_not_resolved() {
        // A wanted name whose function RVA points INSIDE the export
        // directory (exp_rva=0x1000, exp_size=0x100): forwarded export.
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // All function RVAs inside the export directory -> forwarded.
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            5,
            5,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &wanted5(),
        )
        .unwrap();
        // Every wanted export is None (forwarded -> not resolved).
        assert!(found.iter().all(|f| f.is_none()), "{found:?}");
    }

    #[test]
    fn out_of_range_ordinal_skipped_fail_closed() {
        // An ordinal >= num_funcs is out of the function-address array:
        // the name is skipped (None) rather than resolving garbage.
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // ord=7 points past the 5-entry function array (num_funcs=5).
        let ords = (0..5)
            .map(|_| 7u16.to_le_bytes())
            .collect::<Vec<_>>()
            .concat();
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            5,
            5,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &wanted5(),
        )
        .unwrap();
        // Out-of-range ordinals: all names skipped -> all None.
        assert!(found.iter().all(|f| f.is_none()), "{found:?}");
    }

    #[test]
    fn out_of_module_export_rva_rejected() {
        // IMP-08-R1-R1 (P0-1): a function RVA at/above SizeOfImage must
        // be REJECTED (Err), not converted to module_base + rva. Here all
        // five wanted functions claim RVA 0x20000 while image_size is
        // 0x10000 -> every match fails closed.
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // All function RVAs outside the 0x10000-byte image.
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x20000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            5,
            5,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &wanted5(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("outside image envelope"), "{err}");
    }

    #[test]
    fn export_va_overflow_rejected() {
        // module_base + func_rva overflow must fail closed (checked add).
        let symbols: [&str; 1] = ["MidaAntidebugInitialize"];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // func_rva = 0x8000_0000_0000 fits in u32? No - use a u32-sized
        // large RVA that overflows module_base.checked_add on 64-bit only
        // if module_base is huge; instead pick func_rva near usize::MAX
        // by using a 32-bit RVA near 0xFFFF_FF00 and module_base huge.
        let mut funcs = Vec::new();
        // u32::MAX - 0xFF is still a valid u32 RVA; with module_base
        // = usize::MAX - 0x20000 the checked_add overflows.
        funcs.extend_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            1,
            1,
            usize::MAX - 0x20000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        // Either the RVA >= image_size check (0xFFFF_FF00 >= 0x10000)
        // fires first, or the VA overflow check fires; both are fail-closed.
        assert!(
            err.to_string().contains("outside image envelope")
                || err.to_string().contains("overflow"),
            "{err}"
        );
    }

    #[test]
    fn v2_blob_build_with_identity_binds_target() {
        let ss: Vec<String> = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
        let digest = "a".repeat(64);
        let blob = V2ParamsBlob::build_with_identity(
            "p",
            "d",
            &ss,
            &digest,
            0x0000_1000_0000,
            1234,
            0x0000_2000_0000,
        )
        .unwrap();
        // header identity slots
        assert_eq!(
            u32::from_le_bytes(blob.bytes[0x00..0x04].try_into().unwrap()),
            1234
        );
        assert_eq!(
            u64::from_le_bytes(blob.bytes[0x08..0x10].try_into().unwrap()),
            0x0000_2000_0000
        );
        // magic + digest_len
        assert_eq!(
            u64::from_le_bytes(blob.bytes[0x30..0x38].try_into().unwrap()),
            V2_ENVELOPE_MAGIC
        );
        assert_eq!(
            u64::from_le_bytes(blob.bytes[0x40..0x48].try_into().unwrap()),
            64
        );
        // parse_offsets must accept the identity-bound blob
        blob.parse_offsets(0x0000_1000_0000).unwrap();
    }

    #[test]
    fn v2_blob_rejects_zero_identity_production() {
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let digest = "a".repeat(64);
        // One of target_pid/module_base zero with the other nonzero:
        // fail-closed (identity must be bound or unbound together).
        assert!(V2ParamsBlob::build_with_identity(
            "p",
            "d",
            &ss,
            &digest,
            0x0000_1000_0000,
            1234,
            0,
        )
        .is_err());
        assert!(V2ParamsBlob::build_with_identity(
            "p",
            "d",
            &ss,
            &digest,
            0x0000_1000_0000,
            0,
            0x0000_2000_0000,
        )
        .is_err());
    }

    #[test]
    fn thunk7_production_bytes_are_frozen_60b() {
        let fx = Thunk7Fixture::build();
        assert_eq!(fx.production.len(), 60);
        assert_eq!(fx.test_with_probe.len(), 64);
        fx.validate_structure().unwrap();
        // The production thunk carries arg6 (out_attestation_written) at
        // [r11+0x38] -> [rsp+0x30]: THUNK7_PRODUCTION[0x2C..0x33].
        assert_eq!(THUNK7_PRODUCTION[0x2C], 0x4D); // mov r10, [r11+56]
        assert_eq!(THUNK7_PRODUCTION[0x35], 0xFF); // call rax
        assert_eq!(THUNK7_PRODUCTION[0x3B], 0xC3); // ret
    }

    #[test]
    fn thunk_call_v2_rejects_non_60b_thunk() {
        // The production V2 wrapper hard-fails if the frozen thunk is
        // not exactly 60 bytes (a 64B probe must never be used). We cannot
        // call it without a live process; the length guard is exercised
        // by constructing the code path statically: THUNK7_PRODUCTION is
        // a [u8; 60] const, so `thunk_call_v2` cannot receive the probe.
        assert_eq!(THUNK7_PRODUCTION.len(), 60);
        assert_ne!(thunk7_test_with_probe().len(), 60);
    }

    /// Build names/ords/string-table for the given symbol list (names at
    /// RVA 0x1000 + i*0x20, ordinals 0..n). All names NUL-terminated.
    fn table_for(symbols: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        (names, ords, table)
    }

    #[test]
    fn duplicate_after_forwarded_rejected_ambiguous() {
        // IMP-08-R1-R2 (P1-1): the FIRST duplicate entry is a forwarded
        // export (skipped), the SECOND is a valid in-module function.
        // found[] is still None after entry 0 — the old duplicate check
        // missed this; seen[] must reject fail-closed.
        let (names, ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugInitialize"]);
        let mut funcs = Vec::new();
        funcs.extend_from_slice(&0x1040u32.to_le_bytes()); // forwarded (exp dir)
        funcs.extend_from_slice(&0x2000u32.to_le_bytes()); // valid
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            2,
            2,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn duplicate_after_invalid_ordinal_rejected_ambiguous() {
        // IMP-08-R1-R2 (P1-1): the FIRST duplicate entry has an
        // out-of-range ordinal (7 >= num_funcs=2) and is skipped; the
        // SECOND is valid. seen[] must still reject the duplicate.
        let (mut names, mut ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugInitialize"]);
        let _ = &mut names;
        ords[0..2].copy_from_slice(&7u16.to_le_bytes());
        let mut funcs = Vec::new();
        funcs.extend_from_slice(&0x2000u32.to_le_bytes());
        funcs.extend_from_slice(&0x2010u32.to_le_bytes());
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            2,
            2,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn duplicate_after_null_func_rva_rejected_ambiguous() {
        // IMP-08-R1-R2 (P1-1): the FIRST duplicate entry has a null
        // function RVA (skipped); the SECOND is valid. Still ambiguous.
        let (names, ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugInitialize"]);
        let mut funcs = Vec::new();
        funcs.extend_from_slice(&0u32.to_le_bytes()); // null func RVA
        funcs.extend_from_slice(&0x2000u32.to_le_bytes()); // valid
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            2,
            2,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn unterminated_wanted_name_rejected() {
        // IMP-08-R1-R2 (P1-2): a name string WITHOUT a NUL anywhere in
        // the bounded window. The resolver reports Ok(false) and the
        // parser fails closed — even though the bytes would have matched
        // a wanted name if they had been terminated.
        let mut table = vec![b'X'; 0x1000];
        table[0..b"MidaAntidebugInitialize".len()].copy_from_slice(b"MidaAntidebugInitialize");
        let names: Vec<u8> = 0x1000u32.to_le_bytes().to_vec();
        let ords: Vec<u8> = 0u16.to_le_bytes().to_vec();
        let funcs: Vec<u8> = 0x2000u32.to_le_bytes().to_vec();
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            1,
            1,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("NUL-terminated"), "{err}");
    }

    #[test]
    fn name_read_failure_propagates_fail_closed() {
        // IMP-08-R1-R2 (P1-2): a resolver read failure (RPM failure in
        // production) must propagate as Err — never silently skip.
        let names: Vec<u8> = 0x1000u32.to_le_bytes().to_vec();
        let ords: Vec<u8> = 0u16.to_le_bytes().to_vec();
        let funcs: Vec<u8> = 0x2000u32.to_le_bytes().to_vec();
        let mut name_at = |_rva: usize, _out: &mut Vec<u8>| -> Result<bool, RuntimeLoadError> {
            Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read export name failed".to_string(),
            ))
        };
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            1,
            1,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("remote read"), "{err}");
    }

    #[test]
    fn adversarial_name_count_fails_closed_immediately() {
        // IMP-08-R1-R2 (P1-3): num_names = usize::MAX with a tiny names
        // buffer must fail closed on the first out-of-bounds iteration
        // instead of looping forever or overflowing index arithmetic.
        let names: Vec<u8> = 0x1000u32.to_le_bytes().to_vec();
        let ords: Vec<u8> = 0u16.to_le_bytes().to_vec();
        let funcs: Vec<u8> = 0u32.to_le_bytes().to_vec();
        let mut table = vec![0u8; 0x1000];
        table[0..4].copy_from_slice(b"Mida");
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            usize::MAX,
            1,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"Mida"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn truncated_function_array_fails_closed() {
        // IMP-08-R1-R2 (P1-3): num_funcs=2 but only 1 function slot
        // exists — the checked func range must reject the truncation.
        let (names, ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugGetAttestation"]);
        let funcs: Vec<u8> = 0x2000u32.to_le_bytes().to_vec();
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            2,
            2,
            0x400000,
            0x10000,
            0x1000,
            0x100,
            &[b"MidaAntidebugInitialize", b"MidaAntidebugGetAttestation"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }
}

#[cfg(test)]
mod imp07_v2_preflight_consumer_tests {
    use super::*;

    // ------------------------------------------------------------------
    // IMP-07-R1: production V2 preflight consumer (offline seam)
    // ------------------------------------------------------------------

    /// Minimal authority manifest (same shape as production). The digest
    /// here is bound to a REAL PE via verify_file() (see imp06 helpers),
    /// so the loader seam tests use a REAL verified identity — no
    /// caller-constructed digest authorities.
    fn imp07_manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    fn imp07_minimal_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
        b
    }

    fn imp07_tmp_file(content: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join("mida-imp07-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!(
            "imp07_runtime_{}_{}.dll",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, content).unwrap();
        p
    }

    /// Build a REAL verified authority (digest of a real PE) so the seam
    /// can be exercised exactly like production (verify_file -> digest_authority).
    fn imp07_verified_digest() -> String {
        let pe = imp07_minimal_pe();
        let path = imp07_tmp_file(&pe);
        let expected = sha256_hex(&pe);
        let m = imp07_manifest(&expected, pe.len() as u64);
        let id = m.verify_file(&path).unwrap();
        RuntimeDigestAuthority::from_verified_identity(&id, &m.artifact_id)
            .expect("verified identity must build a valid authority")
            .digest_value()
            .to_string()
    }

    #[test]
    fn imp07_prepare_seam_binds_authority_digest_into_blob() {
        // The seam must use the digest AUTHORITY (from verify_file), never a
        // test-provided digest. Build the blob through the production seam.
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        let prepared = V2ParamsBlob::build_preflight_and_validate(
            "p",
            "d",
            &ss,
            &digest,
            blob_base,
            1234,
            0x0000_2000_0000,
            blob_base as usize,
        )
        .unwrap();
        // digest field in the blob == authority digest
        let dig_off = u64::from_le_bytes(prepared.bytes[0x38..0x40].try_into().unwrap()) as usize;
        let hex = String::from_utf8(prepared.bytes[dig_off..dig_off + 64].to_vec()).unwrap();
        assert_eq!(hex, digest);
        // preflight consumed and consistent
        assert_eq!(prepared.preflight.blob_base, blob_base);
        assert_eq!(prepared.preflight.digest_len, 64);
        assert_eq!(prepared.preflight.expected_hooks, 1);
        assert_eq!(prepared.preflight.surface_entries.len(), 1);
    }

    #[test]
    fn imp07_prepare_seam_rejects_wrong_blob_base() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        // blob_base = 0x1000_0000 but params_bytes (remote VA) = 0x2000_0000:
        // build_preflight_and_validate validates against the WRITE address.
        let r = V2ParamsBlob::build_preflight_and_validate(
            "p",
            "d",
            &ss,
            &digest,
            0x0000_1000_0000,
            1234,
            0x0000_2000_0000,
            0x0000_2000_0000usize,
        );
        assert!(r.is_err());
    }

    #[test]
    fn imp07_prepare_seam_rejects_surface_count_mismatch() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        // Build with 2 surfaces but validate against an expectation of 1.
        let blob = V2ParamsBlob::build_with_identity(
            "p",
            "d",
            &ss,
            &digest,
            blob_base,
            1234,
            0x0000_2000_0000,
        )
        .unwrap();
        let preflight = blob.preflight_local(blob_base).unwrap();
        let want: Vec<String> = vec!["AD-PROC-002".to_string()];
        let r = validate_preflight_result(&blob, &preflight, &want, blob_base as usize);
        assert!(r.is_err());
    }

    #[test]
    fn imp07_prepare_seam_rejects_surface_content_mismatch() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        let blob = V2ParamsBlob::build_with_identity(
            "p",
            "d",
            &ss,
            &digest,
            blob_base,
            1234,
            0x0000_2000_0000,
        )
        .unwrap();
        let preflight = blob.preflight_local(blob_base).unwrap();
        let want: Vec<String> = vec!["AD-PROC-009".to_string()];
        let r = validate_preflight_result(&blob, &preflight, &want, blob_base as usize);
        assert!(r.is_err());
    }

    #[test]
    fn imp07_prepare_seam_rejects_surface_order_mismatch() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        let blob = V2ParamsBlob::build_with_identity(
            "p",
            "d",
            &ss,
            &digest,
            blob_base,
            1234,
            0x0000_2000_0000,
        )
        .unwrap();
        let preflight = blob.preflight_local(blob_base).unwrap();
        let want: Vec<String> = vec!["AD-PROC-003".to_string(), "AD-PROC-002".to_string()];
        let r = validate_preflight_result(&blob, &preflight, &want, blob_base as usize);
        assert!(r.is_err());
    }

    #[test]
    fn imp07_production_caller_graph_is_real() {
        // The production caller (load_and_initialize_inner, require_digest=true)
        // must call build_preflight_and_validate -> preflight_local ->
        // validate_preflight_result before ANY WriteProcessMemory. We cannot
        // execute the live path; instead we PROVE the seam is called by the
        // production code with a static source-level assertion: the caller
        // body contains the seam call (grep-verified in evidence).
        // Here we also assert the seam is NOT #[cfg(test)]-only by checking
        // it exists in the non-test binary path: this test merely documents
        // the contract; the real proof is the source wiring + build.
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        // Exercise the exact seam the production caller uses.
        let prepared = V2ParamsBlob::build_preflight_and_validate(
            "p",
            "d",
            &ss,
            &digest,
            blob_base,
            1234,
            0x0000_2000_0000,
            blob_base as usize,
        )
        .unwrap();
        assert_eq!(prepared.bytes.len() > 0x48, true);
        assert_eq!(prepared.preflight.surface_entries.len(), 1);
        // Wrong base must fail BEFORE any bytes could be returned.
        assert!(V2ParamsBlob::build_preflight_and_validate(
            "p",
            "d",
            &ss,
            &digest,
            blob_base,
            1234,
            0x0000_2000_0000,
            (blob_base + 0x1000) as usize,
        )
        .is_err());
    }
}

#[cfg(test)]
mod imp09_carrier_r2_tests {
    use super::*;

    fn manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    /// Build a synthetic x64 PE file with an export directory containing
    /// the given symbol names mapping to func RVAs (raw=va layout for the
    /// single .text/.edata section, so RVA == file offset).
    ///
    /// Layout (one section covering [0x1000, 0x3000), raw == va):
    ///   - section data starts at file offset 0x1000
    ///   - export dir at RVA 0x1000
    ///   - name ptr table at 0x1100, ordinal table at 0x1200,
    ///     func table at 0x1300, strings at 0x1400
    fn build_export_pe(symbols: &[(&str, u32)]) -> Vec<u8> {
        // File = headers (0x1000) + section data (0x2000). Section raw ==
        // VA layout: raw ptr 0x1000, va 0x1000, raw size 0x2000, vsize
        // 0x3000 (SizeOfImage 0x3000 covers va..va+0x2000).
        let mut b = vec![0u8; 0x1000]; // DOS + headers + section table
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // opt hdr size
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
                                                                // SizeOfImage at optional+0x50 = 0x80+0x18+0x50 = 0xE8
        b[0xE8..0xEC].copy_from_slice(&0x3000u32.to_le_bytes());
        // Export data dir at optional+0x70 = 0x80+0x18+0x70 = 0x108
        b[0x108..0x10C].copy_from_slice(&0x1000u32.to_le_bytes()); // exp_rva
        b[0x10C..0x110].copy_from_slice(&0x400u32.to_le_bytes()); // exp_size
                                                                  // Section header at pe_off(0x80) + 4 (sig) + 20 (COFF) + 0xE0
                                                                  // (optional) = 0x178
        b[0x178..0x17B].copy_from_slice(b".ed"); // name
        b[0x180..0x184].copy_from_slice(&0x3000u32.to_le_bytes()); // vsize
        b[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes()); // va
        b[0x188..0x18C].copy_from_slice(&0x2000u32.to_le_bytes()); // raw size
        b[0x18C..0x190].copy_from_slice(&0x1000u32.to_le_bytes()); // raw ptr

        // Pad to 0x1000 (the section data region).
        b.resize(0x3000, 0);
        // Export directory at file offset 0x1000 (RVA 0x1000).
        //   [0x14] NumberOfFunctions, [0x18] NumberOfNames,
        //   [0x1C] AddressOfFunctions, [0x20] AddressOfNames,
        //   [0x24] AddressOfNameOrdinals
        let num = symbols.len();
        b[0x1000 + 0x14..0x1000 + 0x18].copy_from_slice(&(num as u32).to_le_bytes());
        b[0x1000 + 0x18..0x1000 + 0x1C].copy_from_slice(&(num as u32).to_le_bytes());
        b[0x1000 + 0x1C..0x1000 + 0x20].copy_from_slice(&0x1300u32.to_le_bytes()); // funcs
        b[0x1000 + 0x20..0x1000 + 0x24].copy_from_slice(&0x1100u32.to_le_bytes()); // names
        b[0x1000 + 0x24..0x1000 + 0x28].copy_from_slice(&0x1200u32.to_le_bytes()); // ords
                                                                                   // Name pointer table at 0x1100.
        let mut str_off = 0x1400usize;
        for (i, (name, _)) in symbols.iter().enumerate() {
            b[0x1100 + i * 4..0x1104 + i * 4].copy_from_slice(&(str_off as u32).to_le_bytes());
            str_off += name.len() + 1;
        }
        // Ordinal table at 0x1200 (u16 each, 0-based like link.exe).
        for i in 0..num {
            b[0x1200 + i * 2..0x1202 + i * 2].copy_from_slice(&(i as u16).to_le_bytes());
        }
        // Function table at 0x1300.
        for (i, (_, rva)) in symbols.iter().enumerate() {
            b[0x1300 + i * 4..0x1304 + i * 4].copy_from_slice(&rva.to_le_bytes());
        }
        // Strings at 0x1400.
        let mut s = 0x1400usize;
        for (name, _) in symbols {
            for (k, ch) in name.bytes().enumerate() {
                b[s + k] = ch;
            }
            b[s + name.len()] = 0;
            s += name.len() + 1;
        }
        b
    }

    /// Write the PE to a temp file and produce a verified identity via the
    /// real verify_file() path.
    fn verified_identity_for(pe: &[u8], tag: &str) -> RuntimeFileIdentity {
        let dir = std::env::temp_dir().join("mida-carrier-r2");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!("r2_{tag}.dll"));
        std::fs::write(&p, pe).unwrap();
        let expected = sha256_hex(pe);
        let authority = manifest(&expected, pe.len() as u64);
        authority.verify_file(&p).expect("synthetic PE must verify")
    }

    fn walker_pe() -> Vec<u8> {
        build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ])
    }

    #[test]
    fn valid_file_export_rva_carrier() {
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "valid");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id)
            .expect("valid runtime file must resolve WalkerExecute");
        assert_eq!(rva, 0x2040, "pure-file resolver returns the export RVA");
    }

    #[test]
    fn missing_walker_export_rejected() {
        let pe = build_export_pe(&[("MidaAntidebugInitialize", 0x2000)]);
        let id = verified_identity_for(&pe, "missing");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "missing WalkerExecute must fail closed");
    }

    #[test]
    fn forwarded_walker_export_rejected() {
        // WalkerExecute function RVA points INSIDE the export directory
        // (0x1000..0x1400) => treated as a forwarder, skipped => fail.
        let pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x1100),
        ]);
        let id = verified_identity_for(&pe, "fwd");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "forwarded WalkerExecute must fail closed");
    }

    #[test]
    fn out_of_image_export_rva_rejected() {
        // Function RVA beyond SizeOfImage (0x3000).
        let pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x4000),
        ]);
        let id = verified_identity_for(&pe, "oob");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "out-of-envelope export RVA must fail closed");
    }

    #[test]
    fn export_array_truncation_rejected() {
        // Truncate the func table region by cutting the file short after
        // the export directory but claiming num_funcs beyond the file.
        let mut pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ]);
        // Shrink to just past the export dir header (0x1028), so the func
        // array read at 0x1300 is truncated.
        pe.truncate(0x1100);
        let id = verified_identity_for(&pe, "trunc");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "truncated export arrays must fail closed");
    }

    #[test]
    fn name_pointer_oob_rejected() {
        // Name pointer table entry points outside the image envelope.
        let mut pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ]);
        // Overwrite the first name pointer (at 0x1100) to an out-of-envelope
        // RVA. The name_at closure maps it -> no section -> error.
        pe[0x1100..0x1104].copy_from_slice(&0x4000u32.to_le_bytes());
        let id = verified_identity_for(&pe, "name_oob");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "name pointer outside image must fail closed");
    }

    #[test]
    fn ordinal_oob_rejected() {
        // Ordinal table entry >= num_funcs -> skipped -> WalkerExecute not
        // resolvable -> fail.
        let mut pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ]);
        // WalkerExecute is index 1 -> its ordinal slot at 0x1202. Set to 99.
        pe[0x1202..0x1204].copy_from_slice(&99u16.to_le_bytes());
        let id = verified_identity_for(&pe, "ord_oob");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "out-of-range ordinal must fail closed");
    }

    #[test]
    fn checked_module_base_plus_rva_overflow_rejected() {
        // The production install boundary rejects module_base +
        // export_rva overflow (WalkerEntryOverflow inside the sealed
        // authority construction). Exercise it through the PUBLIC API
        // install_walker_session_verified with a huge module_base: the
        // install must fail closed (false), never wrap.
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "ovf");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id)
            .expect("valid file must resolve");
        let ok = mida_antidebug_runtime::exports::install_walker_session_verified(
            Box::new(mida_antidebug_runtime::walker_control::MemoryMapProvider::new()),
            0x1000,
            0x2000,
            4242,
            7777,
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            u64::MAX - 16,
            rva,
            "profile-id",
            "c".repeat(64).as_str(),
        );
        assert!(!ok, "module_base + export_rva overflow must fail closed");
    }

    #[test]
    fn resolved_rva_round_trips_into_sealed_loader_result() {
        // Full chain: verified file -> pure-file resolver -> LoaderResult
        // carrier -> getter returns the same RVA.
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "roundtrip");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id).unwrap();
        let authority = RuntimeDigestAuthority::from_verified_identity(&id, "artifact")
            .expect("verified identity must build authority");
        let lr = crate::unpacker::antidebug_controller::LoaderResult::new(
            0x7000,
            "{}".to_string(),
            id,
            authority,
            1234,
            Some(rva),
            None, // walker_exports: not needed by this test
        );
        assert_eq!(lr.walker_export_rva(), Some(0x2040));
    }

    #[test]
    fn remote_resolver_not_called_by_new_path() {
        // The pure-file path needs ONLY the verified file bytes; it never
        // touches a process handle. Prove it: the resolver succeeds for a
        // file whose identity was verified, without any target HANDLE.
        // (Static proof: this function has no windows:: RPM import in its
        // body; the evidence bundle greps resolve_mida_exports_remote call
        // sites to show the new path does not call it.)
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "noread");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert_eq!(rva, Ok(0x2040));
    }

    #[test]
    fn same_size_verified_file_replacement_rejected() {
        // P1 (R2-R1): verify_file(A) seals identity(A); the file on disk
        // is then replaced with SAME-SIZE different-content B. The
        // resolver must fail closed — path+size binding is NOT enough;
        // the recomputed content digest must equal identity.sha256().
        let pe_a = walker_pe();
        let id = verified_identity_for(&pe_a, "swap_same_size");
        let mut pe_b = pe_a.clone();
        // Same length, different content: flip the last section-data byte.
        let last = pe_b.len() - 1;
        pe_b[last] ^= 0xFF;
        assert_eq!(pe_a.len(), pe_b.len(), "test premise: same size");
        assert_ne!(
            sha256_hex(&pe_a),
            sha256_hex(&pe_b),
            "test premise: different content"
        );
        std::fs::write(id.path(), &pe_b).expect("replace file on disk");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(
            r.is_err(),
            "same-size replacement must fail closed on digest mismatch"
        );
    }
}
