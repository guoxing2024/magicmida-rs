//! ADR-6 loader tests: authority verification, params layout, thunk bytes,
//! and controller lifecycle wiring (all offline, no process creation).
//!
//! The remote-thread machinery itself is exercised by the benign host
//! harness (out-of-tree); these tests pin the deterministic pieces.

use mida_cli::unpacker::runtime_loader::{
    build_init_params_bytes, verify_pe_x64, verify_runtime_provenance, RuntimeAuthorityManifest,
    RuntimeFileIdentity, RuntimeLoadError, ThunkArgs, THUNK_CODE,
};

// ----------------------------------------------------------------
// runtime authority (manifest-based, ADR-6-CORRECTION)
// ----------------------------------------------------------------

fn tmp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("mida-adr6-test");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a minimal valid x64 PE (MZ + PE sig + Machine=AMD64 + PE32+ magic).
fn minimal_pe(machine: u16, magic: u16) -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&machine.to_le_bytes()); // Machine
    b[0x98..0x9A].copy_from_slice(&magic.to_le_bytes()); // Optional magic at pe+0x18
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

#[test]
fn authority_matches_ok_with_real_pe() {
    let pe = minimal_pe(0x8664, 0x20B); // AMD64 + PE32+
    let path = tmp_file("runtime_ok.dll", &pe);
    let authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    let id = authority.verify_file(&path).unwrap();
    assert_eq!(id.sha256, sha256_hex(&pe));
    assert_eq!(id.size_bytes, pe.len() as u64);
    assert_eq!(id.architecture, "x86_64");
    assert!(id.path.is_absolute());
}

#[test]
fn authority_wrong_hash_fails() {
    let pe = minimal_pe(0x8664, 0x20B);
    let path = tmp_file("runtime_badhash.dll", &pe);
    let authority = manifest(&"00".repeat(32), pe.len() as u64);
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn authority_wrong_size_fails() {
    let pe = minimal_pe(0x8664, 0x20B);
    let path = tmp_file("runtime_badsize.dll", &pe);
    let authority = manifest(&sha256_hex(&pe), pe.len() as u64 + 1);
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("size"));
}

#[test]
fn authority_missing_file_fails() {
    let authority = manifest(&"00".repeat(32), 1);
    let err = authority
        .verify_file(&std::path::Path::new("C:/definitely/not/here/nope.dll"))
        .unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityUnavailable(..)));
}
#[test]
fn pe_x86_machine_rejected() {
    let pe = minimal_pe(0x14C, 0x20B); // I386 machine
    let err = verify_pe_x64(&pe).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::ArchitectureUnsupported(_)));
}

#[test]
fn pe_non_pe_rejected() {
    let err = verify_pe_x64(b"not a pe at all").unwrap_err();
    assert!(matches!(err, RuntimeLoadError::ArchitectureUnsupported(_)));
    assert!(err.to_string().contains("MZ"));
}

#[test]
fn pe_pe32_not_pe32plus_rejected() {
    let pe = minimal_pe(0x8664, 0x10B); // AMD64 machine but PE32 optional header
    let err = verify_pe_x64(&pe).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::ArchitectureUnsupported(_)));
}

#[test]
fn pe_arm_machine_rejected() {
    let pe = minimal_pe(0xAA64, 0x20B); // ARM64 machine
    let err = verify_pe_x64(&pe).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::ArchitectureUnsupported(_)));
}

fn ok_provenance(sha256: &str, size: u64) -> serde_json::Value {
    serde_json::json!({
        "schema": "mida.antidebug-provenance/v1",
        "artifact_id": "mida-antidebug-runtime-x64",
        "kind": "runtime-x64",
        "sha256": sha256,
        "size_bytes": size,
        "architecture": "x86_64",
        "toolchain": "rustc",
        "source_ref": "test-commit",
        "third_party": "build-and-serialization-only",
        "dependencies": [],
        "license": "GPL-3.0-only",
        "build_repro": "test",
    })
}

#[test]
fn provenance_hash_mismatch_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_prov.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_hash_mismatch.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256, id.size_bytes);
    prov["sha256"] = serde_json::Value::String("00".repeat(32));
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_hash_mismatch.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn provenance_kind_mismatch_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_prov2.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_kind_mismatch.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256, id.size_bytes);
    prov["kind"] = serde_json::Value::String("runtime-x86".to_string());
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_kind_mismatch.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("kind"));
}

#[test]
fn provenance_missing_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_prov3.dll", &pe);
    let authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    let id = authority.verify_file(&runtime_path).unwrap();
    // No provenance.json in a fresh dir.
    let dir = std::env::temp_dir().join("mida-adr6-test-empty");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
}

#[test]
fn provenance_ok_passes() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_prov_ok.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_ok.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(
        dir.join("prov_ok.json"),
        ok_provenance(&id.sha256, id.size_bytes).to_string(),
    )
    .unwrap();
    let prov = verify_runtime_provenance(&authority, &dir, &id).unwrap();
    assert_eq!(prov["kind"], "runtime-x64");
}

#[test]
fn env_cannot_authorize_arbitrary_runtime() {
    // ADR-6-CORRECTION: a caller setting MIDA_RUNTIME_SHA256 must NOT be
    // able to authorize an arbitrary runtime. The loader reads only the
    // manifest path; expected hashes come from the compiled-in digest.
    // Setting MIDA_RUNTIME_SHA256 must have no effect on authority.
    // We prove this by checking that runtime_authority() ignores it: it
    // fails because no manifest path is configured (or the manifest is
    // missing) regardless of MIDA_RUNTIME_SHA256.
    unsafe {
        std::env::set_var("MIDA_RUNTIME_SHA256", "00".repeat(32));
        std::env::remove_var("MIDA_RUNTIME_AUTHORITY");
    }
    let err = mida_cli::unpacker::runtime_loader::runtime_authority().unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityUnavailable(..)));
    assert!(err.to_string().contains("MIDA_RUNTIME_AUTHORITY"));
    unsafe {
        std::env::remove_var("MIDA_RUNTIME_SHA256");
    }
}

// ----------------------------------------------------------------
// thunk bytes
// ----------------------------------------------------------------

#[test]
fn thunk_code_is_wellformed() {
    // First instruction must preserve the args base (mov r11, rcx).
    assert_eq!(THUNK_CODE[0..3], [0x49, 0x89, 0xCB]);
    // Stack frame must be 0x38 (fixed: 0x28 corrupted the caller frame).
    // sub rsp, 0x38 at offset 22 (after 6 + 4*4 prefix instructions).
    assert_eq!(THUNK_CODE[22..26], [0x48, 0x83, 0xEC, 0x38]);
    // Ends with ret (0xC3) at offset 50 (add rsp,0x38 at 46..50).
    assert_eq!(THUNK_CODE[50], 0xC3);
    // THUNK_CODE is 51 bytes of code + padding (declared length 91).
    assert_eq!(THUNK_CODE.len(), 91);
}

#[test]
fn thunk_args_serialization_roundtrip() {
    let args = ThunkArgs {
        fn_ptr: 0x1111_2222_3333_4444,
        arg0: 1,
        arg1: 2,
        arg2: 3,
        arg3: 4,
        arg4: 5,
        arg5: 6,
        reserved: 0,
    };
    let bytes = args.as_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        0x1111_2222_3333_4444
    );
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 6);
}

// ----------------------------------------------------------------
// init params layout
// ----------------------------------------------------------------

#[test]
fn init_params_layout_matches_runtime_repr_c() {
    let base: u64 = 0x4000;
    let surfaces = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
    let bytes = build_init_params_bytes(4242, "prof", "dig", &surfaces, 0x7000, base).unwrap();
    // struct header
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 4242);
    // module_base at 0x08
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x7000);
    // expected_hooks at 0x20
    assert_eq!(u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap()), 2);
    // profile_id pointer at 0x10 points into the blob
    let pid_ptr = u64::from_le_bytes(bytes[0x10..0x18].try_into().unwrap());
    assert!(pid_ptr >= base + 0x30);
    // surfaces array at 0x28
    let arr_ptr = u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap());
    let arr_off = (arr_ptr - base) as usize;
    // first surface pointer inside the array
    let s0 = u64::from_le_bytes(bytes[arr_off..arr_off + 8].try_into().unwrap());
    assert!(s0 >= base + 0x30);
    // the pointer must point at a NUL-terminated string = AD-PROC-002
    let s0_off = (s0 - base) as usize;
    let s0_end = bytes[s0_off..].iter().position(|b| *b == 0).unwrap();
    assert_eq!(&bytes[s0_off..s0_off + s0_end], b"AD-PROC-002");
    // sanity: the surface string region starts BEFORE the array
    // (strings are written first, the pointer array after them).
    assert!(
        s0_off < arr_off,
        "s0_off {s0_off} must be before array {arr_off}"
    );
}

#[test]
fn init_params_empty_surfaces_ok() {
    let bytes = build_init_params_bytes(1, "p", "d", &[], 0x1000, 0x2000).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[0x20..0x28].try_into().unwrap()), 0);
}

// ----------------------------------------------------------------
// controller lifecycle with loader result (offline)
// ----------------------------------------------------------------

use mida_cli::unpacker::antidebug_controller::{
    AntidebugController, AntidebugOutcome, AntidebugStageOptions, LoaderResult,
};

fn controller_with_loader_result(loader: Option<LoaderResult>) -> AntidebugController {
    // A real temp x64 PE file whose content matches the manifest digest.
    let content = minimal_pe(0x8664, 0x20B);
    let dir = std::env::temp_dir().join("mida-adr6-test");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("r.dll");
    std::fs::write(&p, &content).unwrap();
    let authority = manifest(&sha256_hex(&content), content.len() as u64);
    AntidebugController::new(AntidebugStageOptions {
        sample_id: Some("origin_macro".to_string()),
        target_pid: 1234,
        evidence_dir: None,
        oracle: None,
        cleanup_backend: None,
        runtime_authority: Some(authority),
        runtime_path: Some(p),
        loader_result: loader,
    })
}

fn fake_loader_result() -> LoaderResult {
    LoaderResult {
        module_base: 0x7000,
        attestation_json: serde_json::json!({
            "schema": "mida.antidebug-runtime-attestation/v1",
            "runtime_id": "mida-antidebug-runtime-x64",
            "runtime_version": "0.1.0",
            "architecture": "x86_64",
            "runtime_sha256": "ab".repeat(32),
            "profile_id": "oreans_origin_x64_v1",
            "profile_digest": "adr6-profile-digest",
            "target_pid": 1234,
            "module_base": 0x7000,
            "initialized": true,
            "hooks_expected": ["AD-PROC-002", "AD-PROC-003"],
            "hooks_installed": ["AD-PROC-002", "AD-PROC-003"],
            "hook_failures": [],
            "surface_details": [],
            "telemetry_channel": "ready",
            "cleanup_handler_registered": true,
            "third_party": "build-and-serialization-only",
            "source_revision": "0.1.0",
            "toolchain": "rustc",
        })
        .to_string(),
        file_identity: RuntimeFileIdentity {
            path: std::path::PathBuf::from("C:/tmp/r.dll"),
            sha256: "ab".repeat(32),
            size_bytes: 10,
            architecture: "x86_64".to_string(),
        },
        target_pid: 1234,
    }
}

#[test]
fn controller_proceeds_with_valid_loader_result() {
    let mut c = controller_with_loader_result(Some(fake_loader_result()));
    let outcome = c.run();
    if !matches!(outcome, AntidebugOutcome::Proceed { .. }) {
        if let AntidebugOutcome::Failed {
            state,
            fail_code,
            message,
        } = &outcome
        {
            panic!(
                "expected Proceed, got Failed state={state:?} code={} msg={message}",
                fail_code.as_str()
            );
        }
    }
    assert!(matches!(outcome, AntidebugOutcome::Proceed { .. }));
}

#[test]
fn controller_fails_closed_without_loader_result() {
    let mut c = controller_with_loader_result(None);
    let outcome = c.run();
    assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
}

#[test]
fn controller_fails_closed_on_target_pid_mismatch() {
    let mut loader = fake_loader_result();
    loader.target_pid = 9999;
    let mut c = controller_with_loader_result(Some(loader));
    let outcome = c.run();
    assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
}

#[test]
fn controller_fails_closed_on_bad_attestation() {
    let mut loader = fake_loader_result();
    loader.attestation_json = "{ not json".to_string();
    let mut c = controller_with_loader_result(Some(loader));
    let outcome = c.run();
    assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
}

#[test]
fn controller_fails_closed_on_incomplete_attestation() {
    // hooks_installed missing AD-PROC-003 -> validate fails -> PartialHooks.
    let mut loader = fake_loader_result();
    loader.attestation_json = serde_json::json!({
        "schema": "mida.antidebug-runtime-attestation/v1",
        "runtime_id": "mida-antidebug-runtime-x64",
        "runtime_version": "0.1.0",
        "architecture": "x86_64",
        "runtime_sha256": "ab".repeat(32),
        "profile_id": "oreans_origin_x64_v1",
        "profile_digest": "adr6-profile-digest",
        "target_pid": 1234,
        "module_base": 0x7000,
        "initialized": true,
        "hooks_expected": ["AD-PROC-002", "AD-PROC-003"],
        "hooks_installed": ["AD-PROC-002"],
        "hook_failures": [{"surface_id": "AD-PROC-003", "reason": "failed"}],
        "surface_details": [],
        "telemetry_channel": "ready",
        "cleanup_handler_registered": true,
        "third_party": "build-and-serialization-only",
        "source_revision": "0.1.0",
        "toolchain": "rustc",
    })
    .to_string();
    let mut c = controller_with_loader_result(Some(loader));
    let outcome = c.run();
    assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
}

#[test]
fn controller_authority_mismatch_fails_before_loader() {
    // The file is a real x64 PE but the manifest digest does not match it ->
    // authority verification fails before any loader work.
    let content = minimal_pe(0x8664, 0x20B);
    let dir = std::env::temp_dir().join("mida-adr6-test");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("mismatch.dll");
    std::fs::write(&p, &content).unwrap();
    let authority = manifest(&"cd".repeat(32), content.len() as u64); // wrong digest
    let mut c = AntidebugController::new(AntidebugStageOptions {
        sample_id: Some("origin_macro".to_string()),
        target_pid: 1234,
        evidence_dir: None,
        oracle: None,
        cleanup_backend: None,
        runtime_authority: Some(authority),
        runtime_path: Some(p),
        loader_result: Some(fake_loader_result()),
    });
    let outcome = c.run();
    assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
}
