//! ADR-6 loader tests: authority verification, params layout, thunk bytes,
//! and controller lifecycle wiring (all offline, no process creation).
//!
//! The remote-thread machinery itself is exercised by the benign host
//! harness (out-of-tree); these tests pin the deterministic pieces.

use mida_cli::unpacker::runtime_loader::{
    build_init_params_bytes, RuntimeAuthority, RuntimeLoadError, ThunkArgs, THUNK_CODE,
};

// ----------------------------------------------------------------
// runtime authority
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

#[test]
fn authority_matches_ok() {
    let content = b"fake runtime bytes for authority test";
    let path = tmp_file("runtime_ok.dll", content);
    let authority = RuntimeAuthority {
        file_name: "runtime_ok.dll".to_string(),
        sha256: sha256_hex(content),
        size_bytes: content.len() as u64,
        architecture: "x86_64".to_string(),
        source_revision: "test".to_string(),
        provenance_schema: "mida.antidebug-provenance/v1".to_string(),
    };
    let id = authority.verify_file(&path).unwrap();
    assert_eq!(id.sha256, sha256_hex(content));
    assert_eq!(id.size_bytes, content.len() as u64);
    assert_eq!(id.architecture, "x86_64");
    // canonical path
    assert!(id.path.is_absolute());
}

#[test]
fn authority_wrong_hash_fails() {
    let content = b"fake runtime bytes";
    let path = tmp_file("runtime_badhash.dll", content);
    let authority = RuntimeAuthority {
        file_name: "runtime_badhash.dll".to_string(),
        sha256: "00".repeat(32), // wrong
        size_bytes: content.len() as u64,
        architecture: "x86_64".to_string(),
        source_revision: "test".to_string(),
        provenance_schema: "mida.antidebug-provenance/v1".to_string(),
    };
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn authority_wrong_size_fails() {
    let content = b"fake runtime bytes";
    let path = tmp_file("runtime_badsize.dll", content);
    let authority = RuntimeAuthority {
        file_name: "runtime_badsize.dll".to_string(),
        sha256: sha256_hex(content),
        size_bytes: content.len() as u64 + 1, // wrong
        architecture: "x86_64".to_string(),
        source_revision: "test".to_string(),
        provenance_schema: "mida.antidebug-provenance/v1".to_string(),
    };
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("size"));
}

#[test]
fn authority_missing_file_fails() {
    let authority = RuntimeAuthority {
        file_name: "nope.dll".to_string(),
        sha256: "00".repeat(32),
        size_bytes: 1,
        architecture: "x86_64".to_string(),
        source_revision: "test".to_string(),
        provenance_schema: "mida.antidebug-provenance/v1".to_string(),
    };
    let err = authority
        .verify_file(&std::path::Path::new("C:/definitely/not/here/nope.dll"))
        .unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityUnavailable(..)));
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
use mida_cli::unpacker::runtime_loader::RuntimeFileIdentity;

fn controller_with_loader_result(loader: Option<LoaderResult>) -> AntidebugController {
    // A real temp file whose content matches the pinned authority digest.
    let content = b"pinned-runtime-bytes";
    let dir = std::env::temp_dir().join("mida-adr6-test");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("r.dll");
    std::fs::write(&p, content).unwrap();
    let authority = RuntimeAuthority {
        file_name: "r.dll".to_string(),
        sha256: sha256_hex(content),
        size_bytes: content.len() as u64,
        architecture: "x86_64".to_string(),
        source_revision: "t".to_string(),
        provenance_schema: "mida.antidebug-provenance/v1".to_string(),
    };
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
    // runtime file does not exist -> authority fails -> DependencyUnavailable.
    let authority = RuntimeAuthority {
        file_name: "r.dll".to_string(),
        sha256: "cd".repeat(32), // wrong digest vs file
        size_bytes: 10,
        architecture: "x86_64".to_string(),
        source_revision: "t".to_string(),
        provenance_schema: "mida.antidebug-provenance/v1".to_string(),
    };
    // Write a real file whose content does NOT match the authority digest.
    let dir = std::env::temp_dir().join("mida-adr6-test");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join("mismatch.dll");
    std::fs::write(&p, b"not the pinned bytes").unwrap();
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
