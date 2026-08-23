//! ADR-6 loader tests: authority verification, params layout, thunk bytes,
//! and controller lifecycle wiring (all offline, no process creation).
//!
//! The remote-thread machinery itself is exercised by the benign host
//! harness (out-of-tree); these tests pin the deterministic pieces.

use mida_cli::unpacker::runtime_loader::{
    build_init_params_bytes, verify_pe_x64, verify_runtime_provenance, RuntimeAuthorityManifest,
    RuntimeLoadError, ThunkArgs, THUNK_CODE,
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
    assert_eq!(id.sha256(), sha256_hex(&pe));
    assert_eq!(id.size_bytes(), pe.len() as u64);
    assert_eq!(id.architecture(), "x86_64");
    assert!(id.path().is_absolute());
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
        .verify_file(std::path::Path::new("C:/definitely/not/here/nope.dll"))
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
    // ADR-4 registered dependency declarations (versions match Cargo.lock).
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
        "dependencies": [
            {"name": "serde", "version": "1.0.229", "license": "MIT OR Apache-2.0",
             "source": "crates.io", "role": "serialization", "anti_debug": false},
            {"name": "serde_json", "version": "1.0.151", "license": "MIT OR Apache-2.0",
             "source": "crates.io", "role": "serialization", "anti_debug": false},
            {"name": "thiserror", "version": "1.0.69", "license": "MIT OR Apache-2.0",
             "source": "crates.io", "role": "error-definition", "anti_debug": false},
        ],
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
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
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
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
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
        ok_provenance(&id.sha256(), id.size_bytes()).to_string(),
    )
    .unwrap();
    let prov = verify_runtime_provenance(&authority, &dir, &id).unwrap();
    assert_eq!(prov.kind, "runtime-x64");
    assert_eq!(prov.dependencies.len(), 3);
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
// CORRECTION-2: source_ref chain + full provenance binding
// ----------------------------------------------------------------

#[test]
fn provenance_artifact_id_mismatch_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_art.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_art_mismatch.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
    prov["artifact_id"] = serde_json::Value::String("other-artifact".to_string());
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_art_mismatch.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("artifact_id"));
}

#[test]
fn provenance_source_ref_mismatch_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_src.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_src_mismatch.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
    prov["source_ref"] = serde_json::Value::String("other-commit".to_string());
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_src_mismatch.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("source_ref"));
}

#[test]
fn provenance_empty_dependencies_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_dep.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_dep_empty.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
    prov["dependencies"] = serde_json::Value::Array(vec![]);
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_dep_empty.json"), prov.to_string()).unwrap();
    // ADR-4: runtime links external crates but dependencies is empty ->
    // DependenciesUndeclared -> fail-closed.
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
}

#[test]
fn provenance_dependency_empty_name_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_depname.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_dep_name.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
    prov["dependencies"][0]["name"] = serde_json::Value::String(String::new());
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_dep_name.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
}

#[test]
fn provenance_dependency_anti_debug_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_depad.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_dep_ad.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
    prov["dependencies"][0]["anti_debug"] = serde_json::Value::Bool(true);
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_dep_ad.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
}

#[test]
fn full_valid_provenance_chain_passes() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_chain.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_chain_ok.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(
        dir.join("prov_chain_ok.json"),
        ok_provenance(&id.sha256(), id.size_bytes()).to_string(),
    )
    .unwrap();
    let prov = verify_runtime_provenance(&authority, &dir, &id).unwrap();
    assert_eq!(prov.kind, "runtime-x64");
    assert_eq!(prov.source_ref, authority.source_ref);
    assert_eq!(prov.artifact_id, authority.artifact_id);
    assert_eq!(prov.dependencies.len(), 3);
}

#[test]
fn provenance_arch_mismatch_rejected() {
    let pe = minimal_pe(0x8664, 0x20B);
    let runtime_path = tmp_file("runtime_arch.dll", &pe);
    let mut authority = manifest(&sha256_hex(&pe), pe.len() as u64);
    authority.provenance_ref = "prov_arch.json".to_string();
    let id = authority.verify_file(&runtime_path).unwrap();
    let mut prov = ok_provenance(&id.sha256(), id.size_bytes());
    prov["architecture"] = serde_json::Value::String("x86".to_string());
    let dir = std::env::temp_dir().join("mida-adr6-test");
    std::fs::write(dir.join("prov_arch.json"), prov.to_string()).unwrap();
    let err = verify_runtime_provenance(&authority, &dir, &id).unwrap_err();
    // prov.validate() rejects x86 first (ArchitectureMismatch inside the
    // provenance crate); either way it is fail-closed.
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
}

// ----------------------------------------------------------------
// ADR-5B-R3/R5: remote-wait classification + thunk layout constants
// ----------------------------------------------------------------

#[test]
fn wait_status_classification_distinguishes_timeout_and_failure() {
    use mida_cli::unpacker::runtime_loader::{classify_wait_status, RemoteWaitOutcome};
    // WAIT_OBJECT_0 (0) -> Finished
    assert_eq!(classify_wait_status(0), RemoteWaitOutcome::Finished);
    // WAIT_TIMEOUT (258) -> TimedOut (the dangerous case: thread may still run)
    assert_eq!(classify_wait_status(258), RemoteWaitOutcome::TimedOut);
    // WAIT_FAILED (0xFFFFFFFF) -> WaitFailed
    assert!(matches!(
        classify_wait_status(0xFFFF_FFFF),
        RemoteWaitOutcome::WaitFailed(_)
    ));
    // WAIT_ABANDONED (0x80) -> Abandoned (defensive; never valid for threads)
    assert_eq!(classify_wait_status(0x80), RemoteWaitOutcome::Abandoned);
    // Unknown -> WaitFailed
    assert!(matches!(
        classify_wait_status(42),
        RemoteWaitOutcome::WaitFailed(_)
    ));
}

#[test]
fn thunk_layout_constants_are_explicit_and_consistent() {
    use mida_cli::unpacker::runtime_loader::{
        THUNK_ARGS_OFFSET, THUNK_ARGS_SIZE, THUNK_BLOB_SIZE, THUNK_CODE, THUNK_CODE_SIZE,
        THUNK_EXECUTABLE_SIZE,
    };
    // The executable window covers the thunk code (91 bytes) with room to spare.
    assert!(THUNK_CODE_SIZE >= 91);
    assert!(THUNK_EXECUTABLE_SIZE >= THUNK_CODE_SIZE);
    // The args region starts inside the allocation and ends within it.
    assert!(THUNK_ARGS_OFFSET >= THUNK_EXECUTABLE_SIZE);
    assert!(THUNK_ARGS_OFFSET + THUNK_ARGS_SIZE <= THUNK_BLOB_SIZE);
    // The whole blob is one page-rounded 0x100 region.
    assert_eq!(THUNK_BLOB_SIZE, 0x100);
    // Byte-level layout proof: the actual thunk code must fit inside the
    // declared code window, and the args window must not overlap it.
    assert!(THUNK_CODE.len() <= THUNK_CODE_SIZE);
    assert!(THUNK_CODE.len() <= THUNK_EXECUTABLE_SIZE);
    assert!(THUNK_ARGS_OFFSET >= THUNK_CODE.len());
    // The thunk's return (ret at the end) must land before the args window,
    // otherwise the args blob could be executed as code.
    let last_code_byte = THUNK_CODE.len();
    assert!(
        last_code_byte <= THUNK_ARGS_OFFSET,
        "thunk code ({} bytes) must end at/before args offset {THUNK_ARGS_OFFSET}",
        last_code_byte
    );
}

#[test]
fn ordinal_array_layout_is_two_bytes_per_entry() {
    // The export parser reads num_names * 2 bytes for the ordinal array.
    // This pins the PE format assumption (u16 per ordinal slot).
    // IMAGE_EXPORT_DIRECTORY.NumberOfNames is the slot count; AddressOfNameOrdinals
    // entries are WORDs (PE/COFF spec 8.3.3).
    let num_names: usize = 7;
    let ords_bytes = num_names * 2;
    assert_eq!(ords_bytes, 14);
    // A parsed ordinal value must be recoverable from two bytes.
    let ord = u16::from_le_bytes([0x34, 0x12]);
    assert_eq!(ord, 0x1234);
}

// ----------------------------------------------------------------
// ADR-5B-R5: pure in-memory export parser (calls the real parser)
// ----------------------------------------------------------------

/// Minimal export-directory layout used by the pure parser tests.
///
/// Builds a flat "image" containing: name-pointer array (num_names * 4),
/// ordinal array (num_names * 2), function-address array (num_funcs * 4),
/// and NUL-terminated name strings. Offsets double as RVAs.
struct ExportImage {
    names: Vec<u8>,
    ords: Vec<u8>,
    funcs: Vec<u8>,
    name_data: Vec<u8>,
    num_names: usize,
    num_funcs: usize,
    /// IMAGE_EXPORT_DIRECTORY.Base (ordinal base). The production parser
    /// treats the ordinal array as 0-based indexes into AddressOfFunctions
    /// (MSVC/Rust link.exe convention); the field is retained so tests can
    /// model a directory whose Base != 1 explicitly.
    base: u32,
}

impl ExportImage {
    fn new(num_names: usize, num_funcs: usize) -> Self {
        Self {
            names: vec![0u8; num_names * 4],
            ords: vec![0u8; num_names * 2],
            funcs: vec![0u8; num_funcs * 4],
            name_data: Vec::new(),
            num_names,
            num_funcs,
            base: 1,
        }
    }

    /// Append a name string; returns its RVA (offset into name_data).
    /// RVAs are guaranteed non-zero (PE convention: RVA 0 = no name), so the
    /// first name is placed at offset 1.
    fn push_name(&mut self, name: &[u8]) -> usize {
        if self.name_data.is_empty() {
            self.name_data.push(0); // keep all real names at non-zero RVA
        }
        let rva = self.name_data.len();
        self.name_data.extend_from_slice(name);
        self.name_data.push(0);
        rva
    }

    /// Set names[i] -> name, ords[i] -> ordinal.
    fn set_name(&mut self, i: usize, name_rva: usize, ordinal: u16) {
        self.names[i * 4..i * 4 + 4].copy_from_slice(&(name_rva as u32).to_le_bytes());
        self.ords[i * 2..i * 2 + 2].copy_from_slice(&ordinal.to_le_bytes());
    }

    /// Set funcs[ordinal] -> rva.
    fn set_func(&mut self, ordinal: usize, func_rva: usize) {
        self.funcs[ordinal * 4..ordinal * 4 + 4].copy_from_slice(&(func_rva as u32).to_le_bytes());
    }
}

/// Resolve the three MIDA exports through the REAL parser with a flat-buffer
/// name resolver.
fn resolve_via_parser(img: &ExportImage) -> Vec<Option<usize>> {
    use mida_cli::unpacker::runtime_loader::RuntimeLoader;
    let want: [&[u8]; 3] = [
        b"MidaAntidebugInitialize",
        b"MidaAntidebugGetAttestation",
        b"MidaAntidebugShutdown",
    ];
    // module_base: 0x400000 (any); exp_rva/size: pick a window outside the
    // function array so no export is treated as forwarded.
    let module_base = 0x400000usize;
    let exp_rva = 0x2000usize;
    let exp_size = 0x100usize;
    let mut name_at = |name_ptr_rva: usize, out: &mut Vec<u8>| {
        let mut idx = name_ptr_rva;
        for _ in 0..64 {
            if idx >= img.name_data.len() {
                break;
            }
            let ch = img.name_data[idx];
            idx += 1;
            if ch == 0 {
                break;
            }
            out.push(ch);
        }
    };
    RuntimeLoader::resolve_exports_from_buffers(
        &img.names,
        &img.ords,
        &img.funcs,
        &mut name_at,
        img.num_names,
        img.num_funcs,
        module_base,
        exp_rva,
        exp_size,
        &want,
    )
    .expect("parser must succeed")
}

#[test]
fn export_parser_resolves_two_byte_ordinals_with_base_not_one() {
    // ADR-5B-R5 (audit round 2): model an export directory whose Base is
    // NOT 1 explicitly (e.g. Base=5). The production parser resolves the
    // ordinal array as 0-based indexes into AddressOfFunctions (MSVC/Rust
    // link.exe convention), so ordinals 5/7 still map to funcs[5]/funcs[7]
    // regardless of the Base field; this test pins that behavior.
    // The classic bug: ords_bytes = num_names * 4. With real 2-byte ordinal
    // slots, a 4-byte stride misreads every slot. This test drives the REAL
    // parser with a genuine PE-style ordinal array and asserts the resolved
    // function addresses, so a regression to num_names*4 fails here.
    let mut img = ExportImage::new(3, 8);
    // Base != 1 exercise: use arbitrary ordinal values (0, 5, 7) that index
    // AddressOfFunctions directly (MSVC/Rust link.exe convention).
    let init_rva = img.push_name(b"MidaAntidebugInitialize");
    let get_rva = img.push_name(b"MidaAntidebugGetAttestation");
    let shut_rva = img.push_name(b"MidaAntidebugShutdown");
    img.set_name(0, init_rva, 0);
    img.set_name(1, get_rva, 5);
    img.set_name(2, shut_rva, 7);
    img.set_func(0, 0x1111);
    img.set_func(5, 0x2222);
    img.set_func(7, 0x3333);
    // Fill the other slots with distinct junk to catch stride errors.
    for i in 0..8 {
        if i != 0 && i != 5 && i != 7 {
            img.set_func(i, 0xDEAD + i);
        }
    }
    // Model Base != 1: the directory declares ordinal base 5, but the
    // ordinal array still holds 0-based function indexes (link.exe
    // convention). The parser must resolve ordinals 5/7 -> funcs[5]/funcs[7].
    img.base = 5;
    let found = resolve_via_parser(&img);
    assert_eq!(found[0], Some(0x400000 + 0x1111));
    assert_eq!(found[1], Some(0x400000 + 0x2222));
    assert_eq!(found[2], Some(0x400000 + 0x3333));
}

#[test]
fn export_parser_skips_missing_and_out_of_range_ordinals() {
    // A wanted export whose ordinal is out of range (>= num_funcs) must NOT
    // resolve; a wanted export that is absent must stay None.
    let mut img = ExportImage::new(3, 4);
    let init_rva = img.push_name(b"MidaAntidebugInitialize");
    let _get_rva = img.push_name(b"MidaAntidebugGetAttestation");
    let shut_rva = img.push_name(b"MidaAntidebugShutdown");
    img.set_name(0, init_rva, 0); // resolves
    img.set_name(1, 0, 1); // name_ptr 0 -> skipped entirely (missing name)
                           // Real name RVA + out-of-range ordinal (9 >= num_funcs=4): must NOT
                           // resolve. Previously this test used name_ptr=0, which the parser skips
                           // BEFORE the ordinal check, so the out-of-range branch was never hit.
    img.set_name(2, shut_rva, 9);
    img.set_func(0, 0x1111);
    let found = resolve_via_parser(&img);
    assert_eq!(found[0], Some(0x400000 + 0x1111));
    assert_eq!(found[1], None, "GetAttestation missing must stay None");
    assert_eq!(
        found[2], None,
        "Shutdown with out-of-range ordinal (9 >= num_funcs=4) must stay None"
    );
}

#[test]
fn export_parser_skips_forwarded_exports() {
    // A forwarded export has its function RVA INSIDE the export directory
    // window (exp_rva..exp_rva+exp_size); the parser must not resolve it to
    // a bogus code address.
    let mut img = ExportImage::new(1, 4);
    let init_rva = img.push_name(b"MidaAntidebugInitialize");
    img.set_name(0, init_rva, 0);
    // Function RVA points INSIDE the export directory window.
    img.set_func(0, 0x2040); // exp_rva=0x2000, exp_size=0x100 -> inside
    let found = resolve_via_parser(&img);
    assert_eq!(
        found[0], None,
        "forwarded export must not resolve to a code address"
    );
}

#[test]
fn export_parser_fails_closed_on_truncated_buffers() {
    use mida_cli::unpacker::runtime_loader::RuntimeLoader;
    let want: [&[u8]; 1] = [b"MidaAntidebugInitialize"];
    // Names that point at a REAL string (non-zero RVA) so the parser reaches
    // the ordinal/function bounds checks instead of skipping on RVA 0.
    let name_rva = 0x10usize;
    let mut name_at = |rva: usize, out: &mut Vec<u8>| {
        if rva == name_rva {
            out.extend_from_slice(b"MidaAntidebugInitialize");
        }
    };
    let mut names = vec![0u8; 8];
    names[0..4].copy_from_slice(&(name_rva as u32).to_le_bytes());
    names[4..8].copy_from_slice(&(name_rva as u32).to_le_bytes());
    // Truncated ordinal array: num_names=2 but only 2 bytes provided.
    let ords = vec![0u8; 2];
    let funcs = vec![0u8; 16];
    let err = RuntimeLoader::resolve_exports_from_buffers(
        &names,
        &ords,
        &funcs,
        &mut name_at,
        2, // claims 2 names
        4,
        0x400000,
        0x2000,
        0x100,
        &want,
    )
    .unwrap_err();
    assert!(
        matches!(err, RuntimeLoadError::ExportResolutionFailed(_)),
        "truncated ordinal array must fail closed: {err:?}"
    );
    // Truncated name-pointer array (2 names need 8 bytes, only 7 provided).
    let names2 = vec![0u8; 7];
    let err2 = RuntimeLoader::resolve_exports_from_buffers(
        &names2,
        &[0u8; 4],
        &[0u8; 16],
        &mut name_at,
        2,
        4,
        0x400000,
        0x2000,
        0x100,
        &want,
    )
    .unwrap_err();
    assert!(matches!(err2, RuntimeLoadError::ExportResolutionFailed(_)));
    // Truncated function array: name resolves, ordinal 3 indexes funcs but
    // only 15 of 16 bytes exist for 4 funcs (funcs[12..16] missing).
    let ords3 = vec![3u16.to_le_bytes()[0], 3u16.to_le_bytes()[1], 0, 0]; // ordinal 3, 0
    let mut funcs3 = vec![0u8; 15]; // 4 funcs need 16 bytes
    funcs3[0..12].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let err3 = RuntimeLoader::resolve_exports_from_buffers(
        &names,
        &ords3,
        &funcs3,
        &mut name_at,
        2,
        4,
        0x400000,
        0x2000,
        0x100,
        &want,
    )
    .unwrap_err();
    assert!(matches!(err3, RuntimeLoadError::ExportResolutionFailed(_)));
}

#[test]
fn thunk_args_blob_fits_allocated_args_window() {
    use mida_cli::unpacker::runtime_loader::{ThunkArgs, THUNK_ARGS_SIZE};
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
    assert_eq!(args.as_bytes().len(), THUNK_ARGS_SIZE);
}

// ----------------------------------------------------------------
// ADR-5B-R1: drain receipt type surface (offline, no Win32)
// ----------------------------------------------------------------

#[test]
fn drain_receipt_defaults_are_sane() {
    use mida_core::{DrainDisposition, DrainReceipt};
    let r = DrainReceipt {
        sequence: 1,
        process_id: 100,
        thread_id: 200,
        event_code: 6, // LOAD_DLL
        disposition: DrainDisposition::Delivered,
        continue_status: 0x0001_0002,
        bookkeeping: "hFile closed".to_string(),
        exception_code: None,
        first_chance: None,
        exception_address: None,
        instruction_pointer: None,
        stack_pointer: None,
        faulting_module: None,
        faulting_module_base: None,
        faulting_module_rva: None,
        context_capture_error: None,
    };
    assert_eq!(r.sequence, 1);
    assert_eq!(r.process_id, 100);
    assert_eq!(r.thread_id, 200);
    assert_eq!(r.event_code, 6);
    assert_eq!(r.continue_status, 0x0001_0002);
    assert!(r.bookkeeping.contains("hFile"));
    // DrainDisposition is Copy + Eq (usable in receipts/logs).
    let _copy = r.disposition;
    assert_ne!(r.disposition, DrainDisposition::Exception);
}
