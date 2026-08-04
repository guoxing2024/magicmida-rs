//! R1-A: pure PE modules must not import Win32 / debugger / disasm surfaces.
//!
//! This is a source-boundary lock before large module moves. Live dump adapters
//! may still depend on `windows` and `mida-core` at the crate level.
//!
//! Note: static tables (e.g. `apiset_data`) may mention Win32 *API names as data
//! strings*. The scan targets imports, type paths, and call-shaped identifiers,
//! not bare name substrings inside string literals.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Modules classified pure under docs/VNEXT_R1_PE_API.md.
const PURE_MODULES: &[&str] = &[
    "src/error.rs",
    "src/utils.rs",
    "src/header/mod.rs",
    "src/header/tests.rs",
    "src/section.rs",
    "src/import_table.rs",
    "src/export_table.rs",
    "src/exception_table.rs",
    "src/tls.rs",
    "src/relocation.rs",
    "src/rebuild.rs",
    "src/byte_map.rs",
    "src/postprocess.rs",
    "src/apiset_data.rs",
];

/// Import / type-path surfaces (safe as plain substrings).
const FORBIDDEN_IMPORT_PATTERNS: &[&str] = &[
    "use windows::",
    "windows::Win32",
    "windows::core",
    "mida_core::",
    "use mida_core",
    "mida_disasm::",
    "use mida_disasm",
    "DebuggerCore",
];

/// Win32/live APIs that must not appear as code identifiers / call sites.
/// Bare names alone are insufficient: pure data tables list many of these strings.
const FORBIDDEN_API_TOKENS: &[&str] = &[
    "ReadProcessMemory",
    "WriteProcessMemory",
    "VirtualQueryEx",
    "VirtualProtectEx",
    "OpenProcess",
    "CreateToolhelp32Snapshot",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "GetProcAddress",
];

#[test]
fn pure_pe_modules_exclude_live_and_win32_surfaces() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let report_path = temp_report_path();
    let _report_cleanup = ReportCleanup::new(report_path.clone());

    let mut module_hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut missing = Vec::new();

    for rel in PURE_MODULES {
        let path = manifest_dir.join(rel);
        if !path.is_file() {
            missing.push(rel.to_string());
            continue;
        }
        let src = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("read {}: {e}", path.display());
        });
        let mut hits = Vec::new();
        for pat in FORBIDDEN_IMPORT_PATTERNS {
            if src.contains(pat) {
                hits.push((*pat).to_string());
            }
        }
        for name in FORBIDDEN_API_TOKENS {
            if has_code_api_use(&src, name) {
                hits.push(format!("code use of {name}"));
            }
        }
        if !hits.is_empty() {
            module_hits.insert(rel.replace('\\', "/"), hits);
        }
    }

    let pass = missing.is_empty() && module_hits.is_empty();
    let report = serde_json::json!({
        "schema_version": "mida.pe-purity-boundary/v1",
        "package": "mida-pe",
        "pure_modules": PURE_MODULES,
        "forbidden_import_patterns": FORBIDDEN_IMPORT_PATTERNS,
        "forbidden_api_tokens": FORBIDDEN_API_TOKENS,
        "missing_modules": missing,
        "violations": module_hits,
        "pass": pass,
        "note": "Crate-level windows/mida-core deps remain for adapter modules; pure paths must stay clean. API names inside string data (ApiSet tables) are allowed.",
    });

    write_report(&report_path, &report);

    assert!(
        missing.is_empty(),
        "pure module paths missing from tree: {missing:?}"
    );
    assert!(
        module_hits.is_empty(),
        "pure PE modules contain forbidden live/Win32 surfaces: {module_hits:?}\nSee docs/VNEXT_R1_PE_API.md"
    );
}

#[test]
fn pure_module_list_is_non_empty_and_under_src() {
    assert!(!PURE_MODULES.is_empty());
    for rel in PURE_MODULES {
        assert!(
            rel.starts_with("src/"),
            "pure module must be under src/: {rel}"
        );
        assert!(
            rel.ends_with(".rs"),
            "pure module must be a Rust source file: {rel}"
        );
    }
}

/// True when `name` appears as a Rust code identifier (not only inside string data).
///
/// Matches: `name(`, `::name`, `use ... name`, path segments; ignores `"name"`.
fn has_code_api_use(src: &str, name: &str) -> bool {
    let bytes = src.as_bytes();
    let n = name.as_bytes();
    let mut i = 0;
    while i + n.len() <= bytes.len() {
        if &bytes[i..i + n.len()] == n {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_i = i + n.len();
            let after_ok = after_i >= bytes.len() || !is_ident_byte(bytes[after_i]);
            if before_ok && after_ok {
                let in_string = is_inside_string_literal(src, i);
                if !in_string {
                    return true;
                }
            }
            i += n.len();
        } else {
            i += 1;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Best-effort: track double-quoted string spans (handles simple escapes).
fn is_inside_string_literal(src: &str, index: usize) -> bool {
    let mut in_string = false;
    let mut escape = false;
    for (i, ch) in src.char_indices() {
        if i >= index {
            break;
        }
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
        }
    }
    in_string
}

fn temp_report_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "mida-pe-purity-boundary-{}.json",
        std::process::id()
    ))
}

struct ReportCleanup {
    path: PathBuf,
}

impl ReportCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for ReportCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn write_report(out_path: &Path, report: &serde_json::Value) {
    fs::write(
        out_path,
        serde_json::to_string_pretty(report).expect("serialize purity report") + "\n",
    )
    .unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
}
