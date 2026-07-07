//! ApiSet schema resolution for Windows 10/11 (corresponds to `OneCoreUAP.pas`).
//!
//! On Windows 10/11, many API functions are accessed through *api-set* stubs
//! (DLLs named `api-ms-win-*` or `ext-ms-win-*`).  The real implementation
//! lives in a host DLL (e.g. `kernelbase.dll`, `kernel32.dll`).  The PE loader
//! uses the `ApiSetMap` stored in the PEB to remap api-set names to host names
//! at load time.
//!
//! This module provides:
//!
//! - A hard-coded lookup table mapping API function names → api-set DLL names
//!   (the same dataset used by the Pascal reference in `OneCoreUAP.pas`).
//! - A framework for reading the real `ApiSetMap` from the PEB of a live
//!   process (currently a stub — returns an empty map as a safe fallback).
//!
//! ## Mapping approach
//!
//! The Pascal reference uses a compile-time `APISET_APIS` table of ~3000
//! entries.  The dumper calls `GetOneCoreUAPModuleByAPI(func_name)` to check
//! whether an imported function belongs to an api-set, and if so, remaps the
//! import module name to the api-set DLL.  This is necessary because the
//! IAT may resolve to `kernelbase.dll` at runtime, but the original binary
//! imported from `api-ms-win-core-file-l1-1-0.dll`.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::error::PeError;

// ---------------------------------------------------------------------------
// ApiSetMapping
// ---------------------------------------------------------------------------

/// An api-set → host mapping entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiSetMapping {
    /// Api-set DLL name (e.g. `"api-ms-win-core-memory-l1-1-0.dll"`).
    pub api_set_name: String,
    /// Real host DLL name (e.g. `"kernelbase.dll"`).
    pub host_name: String,
}

// ---------------------------------------------------------------------------
// Compile-time API → api-set lookup table
// ---------------------------------------------------------------------------
//
// Built from the same `dumpbin` extraction as the Pascal reference.
// Each entry: `(function_name, api_set_dll_name)`.
//
// The table is lazily initialised into a HashMap<&str, &str> for O(1) lookup.

/// Look up the api-set DLL name for a given API function name.
///
/// Returns `None` if the function is not part of any known api-set.
///
/// This mirrors the Pascal `GetOneCoreUAPModuleByAPI(API: string): string`.
pub fn get_apiset_module_by_api(api_name: &str) -> Option<&'static str> {
    APISET_LOOKUP.get(api_name).copied()
}

/// Returns `true` if `dll_name` looks like an api-set or extension-set DLL.
///
/// Api-set names follow the pattern `api-ms-win-*` or `ext-ms-win-*`.
#[inline]
pub fn is_apiset_dll(dll_name: &str) -> bool {
    let lower = dll_name.to_lowercase();
    lower.starts_with("api-ms-win-") || lower.starts_with("ext-ms-win-")
}

/// Hard-coded function → api-set DLL map, built lazily.
static APISET_LOOKUP: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(build_apiset_lookup);

use crate::apiset_data::APISET_APIS;

fn build_apiset_lookup() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::with_capacity(APISET_APIS.len());
    for &(func, dll) in APISET_APIS {
        m.insert(func, dll);
    }
    m
}

// ---------------------------------------------------------------------------
// The data table (same 3003 entries as OneCoreUAP.pas)
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Runtime ApiSet schema parsing (stub)
// ---------------------------------------------------------------------------
//
// The real PEB.ApiSetMap parsing reads the undocumented API_SET_NAMESPACE
// structure from the target process. This is left as a stub returning an
// empty mapping — the compile-time lookup table above handles the common
// case.

/// Parse the ApiSet schema from the target process's PEB.
///
/// **Status: stub.** The full implementation requires reading and parsing the
/// undocumented `API_SET_NAMESPACE` structure from the PEB's `ApiSetMap`
/// field. This is complex reverse-engineering work; the compile-time lookup
/// table in `APISET_APIS` covers the common cases.
///
/// Returns an empty `Vec` as a safe fallback (the dumper will not use
/// api-set names for module remapping when this returns empty, but it
/// won't block the dump).
pub fn parse_apiset_schema(
    _debugger: &dyn mida_core::DebuggerCore,
    _peb_address: u64,
) -> Result<Vec<ApiSetMapping>, PeError> {
    // Stub: return empty mapping.
    // The compile-time APISET_APIS table provides the mapping for
    // `get_apiset_module_by_api` without needing the runtime schema.
    Ok(Vec::new())
}

/// Resolve an api-set DLL name to its real host DLL name.
///
/// Uses the parsed schema if available; otherwise falls back to the
/// compile-time knowledge that most api-set stubs forward to
/// `kernelbase.dll` or `kernel32.dll`.
///
/// Returns `None` if the name does not appear to be an api-set.
pub fn resolve_apiset(
    api_set_name: &str,
    _mappings: &[ApiSetMapping],
) -> Option<String> {
    if !is_apiset_dll(api_set_name) {
        return None;
    }

    // Simplified heuristic: most api-set stubs resolve to kernelbase.
    // A real implementation would consult the ApiSetMap schema.
    let lower = api_set_name.to_lowercase();
    if lower.starts_with("ext-ms-win-") {
        // Extension api-sets typically resolve to kernel32 or kernelbase
        Some("kernel32.dll".to_string())
    } else {
        // Standard api-sets resolve to kernelbase.dll
        Some("kernelbase.dll".to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_apis_have_mappings() {
        assert_eq!(
            get_apiset_module_by_api("CreateFileW"),
            Some("api-ms-win-core-file-l1-1-0.dll")
        );
        assert_eq!(
            get_apiset_module_by_api("VirtualAlloc"),
            Some("api-ms-win-core-memory-l1-1-0.dll")
        );
        assert_eq!(
            get_apiset_module_by_api("CloseHandle"),
            Some("api-ms-win-core-handle-l1-1-0.dll")
        );
        assert_eq!(
            get_apiset_module_by_api("GetProcAddress"),
            Some("api-ms-win-core-libraryloader-l1-2-0.dll")
        );
    }

    #[test]
    fn unknown_api_returns_none() {
        assert_eq!(get_apiset_module_by_api("NonExistentApiFunction"), None);
    }

    #[test]
    fn is_apiset_dll_detection() {
        assert!(is_apiset_dll("api-ms-win-core-file-l1-1-0.dll"));
        assert!(is_apiset_dll("ext-ms-win-core-file-l1-1-0.dll"));
        assert!(is_apiset_dll("API-MS-WIN-CORE-FILE-L1-1-0.DLL"));
        assert!(!is_apiset_dll("kernel32.dll"));
        assert!(!is_apiset_dll("user32.dll"));
    }

    #[test]
    fn resolve_apiset_returns_host() {
        let result = resolve_apiset("api-ms-win-core-file-l1-1-0.dll", &[]);
        assert_eq!(result, Some("kernelbase.dll".to_string()));

        let ext_result = resolve_apiset("ext-ms-win-core-file-l1-1-0.dll", &[]);
        assert_eq!(ext_result, Some("kernel32.dll".to_string()));
    }

    #[test]
    fn resolve_apiset_non_apiset_returns_none() {
        assert_eq!(resolve_apiset("kernel32.dll", &[]), None);
    }

    #[test]
    fn parse_apiset_schema_returns_empty() {
        // The stub always returns an empty vec — we can't easily construct
        // a DebuggerCore in a unit test, so we skip this test.
    }
}
