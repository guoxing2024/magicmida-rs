//! Load optional dump capture policy JSON (case-manifest / sidecar file).
//!
//! Format matches `case-manifest` `$defs.capturePolicy` (hex RVA strings +
//! optional `preset`). Host still gates experimental stages on DumpProfile.

use std::fs;
use std::path::Path;

use mida_pe::DumpCapturePolicy;
use serde_json::Value;

/// Parse a capture-policy JSON document into [`DumpCapturePolicy`].
///
/// Merge rules (pre-profile resolve):
/// - non-empty `hot_root_rvas` → explicit custom roots
/// - else `preset: "ahk_gto_defaults"` → built-in AHK/GTO defaults
/// - else `preset: "empty"` or missing → empty policy
/// - numeric knobs / gscript override apply on top when non-zero / Some
pub fn load_capture_policy_file(path: &Path) -> Result<DumpCapturePolicy, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("read capture policy {}: {e}", path.display()))?;
    parse_capture_policy_json(&text)
}

/// Parse capture-policy JSON text.
///
/// Accepts either:
/// - a pure capture-policy object (`preset` / `hot_root_rvas` / knobs), or
/// - a full case-manifest v2 document with a `capture_policy` field.
///
/// Full manifests without `capture_policy` yield an empty policy (not an error).
pub fn parse_capture_policy_json(text: &str) -> Result<DumpCapturePolicy, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid capture policy JSON: {e}"))?;
    parse_capture_policy_document(&v)
}

/// Extract the capture-policy object from a JSON value (pure policy or case-manifest).
fn extract_capture_policy_object(v: &Value) -> Result<Option<&Value>, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "capture policy root must be an object".to_string())?;

    // Full case-manifest: pull nested field (may be absent → empty policy).
    if obj.contains_key("schema_version")
        || obj.contains_key("case_id")
        || obj.contains_key("$schema")
    {
        return match obj.get("capture_policy") {
            None | Some(Value::Null) => Ok(None),
            Some(cp) => {
                if !cp.is_object() {
                    return Err("case-manifest capture_policy must be an object".into());
                }
                Ok(Some(cp))
            }
        };
    }

    // Pure capture-policy document (or any object shaped like the field).
    Ok(Some(v))
}

fn parse_capture_policy_document(v: &Value) -> Result<DumpCapturePolicy, String> {
    match extract_capture_policy_object(v)? {
        None => Ok(DumpCapturePolicy::default()),
        Some(cp) => parse_capture_policy_value(cp),
    }
}

fn parse_capture_policy_value(v: &Value) -> Result<DumpCapturePolicy, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "capture policy root must be an object".to_string())?;

    let hot_root_rvas = parse_hex_rva_list(obj.get("hot_root_rvas"), "hot_root_rvas")?;
    let large_table_rvas = parse_hex_rva_list(obj.get("large_table_rvas"), "large_table_rvas")?;
    let hot_expand_seed_rvas =
        parse_hex_rva_list(obj.get("hot_expand_seed_rvas"), "hot_expand_seed_rvas")?;
    let gscript_root_rva = parse_optional_hex_rva(obj.get("gscript_root_rva"), "gscript_root_rva")?;
    let gscript_root_content_cap =
        parse_usize_knob(obj.get("gscript_root_content_cap"), "gscript_root_content_cap")?;
    let gscript_first_hop_span =
        parse_usize_knob(obj.get("gscript_first_hop_span"), "gscript_first_hop_span")?;
    let gscript_first_hop_probe =
        parse_usize_knob(obj.get("gscript_first_hop_probe"), "gscript_first_hop_probe")?;

    let preset = obj
        .get("preset")
        .and_then(|p| p.as_str())
        .unwrap_or("");

    let mut policy = if !hot_root_rvas.is_empty() {
        DumpCapturePolicy {
            hot_root_rvas,
            large_table_rvas: large_table_rvas.clone(),
            gscript_root_rva,
            gscript_root_content_cap,
            gscript_first_hop_span,
            gscript_first_hop_probe,
            hot_expand_seed_rvas: hot_expand_seed_rvas.clone(),
        }
    } else {
        match preset {
            "ahk_gto_defaults" => DumpCapturePolicy::ahk_gto_default(),
            "empty" | "" => DumpCapturePolicy::default(),
            other => {
                return Err(format!(
                    "unknown capture_policy.preset {other:?} (expected ahk_gto_defaults|empty)"
                ));
            }
        }
    };

    // Knobs override preset defaults when explicitly set in the file.
    if gscript_root_rva.is_some() {
        policy.gscript_root_rva = gscript_root_rva;
    }
    if gscript_root_content_cap != 0 {
        policy.gscript_root_content_cap = gscript_root_content_cap;
    }
    if gscript_first_hop_span != 0 {
        policy.gscript_first_hop_span = gscript_first_hop_span;
    }
    if gscript_first_hop_probe != 0 {
        policy.gscript_first_hop_probe = gscript_first_hop_probe;
    }
    if obj.contains_key("large_table_rvas") {
        policy.large_table_rvas = large_table_rvas;
    }
    if obj.contains_key("hot_expand_seed_rvas") {
        policy.hot_expand_seed_rvas = hot_expand_seed_rvas;
    }

    Ok(policy)
}

fn parse_hex_rva_list(v: Option<&Value>, field: &str) -> Result<Vec<u32>, String> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{field} must be an array of hex RVA strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .ok_or_else(|| format!("{field}[{i}] must be a hex string"))?;
        out.push(parse_hex_u32(s).map_err(|e| format!("{field}[{i}]: {e}"))?);
    }
    Ok(out)
}

fn parse_optional_hex_rva(v: Option<&Value>, field: &str) -> Result<Option<u32>, String> {
    let Some(v) = v else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(None);
    }
    let s = v
        .as_str()
        .ok_or_else(|| format!("{field} must be hex string or null"))?;
    Ok(Some(parse_hex_u32(s).map_err(|e| format!("{field}: {e}"))?))
}

fn parse_usize_knob(v: Option<&Value>, field: &str) -> Result<usize, String> {
    let Some(v) = v else {
        return Ok(0);
    };
    if v.is_null() {
        return Ok(0);
    }
    v.as_u64()
        .map(|n| n as usize)
        .ok_or_else(|| format!("{field} must be a non-negative integer"))
}

fn parse_hex_u32(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let body = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u32::from_str_radix(body, 16).map_err(|e| format!("invalid hex RVA {s:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_ahk_expands() {
        let p = parse_capture_policy_json(r#"{"preset":"ahk_gto_defaults"}"#).unwrap();
        assert_eq!(p, DumpCapturePolicy::ahk_gto_default());
    }

    #[test]
    fn empty_object_is_empty_policy() {
        let p = parse_capture_policy_json("{}").unwrap();
        assert!(p.hot_root_rvas.is_empty());
    }

    #[test]
    fn explicit_roots_win_over_preset() {
        let p = parse_capture_policy_json(
            r#"{"preset":"ahk_gto_defaults","hot_root_rvas":["0x1000","0x2000"],"gscript_root_rva":"0x1000"}"#,
        )
        .unwrap();
        assert_eq!(p.hot_root_rvas, vec![0x1000, 0x2000]);
        assert_eq!(p.gscript_root_rva, Some(0x1000));
    }

    #[test]
    fn preset_with_cap_override() {
        let p = parse_capture_policy_json(
            r#"{"preset":"ahk_gto_defaults","gscript_root_content_cap":4096}"#,
        )
        .unwrap();
        assert!(p.is_hot_root(0x149d50));
        assert_eq!(p.gscript_root_content_cap, 4096);
    }

    #[test]
    fn full_case_manifest_extracts_capture_policy() {
        let p = parse_capture_policy_json(
            r#"{
              "$schema": "./case-manifest.schema.json",
              "schema_version": "mida.case-manifest/v2",
              "case_id": "gto_launcher",
              "capture_policy": {"preset": "ahk_gto_defaults"}
            }"#,
        )
        .unwrap();
        assert_eq!(p, DumpCapturePolicy::ahk_gto_default());
    }

    #[test]
    fn full_case_manifest_without_field_is_empty() {
        let p = parse_capture_policy_json(
            r#"{
              "schema_version": "mida.case-manifest/v2",
              "case_id": "origin_macro"
            }"#,
        )
        .unwrap();
        assert!(p.hot_root_rvas.is_empty());
    }

    #[test]
    fn unknown_preset_errors() {
        let e = parse_capture_policy_json(r#"{"preset":"nope"}"#).unwrap_err();
        assert!(e.contains("unknown capture_policy.preset"));
    }
}
