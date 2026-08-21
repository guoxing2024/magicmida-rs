//! Read-only CLI for the independent acceptance kernel.
//!
//! ```text
//! mida-acceptance check-static <candidate> [options]
//! mida-acceptance check-with-behavior <candidate> --behavior-evidence <json> [options]
//! mida-acceptance oreans-pe-evidence <candidate> [options]
//! mida-acceptance unpack-pe-evidence <candidate> [options]
//! mida-acceptance oreans-two-sample-gate <observations.json> [options]
//! ```
//!
//! Exit codes: 0 = StructuralPassBehaviorPending, Accepted, successful Oreans PE
//! evidence, or a closed two-sample gate; 2 = Rejected, an open gate, or an
//! Oreans validation failure; 1 = I/O or config error.
//! Report writes never alias candidate, oracle, or evidence inputs.

use std::env;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use serde::Deserialize;

use mida_acceptance::oreans_gate::OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION;
use mida_acceptance::{
    build_oreans_pe_evidence, build_unpack_pe_evidence, check_static, check_with_behavior,
    check_with_behavior_managed, check_with_behavior_managed_lab, check_with_behavior_signed,
    evaluate_oreans_two_sample_gate, sha256_hex, BehaviorEvidence, CheckStaticOptions,
    EnvelopePolicy, HmacSha256Verifier, OreansGateVerdict, OreansPeEvidence, OreansPeEvidenceError,
    OreansSampleObservation, SignatureEnvelope, Verdict, VerifiedManagedCandidate, FIXED_CASE_IDS,
    GTO_CASE_ID,
};

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a GTO immutable snapshot path and return its 64-hex hash directory
/// component via the shared contract, WITHOUT relying on canonicalization. The
/// path must be absolute, free of `.`/`..`, of the exact shape
/// `<root>/gto_launcher/<sha256>/snapshot.bin`, and its logical-sample directory
/// must be the GTO lane case id. The returned hash is case-preserved so the
/// caller can compare it (case-normalized) against the sealed
/// `protected_input.sha256`. This runs BEFORE any canonicalize() so a raw `..` or
/// relative path is rejected even if it would later resolve to the same file.
fn gto_snapshot_hash_dir(path: &str) -> Result<String, String> {
    let parsed = mida_acceptance::snapshot_path::parse_snapshot_path(std::path::Path::new(path))?;
    if parsed.logical_sample_id != GTO_CASE_ID {
        return Err(format!(
            "GTO snapshot logical-sample directory {:?} != {GTO_CASE_ID}",
            parsed.logical_sample_id
        ));
    }
    Ok(parsed.sha256)
}

/// Read the `case_id` from a `mida.case-manifest/v2` (best-effort; empty when
/// the manifest is unreadable/malformed).
fn read_manifest_case_id(manifest_path: &Path) -> Option<String> {
    let bytes = fs::read(manifest_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("case_id")
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Bind the ACTUAL `--case` GTO input to the envelope's sealed immutable
/// snapshot path. Independent verifier enforcement (P6.3-G3-R3-R2-R1): a
/// same-bytes different-path live source/alias is refused HERE, not deferred
/// to the CLI launch helper.
///
/// Returns the verified sealed path (for the report) on success, or a reason
/// on failure.
fn bind_gto_actual_input_to_sealed(
    actual_input: &Path,
    env_gto: &CaseConfigEnvelopeV4,
    trusted_snapshot_root: &Path,
) -> Result<String, String> {
    // 1. Sealed path must be present and non-empty.
    let sealed = env_gto
        .protected_input_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| "GTO lane case has no non-empty protected_input_path".to_string())?;
    // 2. Structural validation of the RAW sealed path (absolute, no `.`/`..`,
    //    `<root>/gto_launcher/<sha256>/snapshot.bin`) and return the hash dir.
    let sealed_hash = gto_snapshot_hash_dir(sealed)?;
    // 3. Content-address binding: the path's hash directory must equal the
    //    sealed protected-input SHA-256 (case-normalized).
    if !sealed_hash.eq_ignore_ascii_case(&env_gto.protected_input.sha256) {
        return Err(format!(
            "GTO snapshot path hash dir {sealed_hash:?} != sealed protected_input sha {} \
             (fail-closed)",
            env_gto.protected_input.sha256.to_lowercase()
        ));
    }
    // 4. STRICT disk-level canonical verification of the sealed path and the
    //    actual input, with canonical snapshot_root containment. `canonical_verify_snapshot_path`
    //    strictly canonicalizes (NO loose fallback) and requires the canonical
    //    path to stay under the canonical snapshot_root with the correct
    //    logical/hash layers, so a junction/symlink/reparse escape of the sealed
    //    path's logical/hash/file layer is rejected. A missing file or any
    //    canonicalization failure also fails closed (never falls back to the raw
    //    path).
    let sealed_canon = mida_acceptance::snapshot_path::canonical_verify_snapshot_path(
        Path::new(sealed),
        trusted_snapshot_root,
        GTO_CASE_ID,
        &env_gto.protected_input.sha256,
    )
    .map_err(|e| format!("GTO sealed snapshot path failed disk verification: {e}"))?;
    let actual_canon = mida_acceptance::snapshot_path::canonical_verify_snapshot_path(
        actual_input,
        trusted_snapshot_root,
        GTO_CASE_ID,
        &env_gto.protected_input.sha256,
    )
    .map_err(|e| {
        format!(
            "GTO actual input {} failed disk verification (missing/reparse/escape): {e}",
            actual_input.display()
        )
    })?;
    if actual_canon.snapshot_path != sealed_canon.snapshot_path {
        return Err(format!(
            "GTO actual input {} (canonical {}) != sealed immutable snapshot {} \
             (canonical {}); a live source/alias with identical bytes is refused \
             (identity+path double binding, fail-closed)",
            actual_input.display(),
            actual_canon.snapshot_path.display(),
            sealed,
            sealed_canon.snapshot_path.display()
        ));
    }
    Ok(sealed.to_string())
}

fn main() {
    let code = match run() {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            1
        }
    };
    process::exit(code);
}

fn run() -> Result<i32, String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return Ok(1);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(0)
        }
        "-V" | "--version" | "version" => {
            println!("mida-acceptance {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "check-static" => {
            args.remove(0);
            cmd_check_static(&args)
        }
        "check-with-behavior" => {
            args.remove(0);
            cmd_check_with_behavior(&args)
        }
        "oreans-pe-evidence" => {
            args.remove(0);
            cmd_oreans_pe_evidence(&args)
        }
        "unpack-pe-evidence" => {
            args.remove(0);
            cmd_unpack_pe_evidence(&args)
        }
        "oreans-two-sample-gate" => {
            args.remove(0);
            cmd_oreans_two_sample_gate(&args)
        }
        "classify-gate-report" => {
            args.remove(0);
            cmd_classify_gate_report(&args)
        }
        "preflight" => {
            args.remove(0);
            cmd_preflight(&args)
        }
        other => Err(format!(
            "unknown command '{other}'. Use: check-static | check-with-behavior | oreans-pe-evidence | unpack-pe-evidence | oreans-two-sample-gate | classify-gate-report | preflight"
        )),
    }
}

fn print_help() {
    println!(
        "\
mida-acceptance - independent PE acceptance kernel (R0B + B-A2 compose)

Usage:
  mida-acceptance check-static <candidate> [options]
  mida-acceptance check-with-behavior <candidate> --behavior-evidence <path> [options]
  mida-acceptance oreans-pe-evidence <candidate> [options]
  mida-acceptance unpack-pe-evidence <candidate> [options]
  mida-acceptance oreans-two-sample-gate <observations.json> [options]
  mida-acceptance classify-gate-report <bundle_gate_report.json> [--report PATH]
  mida-acceptance preflight --envelope <path> --output-dir <dir> --cli-binary <path>
                            --repo-root <path> --toolchain-pin <path>
                            --expected-toolchain <ver> --case <manifest> <input> <output>
                            [--case ...]
                            (verifies the runner-config envelope + writes preflight.json)

Options:
  --expected-sha256 <hex>  Fail-closed if file digest does not match
  --expected-size <bytes>  Fail-closed if file length does not match
  --role <role>            Artifact role label (default: candidate)
  --oracle <path>          Legacy oracle file (comparison observation only)
  --behavior-evidence <p>  Pre-recorded mida.behavior-evidence/v0 JSON (compose only)
  --report <path>          Write deterministic JSON report to path
                           (must not alias any input file)
  --allow-unmanaged-candidate
                           check-with-behavior only: allow missing sibling
                           *.transform_manifest.json (experimental / lab)
  --signature-envelope <p> CI signature envelope JSON (mida.signature-envelope/v0)
                           sibling <stem>.signature_envelope.json is also tried
  --allow-hmac-lab         Lab only: permit caller-supplied HMAC trust root
                           (requires --envelope-key-id + --envelope-hmac-key-hex).
                           Product path rejects HMAC without this flag (audit P0).
  --envelope-key-id <id>   Lab HMAC key id (or env MIDA_ENVELOPE_KEY_ID)
  --envelope-hmac-key-hex  Lab HMAC key material hex (or env MIDA_ENVELOPE_HMAC_KEY_HEX)
  --allow-unsigned-managed Lab only: permit managed Accepted without verified envelope
  -h, --help               Show help
  -V, --version            Show version

Exit codes:
  0  StructuralPassBehaviorPending, Accepted, successful Oreans PE evidence, or closed gate
  2  Rejected, open gate, or Oreans validation failure
  1  I/O, configuration, or internal error

Notes:
  check-static never returns Accepted (R0B).
  Product Accepted requires managed manifest + verified signature envelope with a
  non-caller-controlled trust root (Ed25519 reserved; HMAC is lab-only).
  Without envelope, managed compose is capped at StructuralPassBehaviorPending
  unless --allow-unsigned-managed (lab).
"
    );
}

fn cmd_oreans_pe_evidence(args: &[String]) -> Result<i32, String> {
    cmd_pe_evidence_impl(
        args,
        "oreans-pe-evidence",
        build_oreans_pe_evidence,
        "Oreans PE evidence",
    )
}

/// Emit the generic, family-agnostic PE evidence (`mida.unpack-pe-evidence/v1`)
/// through the same acceptance-binary seam as the Oreans PE evidence. The
/// payload build is shared ([`build_unpack_pe_evidence`]); only the schema id
/// differs, so a generic (`ahk_gto`) run never produces Oreans PE evidence.
fn cmd_unpack_pe_evidence(args: &[String]) -> Result<i32, String> {
    cmd_pe_evidence_impl(
        args,
        "unpack-pe-evidence",
        build_unpack_pe_evidence,
        "generic PE evidence",
    )
}

/// Shared PE-evidence command driver: parse `<candidate>` + expected
/// identity/`--report` options, build the family-appropriate PE evidence, and
/// write the report. `build` selects the family-specific schema id.
fn cmd_pe_evidence_impl(
    args: &[String],
    command_name: &str,
    build: fn(&[u8]) -> Result<OreansPeEvidence, OreansPeEvidenceError>,
    label: &str,
) -> Result<i32, String> {
    if args.is_empty() {
        return Err(format!(
            "Usage: mida-acceptance {command_name} <candidate> [--expected-sha256 HEX] \
             [--expected-size BYTES] [--report PATH]"
        ));
    }

    let mut candidate: Option<PathBuf> = None;
    let mut expected_sha256: Option<String> = None;
    let mut expected_size: Option<u64> = None;
    let mut report_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--expected-sha256" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-sha256".into());
                }
                expected_sha256 = Some(parse_expected_sha256(&args[i])?);
            }
            flag if flag.starts_with("--expected-sha256=") => {
                expected_sha256 = Some(parse_expected_sha256(&flag["--expected-sha256=".len()..])?);
            }
            "--expected-size" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-size".into());
                }
                expected_size = Some(parse_expected_size(&args[i])?);
            }
            flag if flag.starts_with("--expected-size=") => {
                expected_size = Some(parse_expected_size(&flag["--expected-size=".len()..])?);
            }
            "--report" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --report".into());
                }
                report_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--report=") => {
                report_path = Some(PathBuf::from(&flag["--report=".len()..]));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if candidate.is_some() {
                    return Err(format!("unexpected argument '{other}'"));
                }
                candidate = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    let candidate = candidate.ok_or_else(|| "missing <candidate> path".to_string())?;
    let (bytes, candidate_file) = read_input(&candidate, "candidate")?;
    let actual_sha256 = mida_acceptance::sha256_hex(&bytes);
    let actual_size = bytes.len() as u64;

    if let Some(expected) = expected_sha256.as_deref() {
        if expected != actual_sha256 {
            eprintln!(
                "error: expected SHA-256 {expected}, candidate '{}' has {actual_sha256}",
                candidate.display()
            );
            return Ok(2);
        }
    }
    if let Some(expected) = expected_size {
        if expected != actual_size {
            eprintln!(
                "error: expected size {expected} bytes, candidate '{}' has {actual_size} bytes",
                candidate.display()
            );
            return Ok(2);
        }
    }

    let evidence = match build(&bytes) {
        Ok(evidence) => evidence,
        Err(error) => {
            eprintln!(
                "error: {label} construction failed for '{}': {error}",
                candidate.display()
            );
            return Ok(2);
        }
    };
    let mut json = serde_json::to_string_pretty(&evidence)
        .map_err(|error| format!("failed to serialize {label}: {error}"))?;
    println!("{json}");

    if let Some(report_path) = report_path {
        json.push('\n');
        write_report(
            &report_path,
            json.as_bytes(),
            (&candidate, &candidate_file),
            None,
        )?;
    }

    Ok(0)
}
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OreansObservationBundle {
    schema_version: String,
    observations: Vec<OreansSampleObservation>,
}

fn cmd_oreans_two_sample_gate(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance oreans-two-sample-gate <observations.json> [--report PATH]"
                .into(),
        );
    }

    let mut observations_path: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --report".into());
                }
                report_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--report=") => {
                report_path = Some(PathBuf::from(&flag["--report=".len()..]));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if observations_path.is_some() {
                    return Err(format!("unexpected argument '{other}'"));
                }
                observations_path = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    let observations_path =
        observations_path.ok_or_else(|| "missing <observations.json> path".to_string())?;
    let (input_bytes, observations_file) = read_input(&observations_path, "observations bundle")?;
    let bundle: OreansObservationBundle =
        serde_json::from_slice(&input_bytes).map_err(|error| {
            format!(
                "invalid Oreans observations bundle JSON '{}': {error}",
                observations_path.display()
            )
        })?;
    if bundle.schema_version != OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION {
        return Err(format!(
            "invalid Oreans observations bundle schema_version '{}'; expected {}",
            bundle.schema_version, OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION
        ));
    }

    let report = match evaluate_oreans_two_sample_gate(&bundle.observations) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: Oreans two-sample gate input cannot form a report: {error}");
            return Ok(2);
        }
    };
    let mut json = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize Oreans two-sample gate report: {error}"))?;
    println!("{json}");

    if let Some(report_path) = report_path {
        json.push('\n');
        write_report_for_input(
            &report_path,
            json.as_bytes(),
            "observations bundle",
            (&observations_path, &observations_file),
        )?;
    }

    Ok(match report.final_verdict {
        OreansGateVerdict::Closed => 0,
        OreansGateVerdict::Open => 2,
    })
}

/// `mida-acceptance classify-gate-report <bundle_gate_report.json>`:
/// reproducible, read-only taxonomy classification of a v8 two-sample gate
/// report's per-sample failures.
///
/// The input report is never modified and must be named explicitly. The output
/// is a stable JSON document binding the input SHA-256 to the per-bucket counts
/// so an audit can reproduce the classification from the same bytes. It never
/// opens a real sample and never touches D:/MidaVault. Exit 0 on success, 1 on
/// I/O or schema error.
fn cmd_classify_gate_report(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance classify-gate-report <bundle_gate_report.json> [--report PATH]"
                .into(),
        );
    }
    let mut report_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --report".into());
                }
                report_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--report=") => {
                report_path = Some(PathBuf::from(&flag["--report=".len()..]));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if input_path.is_some() {
                    return Err(format!("unexpected argument '{other}'"));
                }
                input_path = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }
    let input_path =
        input_path.ok_or_else(|| "missing <bundle_gate_report.json> path".to_string())?;
    let (input_bytes, input_file) = read_input(&input_path, "gate report")?;
    let classification = mida_acceptance::failure_taxonomy::classify_gate_report(&input_bytes)
        .map_err(|error| format!("classify-gate-report: {error}"))?;
    let mut json = serde_json::to_string_pretty(&classification)
        .map_err(|error| format!("failed to serialize classification: {error}"))?;
    println!("{json}");

    if let Some(report_path) = report_path {
        json.push('\n');
        write_report_for_input(
            &report_path,
            json.as_bytes(),
            "gate report",
            (&input_path, &input_file),
        )?;
    }
    Ok(0)
}

fn cmd_check_static(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance check-static <candidate> [--expected-sha256 HEX]".into(),
        );
    }
    let mut candidate: Option<PathBuf> = None;
    let mut expected_sha256: Option<String> = None;
    let mut expected_size: Option<u64> = None;
    let mut role: Option<String> = None;
    let mut oracle: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--expected-sha256" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-sha256".into());
                }
                expected_sha256 = Some(args[i].clone());
            }
            flag if flag.starts_with("--expected-sha256=") => {
                expected_sha256 = Some(flag["--expected-sha256=".len()..].to_string());
            }
            "--expected-size" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-size".into());
                }
                expected_size = Some(parse_expected_size(&args[i])?);
            }
            flag if flag.starts_with("--expected-size=") => {
                expected_size = Some(parse_expected_size(&flag["--expected-size=".len()..])?);
            }
            "--role" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --role".into());
                }
                role = Some(args[i].clone());
            }
            flag if flag.starts_with("--role=") => {
                role = Some(flag["--role=".len()..].to_string());
            }
            "--oracle" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --oracle".into());
                }
                oracle = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--oracle=") => {
                oracle = Some(PathBuf::from(&flag["--oracle=".len()..]));
            }
            "--report" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --report".into());
                }
                report_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--report=") => {
                report_path = Some(PathBuf::from(&flag["--report=".len()..]));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if candidate.is_some() {
                    return Err(format!("unexpected argument '{other}'"));
                }
                candidate = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    let candidate = candidate.ok_or_else(|| "missing <candidate> path".to_string())?;
    let (bytes, candidate_file) = read_input(&candidate, "candidate")?;

    let (oracle_bytes, oracle_file) = match oracle.as_deref() {
        None => (None, None),
        Some(path) => {
            let (bytes, file) = read_input(path, "oracle")?;
            (Some(bytes), Some(file))
        }
    };

    let opts = CheckStaticOptions {
        role,
        expected_sha256,
        expected_size,
        oracle_bytes,
    };

    let report = check_static(&bytes, &opts);
    let json = report
        .to_json()
        .map_err(|e| format!("failed to serialize report: {e}"))?;

    // Always print report to stdout for piping; optional file copy.
    println!("{json}");
    if let Some(path) = report_path {
        // Trailing newline for text-file friendliness; body without path/timestamp.
        let mut file_body = json.clone();
        file_body.push('\n');
        write_report(
            &path,
            file_body.as_bytes(),
            (&candidate, &candidate_file),
            oracle.as_deref().zip(oracle_file.as_ref()),
        )?;
    }

    match report.verdict {
        Verdict::StructuralPassBehaviorPending => Ok(0),
        Verdict::Rejected => Ok(2),
        Verdict::Accepted => {
            // Contract violation if ever reached on static path.
            eprintln!("error: internal contract violation: Accepted verdict in check-static");
            Ok(1)
        }
    }
}

fn cmd_check_with_behavior(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance check-with-behavior <candidate> --behavior-evidence <path>"
                .into(),
        );
    }
    let mut candidate: Option<PathBuf> = None;
    let mut expected_sha256: Option<String> = None;
    let mut expected_size: Option<u64> = None;
    let mut role: Option<String> = None;
    let mut oracle: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut evidence_path: Option<PathBuf> = None;
    let mut allow_unmanaged = false;
    let mut allow_unsigned_managed = false;
    let mut allow_hmac_lab = false;
    let mut envelope_path: Option<PathBuf> = None;
    let mut envelope_key_id: Option<String> = None;
    let mut envelope_hmac_key_hex: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--allow-unmanaged-candidate" => {
                allow_unmanaged = true;
            }
            "--allow-unsigned-managed" => {
                allow_unsigned_managed = true;
            }
            "--allow-hmac-lab" => {
                allow_hmac_lab = true;
            }
            "--signature-envelope" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --signature-envelope".into());
                }
                envelope_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--signature-envelope=") => {
                envelope_path = Some(PathBuf::from(&flag["--signature-envelope=".len()..]));
            }
            "--envelope-key-id" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --envelope-key-id".into());
                }
                envelope_key_id = Some(args[i].clone());
            }
            flag if flag.starts_with("--envelope-key-id=") => {
                envelope_key_id = Some(flag["--envelope-key-id=".len()..].to_string());
            }
            "--envelope-hmac-key-hex" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --envelope-hmac-key-hex".into());
                }
                envelope_hmac_key_hex = Some(args[i].clone());
            }
            flag if flag.starts_with("--envelope-hmac-key-hex=") => {
                envelope_hmac_key_hex = Some(flag["--envelope-hmac-key-hex=".len()..].to_string());
            }
            "--expected-sha256" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-sha256".into());
                }
                expected_sha256 = Some(args[i].clone());
            }
            flag if flag.starts_with("--expected-sha256=") => {
                expected_sha256 = Some(flag["--expected-sha256=".len()..].to_string());
            }
            "--expected-size" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-size".into());
                }
                expected_size = Some(parse_expected_size(&args[i])?);
            }
            flag if flag.starts_with("--expected-size=") => {
                expected_size = Some(parse_expected_size(&flag["--expected-size=".len()..])?);
            }
            "--role" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --role".into());
                }
                role = Some(args[i].clone());
            }
            flag if flag.starts_with("--role=") => {
                role = Some(flag["--role=".len()..].to_string());
            }
            "--oracle" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --oracle".into());
                }
                oracle = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--oracle=") => {
                oracle = Some(PathBuf::from(&flag["--oracle=".len()..]));
            }
            "--behavior-evidence" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --behavior-evidence".into());
                }
                evidence_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--behavior-evidence=") => {
                evidence_path = Some(PathBuf::from(&flag["--behavior-evidence=".len()..]));
            }
            "--report" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --report".into());
                }
                report_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--report=") => {
                report_path = Some(PathBuf::from(&flag["--report=".len()..]));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if candidate.is_some() {
                    return Err(format!("unexpected argument '{other}'"));
                }
                candidate = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    let candidate = candidate.ok_or_else(|| "missing <candidate> path".to_string())?;
    let evidence_path =
        evidence_path.ok_or_else(|| "missing --behavior-evidence <path>".to_string())?;

    let (bytes, candidate_file) = read_input(&candidate, "candidate")?;
    let (ev_bytes, evidence_file) = read_input(&evidence_path, "behavior-evidence")?;
    let evidence = BehaviorEvidence::parse_json(&ev_bytes)
        .map_err(|e| format!("invalid behavior evidence: {e}"))?;

    // Fail-closed: sibling *.transform_manifest.json is required by default
    // (every dump should emit one, including empty ledger). Lab-only escape:
    // --allow-unmanaged-candidate.
    let manifest_path = {
        let mut p = candidate.clone();
        p.set_extension("transform_manifest.json");
        p
    };
    // Keep File handles for report alias protection (audit P1).
    let (manifest_bytes, manifest_file, managed) = if manifest_path.is_file() {
        let (mbytes, mfile) = read_input(&manifest_path, "transform_manifest")?;
        let managed = VerifiedManagedCandidate::verify(&bytes, &mbytes)
            .map_err(|e| format!("invalid/unbound transform_manifest: {e}"))?;
        (Some(mbytes), Some(mfile), Some(managed))
    } else if !allow_unmanaged {
        return Err(format!(
            "missing required sibling transform_manifest at '{}' \
             (dumps always emit one; pass --allow-unmanaged-candidate for lab inputs)",
            manifest_path.display()
        ));
    } else {
        (None, None, None)
    };

    // Signature envelope: explicit path, else sibling <stem>.signature_envelope.json.
    let resolved_envelope = envelope_path.or_else(|| {
        let mut p = candidate.clone();
        p.set_extension("signature_envelope.json");
        p.is_file().then_some(p)
    });

    let (oracle_bytes, oracle_file) = match oracle.as_deref() {
        None => (None, None),
        Some(path) => {
            let (b, file) = read_input(path, "oracle")?;
            (Some(b), Some(file))
        }
    };

    let opts = CheckStaticOptions {
        role,
        expected_sha256,
        expected_size,
        oracle_bytes,
    };

    // Product path:
    //   managed + verified envelope (non-caller trust root) → may Accept
    //   managed + HMAC envelope only with --allow-hmac-lab (lab; not product)
    //   managed without envelope → cap Pending unless --allow-unsigned-managed
    //   unmanaged → never Accept
    //
    // Note: `evidence` from CLI parse is used for *unsigned* paths only.
    // Signed path seals evidence from hashed JSON inside verify_bundle (audit P0).
    let mut envelope_file: Option<File> = None;
    let mut report = if let (Some(env_path), Some(man_bytes), Some(_)) = (
        resolved_envelope.as_ref(),
        manifest_bytes.as_ref(),
        managed.as_ref(),
    ) {
        let (env_bytes, env_file) = read_input(env_path, "signature-envelope")?;
        envelope_file = Some(env_file);
        let envelope = SignatureEnvelope::parse_json(&env_bytes)
            .map_err(|e| format!("invalid signature envelope: {e}"))?;

        // Product trust root is not implemented yet (Ed25519 reserved).
        // Caller-supplied HMAC is lab-only and requires an explicit flag so it
        // cannot be mistaken for product authenticity (audit P0).
        if !allow_hmac_lab {
            return Err(
                "signature envelope present, but product trust root is not configured. \
                 Ed25519 CI allowlist is not implemented yet. For lab HMAC only, pass \
                 --allow-hmac-lab with --envelope-key-id and --envelope-hmac-key-hex \
                 (or MIDA_ENVELOPE_KEY_ID / MIDA_ENVELOPE_HMAC_KEY_HEX). \
                 Without a trusted envelope, omit the envelope file and use \
                 --allow-unsigned-managed for lab Accepted."
                    .into(),
            );
        }

        let key_id = envelope_key_id
            .or_else(|| env::var("MIDA_ENVELOPE_KEY_ID").ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "--allow-hmac-lab requires --envelope-key-id / MIDA_ENVELOPE_KEY_ID".to_string()
            })?;
        let hmac_hex = envelope_hmac_key_hex
            .or_else(|| env::var("MIDA_ENVELOPE_HMAC_KEY_HEX").ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "--allow-hmac-lab requires --envelope-hmac-key-hex / MIDA_ENVELOPE_HMAC_KEY_HEX"
                    .to_string()
            })?;
        let key = hex_decode_key(&hmac_hex)?;
        let policy = EnvelopePolicy::hmac_lab_key(key_id.clone());
        let verifier = HmacSha256Verifier { key_id, key };
        let signed = envelope
            .verify_bundle(&bytes, man_bytes, &ev_bytes, &policy, &verifier)
            .map_err(|e| format!("signature envelope verification failed: {e}"))?;
        // Sealed evidence only — no external evidence parameter (audit P0).
        check_with_behavior_signed(&bytes, &opts, &signed)
    } else if let Some(ref managed) = managed {
        // Library managed is already Pending-capped; lab flag uses explicit lab API.
        if allow_unsigned_managed {
            check_with_behavior_managed_lab(&bytes, &opts, &evidence, managed)
        } else {
            check_with_behavior_managed(&bytes, &opts, &evidence, managed)
        }
    } else {
        check_with_behavior(&bytes, &opts, &evidence)
    };

    if report.verdict == Verdict::Accepted && allow_hmac_lab {
        report.warnings.push(mida_acceptance::WarningRecord {
            code: "hmac_lab_not_product_trust".to_string(),
            message: "Accepted via --allow-hmac-lab uses a caller-supplied HMAC trust root; \
                 this is lab diagnostic only, not product authenticity"
                .to_string(),
        });
        // P1/P2: an HMAC trust root is lab-only. `check_with_behavior_signed`
        // already labels the HMAC algorithm as Lab at the library level (it
        // never labels an HMAC envelope Product; only Ed25519 is Product and it
        // is not yet implemented). This defense-in-depth re-asserts Lab and
        // product_acceptable=false so the report and exit code never look like a
        // product acceptance through the HMAC lab path.
        report.trust_tier = mida_acceptance::TrustTier::Lab;
        report.product_acceptable = false;
    } else {
        // Recompute from whatever tier the library assigned.
        report.refresh_product_acceptable();
    }

    let json = report
        .to_json()
        .map_err(|e| format!("failed to serialize report: {e}"))?;

    println!("{json}");
    if let Some(path) = report_path {
        let mut file_body = json.clone();
        file_body.push('\n');
        write_report_with_extra(
            &path,
            file_body.as_bytes(),
            (&candidate, &candidate_file),
            oracle.as_deref().zip(oracle_file.as_ref()),
            Some((evidence_path.as_path(), &evidence_file)),
            manifest_file.as_ref().map(|f| (manifest_path.as_path(), f)),
            envelope_file
                .as_ref()
                .and_then(|f| resolved_envelope.as_ref().map(|p| (p.as_path(), f))),
        )?;
    }

    // P1 Lab/Product exit-code isolation. Exit 0 is reserved for PRODUCT
    // acceptance. A lab/unsigned `Accepted` (trust_tier != Product) returns a
    // distinct exit code (3) so a script reading only the exit code can never
    // mistake a lab diagnostic for a product acceptance. Rejected stays 2,
    // pending stays 0 (pending is not an accept).
    let exit = match report.verdict {
        Verdict::Accepted if report.trust_tier == mida_acceptance::TrustTier::Product => 0,
        Verdict::Accepted => 3, // lab / unsigned Accept → not product
        Verdict::Rejected => 2,
        Verdict::StructuralPassBehaviorPending => 0,
    };
    Ok(exit)
}

fn hex_decode_key(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.is_empty() || !t.len().is_multiple_of(2) || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("envelope HMAC key must be non-empty even-length hex".into());
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let b = t.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("invalid hex in envelope key".into()),
    }
}

fn parse_expected_sha256(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid --expected-sha256 value '{raw}' (expected 64 hexadecimal characters)"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_expected_size(raw: &str) -> Result<u64, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty --expected-size value".into());
    }
    t.parse::<u64>()
        .map_err(|_| format!("invalid --expected-size value '{raw}' (expected unsigned integer)"))
}

fn read_input(path: &Path, label: &str) -> Result<(Vec<u8>, File), String> {
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open {label} '{}': {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read {label} '{}': {e}", path.display()))?;
    Ok((bytes, file))
}

fn write_report(
    report_path: &Path,
    body: &[u8],
    candidate: (&Path, &File),
    oracle: Option<(&Path, &File)>,
) -> Result<(), String> {
    write_report_with_extra(report_path, body, candidate, oracle, None, None, None)
}

fn write_report_for_input(
    report_path: &Path,
    body: &[u8],
    input_label: &str,
    input: (&Path, &File),
) -> Result<(), String> {
    write_report_with_extra_label(
        report_path,
        body,
        input_label,
        input,
        None,
        None,
        None,
        None,
    )
}

/// Write report after rejecting alias against candidate, optional oracle,
/// behavior-evidence, transform_manifest, and signature envelope (audit P1).
fn write_report_with_extra(
    report_path: &Path,
    body: &[u8],
    candidate: (&Path, &File),
    oracle: Option<(&Path, &File)>,
    evidence: Option<(&Path, &File)>,
    manifest: Option<(&Path, &File)>,
    envelope: Option<(&Path, &File)>,
) -> Result<(), String> {
    write_report_with_extra_label(
        report_path,
        body,
        "candidate",
        candidate,
        oracle,
        evidence,
        manifest,
        envelope,
    )
}

fn write_report_with_extra_label(
    report_path: &Path,
    body: &[u8],
    input_label: &str,
    input: (&Path, &File),
    oracle: Option<(&Path, &File)>,
    evidence: Option<(&Path, &File)>,
    manifest: Option<(&Path, &File)>,
    envelope: Option<(&Path, &File)>,
) -> Result<(), String> {
    // Open without truncate so alias checks cannot damage an input file.
    let mut report_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(report_path)
        .map_err(|e| format!("failed to open report '{}': {e}", report_path.display()))?;
    let report_metadata = report_file
        .metadata()
        .map_err(|e| format!("failed to inspect report '{}': {e}", report_path.display()))?;

    reject_input_alias(
        report_path,
        &report_file,
        &report_metadata,
        input_label,
        input.0,
        input.1,
    )?;
    if let Some((oracle_path, oracle_file)) = oracle {
        reject_input_alias(
            report_path,
            &report_file,
            &report_metadata,
            "oracle",
            oracle_path,
            oracle_file,
        )?;
    }
    if let Some((evidence_path, evidence_file)) = evidence {
        reject_input_alias(
            report_path,
            &report_file,
            &report_metadata,
            "behavior-evidence",
            evidence_path,
            evidence_file,
        )?;
    }
    if let Some((manifest_path, manifest_file)) = manifest {
        reject_input_alias(
            report_path,
            &report_file,
            &report_metadata,
            "transform_manifest",
            manifest_path,
            manifest_file,
        )?;
    }
    if let Some((envelope_path, envelope_file)) = envelope {
        reject_input_alias(
            report_path,
            &report_file,
            &report_metadata,
            "signature-envelope",
            envelope_path,
            envelope_file,
        )?;
    }

    report_file
        .set_len(0)
        .and_then(|_| report_file.write_all(body))
        .map_err(|e| format!("failed to write report '{}': {e}", report_path.display()))
}

fn reject_input_alias(
    report_path: &Path,
    report_file: &File,
    report_metadata: &Metadata,
    input_label: &str,
    input_path: &Path,
    input_file: &File,
) -> Result<(), String> {
    let input_metadata = input_file.metadata().map_err(|e| {
        format!(
            "failed to inspect {input_label} '{}': {e}",
            input_path.display()
        )
    })?;

    let aliases =
        same_file(input_file, &input_metadata, report_file, report_metadata).map_err(|e| {
            format!(
                "failed to compare report '{}' with {input_label} '{}': {e}",
                report_path.display(),
                input_path.display()
            )
        })?;
    if aliases {
        return Err(format!(
            "report path '{}' aliases {input_label} '{}'; input files are protected from report writes",
            report_path.display(),
            input_path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(
    _left_file: &File,
    left: &Metadata,
    _right_file: &File,
    right: &Metadata,
) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_file(
    left_file: &File,
    _left: &Metadata,
    right_file: &File,
    _right: &Metadata,
) -> std::io::Result<bool> {
    Ok(windows_file_id(left_file)? == windows_file_id(right_file)?)
}

#[cfg(windows)]
fn windows_file_id(file: &File) -> std::io::Result<(u32, u64)> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = ByHandleFileInformation::default();
    // SAFETY: the raw handle remains owned by `file`, and `information` is a valid output buffer.
    let success = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file_index =
        (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
    Ok((information.volume_serial_number, file_index))
}

#[cfg(not(any(unix, windows)))]
fn same_file(
    _left_file: &File,
    _left: &Metadata,
    _right_file: &File,
    _right: &Metadata,
) -> std::io::Result<bool> {
    Ok(false)
}

/// Verifier-side copy of the `mida.runner-config-envelope/v4` emitted by the
/// runner (`mida-cli`). Deny-unknown-fields: any tampered or drifted field
/// fails closed. The acceptance crate stays dependency-free of production.
///
/// P6.3.3: configuration is case-bound — each case has its own config and
/// digest; `case_set_digest` seals the whole set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerConfigEnvelopeV4 {
    #[serde(rename = "$schema")]
    #[allow(dead_code)]
    schema: String,
    schema_version: String,
    cli_binary_sha256: String,
    tool_revision: String,
    verifier_source: String,
    verifier_path: String,
    verifier_sha256: String,
    case_set_digest: String,
    case_configs: Vec<CaseConfigEnvelopeV4>,
}

/// One case-bound config entry in the v4 envelope (verifier copy).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseConfigEnvelopeV4 {
    case_id: String,
    /// The packer family this case's run belongs to (staging-sealed; part of
    /// the case-set digest). The verifier checks it is a known family.
    family_id: String,
    protected_input: mida_acceptance::FileIdentity,
    /// Optional trusted protected-input path (G3-R3-R1): the immutable GTO lane
    /// seals its `snapshot.bin` path so launch can bind identity + path. Oreans
    /// fixed cases carry `None` (live-input lane). `default` keeps old-schema
    /// envelopes readable. Included in the recomputed case-set digest.
    #[serde(default)]
    protected_input_path: Option<String>,
    runner_config: serde_json::Value,
    runner_config_digest: String,
}

/// Worktree probe host: runs `git` in the repository root. Any probe failure
/// yields `clean_determined = false` (fail closed).
struct GitWorktreeProbe {
    repo_root: PathBuf,
}

impl mida_acceptance::WorktreeProbe for GitWorktreeProbe {
    fn probe(&self) -> mida_acceptance::WorktreeState {
        use std::process::Command;
        let head = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args(["rev-parse", "--verify", "HEAD"])
            .output();
        let status = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args(["status", "--porcelain"])
            .output();
        match (head, status) {
            (Ok(h), Ok(s)) if h.status.success() && s.status.success() => {
                mida_acceptance::WorktreeState {
                    head_revision: String::from_utf8_lossy(&h.stdout).trim().to_string(),
                    clean: s.stdout.is_empty(),
                    clean_determined: true,
                }
            }
            _ => mida_acceptance::WorktreeState {
                head_revision: String::new(),
                clean: false,
                clean_determined: false,
            },
        }
    }
}

/// `mida-acceptance preflight`: independent verifier of the runner-emitted
/// envelope. Reparses the envelope JSON with the acceptance `RunnerConfig`,
/// recomputes the digest with the acceptance canonical implementation, and
/// cross-checks it against the producer digest before running every offline
/// check. Writes `preflight.json` under the output dir.
///
/// Exit codes: 0 = Ready, 2 = NotReady, 1 = I/O or configuration error.
fn cmd_preflight(args: &[String]) -> Result<i32, String> {
    use std::path::{Path, PathBuf};

    let mut envelope_path: Option<PathBuf> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut snapshot_root: Option<PathBuf> = None;
    let mut cli_binary: Option<PathBuf> = None;
    let mut repo_root: Option<PathBuf> = None;
    let mut toolchain_pin: Option<PathBuf> = None;
    let mut expected_toolchain: Option<String> = None;
    let mut cases: Vec<(PathBuf, PathBuf, PathBuf)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let take = |i: &mut usize, label: &str| -> Result<PathBuf, String> {
            *i += 1;
            if *i >= args.len() {
                return Err(format!("Missing value after {label}."));
            }
            Ok(PathBuf::from(&args[*i]))
        };
        match arg.as_str() {
            "--envelope" => envelope_path = Some(take(&mut i, "--envelope")?),
            "--output-dir" => output_dir = Some(take(&mut i, "--output-dir")?),
            "--snapshot-root" => snapshot_root = Some(take(&mut i, "--snapshot-root")?),
            "--cli-binary" => cli_binary = Some(take(&mut i, "--cli-binary")?),
            "--repo-root" => repo_root = Some(take(&mut i, "--repo-root")?),
            "--toolchain-pin" => toolchain_pin = Some(take(&mut i, "--toolchain-pin")?),
            "--expected-toolchain" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value after --expected-toolchain.".into());
                }
                expected_toolchain = Some(args[i].clone());
            }
            "--case" => {
                let manifest = take(&mut i, "--case")?;
                let input = take(&mut i, "--case")?;
                let output = take(&mut i, "--case")?;
                cases.push((manifest, input, output));
            }
            other => return Err(format!("Unknown preflight option: {other}")),
        }
        i += 1;
    }

    let envelope_path = envelope_path.ok_or("Missing --envelope <path>.")?;
    let output_dir = output_dir.ok_or("Missing --output-dir <dir>.")?;
    let cli_binary = cli_binary.ok_or("Missing --cli-binary <path>.")?;
    let repo_root = repo_root.ok_or("Missing --repo-root <path>.")?;
    let toolchain_pin = toolchain_pin.ok_or("Missing --toolchain-pin <path>.")?;
    let expected_toolchain = expected_toolchain.ok_or("Missing --expected-toolchain <ver>.")?;
    // `--snapshot-root` is OPTIONAL and only required when a GTO case is present
    // (Oreans-only envelopes run the legacy live-input lane without it). A GTO
    // case without it fails closed per-case; the root is never guessed from the
    // sealed path, the actual input, or the output dir.

    let envelope_bytes = fs::read(&envelope_path)
        .map_err(|e| format!("cannot read envelope {}: {e}", envelope_path.display()))?;
    let envelope: RunnerConfigEnvelopeV4 =
        serde_json::from_slice(&envelope_bytes).map_err(|e| {
            format!(
                "envelope {} rejected (unknown/malformed fields): {e}",
                envelope_path.display()
            )
        })?;
    if envelope.schema_version != "mida.runner-config-envelope/v4" {
        return Err(format!(
            "envelope schema_version {:?} != mida.runner-config-envelope/v4 \
             (a v3 single-config envelope is refused; case-bound v4 required)",
            envelope.schema_version
        ));
    }
    // P6.3: `$schema` is part of the strict envelope identity — a drifted
    // schema reference is a config error on both the runner and verifier
    // sides.
    if envelope.schema != "./runner-config-envelope.schema.json" {
        return Err(format!(
            "envelope $schema {:?} != ./runner-config-envelope.schema.json",
            envelope.schema
        ));
    }
    if envelope.verifier_source != "<cli-dir>/mida-acceptance.exe" {
        return Err(format!(
            "envelope verifier_source {:?} != <cli-dir>/mida-acceptance.exe",
            envelope.verifier_source
        ));
    }
    if envelope.verifier_path.trim().is_empty() {
        return Err("envelope verifier_path must be non-empty".to_string());
    }
    if envelope.verifier_sha256.len() != 64
        || !envelope
            .verifier_sha256
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return Err("envelope verifier_sha256 must be exactly 64 hex chars".to_string());
    }
    if !is_64_hex(&envelope.case_set_digest) {
        return Err("envelope case_set_digest must be exactly 64 hex chars".to_string());
    }

    let mut reasons: Vec<String> = Vec::new();

    // P6.3.3.1: TRUE case_id-keyed validation. The verifier builds a unique
    // case_id -> envelope case map from the envelope (duplicate case_ids are
    // refused), then for EACH fixed case validates:
    //   - the envelope case's protected_input matches the manifest-declared
    //     identity (case_id <-> protected identity binding);
    //   - the per-case runner_config_digest recomputes from its own config;
    //   - the case_id belongs to the exact two fixed cases.
    // No array index is trusted; the case_set_digest is recomputed in a fixed
    // canonical order (origin_macro, lunlun_software).

    // 1. Envelope case set shape + unique case_id map.
    let mut envelope_by_case: std::collections::BTreeMap<String, &CaseConfigEnvelopeV4> =
        std::collections::BTreeMap::new();
    for case in &envelope.case_configs {
        if envelope_by_case.contains_key(&case.case_id) {
            reasons.push(format!(
                "envelope contains duplicate case_id {:?}; each case must appear exactly once",
                case.case_id
            ));
        } else {
            envelope_by_case.insert(case.case_id.clone(), case);
        }
    }
    for id in FIXED_CASE_IDS {
        if !envelope_by_case.contains_key(id) {
            reasons.push(format!("envelope is missing case config {id}"));
        }
    }
    // Any present case must be either an Oreans fixed case or the GTO lane.
    for case in &envelope.case_configs {
        if !FIXED_CASE_IDS.contains(&case.case_id.as_str()) && case.case_id != GTO_CASE_ID {
            reasons.push(format!(
                "envelope case {:?} is neither an Oreans fixed case nor the GTO lane case",
                case.case_id
            ));
        }
    }

    // 2. Per-case keyed validation: protected identity <-> case_id <-> digest.
    // P6.3.3.2: per-case digests are collected KEYED by case_id (never as an
    // index-aligned vector), so a reordered envelope `case_configs` or a
    // reordered `--case` vector cannot re-bind a digest to the wrong case.
    let mut case_config_digests: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for case in &envelope.case_configs {
        // Common shape (both lanes): family must be a known packer family, and
        // the protected-input identity must be well-formed.
        if case.family_id.trim().is_empty()
            || !mida_acceptance::is_known_packer_family(&case.family_id)
        {
            reasons.push(format!(
                "case {} family_id {:?} is not a known packer family (fail-closed)",
                case.case_id, case.family_id
            ));
        }
        if !is_64_hex(&case.protected_input.sha256) || case.protected_input.size_bytes == 0 {
            reasons.push(format!(
                "case {} protected_input identity is malformed",
                case.case_id
            ));
        }

        // G3-R3-R2 lane/path schema: the GTO lane MUST seal a non-empty immutable
        // protected-input path; Oreans fixed cases MUST carry None (live-input).
        if case.case_id == GTO_CASE_ID {
            if !mida_acceptance::is_generic_packer_family(&case.family_id) {
                reasons.push(format!(
                    "GTO lane case {} must carry a registered generic family (ahk_gto), \
                     got {:?} (fail-closed)",
                    case.case_id, case.family_id
                ));
            }
            match case.protected_input_path.as_deref() {
                Some(p) if !p.trim().is_empty() => {
                    // G3-R3-R2 content-addressed binding: the snapshot path must be
                    // a well-formed `<root>/gto_launcher/<sha256>/snapshot.bin`
                    // whose hash directory equals the sealed protected-input hash
                    // (case-normalized). This runs BEFORE any canonicalization so a
                    // raw `.`/`..` or absolute-path bypass is rejected.
                    match gto_snapshot_hash_dir(p) {
                        Ok(dir_hash) => {
                            if !dir_hash.eq_ignore_ascii_case(&case.protected_input.sha256) {
                                reasons.push(format!(
                                    "GTO case {} snapshot path hash dir {dir_hash:?} != \
                                     sealed protected_input sha {} (fail-closed)",
                                    case.case_id,
                                    case.protected_input.sha256.to_lowercase()
                                ));
                            }
                        }
                        Err(e) => {
                            reasons.push(format!(
                                "GTO case {} snapshot path rejected: {e}",
                                case.case_id
                            ));
                        }
                    }
                }
                _ => {
                    reasons.push(format!(
                        "GTO lane case {} must carry a non-empty protected_input_path \
                         (immutable snapshot) (fail-closed)",
                        case.case_id
                    ));
                }
            }
        } else if FIXED_CASE_IDS.contains(&case.case_id.as_str()) {
            if case.protected_input_path.is_some() {
                reasons.push(format!(
                    "Oreans fixed case {} must NOT carry a protected_input_path \
                     (live-input lane) (fail-closed)",
                    case.case_id
                ));
            }
            // Oreans-only: the manifest-declared protected identity for this
            // case_id must match the envelope's protected_input exactly.
            let locked = mida_acceptance::locked_manifest(&case.case_id);
            match locked {
                None => {
                    reasons.push(format!(
                        "envelope case {:?} is not one of the two fixed Oreans cases",
                        case.case_id
                    ));
                }
                Some(manifest) => {
                    if case.protected_input.sha256.to_lowercase()
                        != manifest.protected_input_sha256.to_lowercase()
                        || case.protected_input.size_bytes != manifest.protected_input_size_bytes
                    {
                        reasons.push(format!(
                            "case {} protected_input identity does not match the locked manifest \
                             (envelope {}/{} vs manifest {}/{})",
                            case.case_id,
                            case.protected_input.sha256.to_lowercase(),
                            case.protected_input.size_bytes,
                            manifest.protected_input_sha256.to_lowercase(),
                            manifest.protected_input_size_bytes,
                        ));
                    }
                }
            }
        }
        // Independent reparse + per-case digest recompute keyed by case_id. This
        // common block runs for BOTH the Oreans fixed lane and the GTO generic
        // no-gate lane — GTO must be validated exactly as strictly as Oreans
        // (P1 G3-R3-R2: no `continue` shortcut).
        let parsed: mida_acceptance::RunnerConfig =
            match serde_json::from_value(case.runner_config.clone()) {
                Ok(c) => c,
                Err(e) => {
                    reasons.push(format!("case {} runner config rejected: {e}", case.case_id));
                    continue;
                }
            };
        if !is_64_hex(&case.runner_config_digest) {
            reasons.push(format!(
                "case {} runner_config_digest must be exactly 64 hex chars",
                case.case_id
            ));
        }
        // G2-R1: the envelope's staging-sealed family must agree with the family
        // embedded in the per-case runner config. A mismatch fails closed.
        if parsed.packer_family != case.family_id {
            reasons.push(format!(
                "case {} runner-config packer_family {:?} != envelope family_id {:?} (fail-closed)",
                case.case_id, parsed.packer_family, case.family_id
            ));
        }
        let recomputed = mida_acceptance::runner_config_digest(&parsed);
        if recomputed != case.runner_config_digest.to_lowercase() {
            reasons.push(format!(
                "case {} runner-config digest drift: acceptance recomputed {recomputed}, \
                 producer emitted {}",
                case.case_id, case.runner_config_digest
            ));
        }
        if envelope.tool_revision != parsed.tool_revision {
            reasons.push(format!(
                "case {} tool_revision {:?} does not match runner config {:?}",
                case.case_id, envelope.tool_revision, parsed.tool_revision
            ));
        }
        case_config_digests.insert(
            case.case_id.clone(),
            case.runner_config_digest.to_lowercase(),
        );
    }

    // 3. Recompute the sealed case-set digest over EVERY envelope case config
    // (fixed canonical order applied by sorting, keyed by case_id) and
    // cross-check the envelope. This mirrors the CLI producer, which hashes
    // every case (Oreans fixed + optional GTO lane).
    {
        let mut entries: Vec<String> = Vec::with_capacity(envelope.case_configs.len());
        for case in &envelope.case_configs {
            // Mirror the CLI producer's canonical case entry EXACTLY, including
            // the optional sealed protected-input path lowercased (G3-R3-R2: the
            // CLI lowercases it, so the acceptance recompute must too, or a
            // mixed-case Windows path drifts the digest). Any divergence
            // (including a tampered path) breaks the digest cross-check.
            let path = case
                .protected_input_path
                .clone()
                .unwrap_or_default()
                .to_lowercase();
            entries.push(format!(
                "case={}\nfamily={}\nprotected_input={}|{}\nprotected_input_path={}\nrunner_config_digest={}\n",
                case.case_id,
                case.family_id.to_lowercase(),
                case.protected_input.sha256.to_lowercase(),
                case.protected_input.size_bytes,
                path,
                case.runner_config_digest.to_lowercase()
            ));
        }
        entries.sort();
        let recomputed_set = sha256_hex(entries.concat().as_bytes());
        if recomputed_set != envelope.case_set_digest.to_lowercase() {
            reasons.push(format!(
                "envelope case_set_digest drift: acceptance recomputed {recomputed_set}, \
                 producer emitted {}",
                envelope.case_set_digest
            ));
        }
    }

    // P6.3-G3-R3-R2-R1 / -R1: independently bind each GTO `--case` actual input
    // to the envelope's sealed `protected_input_path`, and enforce the
    // bidirectional case-set ↔ `--case` correspondence. The verifier refuses a
    // same-bytes different-path live source/alias by itself (canonical equality
    // + content-address structure), never relying on the CLI launch helper.
    // Oreans fixed cases keep their live-input lane and are not path-bound.
    //
    // Bidirectional correspondence (section 二): the envelope's case inventory
    // and the `--case` manifest inventory must match case-for-case (by case_id,
    // order-independent). Oreans fixed lane must contain origin_macro and
    // lunlun_software exactly once each; the optional GTO lane must be present
    // in the envelope IFF it is present in the `--case` inputs (and at most
    // once in each). Malformed/unreadable `--case` manifests fail closed.
    let mut envelope_case_inventory: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for c in &envelope.case_configs {
        *envelope_case_inventory
            .entry(c.case_id.clone())
            .or_insert(0) += 1;
    }
    let mut request_case_inventory: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (manifest, _input, _output) in &cases {
        match read_manifest_case_id(manifest) {
            Some(id) => *request_case_inventory.entry(id).or_insert(0) += 1,
            None => reasons.push(format!(
                "case manifest {} has an unreadable/malformed case_id; \
                 GTO binding must not be silently skipped (fail-closed)",
                manifest.display()
            )),
        }
    }
    // Oreans fixed lane: exactly once each (request side).
    for id in FIXED_CASE_IDS {
        if request_case_inventory.get(id).copied().unwrap_or(0) != 1 {
            reasons.push(format!(
                "--case must contain exactly one {id}, got {} (fail-closed)",
                request_case_inventory.get(id).copied().unwrap_or(0)
            ));
        }
        if envelope_case_inventory.get(id).copied().unwrap_or(0) != 1 {
            reasons.push(format!(
                "envelope must contain exactly one {id}, got {} (fail-closed)",
                envelope_case_inventory.get(id).copied().unwrap_or(0)
            ));
        }
    }
    // GTO lane bidirectional correspondence: present in envelope IFF present in
    // --case, exactly once in each.
    let env_gto_count = envelope_case_inventory
        .get(GTO_CASE_ID)
        .copied()
        .unwrap_or(0);
    let req_gto_count = request_case_inventory
        .get(GTO_CASE_ID)
        .copied()
        .unwrap_or(0);
    if env_gto_count != req_gto_count {
        reasons.push(format!(
            "GTO lane correspondence mismatch: envelope has {env_gto_count} \
             gto_launcher case(s), --case has {req_gto_count} (must match; fail-closed)"
        ));
    }
    if env_gto_count > 1 || req_gto_count > 1 {
        reasons.push(format!(
            "GTO lane must appear at most once per side: envelope {env_gto_count}, \
             --case {req_gto_count} (fail-closed)"
        ));
    }
    // Any unknown case_id in either inventory fails closed.
    for id in envelope_case_inventory
        .keys()
        .chain(request_case_inventory.keys())
    {
        if !FIXED_CASE_IDS.contains(&id.as_str()) && id != GTO_CASE_ID {
            reasons.push(format!(
                "case {id:?} is not a recognized lane case (fail-closed)"
            ));
        }
    }

    let mut gto_protected_input_path: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut gto_path_binding_failures: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (manifest, input, _output) in &cases {
        let case_id = read_manifest_case_id(manifest).unwrap_or_default();
        if case_id != GTO_CASE_ID {
            continue;
        }
        let env_gto = envelope
            .case_configs
            .iter()
            .find(|c| c.case_id == GTO_CASE_ID);
        let Some(env_gto) = env_gto else {
            // Envelope lacks the GTO case while `--case` provides one: record a
            // per-case binding failure (not a hard error) so the report is
            // produced with the correspondence reason and a GTO per-case failure.
            gto_path_binding_failures.insert(
                GTO_CASE_ID.to_string(),
                "envelope is missing the gto_launcher case".to_string(),
            );
            continue;
        };
        let Some(trusted_snapshot_root) = snapshot_root.as_deref() else {
            // A GTO case is present but `--snapshot-root` was not supplied:
            // fail-closed per-case (never guess the root from the sealed path,
            // actual input, or output dir).
            gto_path_binding_failures.insert(
                GTO_CASE_ID.to_string(),
                "GTO case present but --snapshot-root was not provided".to_string(),
            );
            continue;
        };
        match bind_gto_actual_input_to_sealed(input, env_gto, trusted_snapshot_root) {
            Ok(sealed) => {
                gto_protected_input_path.insert(GTO_CASE_ID.to_string(), sealed);
            }
            Err(e) => {
                // Per-case verdict failure: the GTO case itself is reported as
                // identity_ok=false with this reason, never a top-level-only note.
                gto_path_binding_failures.insert(GTO_CASE_ID.to_string(), e);
            }
        }
    }

    // The report's runner_config_digest is the sealed case-set digest; the
    // per-case digests flow into the report's cases. For the (legacy,
    // rejected) single-config path we keep a placeholder that can never pass
    // the v4 schema check.
    let probe = GitWorktreeProbe {
        repo_root: repo_root.clone(),
    };
    let borrowed: Vec<(&Path, &Path, &Path)> = cases
        .iter()
        .map(|(m, i, o)| (m.as_path(), i.as_path(), o.as_path()))
        .collect();
    let request = mida_acceptance::PreflightRequest {
        cases: borrowed,
        output_dir: &output_dir,
        cli_binary: Some(&cli_binary),
        expected_cli_sha256: &envelope.cli_binary_sha256,
        runner_config: &mida_acceptance::RunnerConfig::placeholder_for_preflight(
            &envelope.tool_revision,
            &envelope.cli_binary_sha256,
        ),
        worktree: &probe,
        output_probe: &mida_acceptance::FsOutputProbe,
        toolchain_pin_file: &toolchain_pin,
        expected_toolchain: &expected_toolchain,
        repo_root: &repo_root,
        case_config_digests,
        gto_protected_input_path,
        gto_path_binding_failures,
        case_set_digest: envelope.case_set_digest.clone(),
    };
    let mut report = mida_acceptance::run_offline_preflight(&request);
    if !reasons.is_empty() {
        report.reasons.extend(reasons);
        report.status = mida_acceptance::PreflightStatus::NotReady;
    }
    let destination = mida_acceptance::write_preflight_report(&output_dir, &report)
        .map_err(|e| format!("cannot write preflight report: {e}"))?;
    match report.status {
        mida_acceptance::PreflightStatus::Ready => {
            println!("preflight: READY ({})", destination.display());
            Ok(0)
        }
        mida_acceptance::PreflightStatus::NotReady => {
            eprintln!("preflight: NOT READY �� {}", report.reasons.join("; "));
            Ok(2)
        }
    }
}
