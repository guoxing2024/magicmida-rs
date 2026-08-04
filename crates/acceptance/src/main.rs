//! Read-only CLI for the independent acceptance kernel.
//!
//! ```text
//! mida-acceptance check-static <candidate> [options]
//! mida-acceptance check-with-behavior <candidate> --behavior-evidence <json> [options]
//! mida-acceptance oreans-pe-evidence <candidate> [options]
//! mida-acceptance oreans-two-sample-gate <observations.json> [options]
//! ```
//!
//! Exit codes: 0 = StructuralPassBehaviorPending, Accepted, successful Oreans PE
//! evidence, or a closed two-sample gate; 2 = Rejected, an open gate, or an
//! Oreans validation failure; 1 = I/O or config error.
//! Report writes never alias candidate, oracle, or evidence inputs.

use std::env;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use mida_acceptance::oreans_gate::OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION;
use mida_acceptance::{
    build_oreans_pe_evidence, check_static, check_with_behavior, check_with_behavior_managed,
    check_with_behavior_managed_lab, check_with_behavior_signed, evaluate_oreans_two_sample_gate,
    BehaviorEvidence, CheckStaticOptions, EnvelopePolicy, HmacSha256Verifier, OreansGateVerdict,
    OreansSampleObservation, SignatureEnvelope, Verdict, VerifiedManagedCandidate,
};

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
        "oreans-two-sample-gate" => {
            args.remove(0);
            cmd_oreans_two_sample_gate(&args)
        }
        other => Err(format!(
            "unknown command '{other}'. Use: check-static | check-with-behavior | oreans-pe-evidence | oreans-two-sample-gate"
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
  mida-acceptance oreans-two-sample-gate <observations.json> [options]

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
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance oreans-pe-evidence <candidate> [--expected-sha256 HEX] [--expected-size BYTES] [--report PATH]".into(),
        );
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

    let evidence = match build_oreans_pe_evidence(&bytes) {
        Ok(evidence) => evidence,
        Err(error) => {
            eprintln!(
                "error: Oreans PE evidence construction failed for '{}': {error}",
                candidate.display()
            );
            return Ok(2);
        }
    };
    let mut json = serde_json::to_string_pretty(&evidence)
        .map_err(|error| format!("failed to serialize Oreans PE evidence: {error}"))?;
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
    let mut report = if let (Some(ref env_path), Some(ref man_bytes), Some(_)) = (
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

    Ok(report.verdict.exit_code())
}

fn hex_decode_key(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.is_empty() || t.len() % 2 != 0 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
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
