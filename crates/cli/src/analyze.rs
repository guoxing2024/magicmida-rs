//! `/analyze` — static packer analysis.
//!
//! This is the entry point for the capabilities that need no debugger and no
//! interactive desktop session, so unlike `/unpack` it works headless and in
//! CI.  It answers three questions:
//!
//! 1. **Which packer, and in which mode?**  With the evidence, so a wrong or
//!    surprising verdict is diagnosable rather than a bare `false`.
//! 2. **What is the static structure?**  Runtime section, packed sections,
//!    virtualised-function stubs, scrambled `.pdata`, relocated exception
//!    directory.
//! 3. **Where is the payload?**  And with `--extract`, write it out.
//!
//! ## Why `/analyze` exists separately from `/unpack`
//!
//! Before it, the only way to read this report was to run `/unpack` and read
//! the resulting error, because `/unpack`'s packer gate prints the report
//! before refusing.  A capability that can only be reached through a failure
//! is not one that can be documented or promised.

use std::path::Path;

use anyhow::{anyhow, Context};
use mida_packers_vmprotect::{
    analyze, detect, section_name, LargeResource, VmProtectReport,
};
use mida_pe::PeHeader;

use crate::log::{self, LogType};

/// Inputs for [`analyze_file`].
pub struct AnalyzeOptions<'a> {
    /// File to analyse.
    pub input: &'a Path,
    /// Directory to write extractable payloads into, when `Some`.
    pub extract_to: Option<&'a Path>,
}

/// Analyse `opts.input` and print the report; optionally extract payloads.
///
/// # Errors
///
/// Returns an error when the file cannot be read or parsed, when no packer is
/// recognised, or when `--extract` was requested but nothing in the file could
/// be extracted — the last one is a deliberate failure, because silently
/// writing no file would look like success.
pub fn analyze_file(opts: &AnalyzeOptions<'_>) -> Result<(), anyhow::Error> {
    let image = std::fs::read(opts.input)
        .with_context(|| format!("Failed to read {}", opts.input.display()))?;
    let pe = PeHeader::from_bytes(&image)
        .with_context(|| format!("Failed to parse PE header of {}", opts.input.display()))?;

    log::log(LogType::Info, &format!("File: {}", opts.input.display()));
    log::log(
        LogType::Info,
        &format!(
            "Architecture: {}, entry point {:#x}, {} sections, {} bytes",
            if pe.is_64bit { "x64" } else { "x86" },
            pe.entry_point,
            pe.sections.len(),
            image.len()
        ),
    );

    let Some(detection) = detect(&pe, &image) else {
        return analyze_themida_or_fail(&pe, opts);
    };

    log::log(LogType::Good, &format!("Packer: {}", detection.summary()));
    for line in detection.render_evidence() {
        log::log(LogType::Info, &format!("  {line}"));
    }

    let report = analyze(&pe, &image);
    // The report goes to stdout so it can be captured; the log lines above
    // carry the verdict and the evidence.
    print!("{report}");

    match opts.extract_to {
        Some(dir) => extract_payloads(opts.input, &image, &report, dir),
        None => Ok(()),
    }
}

/// `/analyze` answers for Themida too.
///
/// It must, otherwise a Themida sample comes back as "no recognised packer",
/// which is simply wrong — the first draft of this function did exactly that
/// against `D:\Projects\shiguang\时光一键宏.exe`.  The static report is
/// VMProtect-shaped, so for Themida this prints the section inventory and
/// points at the pipeline that can actually unpack it.
fn analyze_themida_or_fail(pe: &PeHeader, opts: &AnalyzeOptions<'_>) -> Result<(), anyhow::Error> {
    let mut sections: Vec<&str> = Vec::new();
    for section in pe.sections.iter() {
        if mida_packers_themida::is_themida_section(section) {
            sections.push(section_name(section));
        }
    }

    if sections.is_empty() {
        return Err(anyhow!(
            "no recognised packer for {} — this build recognises Themida \
             (`.winlice`/`.boot`/`.themida`) and VMProtect; the file is neither",
            opts.input.display()
        ));
    }

    log::log(LogType::Good, "Packer: Themida");
    log::log(
        LogType::Info,
        &format!("  Themida sections: {}", sections.join(", ")),
    );
    println!("Themida");
    println!("  Themida sections    {}", sections.join(", "));
    println!("  next                /unpack {}", opts.input.display());

    if opts.extract_to.is_some() {
        return Err(anyhow!(
            "--extract only applies to a payload that lives in the file; \
             Themida's code does not — use /unpack {}",
            opts.input.display()
        ));
    }
    Ok(())
}

/// Write every payload that is actually present in the file.
///
/// `Packed` samples carry their payload only in memory, so this reports that
/// nothing could be extracted and fails, naming the reason — see
/// `mida_packers_vmprotect::VmProtectReport::requires_runtime_dump`.
fn extract_payloads(
    input: &Path,
    image: &[u8],
    report: &VmProtectReport,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create extraction directory {}", dir.display()))?;

    let mut written = 0usize;
    let mut skipped: Vec<String> = Vec::new();

    for resource in &report.large_resources {
        match resource.bytes(image) {
            Some(bytes) => {
                let path = dir.join(payload_file_name(input, resource));
                std::fs::write(&path, bytes)
                    .with_context(|| format!("Failed to write {}", path.display()))?;
                log::log(
                    LogType::Good,
                    &format!(
                        "Extracted {} B to {} (sha256 {})",
                        bytes.len(),
                        path.display(),
                        resource.sha256.as_deref().unwrap_or("unavailable")
                    ),
                );
                written += 1;
            }
            None => {
                skipped.push(format!(
                    "resource {} ({} B) is not in the file — only {} B of it are present",
                    describe(resource),
                    resource.size,
                    resource.bytes_in_file
                ));
            }
        }
    }

    if written == 0 {
        let detail = if skipped.is_empty() {
            "no resource of 1 MiB or more was found".to_string()
        } else {
            skipped.join("; ")
        };
        let why = if report.requires_runtime_dump() {
            format!(
                "{} — this mode reconstructs the image at runtime, so use \
                 /dump-process <pid> against a running instance instead",
                detail
            )
        } else {
            detail
        };
        return Err(anyhow!("nothing to extract: {why}"));
    }
    Ok(())
}

/// `stem.rcdata<id>.<ext>` — the resource id makes the name stable, and the
/// extension follows what the bytes actually are rather than the resource
/// type (both measured payloads are `RT_RCDATA` but one is a PE image).
fn payload_file_name(input: &Path, resource: &LargeResource) -> String {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "payload".to_string());
    let id = match (resource.name_id, &resource.name) {
        (Some(id), _) => id.to_string(),
        (None, Some(name)) => name.clone(),
        (None, None) => "unknown".to_string(),
    };
    let ext = if resource.looks_like_pe { "exe" } else { "bin" };
    format!("{stem}.rcdata{id}.{ext}")
}

fn describe(resource: &LargeResource) -> String {
    match (resource.type_id, resource.name_id) {
        (Some(t), Some(id)) => format!("type {t} id {id}"),
        (Some(t), None) => format!("type {t}"),
        _ => "resource".to_string(),
    }
}