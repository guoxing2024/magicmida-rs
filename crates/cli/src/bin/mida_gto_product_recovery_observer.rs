//! Memory-state-epoch external observer for GTO-PRODUCT-RECOVERY Route A.
//!
//! Strict scope (per `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md` §1):
//! - External observer (separate process), no DLL injection, no in-process hook.
//! - Read-only `ReadProcessMemory` + `VirtualQueryEx` polling.
//! - No DRx, no VEH, no `GetThreadContext` debug-register fetch.
//! - No `bwhook` / `gto_host` / `_r1b_transient_epoch_trap` modification.
//! - Env default: `MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` absent.
//!
//! Build: `cargo build --release -p mida-cli --bin mida_gto_product_recovery_observer`
//! Run:   `mida_gto_product_recovery_observer --spawn <path-to-gto_protected.exe> --out-dir <dir>`

#![allow(clippy::needless_range_loop)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, STARTUPINFOW,
};

// ---------------------------------------------------------------------------
// CLI arg parsing
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Args {
    spawn: Option<PathBuf>,
    target_pid: Option<u32>,
    observation_window_ms: u32,
    poll_period_ms: u32,
    out_dir: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut spawn: Option<PathBuf> = None;
    let mut target_pid: Option<u32> = None;
    let mut observation_window_ms: u32 = 60_000;
    let mut poll_period_ms: u32 = 20;
    let mut out_dir: Option<PathBuf> = None;

    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--spawn" => {
                spawn = Some(PathBuf::from(
                    it.next().ok_or("--spawn requires path")?,
                ));
            }
            "--target-pid" => {
                target_pid = Some(
                    it.next()
                        .ok_or("--target-pid requires pid")?
                        .parse::<u32>()
                        .map_err(|e| format!("bad --target-pid: {e}"))?,
                );
            }
            "--observation-window-ms" => {
                observation_window_ms = it
                    .next()
                    .ok_or("--observation-window-ms requires value")?
                    .parse::<u32>()
                    .map_err(|e| format!("bad --observation-window-ms: {e}"))?;
            }
            "--poll-period-ms" => {
                poll_period_ms = it
                    .next()
                    .ok_or("--poll-period-ms requires value")?
                    .parse::<u32>()
                    .map_err(|e| format!("bad --poll-period-ms: {e}"))?;
            }
            "--out-dir" => {
                out_dir = Some(PathBuf::from(
                    it.next().ok_or("--out-dir requires path")?,
                ));
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }

    if spawn.is_none() && target_pid.is_none() {
        return Err("must provide either --spawn <path> or --target-pid <pid>".into());
    }
    let out_dir = out_dir.ok_or("--out-dir is required")?;
    Ok(Args {
        spawn,
        target_pid,
        observation_window_ms,
        poll_period_ms,
        out_dir,
    })
}

fn print_help() {
    eprintln!(
        "mida_gto_product_recovery_observer — Route A memory-state-epoch observer\n\
         \n\
         USAGE:\n  \
         mida_gto_product_recovery_observer --spawn <path> --out-dir <dir>\n\
                                  [--observation-window-ms <u32>] [--poll-period-ms <u32>]\n\
         mida_gto_product_recovery_observer --target-pid <pid> --out-dir <dir>\n\
                                  [--observation-window-ms <u32>] [--poll-period-ms <u32>]\n\
         \n\
         SCOPE: read-only external observer; no DRx, no VEH, no debug-register fetch."
    );
}

// ---------------------------------------------------------------------------
// Region snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RegionSnap {
    base: u64,
    size: usize,
    protect: u32,
    state: u32,
    #[serde(rename = "type")]
    ty: u32,
    checksum_lo: u64,
    checksum_hi: u64,
    is_boot_named: bool,
    is_pe_image: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct NamedObservation {
    name: String,
    first_tick: u32,
    count: u32,
    evidence_binding: String,
    sample_base: u64,
    sample_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProtectionTransition {
    base: u64,
    from_protect: u32,
    to_protect: u32,
    tick: u32,
    region_was_boot_named: bool,
}

// ---------------------------------------------------------------------------
// Outcome JSON schema
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct Outcome {
    run_id: String,
    route: String,
    method_class: String,
    bypass_used: bool,
    semantic_repair_used: bool,
    target_sample: String,
    target_pid: u32,
    target_image_path: String,
    observation_window_ms: u32,
    poll_period_ms: u32,
    tick_count: u32,
    observed_regions: Vec<RegionSnap>,
    vm_owned_region_candidates: Vec<RegionSnap>,
    boot_region_candidates: Vec<RegionSnap>,
    allocation_epoch: Vec<NamedObservation>,
    protection_transitions: Vec<ProtectionTransition>,
    named_observations: Vec<NamedObservation>,
    failure_class: String,
    source_commit: String,
    artifact_hashes: ArtifactHashes,
    rsp_source: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArtifactHashes {
    binary_sha256: String,
    manifest_sha256: String,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Protect helpers
// ---------------------------------------------------------------------------

fn is_writable(p: u32) -> bool {
    matches!(
        p,
        x if x == PAGE_READWRITE.0
            || x == PAGE_EXECUTE_READWRITE.0
            || x == PAGE_EXECUTE_WRITECOPY.0
            || x == PAGE_WRITECOPY.0
    )
}

fn is_executable(p: u32) -> bool {
    matches!(
        p,
        x if x == PAGE_EXECUTE_READ.0
            || x == PAGE_EXECUTE_READWRITE.0
            || x == PAGE_EXECUTE_WRITECOPY.0
    )
}

fn is_rwx(p: u32) -> bool {
    p == PAGE_EXECUTE_READWRITE.0
}

fn is_no_access(p: u32) -> bool {
    p == PAGE_NOACCESS.0
}

// ---------------------------------------------------------------------------
// Polling loop
// ---------------------------------------------------------------------------

fn poll_loop(
    pid: u32,
    window_ms: u32,
    period_ms: u32,
    image_path: String,
) -> Result<(Vec<RegionSnap>, Vec<ProtectionTransition>, u32, Vec<RegionSnap>, Vec<RegionSnap>), String> {
    // Acquire process handle. VirtualQueryEx requires PROCESS_QUERY_INFORMATION;
    // ReadProcessMemory requires PROCESS_VM_READ. Combine both.
    let hprocess: HANDLE = unsafe {
        let ok = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        match ok {
            Ok(h) => h,
            Err(e) => return Err(format!("OpenProcess failed: {e:?}")),
        }
    };

    // Enumerate modules to learn which region is .boot-named.
    let modules = enumerate_modules(pid).unwrap_or_default();
    let mut module_ranges: Vec<(u64, u64, String)> = Vec::new();
    for m in &modules {
        let base = m.modBaseAddr as u64;
        let size = m.modBaseSize as u64;
        let name = String::from_utf16_lossy(&m.szModule).to_lowercase();
        module_ranges.push((base, base.saturating_add(size), name));
    }

    let deadline = Instant::now() + Duration::from_millis(window_ms as u64);
    let mut tick: u32 = 0;
    let mut prev_regions: BTreeMap<u64, RegionSnap> = BTreeMap::new();
    let mut latest_regions: Vec<RegionSnap> = Vec::new();
    let mut latest_vm_owned: Vec<RegionSnap> = Vec::new();
    let mut latest_boot: Vec<RegionSnap> = Vec::new();
    let mut transitions: Vec<ProtectionTransition> = Vec::new();

    loop {
        if Instant::now() >= deadline {
            break;
        }
        tick = tick.saturating_add(1);

        let mut current: BTreeMap<u64, RegionSnap> = BTreeMap::new();
        let mut addr: u64 = 0;
        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let cb = std::mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32;
            let written = unsafe {
                VirtualQueryEx(
                    hprocess,
                    Some(addr as *const std::ffi::c_void),
                    &mut mbi,
                    cb as usize,
                )
            };
            if written == 0 {
                break;
            }
            let base = mbi.BaseAddress as u64;
            let size = mbi.RegionSize;
            let protect = mbi.Protect.0;
            let state = mbi.State.0;
            let ty = mbi.Type.0;

            let mut snap = RegionSnap {
                base,
                size,
                protect,
                state,
                ty,
                checksum_lo: 0,
                checksum_hi: 0,
                is_boot_named: false,
                is_pe_image: false,
            };

            // Best-effort 4 KiB content checksum (only for committed, with read rights).
            if state == MEM_COMMIT.0 && !is_no_access(protect) && size > 0 {
                let mut buf = vec![0u8; 4096.min(size)];
                let mut hasher = Sha256::new();
                let mut bytes_read: usize = 0;
                unsafe {
                    let ok = ReadProcessMemory(
                        hprocess,
                        base as *const std::ffi::c_void,
                        buf.as_mut_ptr() as *mut std::ffi::c_void,
                        buf.len(),
                        Some(&mut bytes_read),
                    );
                    if ok.is_ok() && bytes_read > 0 {
                        hasher.update(&buf[..bytes_read]);
                    }
                }
                let digest = hasher.finalize();
                snap.checksum_lo = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0; 8]));
                snap.checksum_hi = u64::from_le_bytes(digest[8..16].try_into().unwrap_or([0; 8]));
            }

            // Module-name lookup: which module does this region belong to?
            for (lo, hi, name) in &module_ranges {
                if base >= *lo && base < *hi {
                    if name.contains(".boot") || name.contains("boot") {
                        snap.is_boot_named = true;
                    } else if !name.is_empty() {
                        snap.is_pe_image = true;
                    }
                    break;
                }
            }

            // Heuristic for VM-owned: private committed region, large, RWX or RX.
            let is_vm_owned = !snap.is_pe_image
                && ty == windows::Win32::System::Memory::MEM_PRIVATE.0
                && state == MEM_COMMIT.0
                && (is_rwx(protect) || is_executable(protect))
                && size > 0x1000;

            current.insert(base, snap.clone());

// Compute transitions vs prev.
            let boot_named_now = snap.is_boot_named;
            let vm_owned_now = is_vm_owned;
            if let Some(prev) = prev_regions.get(&base) {
                if prev.protect != protect && is_writable(protect) {
                    let was_boot_named = prev.is_boot_named || boot_named_now;
                    transitions.push(ProtectionTransition {
                        base,
                        from_protect: prev.protect,
                        to_protect: protect,
                        tick,
                        region_was_boot_named: was_boot_named,
                    });
                }
            }

            // Push to accumulators (after transition check).
            if boot_named_now {
                latest_boot.push(snap.clone());
            }
            if vm_owned_now {
                latest_vm_owned.push(snap.clone());
            }
            latest_regions.push(snap);

            // Advance.
            let next = (base as usize).saturating_add(size);
            if next == 0 || next as u64 <= base {
                break;
            }
            addr = next as u64;
            if addr > 0x7fff_ffff_ffff {
                break;
            }
        }

        prev_regions = current;
        std::thread::sleep(Duration::from_millis(period_ms as u64));
    }

    unsafe {
        let _ = CloseHandle(hprocess);
    }

    Ok((latest_regions, transitions, tick, latest_vm_owned, latest_boot))
}

#[derive(Debug)]
#[repr(C)]
struct ModuleEntry32W {
    modBaseAddr: *mut u8,
    modBaseSize: u32,
    szModule: [u16; 256],
}
unsafe impl Sync for ModuleEntry32W {}
unsafe impl Send for ModuleEntry32W {}

fn enumerate_modules(pid: u32) -> Result<Vec<MODULEENTRY32W>, String> {
    let snap = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    };
    let snap = match snap {
        Ok(s) => s,
        Err(e) => return Err(format!("CreateToolhelp32Snapshot failed: {e:?}")),
    };
    let mut entries: Vec<MODULEENTRY32W> = Vec::new();
    unsafe {
        let mut me: MODULEENTRY32W = std::mem::zeroed();
        me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap, &mut me).is_ok() {
            loop {
                entries.push(me);
                me = std::mem::zeroed();
                me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
                if Module32NextW(snap, &mut me).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Spawn helper
// ---------------------------------------------------------------------------

fn spawn_target(path: &Path) -> Result<(u32, String), String> {
    use std::os::windows::ffi::OsStrExt;
    let path_w: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    unsafe {
        let ok = CreateProcessW(
            windows::core::PCWSTR(path_w.as_ptr()),
            windows::core::PWSTR::null(),
            None,
            None,
            false,
            windows::Win32::System::Threading::CREATE_SUSPENDED,
            None,
            windows::core::PCWSTR::null(),
            &si,
            &mut pi,
        );
        match ok {
            Ok(_) => {}
            Err(e) => return Err(format!("CreateProcessW failed: {e:?}")),
        }
        // ResumeThread.
        let _ = ResumeThread(pi.hThread);
        let _ = CloseHandle(pi.hThread);
        let pid = pi.dwProcessId;
        let _ = CloseHandle(pi.hProcess);
        Ok((pid, path.to_string_lossy().to_string()))
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn git_head() -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let data = fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    let mut h = Sha256::new();
    h.update(&data);
    let digest = h.finalize();
    Ok(hex_lower(&digest))
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[observer] arg error: {e}");
            eprintln!("[observer] run with --help for usage");
            std::process::exit(2);
        }
    };

    fs::create_dir_all(&args.out_dir).ok();

    let mut failure_class = "none".to_string();
    let mut target_pid = args.target_pid.unwrap_or(0);
    let mut image_path = String::from("");

    if let Some(p) = &args.spawn {
        if !p.exists() {
            eprintln!("[observer] spawn target missing: {}", p.display());
            std::process::exit(3);
        }
        match spawn_target(p) {
            Ok((pid, path)) => {
                target_pid = pid;
                image_path = path;
            }
            Err(e) => {
                eprintln!("[observer] spawn failed: {e}");
                std::process::exit(4);
            }
        }
    } else if let Some(pid) = args.target_pid {
        target_pid = pid;
        image_path = format!("<attached pid={pid}>");
    }

    eprintln!(
        "[observer] pid={target_pid} window_ms={} period_ms={} out_dir={}",
        args.observation_window_ms,
        args.poll_period_ms,
        args.out_dir.display()
    );

    let (latest_regions, transitions, tick_count, vm_owned, boot) =
        match poll_loop(target_pid, args.observation_window_ms, args.poll_period_ms, image_path.clone()) {
            Ok(v) => v,
            Err(e) => {
                failure_class = e;
                (
                    Vec::new(),
                    Vec::new(),
                    0u32,
                    Vec::new(),
                    Vec::new(),
                )
            }
        };

    // Build named observations from raw data.
    let mut named: Vec<NamedObservation> = Vec::new();

    // 1) boot_section_first_committed
    if !boot.is_empty() {
        let s = &boot[0];
        named.push(NamedObservation {
            name: "boot_section_first_committed".into(),
            first_tick: 0,
            count: boot.len() as u32,
            evidence_binding: ".boot-named region observed in MEM_COMMIT".into(),
            sample_base: s.base,
            sample_size: s.size as u64,
        });
    }
    // 2) vm_protection_transition
    if !transitions.is_empty() {
        let first = &transitions[0];
        named.push(NamedObservation {
            name: "vm_protection_transition".into(),
            first_tick: first.tick,
            count: transitions.len() as u32,
            evidence_binding: if first.region_was_boot_named {
                ".boot region protection change"
            } else {
                "MEM_PRIVATE committed region protection change"
            }
            .into(),
            sample_base: first.base,
            sample_size: 0,
        });
    }
    // 3) vm_owned_region_write_storm — heuristic: VM-owned region with RWX protect.
    let rwx_count = vm_owned
        .iter()
        .filter(|r| is_rwx(r.protect))
        .count() as u32;
    if rwx_count > 0 {
        let s = vm_owned.iter().find(|r| is_rwx(r.protect)).unwrap();
        named.push(NamedObservation {
            name: "vm_owned_region_write_storm".into(),
            first_tick: 0,
            count: rwx_count,
            evidence_binding: "MEM_PRIVATE RWX region (VM-bytecode container candidate)".into(),
            sample_base: s.base,
            sample_size: s.size as u64,
        });
    }

    // 4) vm_codegen_region_expand
    let mut sizes_seen: BTreeMap<u64, usize> = BTreeMap::new();
    for r in &latest_regions {
        sizes_seen.insert(r.base, r.size);
    }
    // We don't track per-base growth across ticks in this minimal pass; emit only if any region
    // exhibits > 1 MiB and is VM-owned.
    let expand_count = vm_owned.iter().filter(|r| r.size > 0x100000).count() as u32;
    if expand_count > 0 {
        let s = vm_owned.iter().find(|r| r.size > 0x100000).unwrap();
        named.push(NamedObservation {
            name: "vm_codegen_region_expand".into(),
            first_tick: 0,
            count: expand_count,
            evidence_binding: "MEM_PRIVATE RWX region > 1 MiB (codegen candidate)".into(),
            sample_base: s.base,
            sample_size: s.size as u64,
        });
    }

    // 5) vm_allocation_anchor — regions at base >= image_base + 0x10000000
    // We don't know image_base here; skip in this pass (named[0] may still bind).

    let outcome = Outcome {
        run_id: uuid_like(&args.out_dir),
        route: "GTO-PRODUCT-RECOVERY/RouteA".into(),
        method_class: "memory-state-epoch external observer".into(),
        bypass_used: false,
        semantic_repair_used: false,
        target_sample: "gto_launcher".into(),
        target_pid,
        target_image_path: image_path.clone(),
        observation_window_ms: args.observation_window_ms,
        poll_period_ms: args.poll_period_ms,
        tick_count,
        observed_regions: latest_regions,
        vm_owned_region_candidates: vm_owned,
        boot_region_candidates: boot,
        allocation_epoch: Vec::new(),
        protection_transitions: transitions,
        named_observations: named,
        failure_class,
        source_commit: git_head(),
        artifact_hashes: ArtifactHashes {
            binary_sha256: sha256_file(&Path::new(&image_path))
                .unwrap_or_else(|_| "<unreadable>".into()),
            manifest_sha256: "TBD".into(),
        },
        rsp_source: "external-observer".into(),
    };

    let outcome_path = args.out_dir.join("outcomes.json");
    let json = match serde_json::to_string_pretty(&outcome) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[observer] serialize failed: {e}");
            std::process::exit(5);
        }
    };
    if let Err(e) = fs::write(&outcome_path, &json) {
        eprintln!("[observer] write failed: {e}");
        std::process::exit(6);
    }

    // Compute manifest sha256 and patch the JSON.
    let manifest_hash = sha256_file(&outcome_path).unwrap_or_else(|_| "err".into());
    let mut patched: Outcome = serde_json::from_str(&json).unwrap_or(outcome);
    patched.artifact_hashes.manifest_sha256 = manifest_hash;
    let json2 = serde_json::to_string_pretty(&patched).unwrap_or(json);
    let _ = fs::write(&outcome_path, &json2);

    // Sidecar log.
    let log_path = args.out_dir.join("observer.log");
    let log_body = format!(
        "[observer] finished at unix_ms={} tick_count={} named_count={} manifest_sha256={}\n",
        now_unix_ms(),
        tick_count,
        patched.named_observations.len(),
        patched.artifact_hashes.manifest_sha256
    );
    let _ = fs::write(log_path, log_body);

    eprintln!(
        "[observer] done. outcomes={} manifest_sha256={} named={}",
        outcome_path.display(),
        patched.artifact_hashes.manifest_sha256,
        patched.named_observations.len()
    );
}

fn uuid_like(out_dir: &Path) -> String {
    let ms = now_unix_ms();
    let pid = std::process::id();
    let tag = out_dir
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "obs".into());
    format!("mtr_acq_observe_{tag}_{ms}_{pid}")
}