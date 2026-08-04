//! Memory-state-epoch external observer for GTO-PRODUCT-RECOVERY Route A.
//!
//! Strict scope (R1 plan + R2 authorization 2026-07-30):
//! - External observer (separate process), no DLL injection, no in-process hook.
//! - Read-only `ReadProcessMemory` + `VirtualQueryEx` polling.
//! - No DRx, no VEH, no `GetThreadContext` debug-register fetch.
//! - No `bwhook` / `gto_host` / `_r1b_transient_epoch_trap` modification.
//! - Env default: `MIDA_GTO_NO_BYPASS=1`, `MIDA_GTO_BYPASS` absent.
//! - R2: strengthen identity of stable executable private >1 MiB candidates
//!   (first/last tick, multi-page fingerprint, neighborhood). Expansion is NOT
//!   claimed; protect=32 is PAGE_EXECUTE_READ, not necessarily RWX.
//!
//! Build: `cargo build -p mida-cli --bin mida_gto_product_recovery_observer`
//! Run:   `mida_gto_product_recovery_observer --spawn <path> --out-dir <dir>`

#![allow(clippy::needless_range_loop)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, ResumeThread, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ, STARTUPINFOW,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Args {
    spawn: Option<PathBuf>,
    target_pid: Option<u32>,
    observation_window_ms: u32,
    poll_period_ms: u32,
    out_dir: PathBuf,
    round: String,
}

fn parse_args() -> Result<Args, String> {
    let mut spawn: Option<PathBuf> = None;
    let mut target_pid: Option<u32> = None;
    let mut observation_window_ms: u32 = 60_000;
    let mut poll_period_ms: u32 = 20;
    let mut out_dir: Option<PathBuf> = None;
    let mut round: String = "R2".into();

    let mut it = env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--spawn" => {
                spawn = Some(PathBuf::from(it.next().ok_or("--spawn requires path")?));
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
                out_dir = Some(PathBuf::from(it.next().ok_or("--out-dir requires path")?));
            }
            "--round" => {
                round = it.next().ok_or("--round requires value")?;
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
        round,
    })
}

fn print_help() {
    eprintln!(
        "mida_gto_product_recovery_observer — Route A memory-state-epoch observer\n\
         \n\
         USAGE:\n  \
         mida_gto_product_recovery_observer --spawn <path> --out-dir <dir>\n\
                                  [--observation-window-ms <u32>] [--poll-period-ms <u32>]\n\
                                  [--round R1|R2]\n\
         \n\
         SCOPE: read-only external observer; no DRx, no VEH, no debug-register fetch,\n\
         no WriteProcessMemory, no injection, no R1B/E2/bypass."
    );
}

// ---------------------------------------------------------------------------
// Snapshot types
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
    /// Best-effort size at transition time (0 if unknown). R2 strengthening.
    size: u64,
    /// Best-effort state at transition time.
    state: u32,
    /// Best-effort type at transition time.
    #[serde(rename = "type")]
    ty: u32,
}

/// R2 strengthened candidate identity for executable private >1 MiB regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CandidateRegion {
    base: u64,
    size: usize,
    protect: u32,
    state: u32,
    #[serde(rename = "type")]
    ty: u32,
    first_seen_tick: u32,
    last_seen_tick: u32,
    tick_count_seen: u32,
    checksum_4k: String,
    checksum_multi_page: Option<String>,
    executable_private: bool,
    image_backed: bool,
    nearest_module: String,
    neighborhood_summary: String,
    protect_name: String,
    size_class: String,
}

// ---------------------------------------------------------------------------
// Outcome JSON schema (R2)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct Outcome {
    run_id: String,
    route: String,
    round: String,
    method_class: String,
    bypass_used: bool,
    semantic_repair_used: bool,
    drx_used: bool,
    veh_used: bool,
    injection_used: bool,
    target_sample: String,
    target_pid: u32,
    target_image_path: String,
    target_sha256: String,
    observer_sha256: String,
    observation_window_ms: u32,
    poll_period_ms: u32,
    tick_count: u32,
    observed_regions: Vec<RegionSnap>,
    vm_owned_region_candidates: Vec<RegionSnap>,
    boot_region_candidates: Vec<RegionSnap>,
    candidate_regions: Vec<CandidateRegion>,
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

fn protect_name(p: u32) -> String {
    if p == PAGE_EXECUTE_READ.0 {
        "PAGE_EXECUTE_READ".into()
    } else if p == PAGE_EXECUTE_READWRITE.0 {
        "PAGE_EXECUTE_READWRITE".into()
    } else if p == PAGE_EXECUTE_WRITECOPY.0 {
        "PAGE_EXECUTE_WRITECOPY".into()
    } else if p == PAGE_READWRITE.0 {
        "PAGE_READWRITE".into()
    } else if p == PAGE_WRITECOPY.0 {
        "PAGE_WRITECOPY".into()
    } else if p == PAGE_NOACCESS.0 {
        "PAGE_NOACCESS".into()
    } else {
        format!("PROTECT_0x{p:x}")
    }
}

fn size_class(size: usize) -> String {
    if size > 0x200000 {
        ">2MiB".into()
    } else if size > 0x100000 {
        ">1MiB".into()
    } else if size > 0x10000 {
        ">64KiB".into()
    } else {
        "small".into()
    }
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn checksum_4k_hex(lo: u64, hi: u64) -> String {
    // Reconstruct first 16 bytes of SHA-256 as a stable fingerprint string.
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&lo.to_le_bytes());
    buf[8..16].copy_from_slice(&hi.to_le_bytes());
    hex_lower(&buf)
}

// ---------------------------------------------------------------------------
// Lifetime tracker for primary-anchor candidates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CandTrack {
    base: u64,
    size: usize,
    protect: u32,
    state: u32,
    ty: u32,
    first_seen_tick: u32,
    last_seen_tick: u32,
    tick_count_seen: u32,
    checksum_lo: u64,
    checksum_hi: u64,
    multi_page_hex: Option<String>,
    is_pe_image: bool,
    is_boot_named: bool,
    nearest_module: String,
}

// ---------------------------------------------------------------------------
// Polling loop
// ---------------------------------------------------------------------------

struct PollResult {
    latest_regions: Vec<RegionSnap>,
    transitions: Vec<ProtectionTransition>,
    tick_count: u32,
    vm_owned: Vec<RegionSnap>,
    boot: Vec<RegionSnap>,
    candidates: Vec<CandidateRegion>,
}

fn poll_loop(
    pid: u32,
    window_ms: u32,
    period_ms: u32,
) -> Result<PollResult, String> {
    // VirtualQueryEx needs PROCESS_QUERY_INFORMATION; ReadProcessMemory needs PROCESS_VM_READ.
    let hprocess: HANDLE = unsafe {
        match OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(e) => return Err(format!("OpenProcess failed: {e:?}")),
        }
    };

    let modules = enumerate_modules(pid).unwrap_or_default();
    let mut module_ranges: Vec<(u64, u64, String)> = Vec::new();
    for m in &modules {
        let base = m.modBaseAddr as u64;
        let size = m.modBaseSize as u64;
        let name = String::from_utf16_lossy(
            &m.szModule[..m
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(m.szModule.len())],
        )
        .to_lowercase();
        module_ranges.push((base, base.saturating_add(size), name));
    }

    let deadline = Instant::now() + Duration::from_millis(window_ms as u64);
    let mut tick: u32 = 0;
    let mut prev_regions: BTreeMap<u64, RegionSnap> = BTreeMap::new();
    let mut latest_regions: Vec<RegionSnap> = Vec::new();
    let mut latest_vm_owned: Vec<RegionSnap> = Vec::new();
    let mut latest_boot: Vec<RegionSnap> = Vec::new();
    let mut transitions: Vec<ProtectionTransition> = Vec::new();
    // Per-base lifetime for primary-anchor candidates (exec private >1 MiB).
    let mut cand_tracks: BTreeMap<u64, CandTrack> = BTreeMap::new();
    // Last full committed snapshot for neighborhood (refreshed each tick).
    let mut last_full: BTreeMap<u64, RegionSnap> = BTreeMap::new();

    loop {
        if Instant::now() >= deadline {
            break;
        }
        tick = tick.saturating_add(1);

        let mut current: BTreeMap<u64, RegionSnap> = BTreeMap::new();
        let mut addr: u64 = 0;
        // Per-tick dedup for latest_* lists: keep one snap per base (final this tick).
        let mut tick_vm: BTreeMap<u64, RegionSnap> = BTreeMap::new();
        let mut tick_boot: BTreeMap<u64, RegionSnap> = BTreeMap::new();
        let mut tick_all: BTreeMap<u64, RegionSnap> = BTreeMap::new();

        loop {
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let cb = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            let written = unsafe {
                VirtualQueryEx(
                    hprocess,
                    Some(addr as *const std::ffi::c_void),
                    &mut mbi,
                    cb,
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

            // Best-effort 4 KiB content checksum.
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

            let mut nearest_module = String::from("<none>");
            for (lo, hi, name) in &module_ranges {
                if base >= *lo && base < *hi {
                    nearest_module = name.clone();
                    if name.contains(".boot") || name.contains("boot") {
                        snap.is_boot_named = true;
                    } else if !name.is_empty() {
                        snap.is_pe_image = true;
                    }
                    break;
                }
            }
            // Image-backed if MEM_IMAGE type even without module name match.
            if ty == MEM_IMAGE.0 {
                snap.is_pe_image = true;
            }

            // Heuristic for VM-owned: private committed, executable (RX/RWX-class), >4KiB, not image.
            let is_vm_owned = !snap.is_pe_image
                && ty == MEM_PRIVATE.0
                && state == MEM_COMMIT.0
                && is_executable(protect)
                && size > 0x1000;

            current.insert(base, snap.clone());
            tick_all.insert(base, snap.clone());

            if let Some(prev) = prev_regions.get(&base) {
                if prev.protect != protect {
                    // Record any protect flip (R1 only recorded writable targets; R2 records all
                    // for weak supporting observation — still not a primary anchor).
                    let was_boot_named = prev.is_boot_named || snap.is_boot_named;
                    transitions.push(ProtectionTransition {
                        base,
                        from_protect: prev.protect,
                        to_protect: protect,
                        tick,
                        region_was_boot_named: was_boot_named,
                        size: size as u64,
                        state,
                        ty,
                    });
                    // Keep legacy filter note: is_writable used only for diagnostics, not gating.
                    let _ = is_writable(protect);
                }
            }

            if snap.is_boot_named {
                tick_boot.insert(base, snap.clone());
            }
            if is_vm_owned {
                tick_vm.insert(base, snap.clone());
            }

            // Primary-anchor tracker: MEM_PRIVATE + executable + size > 1 MiB.
            let is_primary_cand = ty == MEM_PRIVATE.0
                && state == MEM_COMMIT.0
                && is_executable(protect)
                && size > 0x100000
                && !snap.is_pe_image;

            if is_primary_cand {
                // Multi-page fingerprint once per base (first sighting), up to 64 KiB.
                let multi = if !cand_tracks.contains_key(&base) {
                    read_multipage_checksum(hprocess, base, size)
                } else {
                    None
                };
                cand_tracks
                    .entry(base)
                    .and_modify(|t| {
                        t.size = size;
                        t.protect = protect;
                        t.state = state;
                        t.ty = ty;
                        t.last_seen_tick = tick;
                        t.tick_count_seen = t.tick_count_seen.saturating_add(1);
                        // Refresh 4k checksum to latest observation.
                        t.checksum_lo = snap.checksum_lo;
                        t.checksum_hi = snap.checksum_hi;
                    })
                    .or_insert_with(|| CandTrack {
                        base,
                        size,
                        protect,
                        state,
                        ty,
                        first_seen_tick: tick,
                        last_seen_tick: tick,
                        tick_count_seen: 1,
                        checksum_lo: snap.checksum_lo,
                        checksum_hi: snap.checksum_hi,
                        multi_page_hex: multi,
                        is_pe_image: snap.is_pe_image,
                        is_boot_named: snap.is_boot_named,
                        nearest_module: nearest_module.clone(),
                    });
            }

            let next = (base as usize).saturating_add(size);
            if next == 0 || next as u64 <= base {
                break;
            }
            addr = next as u64;
            if addr > 0x7fff_ffff_ffff {
                break;
            }
        }

        // Replace latest_* with this tick's unique-per-base snaps (avoid R1-style explosion).
        latest_regions = tick_all.values().cloned().collect();
        latest_vm_owned = tick_vm.values().cloned().collect();
        latest_boot = tick_boot.values().cloned().collect();
        last_full = tick_all;
        prev_regions = current;
        std::thread::sleep(Duration::from_millis(period_ms as u64));
    }

    unsafe {
        let _ = CloseHandle(hprocess);
    }

    // Build candidate_regions with neighborhood from last full snapshot.
    let mut candidates: Vec<CandidateRegion> = Vec::new();
    for t in cand_tracks.values() {
        let neighborhood = neighborhood_summary(t.base, t.size, &last_full);
        candidates.push(CandidateRegion {
            base: t.base,
            size: t.size,
            protect: t.protect,
            state: t.state,
            ty: t.ty,
            first_seen_tick: t.first_seen_tick,
            last_seen_tick: t.last_seen_tick,
            tick_count_seen: t.tick_count_seen,
            checksum_4k: checksum_4k_hex(t.checksum_lo, t.checksum_hi),
            checksum_multi_page: t.multi_page_hex.clone(),
            executable_private: t.ty == MEM_PRIVATE.0
                && is_executable(t.protect)
                && !t.is_pe_image,
            image_backed: t.is_pe_image || t.ty == MEM_IMAGE.0,
            nearest_module: t.nearest_module.clone(),
            neighborhood_summary: neighborhood,
            protect_name: protect_name(t.protect),
            size_class: size_class(t.size),
        });
    }
    // Prefer longer-lived / larger candidates first.
    candidates.sort_by(|a, b| {
        b.tick_count_seen
            .cmp(&a.tick_count_seen)
            .then(b.size.cmp(&a.size))
            .then(a.base.cmp(&b.base))
    });

    Ok(PollResult {
        latest_regions,
        transitions,
        tick_count: tick,
        vm_owned: latest_vm_owned,
        boot: latest_boot,
        candidates,
    })
}

fn read_multipage_checksum(hprocess: HANDLE, base: u64, size: usize) -> Option<String> {
    // Up to 16 pages (64 KiB) rolling SHA-256, external ReadProcessMemory only.
    let want = 64 * 1024usize;
    let n = want.min(size);
    if n == 0 {
        return None;
    }
    let mut buf = vec![0u8; n];
    let mut bytes_read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            hprocess,
            base as *const std::ffi::c_void,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            buf.len(),
            Some(&mut bytes_read),
        )
    };
    if ok.is_err() || bytes_read == 0 {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..bytes_read]);
    Some(hex_lower(&hasher.finalize()))
}

fn neighborhood_summary(base: u64, size: usize, full: &BTreeMap<u64, RegionSnap>) -> String {
    // Summarize nearby committed regions within ±0x200000 of [base, base+size).
    const WINDOW: u64 = 0x20_0000;
    let lo = base.saturating_sub(WINDOW);
    let hi = base.saturating_add(size as u64).saturating_add(WINDOW);
    let mut nearby: Vec<&RegionSnap> = full
        .values()
        .filter(|r| r.base >= lo && r.base < hi && r.base != base)
        .collect();
    nearby.sort_by_key(|r| r.base);
    let n = nearby.len();
    let exec_n = nearby
        .iter()
        .filter(|r| is_executable(r.protect))
        .count();
    let priv_n = nearby
        .iter()
        .filter(|r| r.ty == MEM_PRIVATE.0)
        .count();
    let sample: Vec<String> = nearby
        .iter()
        .take(5)
        .map(|r| {
            format!(
                "0x{:x}/0x{:x}/p=0x{:x}",
                r.base, r.size, r.protect
            )
        })
        .collect();
    format!(
        "±2MiB neighbors={n} exec={exec_n} private={priv_n} sample=[{}]",
        sample.join(", ")
    )
}

fn enumerate_modules(pid: u32) -> Result<Vec<MODULEENTRY32W>, String> {
    // SNAPMODULE | SNAPMODULE32 covers both 64-bit and WOW64 module lists.
    let flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32;
    let snap = unsafe { CreateToolhelp32Snapshot(flags, pid) };
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
    let out = Command::new("git").args(["rev-parse", "HEAD"]).output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Err(_) => "unknown".to_string(),
    }
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let data = fs::read(p).map_err(|e| format!("read {}: {e}", p.display()))?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(hex_lower(&h.finalize()))
}

fn self_exe_sha256() -> String {
    match env::current_exe() {
        Ok(p) => sha256_file(&p).unwrap_or_else(|_| "<unreadable-self>".into()),
        Err(_) => "<no-self-path>".into(),
    }
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
        "[observer] round={} pid={target_pid} window_ms={} period_ms={} out_dir={}",
        args.round,
        args.observation_window_ms,
        args.poll_period_ms,
        args.out_dir.display()
    );

    let poll = match poll_loop(target_pid, args.observation_window_ms, args.poll_period_ms) {
        Ok(v) => v,
        Err(e) => {
            failure_class = e;
            PollResult {
                latest_regions: Vec::new(),
                transitions: Vec::new(),
                tick_count: 0,
                vm_owned: Vec::new(),
                boot: Vec::new(),
                candidates: Vec::new(),
            }
        }
    };

    let latest_regions = poll.latest_regions;
    let transitions = poll.transitions;
    let tick_count = poll.tick_count;
    let vm_owned = poll.vm_owned;
    let boot = poll.boot;
    let candidates = poll.candidates;

    // Build named observations (honest R2 bindings).
    let mut named: Vec<NamedObservation> = Vec::new();

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

    if !transitions.is_empty() {
        let first = &transitions[0];
        named.push(NamedObservation {
            name: "vm_protection_transition".into(),
            first_tick: first.tick,
            count: transitions.len() as u32,
            // Supporting weak observation only — not primary pass anchor.
            evidence_binding:
                "supporting-weak: protect flip observed (state/type/size recorded in transition; MEM_PRIVATE committed binding not assumed)"
                    .into(),
            sample_base: first.base,
            sample_size: first.size,
        });
    }

    let rwx_count = vm_owned.iter().filter(|r| is_rwx(r.protect)).count() as u32;
    if rwx_count > 0 {
        let s = vm_owned.iter().find(|r| is_rwx(r.protect)).unwrap();
        named.push(NamedObservation {
            name: "vm_owned_region_write_storm".into(),
            first_tick: 0,
            count: rwx_count,
            evidence_binding: "MEM_PRIVATE PAGE_EXECUTE_READWRITE region (true RWX)".into(),
            sample_base: s.base,
            sample_size: s.size as u64,
        });
    }

    // Primary R1/R2 anchor name retained; binding text corrected (no expand claim, no RWX claim).
    if !candidates.is_empty() {
        let s = &candidates[0];
        named.push(NamedObservation {
            name: "vm_codegen_region_expand".into(),
            first_tick: s.first_seen_tick,
            count: s.tick_count_seen,
            evidence_binding: format!(
                "stable executable private region >1MiB (RX/RWX-class); protect_name={}; expansion NOT proven; candidate identity via size+checksum+lifetime",
                s.protect_name
            ),
            sample_base: s.base,
            sample_size: s.size as u64,
        });
    }

    let target_sha = sha256_file(Path::new(&image_path)).unwrap_or_else(|_| "<unreadable>".into());
    let observer_sha = self_exe_sha256();

    let outcome = Outcome {
        run_id: uuid_like(&args.out_dir),
        route: "GTO-PRODUCT-RECOVERY/RouteA".into(),
        round: args.round.clone(),
        method_class: "memory-state-epoch external observer".into(),
        bypass_used: false,
        semantic_repair_used: false,
        drx_used: false,
        veh_used: false,
        injection_used: false,
        target_sample: "gto_launcher".into(),
        target_pid,
        target_image_path: image_path.clone(),
        target_sha256: target_sha.clone(),
        observer_sha256: observer_sha,
        observation_window_ms: args.observation_window_ms,
        poll_period_ms: args.poll_period_ms,
        tick_count,
        observed_regions: latest_regions,
        vm_owned_region_candidates: vm_owned,
        boot_region_candidates: boot,
        candidate_regions: candidates,
        allocation_epoch: Vec::new(),
        protection_transitions: transitions,
        named_observations: named,
        failure_class,
        source_commit: git_head(),
        artifact_hashes: ArtifactHashes {
            binary_sha256: target_sha,
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

    let manifest_hash = sha256_file(&outcome_path).unwrap_or_else(|_| "err".into());
    let mut patched: Outcome = serde_json::from_str(&json).unwrap_or(outcome);
    patched.artifact_hashes.manifest_sha256 = manifest_hash;
    let json2 = serde_json::to_string_pretty(&patched).unwrap_or(json);
    let _ = fs::write(&outcome_path, &json2);

    let log_path = args.out_dir.join("observer.log");
    let log_body = format!(
        "[observer] finished at unix_ms={} tick_count={} named_count={} candidates={} manifest_sha256={}\n",
        now_unix_ms(),
        tick_count,
        patched.named_observations.len(),
        patched.candidate_regions.len(),
        patched.artifact_hashes.manifest_sha256
    );
    let _ = fs::write(log_path, log_body);

    eprintln!(
        "[observer] done. outcomes={} candidates={} named={} manifest_sha256={}",
        outcome_path.display(),
        patched.candidate_regions.len(),
        patched.named_observations.len(),
        patched.artifact_hashes.manifest_sha256
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
