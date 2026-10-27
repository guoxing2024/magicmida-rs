//! Common state carried through the Themida unpacking process.

use std::collections::HashSet;
use crate::init::ThemidaPeInfo;

/// Mutable state shared across the Themida unpacking pipeline.
#[derive(Debug, Clone)]
pub struct ThemidaState {
    pub pe_info: ThemidaPeInfo,
    pub create_data_sections: bool,
    pub guard_addrs: Vec<usize>,
    pub traced_api: usize,
    pub sleep_api: usize,
    pub lstrlen_api: usize,
    pub trace_start_sp: usize,
    pub trace_in_vm: bool,
    // x64-specific fields
    pub ftm_guard: bool,
    pub trace_msvc_oep: bool,
    pub msvc_init_cookie: usize,
    pub msvc_oep: usize,
    pub guard_protection: u32,
    pub guard_start: usize,
    pub guard_end: usize,
    pub guard_installed: bool,
    /// When true, the guard was temporarily removed for a single-step (library
    /// read or Themida write) and must be re-armed on the next `SINGLE_STEP`
    /// event.  Mirrors Pascal `FGuardStepping`.
    pub guard_stepping: bool,
    /// Number of TLS callbacks expected (derived from the PE TLS directory,
    /// matching `FTLSTotal` in the Pascal reference). Zero if unknown.
    pub tls_total: u32,
    /// Number of TLS callbacks already skipped (= `FTLSCounter`).
    pub tls_counter: u32,
    /// IAT monitoring mode: when true, the guard is set on the Themida section
    /// and we're waiting for enough writes to consider the IAT decrypted.
    pub iat_monitoring: bool,
    /// Themida 1.1.1-shape: the shell materialised the original program as a
    /// file-mapped image (the `.text` guard chain never fires — the program
    /// simply runs and exits).  When set, the pipeline steps the shell into
    /// the image to find the OEP and dumps the image directly.
    pub pending_mapped_dump: Option<mida_pe::dumper::MappedImage>,
    /// Last time the periodic mapped-image scan ran (the CloseHandle hit is
    /// not a reliable trigger for 1.1.1 shells — measured: some runs exit
    /// without it ever firing, so the pipeline scans on its own).
    pub last_map_scan: std::time::Instant,
    /// The shell's main thread (from the CreateProcess event).  The jump
    /// into the materialised image happens on it, so the OEP single-step
    /// must arm TF on this thread, not on whatever thread delivered the
    /// current event (measured: worker threads deliver events during the
    /// decompression storm).
    pub main_thread_id: u32,
    /// Image bases seen by the first periodic scan (the startup DLL set).
    /// Later scans only consider images that appeared afterwards — the
    /// materialised program is LoadLibrary'd by the shell mid-run, while
    /// the shell's own DLLs and the system DLLs are all in the initial set.
    pub seen_image_bases: std::collections::HashSet<u64>,
    /// Set of unique write addresses detected during IAT monitoring.
    /// Using HashSet to avoid counting duplicate writes to the same address.
    pub iat_write_addresses: HashSet<usize>,
    /// Maximum number of unique write addresses to wait for before considering IAT ready.
    pub iat_write_threshold: u32,
    /// Set to true when IAT monitoring has detected enough writes.
    pub iat_ready: bool,
    /// The address being monitored (target IAT region start).
    /// Used for direct IAT decryption checks.
    pub iat_monitor_address: usize,
    /// The size of the IAT region being monitored.
    pub iat_monitor_size: usize,
    /// Total write count (including duplicates) for timeout detection.
    pub iat_total_writes: u64,
    /// Timeout: if total writes exceed this without reaching unique threshold,
    /// force IAT ready (VM may be stuck in a loop).
    pub iat_timeout_threshold: u64,
    /// A planted `int3` standing in for the FTMGuard re-arm fault.
    ///
    /// `Some((address, original_byte))` while armed.  See
    /// [`crate::guard::process_guarded_access`] branch 4: the TLS-callback
    /// branch leaves `.text` executable and expects the callback's return into
    /// the Themida section to fault, which is what re-arms `.text`.  When DEP is
    /// not enforced for the image that fault never arrives, so the return site
    /// is patched with `int3` instead — a deterministic, DEP-independent trigger
    /// for the same transition.
    pub tm_return_int3: Option<(usize, u8)>,
    /// Classic (v1-generation) OEP verification: the return address a
    /// candidate OEP was called with, armed as an execute hardware breakpoint.
    /// `None` while no candidate is being verified.
    pub classic_pending_ret: Option<usize>,
    /// Set when the armed return-address breakpoint fired: the candidate
    /// returned to the protector, so it was a shell helper, not the OEP.
    pub classic_ret_hit: bool,
    /// Classic OEP verification by guarding the protector's home section:
    /// `Some((candidate, armed_at))` while the candidate is being proven.
    /// The `.text` guard comes DOWN and the section holding the packed entry
    /// point goes to `PAGE_NOACCESS` — the shell's final-stage helper faults
    /// the moment it returns home (rejected), while the real OEP never
    /// touches the protector and is accepted after a quiet window.  A
    /// single-stepping variant was measured to fail: the stage's own
    /// pushfd/popfd overwrites the trap flag and stepping dies silently
    /// after two instructions (2026-10-27).
    pub classic_verify: Option<(usize, std::time::Instant)>,
    /// Candidate addresses already rejected by the stepping verification —
    /// the shell's decompression stage is called in a loop, so the same
    /// `.text` address faults again and again; a repeated candidate is
    /// dismissed without re-running the stepping dance (measured: the stage
    /// at `0x4271dc` is entered thousands of times).
    pub classic_rejected: Vec<usize>,
    /// Ancient (1.1.1) exit-window watch.  The materialised image is created
    /// AND wiped entirely inside the last tens of milliseconds before
    /// `ExitProcess` (measured: at the CloseHandle hit the scan finds only
    /// the packed image and system DLLs; at the `ExitProcess` event the
    /// image exists but its content is already destroyed).  After the
    /// CloseHandle hit the pipeline therefore scans after EVERY debug
    /// event and writes a numbered raw snapshot each time the image
    /// appears — each debug event freezes the process, so every snapshot
    /// is a consistent catch of the window, and the best one (usually the
    /// last before the wipe) is picked offline.
    pub ancient_watch: bool,
    /// Module bases cached when the watch started (the watch filter is
    /// "not the packed image and not a registered module"; re-taking the
    /// module snapshot at every event is too slow for the exit window).
    pub ancient_module_bases: std::collections::HashSet<u64>,
    /// Numbered raw snapshots written during the watch.
    pub ancient_snapshots: u32,
}

impl ThemidaState {
    #[must_use]
    pub fn new(pe_info: ThemidaPeInfo, create_data_sections: bool) -> Self {
        Self {
            pe_info,
            create_data_sections,
            guard_addrs: Vec::new(),
            traced_api: 0,
            sleep_api: 0,
            lstrlen_api: 0,
            trace_start_sp: 0,
            trace_in_vm: false,
            ftm_guard: false,
            trace_msvc_oep: false,
            msvc_init_cookie: 0,
            msvc_oep: 0,
            guard_protection: 0x01,
            guard_start: 0,
            guard_end: 0,
            guard_installed: false,
            guard_stepping: false,
            tls_total: 0,
            tls_counter: 0,
            iat_monitoring: false,
            pending_mapped_dump: None,
            last_map_scan: std::time::Instant::now(),
            main_thread_id: 0,
            seen_image_bases: std::collections::HashSet::new(),
            ancient_watch: false,
            ancient_module_bases: std::collections::HashSet::new(),
            ancient_snapshots: 0,
            iat_write_addresses: HashSet::new(),
            // Default: wait for 3 unique write addresses before considering IAT ready.
            // This is a low threshold because the VM may write to the same address
            // multiple times. Once we see a few unique writes, the IAT is likely ready.
            iat_write_threshold: 3,
            iat_ready: false,
            iat_monitor_address: 0,
            iat_monitor_size: 0,
            iat_total_writes: 0,
            // Timeout: if we see 1000 writes but still haven't reached the unique
            // threshold, the VM is likely stuck in a loop. Force ready.
            iat_timeout_threshold: 1_000,
            tm_return_int3: None,
            classic_pending_ret: None,
            classic_ret_hit: false,
            classic_verify: None,
            classic_rejected: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::ThemidaVersion;

    fn make_minimal_info() -> ThemidaPeInfo {
        ThemidaPeInfo {
            image_base: 0x140000000,
            image_boundary: 0x140006000,
            base_of_data: 0x2000,
            pe_sections: Vec::new(),
            major_linker_version: 14,
            packed_entry_point: 0,
            themida_version: ThemidaVersion::V3,
            is_vm_oep: false,
            themida_section: None,
            tls_total: 0,
        }
    }

    #[test]
    fn new_state_defaults() {
        let info = make_minimal_info();
        let state = ThemidaState::new(info.clone(), true);
        assert_eq!(state.pe_info.image_base, info.image_base);
        assert!(state.create_data_sections);
        assert!(state.guard_addrs.is_empty());
        assert_eq!(state.traced_api, 0);
    }
}