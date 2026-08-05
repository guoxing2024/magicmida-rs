//! Replay tests for the extracted AV/OEP decision handler (P3-B).
//!
//! A scripted [`AvOepQuery`] fake drives the decision; every capability call
//! is recorded so the tests assert exactly what the host must execute (guard
//! ops, redirects, continues) and which action is returned. No Win32, no
//! debugger.

use mida_packers_themida::{
    decide_av_oep, AvOepAction, AvOepInput, AvOepQuery, AvOepState, GuardAccessResult, LogLevel,
    ThemidaPeInfo, ThemidaState, ThemidaVersion, TlsCallbackResult,
};

const BASE: u64 = 0x14000_0000;

fn pe_info() -> ThemidaPeInfo {
    ThemidaPeInfo {
        image_base: BASE,
        image_boundary: BASE + 0x6000,
        base_of_data: 0x2000,
        pe_sections: vec![
            mida_pe::PeSection {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x200,
                raw_size: 0x1000,
                characteristics: 0x6000_0020,
                ..mida_pe::PeSection::default()
            },
            mida_pe::PeSection {
                name: ".themida".to_string(),
                virtual_address: 0x3000,
                virtual_size: 0x2000,
                raw_offset: 0x1200,
                raw_size: 0x2000,
                characteristics: 0xC000_0040,
                ..mida_pe::PeSection::default()
            },
        ],
        major_linker_version: 14,
        themida_version: ThemidaVersion::V3,
        is_vm_oep: false,
        themida_section: Some(1),
        tls_total: 0,
    }
}

fn state() -> ThemidaState {
    ThemidaState::new(pe_info(), false)
}

fn input() -> AvOepInput {
    AvOepInput {
        event_thread_id: 2,
        exception_addr: BASE + 0x1000,
        target_address: BASE + 0x1000,
        exc_type: 8,
        entry_point_rva: 0x13e0,
        virtualized_oep_max_retries: 3,
        unrelated_av_storm_threshold: 8,
        unrelated_av_null_storm_threshold: 4,
    }
}

/// Scripted query fake: records every capability call and returns scripted
/// answers.
#[derive(Default)]
struct ScriptedQuery {
    guarded: Option<GuardAccessResult>,
    ret_addr: Option<u64>,
    tls: Option<TlsCallbackResult>,
    pattern_oep: Option<usize>,
    scan_oep: Option<usize>,
    virtualized: bool,
    code_bytes: Option<Vec<u8>>,
    guard_removes: u32,
    guard_installs: u32,
    redirects: Vec<(u64, u64)>,
    logs: Vec<(LogLevel, String)>,
    redirect_ok: bool,
}

impl ScriptedQuery {
    fn with_guard(result: GuardAccessResult) -> Self {
        Self {
            guarded: Some(result),
            ..Self::default()
        }
    }
}

impl AvOepQuery for ScriptedQuery {
    fn log(&mut self, level: LogLevel, message: &str) {
        self.logs.push((level, message.to_string()));
    }
    fn image_base(&self) -> u64 {
        BASE
    }
    fn process_guarded_access(
        &mut self,
        _themida: &mut ThemidaState,
        _target: usize,
        _exc: usize,
        _thread: u32,
        _exc_type: u8,
    ) -> Result<GuardAccessResult, String> {
        self.guarded
            .clone()
            .ok_or_else(|| "no scripted guard result".to_string())
    }
    fn read_ret_addr(&mut self, _thread: u32) -> Option<u64> {
        self.ret_addr
    }
    fn handle_tls_callbacks(
        &mut self,
        _address: usize,
        _tls_total: u32,
        _tls_counter: &mut u32,
    ) -> Result<TlsCallbackResult, String> {
        self.tls
            .clone()
            .ok_or_else(|| "no scripted tls result".to_string())
    }
    fn try_find_correct_oep(
        &mut self,
        _themida: &mut ThemidaState,
        _pe_entry_point: usize,
    ) -> Option<usize> {
        self.pattern_oep
    }
    fn scan_for_oep(&mut self, _text_rva: u32, _text_size: u32) -> Option<usize> {
        self.scan_oep
    }
    fn is_oep_virtualized(&mut self, _oep: usize, _tm_start: usize) -> bool {
        self.virtualized
    }
    fn read_code_bytes(&mut self, _address: usize, _len: usize) -> Option<Vec<u8>> {
        self.code_bytes.clone()
    }
    fn remove_code_guard(&mut self) -> Result<(), String> {
        self.guard_removes += 1;
        Ok(())
    }
    fn install_code_guard(&mut self) -> Result<(), String> {
        self.guard_installs += 1;
        Ok(())
    }
    fn set_redirect(&mut self, rip: u64, rsp_delta: u64) -> Result<(), String> {
        self.redirects.push((rip, rsp_delta));
        if self.redirect_ok {
            Ok(())
        } else {
            Err("scripted redirect failure".to_string())
        }
    }
}

fn decide(
    query: &mut dyn AvOepQuery,
    themida: &mut ThemidaState,
    av: &mut AvOepState,
    input: &AvOepInput,
) -> (AvOepAction, AvOepState) {
    let outcome = decide_av_oep(query, themida, av, input).expect("decision");
    (outcome.action, outcome.state)
}

#[test]
fn unrelated_av_without_guard_returns_continue() {
    let mut query = ScriptedQuery::default();
    let mut themida = state();
    let mut av = AvOepState::default();
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    assert_eq!(action, AvOepAction::Continue);
    assert!(!out.storm_escape_freeze);
    // No guard ops and no redirects: the host only continues once.
    assert_eq!(query.guard_removes, 0);
    assert!(query.redirects.is_empty());
}

#[test]
fn guard_av_handled_resets_streak_and_continues() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::Handled {
        address: (BASE + 0x1000) as usize,
        thread_id: 2,
    });
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        unrelated_av_streak: 5,
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    assert_eq!(action, AvOepAction::Continue);
    assert_eq!(
        out.unrelated_av_streak, 0,
        "handled guard AV resets the streak"
    );
    assert!(out.oep.is_none());
}

#[test]
fn tls_callback_continues_without_streak_reset() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::TlsCallback {
        address: (BASE + 0x3000) as usize,
    });
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        unrelated_av_streak: 3,
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    assert_eq!(action, AvOepAction::Continue);
    // The CLI tree does not reset the streak on the TLS arm.
    assert_eq!(out.unrelated_av_streak, 3);
    assert!(query
        .logs
        .iter()
        .any(|(_, m)| m.contains("TLS callback detected")));
}

#[test]
fn msvc_trace_complete_breaks_with_trace_provenance() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::MsvcTraceComplete {
        address: (BASE + 0x13e0) as usize,
    });
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    match action {
        AvOepAction::Break {
            oep, provenance, ..
        } => {
            assert_eq!(oep as u64, BASE + 0x13e0);
            assert_eq!(provenance.source, mida_core::OepSource::Trace);
            assert!(provenance.application_oep);
            assert!(!provenance.bootstrap_or_ambiguous);
        }
        other => panic!("expected Break, got {other:?}"),
    }
    assert_eq!(out.oep, Some((BASE + 0x13e0) as usize));
    assert_eq!(query.guard_removes, 1, "guard removed before break");
    assert!(!out.oep_found_via_scanning);
}

#[test]
fn oep_capture_via_pattern_breaks_with_trace_provenance() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::PossibleOEP {
        address: (BASE + 0x13e0) as usize,
    });
    query.ret_addr = Some(BASE + 0x3000); // inside .themida
    query.tls = Some(TlsCallbackResult {
        oep_found: false,
        oep_address: None,
        tls_callbacks_executed: 0,
    });
    query.pattern_oep = Some((BASE + 0x13e0) as usize);
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    match action {
        AvOepAction::Break {
            oep, provenance, ..
        } => {
            assert_eq!(oep as u64, BASE + 0x13e0);
            assert_eq!(provenance.source, mida_core::OepSource::Trace);
        }
        other => panic!("expected Break, got {other:?}"),
    }
    assert_eq!(out.oep, Some((BASE + 0x13e0) as usize));
    assert_eq!(query.guard_removes, 1);
}

#[test]
fn virtualized_oep_redirect_returns_redirect_and_continues() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::PossibleOEP {
        address: (BASE + 0x13e0) as usize,
    });
    query.ret_addr = Some(BASE + 0x3000);
    query.tls = Some(TlsCallbackResult {
        oep_found: false,
        oep_address: None,
        tls_callbacks_executed: 0,
    });
    query.redirect_ok = true;
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    match action {
        AvOepAction::RedirectAndContinue {
            rip,
            rsp_delta,
            reinstall_guard,
        } => {
            assert_eq!(rip, BASE + 0x3000);
            assert_eq!(rsp_delta, 8);
            assert!(!reinstall_guard, "install was executed via the query");
        }
        other => panic!("expected RedirectAndContinue, got {other:?}"),
    }
    assert_eq!(query.redirects, vec![(BASE + 0x3000, 8)]);
    assert_eq!(query.guard_installs, 1);
    assert_eq!(out.virtualized_oep_retries, 1);
    assert_eq!(out.last_possible_oep, Some((BASE + 0x13e0) as usize));
}

#[test]
fn valid_x64_code_branch_keeps_runtime_va_and_trace_provenance() {
    // P8-B regression: the "OEP looks like valid x64 code — using as-is for
    // non-MSVC compiler" branch previously set provenance to Unknown, dropping
    // the runtime VA/RVA and forcing the OEP evidence sidecar to fail closed.
    // A runtime PossibleOEP whose bytes confirm an x64 application prologue
    // must keep source=Trace, va=Some, rva derivable, application_oep=true.
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::PossibleOEP {
        address: (BASE + 0x13e0) as usize,
    });
    query.ret_addr = Some(BASE + 0x3000); // inside .themida → virtualized path
    query.tls = Some(TlsCallbackResult {
        oep_found: false,
        oep_address: None,
        tls_callbacks_executed: 0,
    });
    query.pattern_oep = None; // try_find_correct_oep returns nothing
    query.scan_oep = None; // no scan replacement
    query.code_bytes = Some(vec![0x48, 0x89, 0x5c, 0x24]); // rex.W mov [rsp+..],rbx (valid x64 prologue)
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        virtualized_oep_retries: 3, // retries exhausted → last PossibleOEP path
        last_possible_oep: Some((BASE + 0x13e0) as usize),
        ..AvOepState::default()
    };
    let mut input = input();
    input.virtualized_oep_max_retries = 3;
    let (_action, out) = decide(&mut query, &mut themida, &mut av, &input);

    assert_eq!(out.oep, Some((BASE + 0x13e0) as usize));
    assert_eq!(out.provenance.source, mida_core::OepSource::Trace);
    assert_eq!(out.provenance.va, Some(BASE + 0x13e0));
    assert!(out.provenance.application_oep);
    assert!(!out.provenance.bootstrap_or_ambiguous);
    // RVA is derived later at the CLI layer via record_oep_provenance
    // (oep_va_to_rva against the runtime base); at the handler layer the VA is
    // authoritative and the RVA may still be unset.
    assert!(
        !out.oep_found_via_scanning,
        "valid-x64 acceptance is not a scan"
    );
}

#[test]
fn unconfirmed_possible_oep_keeps_runtime_va() {
    // P8-B: a PossibleOEP accepted without a confirming pattern/scan trace
    // still keeps its runtime VA (source=Trace), so the OEP evidence is not
    // forced to unknown; the gate still fails closed on any entry mismatch.
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::PossibleOEP {
        address: (BASE + 0x13e0) as usize,
    });
    query.ret_addr = Some(BASE + 0x3000); // inside .themida
    query.tls = Some(TlsCallbackResult {
        oep_found: false,
        oep_address: None,
        tls_callbacks_executed: 0,
    });
    query.pattern_oep = None;
    query.scan_oep = None;
    query.code_bytes = Some(vec![0x90, 0x90, 0x90, 0x90]); // NOPs: NOT a valid x64 prologue
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        virtualized_oep_retries: 3,
        last_possible_oep: Some((BASE + 0x13e0) as usize),
        ..AvOepState::default()
    };
    let mut input = input();
    input.virtualized_oep_max_retries = 3;
    let (_action, out) = decide(&mut query, &mut themida, &mut av, &input);

    // Even without byte confirmation, the accepted PossibleOEP keeps its VA.
    assert_eq!(out.provenance.source, mida_core::OepSource::Trace);
    assert_eq!(out.provenance.va, Some(BASE + 0x13e0));
}

#[test]
fn not_guarded_av_storm_breaks_with_fallback_and_freeze() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::NotGuarded);
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        virtualized_oep_retries: 1,
        last_possible_oep: Some((BASE + 0x13e0) as usize),
        unrelated_av_streak: 7,
        ..AvOepState::default()
    };
    let mut input = input();
    input.unrelated_av_storm_threshold = 8;
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input);
    match action {
        AvOepAction::Break {
            oep, provenance, ..
        } => {
            assert_eq!(oep as u64, BASE + 0x13e0);
            assert_eq!(provenance.source, mida_core::OepSource::Unknown);
        }
        other => panic!("expected Break, got {other:?}"),
    }
    assert!(out.storm_escape_freeze);
    assert_eq!(out.unrelated_av_streak, 8);
    assert!(!out.oep_found_via_scanning);
    assert_eq!(query.guard_removes, 1);
}

#[test]
fn non_storm_not_guarded_av_continues() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::NotGuarded);
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        unrelated_av_streak: 2,
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    assert_eq!(action, AvOepAction::Continue);
    assert_eq!(out.unrelated_av_streak, 3);
    assert!(!out.storm_escape_freeze);
}

#[test]
fn oep_provenance_is_scan_fallback_when_virtualized_oep_is_scanned() {
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::PossibleOEP {
        address: (BASE + 0x13e0) as usize,
    });
    query.tls = Some(TlsCallbackResult {
        oep_found: false,
        oep_address: None,
        tls_callbacks_executed: 0,
    });
    query.virtualized = true;
    query.scan_oep = Some((BASE + 0x13e0) as usize);
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        oep: Some((BASE + 0x13e0) as usize),
        ..AvOepState::default()
    };
    let (action, out) = decide(&mut query, &mut themida, &mut av, &input());
    assert_eq!(action, AvOepAction::Continue);
    assert_eq!(out.provenance.source, mida_core::OepSource::ScanFallback);
    assert!(out.oep_found_via_scanning);
}

#[test]
fn no_branch_implicitly_continues_twice() {
    // Every action is explicit: run the storm path and assert the host gets
    // exactly one instruction (Break) — no implicit continue sneaks out.
    let mut query = ScriptedQuery::with_guard(GuardAccessResult::NotGuarded);
    let mut themida = state();
    let mut av = AvOepState {
        guard_installed: true,
        virtualized_oep_retries: 2,
        last_possible_oep: Some((BASE + 0x1000) as usize),
        unrelated_av_streak: 9,
        ..AvOepState::default()
    };
    let (action, _) = decide(&mut query, &mut themida, &mut av, &input());
    assert!(matches!(action, AvOepAction::Break { .. }));
    assert_eq!(query.redirects.len(), 0);
    assert!(query.guard_installs == 0);
}
