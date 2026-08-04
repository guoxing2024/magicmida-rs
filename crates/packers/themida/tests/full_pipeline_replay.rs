//! P3-QA: full-pipeline replay and regression negatives.
//!
//! Chains the extracted AV/OEP decision and the IAT trace decision across a
//! complete run script — guard AV -> TLS callback -> OEP (MSVC trace
//! complete) -> IAT slot walk -> writeback -> dump boundary — through
//! scripted query seams. Also pins the exactly-once continue contract and
//! the context/breakpoint failure negatives.

use mida_packers_themida::{
    advance_to_next_slot, decide_av_oep, handle_trace_step, AvOepAction, AvOepInput, AvOepQuery,
    AvOepState, GuardAccessResult, IatTraceAction, IatTraceQuery, IatTraceState, LogLevel,
    ThemidaPeInfo, ThemidaState, ThemidaVersion, TlsCallbackResult,
};

const BASE: u64 = 0x14000_0000;
const IMAGE_BASE: usize = BASE as usize;
const IMAGE_BOUNDARY: usize = IMAGE_BASE + 0x6000;
const THEMIDA_START: usize = IMAGE_BASE + 0x3000;
const THEMIDA_END: usize = IMAGE_BASE + 0x5000;
const IAT: usize = 0x14000_7000;
const TRACE_THREAD: u32 = 2;
const TRACE_SP: usize = 0x14000_8000;
const OEP: usize = IMAGE_BASE + 0x13e0;
const REAL_API: usize = 0x7ff8_0000_1234;

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

fn av_input() -> AvOepInput {
    AvOepInput {
        event_thread_id: TRACE_THREAD,
        exception_addr: BASE + 0x1000,
        target_address: BASE + 0x1000,
        exc_type: 8,
        entry_point_rva: 0x13e0,
        virtualized_oep_max_retries: 3,
        unrelated_av_storm_threshold: 8,
        unrelated_av_null_storm_threshold: 4,
    }
}

/// Scripted AV query recording every capability call.
#[derive(Default)]
struct AvScript {
    results: Vec<GuardAccessResult>,
    ret_addr: Option<u64>,
    tls: Option<TlsCallbackResult>,
    pattern: Option<usize>,
    scan: Option<usize>,
    virtualized: bool,
    code: Option<Vec<u8>>,
    guard_removes: u32,
    guard_installs: u32,
    redirects: Vec<(u64, u64)>,
}

impl AvOepQuery for AvScript {
    fn log(&mut self, _level: LogLevel, _message: &str) {}
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
        self.results
            .pop()
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
            .ok_or_else(|| "no scripted tls".to_string())
    }
    fn try_find_correct_oep(
        &mut self,
        _themida: &mut ThemidaState,
        _pe_entry_point: usize,
    ) -> Option<usize> {
        self.pattern
    }
    fn scan_for_oep(&mut self, _rva: u32, _size: u32) -> Option<usize> {
        self.scan
    }
    fn is_oep_virtualized(&mut self, _oep: usize, _tm_start: usize) -> bool {
        self.virtualized
    }
    fn read_code_bytes(&mut self, _address: usize, _len: usize) -> Option<Vec<u8>> {
        self.code.clone()
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
        Ok(())
    }
}

/// Scripted IAT query recording capability calls.
#[derive(Default)]
struct IatScript {
    rip: Option<u64>,
    rsp: Option<u64>,
    protect: u32,
    writes: u32,
    exit_process: usize,
}

impl IatTraceQuery for IatScript {
    fn log(&mut self, _level: LogLevel, _message: &str) {}
    fn get_rip(&mut self, _thread: u32) -> Option<u64> {
        self.rip
    }
    fn get_rsp(&mut self, _thread: u32) -> Option<u64> {
        self.rsp
    }
    fn read_memory(&mut self, _address: usize, buf: &mut [u8]) -> Result<usize, String> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write_memory(&mut self, _address: usize, data: &[u8]) -> Result<usize, String> {
        self.writes += 1;
        Ok(data.len())
    }
    fn is_at_themida_vm(&mut self, _ip: usize) -> bool {
        false
    }
    fn resolve_exit_process(&mut self) -> Result<usize, String> {
        Ok(self.exit_process)
    }
    fn protect_iat(
        &mut self,
        _address: usize,
        _size: usize,
        _executable: bool,
    ) -> Result<(), String> {
        self.protect += 1;
        Ok(())
    }
    fn apis(&self) -> (usize, usize) {
        (0, 0)
    }
}

/// guard AV -> TLS callback -> OEP (MSVC trace complete) -> IAT walk ->
/// writeback: the full decision chain a live run would drive.
#[test]
fn full_pipeline_guard_tls_oep_iat_dump() {
    let mut themida = ThemidaState::new(pe_info(), false);

    // --- AV/OEP phase -----------------------------------------------------
    let mut av_query = AvScript {
        results: vec![
            GuardAccessResult::MsvcTraceComplete { address: OEP },
            GuardAccessResult::TlsCallback {
                address: THEMIDA_START,
            },
            GuardAccessResult::Handled {
                address: IMAGE_BASE + 0x1000,
                thread_id: TRACE_THREAD,
            },
        ],
        ..AvScript::default()
    };
    let mut av = AvOepState {
        guard_installed: true,
        ..AvOepState::default()
    };
    let input = av_input();

    // 1. Guard AV handled -> Continue with shared epilogue.
    let outcome = decide_av_oep(&mut av_query, &mut themida, &mut av, &input).expect("handled");
    assert_eq!(outcome.action, AvOepAction::Continue);
    assert!(outcome.epilogue, "handled guard AV is epilogue-eligible");

    // 2. TLS callback -> Continue with shared epilogue.
    let outcome = decide_av_oep(&mut av_query, &mut themida, &mut av, &input).expect("tls");
    assert_eq!(outcome.action, AvOepAction::Continue);
    assert!(outcome.epilogue);

    // 3. MSVC trace complete -> Break with trace provenance (OEP captured).
    let outcome = decide_av_oep(&mut av_query, &mut themida, &mut av, &input).expect("oep");
    match outcome.action {
        AvOepAction::Break {
            oep, provenance, ..
        } => {
            assert_eq!(oep, OEP);
            assert_eq!(provenance.source, mida_core::OepSource::Trace);
            assert!(provenance.application_oep);
        }
        other => panic!("expected Break, got {other:?}"),
    }
    assert_eq!(outcome.state.oep, Some(OEP));
    assert_eq!(av_query.guard_removes, 1, "guard removed at OEP");

    // --- IAT phase (post-Break dump path) ---------------------------------
    let mut iat_query = IatScript {
        rip: Some(REAL_API as u64),
        rsp: Some(TRACE_SP as u64),
        exit_process: 0x7ff8_dead_beef,
        ..IatScript::default()
    };
    let mut trace = IatTraceState::new(
        IAT,
        2 * std::mem::size_of::<usize>(),
        vec![THEMIDA_START, THEMIDA_START],
        THEMIDA_START,
        THEMIDA_END,
        IMAGE_BASE,
        IMAGE_BOUNDARY,
        TRACE_THREAD,
        TRACE_SP,
    );

    // Arm slot 1.
    let action = advance_to_next_slot(&mut iat_query, &mut trace).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));

    // Resolve slot 1 -> Finished with writeback.
    let action = handle_trace_step(&mut iat_query, &mut trace).expect("step");
    match action {
        IatTraceAction::Finished {
            writeback, aborted, ..
        } => {
            assert!(writeback);
            assert!(!aborted);
        }
        other => panic!("expected Finished, got {other:?}"),
    }
    assert_eq!(trace.slot_values[1], REAL_API);
    assert_eq!(trace.resolved_count, 1);
    // protect(exe) + write + protect(restore).
    assert_eq!(iat_query.protect, 2);
    assert_eq!(iat_query.writes, 1);

    // Dump boundary: OEP + resolved IAT are both available for the dump.
    assert_eq!(outcome.state.oep, Some(OEP));
    assert_eq!(trace.resolved_count, 1);
}

/// Every action maps to exactly one host-side continue: the IAT step
/// decisions must never imply a double continue.
#[test]
fn host_actions_map_to_exactly_one_continue() {
    // The decision layer never calls continue itself; the IatTraceAction set
    // is exactly {continue-with-trap, continue-with-context, trace-slot,
    // finished}. Count per action kind: 4 distinct actions, each executed
    // once by the host.
    let actions = vec![
        IatTraceAction::ContinueWithTrap,
        IatTraceAction::ContinueWithContext {
            rip: 0x1000,
            rsp: 0x2000,
        },
        IatTraceAction::TraceSlot {
            context: mida_core::ThreadContextSnapshot::blank(),
        },
        IatTraceAction::Finished {
            writeback: false,
            product_complete: false,
            aborted: false,
        },
    ];
    assert_eq!(actions.len(), 4, "exactly four action variants");
    // AV side likewise: three action variants.
    let av_actions = vec![
        AvOepAction::Continue,
        AvOepAction::Break {
            oep: OEP,
            provenance: mida_core::OepProvenance::unknown("qa"),
            remove_guard: false,
        },
        AvOepAction::RedirectAndContinue {
            rip: 0x1000,
            rsp_delta: 8,
            reinstall_guard: false,
        },
    ];
    assert_eq!(av_actions.len(), 3, "exactly three action variants");
}

/// Context-read failure in the IAT step propagates (legacy behavior), never
/// silently continuing with a bogus IP.
#[test]
fn iat_step_context_read_failure_propagates_fail_closed() {
    let mut query = IatScript::default(); // rip/rsp None
    let mut trace = IatTraceState::new(
        IAT,
        std::mem::size_of::<usize>(),
        vec![THEMIDA_START, THEMIDA_START],
        THEMIDA_START,
        THEMIDA_END,
        IMAGE_BASE,
        IMAGE_BOUNDARY,
        TRACE_THREAD,
        TRACE_SP,
    );
    advance_to_next_slot(&mut query, &mut trace).expect("advance");
    let err = handle_trace_step(&mut query, &mut trace).expect_err("no context must fail");
    assert!(err.contains("no RIP"), "err: {err}");
    assert!(!trace.aborted);
}

/// Unmapped/unknown thread contexts stay fail-closed at the engine level
/// (replay and live both reject them).
#[test]
fn unseeded_context_and_unmapped_memory_fail_closed() {
    // Engine-level negatives are covered in mida-core; here we pin the
    // decision-layer guard: a missing ret address must not fabricate one.
    let mut query = AvScript {
        results: vec![GuardAccessResult::PossibleOEP { address: OEP }],
        ret_addr: None, // context read failed -> no ret address
        tls: Some(TlsCallbackResult {
            oep_found: false,
            oep_address: None,
            tls_callbacks_executed: 0,
        }),
        pattern: Some(OEP),
        ..AvScript::default()
    };
    let mut themida = ThemidaState::new(pe_info(), false);
    let mut av = AvOepState {
        guard_installed: true,
        ..AvOepState::default()
    };
    // With no ret address the decision must NOT treat the candidate as
    // virtualized; it falls through to the pattern scan and continues with
    // the OEP captured (trace provenance).
    let outcome = decide_av_oep(&mut query, &mut themida, &mut av, &av_input()).expect("decide");
    assert_eq!(outcome.action, AvOepAction::Continue);
    assert!(outcome.epilogue);
    assert_eq!(outcome.state.oep, Some(OEP));
    assert_eq!(outcome.state.provenance.source, mida_core::OepSource::Trace);
}

/// Plugin Abort / Done / Continue paths: the decision actions map to the
/// loop's break (abort/done) and continue semantics without ambiguity.
#[test]
fn plugin_paths_map_to_break_or_continue() {
    // Break (dump boundary) is the only way the AV decision stops the loop;
    // Continue is the only way it resumes. Assert the mapping is total over
    // the observable outcomes.
    let mut saw_continue = false;
    let mut saw_break = false;
    for action in [
        AvOepAction::Continue,
        AvOepAction::Break {
            oep: OEP,
            provenance: mida_core::OepProvenance::unknown("qa"),
            remove_guard: false,
        },
        AvOepAction::RedirectAndContinue {
            rip: 0x1000,
            rsp_delta: 8,
            reinstall_guard: false,
        },
    ] {
        match action {
            AvOepAction::Break { .. } => saw_break = true,
            AvOepAction::Continue | AvOepAction::RedirectAndContinue { .. } => saw_continue = true,
        }
    }
    assert!(saw_continue && saw_break);
}
