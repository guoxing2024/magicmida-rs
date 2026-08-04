//! Replay tests for the extracted IAT trace handler (P3-C).
//!
//! A scripted [`IatTraceQuery`] drives slot walks and single-step decisions;
//! every capability call and log is recorded so tests assert exactly what the
//! host must execute and which action is returned. No Win32, no debugger.
//!
//! Note (P6-0): the legacy walk pre-incremented `current_slot` and never
//! classified slot 0. That off-by-one was fixed explicitly after the P3
//! migration: the walk now classifies every slot from index 0, so non-empty
//! tables can reach product_complete. These tests pin the corrected
//! semantics.

use mida_packers_themida::{
    advance_to_next_slot, handle_trace_step, IatTraceAction, IatTraceQuery, IatTraceState,
    LogLevel, TracePhase,
};

const IMAGE_BASE: usize = 0x14000_0000;
const IMAGE_BOUNDARY: usize = IMAGE_BASE + 0x6000;
const THEMIDA_START: usize = IMAGE_BASE + 0x3000;
const THEMIDA_END: usize = IMAGE_BASE + 0x5000;
const IAT: usize = 0x14000_7000;
const TRACE_THREAD: u32 = 9;
const TRACE_SP: usize = 0x14000_8000;
const REAL_API: usize = 0x7ff8_0000_1234;

fn trace(slot_values: Vec<usize>) -> IatTraceState {
    IatTraceState::new(
        IAT,
        slot_values.len() * std::mem::size_of::<usize>(),
        slot_values,
        THEMIDA_START,
        THEMIDA_END,
        IMAGE_BASE,
        IMAGE_BOUNDARY,
        TRACE_THREAD,
        TRACE_SP,
    )
}

#[derive(Default)]
struct ScriptedQuery {
    rip: Option<u64>,
    rsp: Option<u64>,
    memory: Vec<u8>,
    vm_entry: bool,
    exit_process: usize,
    sleep_api: usize,
    lstrlen_api: usize,
    protect_calls: Vec<(usize, usize, bool)>,
    writes: Vec<(usize, usize)>,
    logs: Vec<(LogLevel, String)>,
    read_fail: bool,
    stack_addr: usize,
}

impl ScriptedQuery {
    fn scripted(rip: u64, rsp: u64) -> Self {
        Self {
            rip: Some(rip),
            rsp: Some(rsp),
            stack_addr: TRACE_SP - 8,
            ..Self::default()
        }
    }

    fn finished_logs(&self) -> usize {
        self.logs
            .iter()
            .filter(|(_, m)| m.contains("IAT trace finished"))
            .count()
    }
}

impl IatTraceQuery for ScriptedQuery {
    fn log(&mut self, level: LogLevel, message: &str) {
        self.logs.push((level, message.to_string()));
    }
    fn get_rip(&mut self, _thread: u32) -> Option<u64> {
        self.rip
    }
    fn get_rsp(&mut self, _thread: u32) -> Option<u64> {
        self.rsp
    }
    fn read_memory(&mut self, address: usize, buf: &mut [u8]) -> Result<usize, String> {
        if self.read_fail {
            return Err("scripted read failure".to_string());
        }
        let base = self.stack_addr;
        if address < base || address >= base + self.memory.len() {
            return Err("scripted read out of range".to_string());
        }
        let offset = address - base;
        let n = buf.len().min(self.memory.len() - offset);
        buf[..n].copy_from_slice(&self.memory[offset..offset + n]);
        Ok(n)
    }
    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, String> {
        self.writes.push((address, data.len()));
        Ok(data.len())
    }
    fn is_at_themida_vm(&mut self, _ip: usize) -> bool {
        self.vm_entry
    }
    fn resolve_exit_process(&mut self) -> Result<usize, String> {
        Ok(self.exit_process)
    }
    fn protect_iat(&mut self, address: usize, size: usize, executable: bool) -> Result<(), String> {
        self.protect_calls.push((address, size, executable));
        Ok(())
    }
    fn apis(&self) -> (usize, usize) {
        (self.sleep_api, self.lstrlen_api)
    }
}

#[test]
fn slot_walk_skips_null_and_real_api_then_traces_vm_slot() {
    let mut query = ScriptedQuery::default();
    query.rip = Some(THEMIDA_START as u64);
    let mut t = trace(vec![0, REAL_API, THEMIDA_START, 0]);

    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    // P6-0 walk starts at slot 0: null slot 0 and real-API slot 1 are
    // validated skips; slot 2 (VM entry) is armed.
    assert_eq!(t.skip_count, 2);
    assert_eq!(t.current_slot, 2);
    match action {
        IatTraceAction::TraceSlot { context } => {
            assert_eq!(context.rip, THEMIDA_START as u64);
            assert_eq!(context.rsp, TRACE_SP as u64);
            assert_ne!(context.eflags & 0x100, 0, "trap flag set");
        }
        other => panic!("expected TraceSlot, got {other:?}"),
    }
    assert_eq!(t.trace_phase, TracePhase::Tracing);
}

#[test]
fn found_api_resolves_slot_and_finishes_with_single_writeback() {
    let mut query = ScriptedQuery::scripted(REAL_API as u64, TRACE_SP as u64);
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);

    // Arm slot 0.
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));
    assert_eq!(t.current_slot, 0);

    // Single-step resolves the real API at slot 0, then the walk arms slot 1.
    let action = handle_trace_step(&mut query, &mut t).expect("step");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));
    assert_eq!(t.slot_values[0], REAL_API);
    assert_eq!(t.resolved_count, 1);

    // Resolve slot 1 -> Finished with writeback, product-complete.
    let action = handle_trace_step(&mut query, &mut t).expect("step");
    match action {
        IatTraceAction::Finished {
            writeback,
            product_complete,
            aborted,
        } => {
            assert!(writeback, "resolved slots must be written back");
            assert!(
                product_complete,
                "P6-0: a fully accounted non-empty table is product-complete"
            );
            assert!(!aborted);
        }
        other => panic!("expected Finished, got {other:?}"),
    }
    assert_eq!(t.slot_values[1], REAL_API);
    assert_eq!(t.resolved_count, 2);
    assert_eq!(t.failed_count, 0);
    assert_eq!(t.skip_count, 0);
    assert_eq!(t.slots_accounted(), 2);
    assert!(t.product_complete());
    // Writeback: protect(exe) + write + protect(restore), exactly once.
    assert_eq!(query.protect_calls.len(), 2);
    assert_eq!(query.writes.len(), 1);
    // Exactly one completion milestone.
    assert_eq!(query.finished_logs(), 1);
}

#[test]
fn trace_limit_gives_up_slot_fail_closed() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));

    // Drive past TRACE_LIMIT (500_000): the slot must fail and the walk must
    // finish without writeback and without a false product-complete.
    for _ in 0..500_001 {
        let _ = handle_trace_step(&mut query, &mut t).expect("step");
    }
    assert_eq!(t.failed_count, 1, "slot 0 gave up");
    assert_eq!(t.resolved_count, 0);
    // The walk arms slot 1 after the give-up; drive it past the limit too.
    for _ in 0..500_001 {
        let _ = handle_trace_step(&mut query, &mut t).expect("step");
    }
    assert_eq!(t.failed_count, 2);
    assert_eq!(t.resolved_count, 0);
    assert!(query.writes.is_empty());
    assert!(!t.product_complete());
    assert!(query.finished_logs() >= 1);
}

#[test]
fn hit_vm_resolves_exit_process_once_then_fails_second_time() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    query.exit_process = 0x7ff8_dead_beef;
    // Three VM slots: first traced hit resolves ExitProcess, the next must
    // fail (already set).
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START, THEMIDA_START]);
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));
    assert_eq!(t.current_slot, 0, "P6-0: walk starts at slot 0");

    // Drive the trace counter into the HitVm window (101..5000) inside the
    // Themida section (each step is a plain trap continue).
    for _ in 0..102 {
        let action = handle_trace_step(&mut query, &mut t).expect("step");
        assert_eq!(action, IatTraceAction::ContinueWithTrap);
    }
    // Now a VM entry hit resolves ExitProcess for the armed slot.
    query.vm_entry = true;
    let action = handle_trace_step(&mut query, &mut t).expect("step");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));
    assert_eq!(t.slot_values[0], query.exit_process);
    assert_eq!(t.resolved_count, 1);
    assert_eq!(t.failed_count, 0);
    assert_eq!(t.current_slot, 1);

    // Second armed slot: drive the counter again (no VM entry yet), then hit
    // the VM — the second hit fails because ExitProcess was already resolved.
    query.vm_entry = false;
    for _ in 0..102 {
        let action = handle_trace_step(&mut query, &mut t).expect("step");
        assert_eq!(action, IatTraceAction::ContinueWithTrap);
    }
    query.vm_entry = true;
    let action = handle_trace_step(&mut query, &mut t).expect("step");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));
    assert_eq!(t.failed_count, 1, "second VM hit fails (already resolved)");

    // Third armed slot: same failure path, then the walk finishes.
    query.vm_entry = false;
    for _ in 0..102 {
        let action = handle_trace_step(&mut query, &mut t).expect("step");
        assert_eq!(action, IatTraceAction::ContinueWithTrap);
    }
    query.vm_entry = true;
    let action = handle_trace_step(&mut query, &mut t).expect("step");
    match action {
        IatTraceAction::Finished { aborted, .. } => assert!(!aborted),
        other => panic!("expected Finished, got {other:?}"),
    }
    assert_eq!(t.failed_count, 2);
    assert_eq!(t.resolved_count, 1);
    assert!(
        !t.product_complete(),
        "failed slots are never product-complete"
    );
}

#[test]
fn anti_trace_api_returns_continue_with_context() {
    let sleep = 0x7ff8_0000_2222;
    let mut query = ScriptedQuery::scripted(sleep as u64, (TRACE_SP - 8) as u64);
    query.sleep_api = sleep;
    // Ret addr on the scripted stack at rsp.
    query.memory = 0x7ff8_0000_3333u64.to_le_bytes().to_vec();
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));

    let action = handle_trace_step(&mut query, &mut t).expect("step");
    match action {
        IatTraceAction::ContinueWithContext { rip, rsp } => {
            assert_eq!(rip, 0x7ff8_0000_3333, "pop return address");
            assert_eq!(rsp, (TRACE_SP - 8 + 8) as u64, "stack popped");
        }
        other => panic!("expected ContinueWithContext, got {other:?}"),
    }
}

#[test]
fn inside_themida_step_returns_continue_with_trap() {
    let mut query = ScriptedQuery::scripted((THEMIDA_START + 0x40) as u64, TRACE_SP as u64);
    query.vm_entry = false;
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));

    let action = handle_trace_step(&mut query, &mut t).expect("step");
    assert_eq!(action, IatTraceAction::ContinueWithTrap);
}

#[test]
fn trash_storm_aborts_fail_closed() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    // 70 consecutive invalid (non-null, non-image, non-themida) slots.
    // 0x1000 is below the real-API floor (0x10000) and outside all ranges.
    let values = vec![0x1000usize; 70];
    let mut t = trace(values);
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    match action {
        IatTraceAction::Finished {
            writeback,
            product_complete,
            aborted,
        } => {
            assert!(aborted, "trash storm must abort");
            assert!(!writeback);
            assert!(!product_complete);
        }
        other => panic!("expected Finished(aborted), got {other:?}"),
    }
    assert!(t.aborted);
    assert!(t.abort_reason.is_some());
    assert!(query.writes.is_empty());
    assert_eq!(t.failed_count, 65);
}

#[test]
fn read_failure_fails_closed_without_advancing_to_complete() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    query.read_fail = true;
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    assert!(matches!(action, IatTraceAction::TraceSlot { .. }));
    // A short-read failure in the step just means no ret address; the step
    // itself stays fail-closed (no panic, no completion).
    let action = handle_trace_step(&mut query, &mut t).expect("step");
    assert!(matches!(action, IatTraceAction::ContinueWithTrap));
    assert!(!t.aborted);
}

#[test]
fn empty_table_is_complete_without_work() {
    let mut query = ScriptedQuery::default();
    let mut t = trace(Vec::new());
    let action = advance_to_next_slot(&mut query, &mut t).expect("advance");
    match action {
        IatTraceAction::Finished {
            writeback,
            product_complete,
            aborted,
        } => {
            assert!(!writeback);
            assert!(product_complete, "empty table is complete iff !aborted");
            assert!(!aborted);
        }
        other => panic!("expected Finished, got {other:?}"),
    }
    assert_eq!(query.finished_logs(), 1);
}

// ---------------------------------------------------------------------------
// P6-0: slot-0 accounting semantic fix — dedicated positives and negatives.
// ---------------------------------------------------------------------------

/// A fully accounted non-empty table must be product-complete (the P6-0
/// fix; the legacy walk could never reach this for non-empty tables).
#[test]
fn non_empty_full_table_is_product_complete() {
    let mut query = ScriptedQuery::scripted(REAL_API as u64, TRACE_SP as u64);
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    assert!(matches!(
        advance_to_next_slot(&mut query, &mut t).expect("arm slot 0"),
        IatTraceAction::TraceSlot { .. }
    ));
    assert!(matches!(
        handle_trace_step(&mut query, &mut t).expect("resolve slot 0"),
        IatTraceAction::TraceSlot { .. }
    ));
    match handle_trace_step(&mut query, &mut t).expect("resolve slot 1") {
        IatTraceAction::Finished {
            writeback,
            product_complete,
            aborted,
        } => {
            assert!(writeback);
            assert!(product_complete, "non-empty complete table");
            assert!(!aborted);
        }
        other => panic!("expected Finished, got {other:?}"),
    }
    assert_eq!(t.resolved_count, 2);
    assert_eq!(t.slots_accounted(), 2);
    assert_eq!(t.failed_count, 0);
    assert_eq!(t.skip_count, 0);
    assert!(t.product_complete());
}

/// An unaccounted slot (walk stopped with an armed-but-unresolved slot) is
/// never product-complete.
#[test]
fn unaccounted_walk_is_not_product_complete() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    assert!(matches!(
        advance_to_next_slot(&mut query, &mut t).expect("arm slot 0"),
        IatTraceAction::TraceSlot { .. }
    ));
    // Host aborts before the armed slot resolves: slot 0 stays unaccounted.
    t.abort("host aborted mid-walk (unaccounted slot)");
    assert_eq!(t.slots_accounted(), 0);
    assert_eq!(t.current_slot, 2);
    assert!(
        !t.product_complete(),
        "unaccounted slot must fail the invariant"
    );
}

/// Duplicate null terminators are validated skips — each counted exactly
/// once, never failed or resolved — and a fully-skipped table completes.
#[test]
fn duplicate_terminators_are_validated_skips() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    let mut t = trace(vec![0, 0]);
    match advance_to_next_slot(&mut query, &mut t).expect("advance") {
        IatTraceAction::Finished {
            writeback,
            product_complete,
            aborted,
        } => {
            assert!(!writeback, "no resolves, no writeback");
            assert!(product_complete, "all slots accounted as validated skips");
            assert!(!aborted);
        }
        other => panic!("expected Finished, got {other:?}"),
    }
    assert_eq!(t.skip_count, 2, "each terminator counted exactly once");
    assert_eq!(t.failed_count, 0);
    assert_eq!(t.resolved_count, 0);
    assert_eq!(t.slots_accounted(), 2);
    assert!(t.product_complete());
}

/// A short read discovered mid-walk must abort fail-closed, never reaching
/// product-complete.
#[test]
fn short_read_abort_never_complete() {
    let mut query = ScriptedQuery::scripted(THEMIDA_START as u64, TRACE_SP as u64);
    let mut t = trace(vec![THEMIDA_START, THEMIDA_START]);
    assert!(matches!(
        advance_to_next_slot(&mut query, &mut t).expect("arm slot 0"),
        IatTraceAction::TraceSlot { .. }
    ));
    // The host discovered a short IAT read: abort explicitly.
    t.abort("short read: requested 16 bytes, got 8");
    assert!(t.aborted);
    assert!(!t.product_complete());
    assert!(query.writes.is_empty());
}
