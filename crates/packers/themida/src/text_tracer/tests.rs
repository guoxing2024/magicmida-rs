//! Tests for [`super`] text-trace decision logic.

use super::*;

#[test]
fn decide_continue_while_in_themida() {
    // IP inside Themida section → keep walking.
    assert_eq!(
        decide_text_trace_step(
            0x140005000, // ip: inside themida
            0x0010_0000, // sp: same as start (not nested)
            0x0010_0000, // trace_start_sp
            0x140004000, // themida_start
            0x140009000, // themida_end
            0x140001000, // text_start
            0x140004000, // text_end
            0x7FFE_0000, // sleep_api
            0x7FFE_1000, // lstrlen_api
            false,       // is_vm_entry
            0,
        ),
        TextTraceDecision::Continue,
    );
}

#[test]
fn decide_candidate_when_in_text_not_vm() {
    // IP inside .text, not VM entry → candidate.
    assert_eq!(
        decide_text_trace_step(
            0x1400013E0, // ip: inside .text (after themida)
            0x0010_0000, // sp
            0x0010_0000, // trace_start_sp
            0x140004000, // themida_start
            0x140009000, // themida_end
            0x140001000, // text_start
            0x140004000, // text_end
            0x7FFE_0000,
            0x7FFE_1000,
            false, // NOT vm entry
            0,
        ),
        TextTraceDecision::CandidateRealOep { ip: 0x1400013E0 },
    );
}

#[test]
fn decide_continue_if_text_but_vm_entry() {
    // IP inside .text BUT is the VM entry → not a real OEP.  Keep walking.
    assert_eq!(
        decide_text_trace_step(
            0x140002000,
            0x0010_0000,
            0x0010_0000,
            0x140004000,
            0x140009000,
            0x140001000,
            0x140004000,
            0x7FFE_0000,
            0x7FFE_1000,
            true, // IS vm entry
            0,
        ),
        TextTraceDecision::Continue,
    );
}

#[test]
fn decide_skip_anti_trace_sleep() {
    assert_eq!(
        decide_text_trace_step(
            0x7FFE_0000, // ip == sleep_api
            0x000F_F000, // sp: below trace_start_sp → nested
            0x0010_0000, // trace_start_sp
            0x140004000,
            0x140009000,
            0x140001000,
            0x140004000,
            0x7FFE_0000,
            0x7FFE_1000,
            false,
            0x14004321, // return_addr to pop
        ),
        TextTraceDecision::SkipAntiTraceApi {
            ip: 0x7FFE_0000,
            ret_addr: 0x14004321,
        },
    );
}

#[test]
fn decide_no_skip_when_sp_at_start() {
    // IP matches Sleep but sp == trace_start_sp → NOT inside a nested
    // call → we're genuinely executing Sleep → keep walking.
    assert_eq!(
        decide_text_trace_step(
            0x7FFE_0000, // ip == sleep_api
            0x0010_0000, // sp: == trace_start_sp → NOT nested
            0x0010_0000, // trace_start_sp
            0x140004000,
            0x140009000,
            0x140001000,
            0x140004000,
            0x7FFE_0000,
            0x7FFE_1000,
            false,
            0,
        ),
        TextTraceDecision::Continue,
    );
}

#[test]
fn decide_continue_outside_themida_outside_text() {
    // IP outside both Themida and .text (e.g. import resolver helper) → keep walking.
    assert_eq!(
        decide_text_trace_step(
            0x7FFE_0000, // ip: outside image completely
            0x0010_0000,
            0x0010_0000,
            0x140004000,
            0x140009000,
            0x140001000,
            0x140004000,
            0x7FFE_0000,
            0x7FFE_1000,
            false,
            0,
        ),
        TextTraceDecision::Continue,
    );
}
