//! Themida / Oreans [`PackerPlugin`] (R2 Slice 3b + R3-prep offline harness).
//!
//! Offline identify + live **event→policy** (CreateProcess / ExitProcess),
//! **host-reported milestones** (guard / OEP / IAT / dump), **loop decision
//! flags** ([`PackerPlugin::refresh_loop_policy`]), **3b-4** AV/text thresholds,
//! **3b-5/3b-6** skip-vs-complete IAT + dump-enter host helpers, and **offline
//! replay** tests against [`mida_core::ReplayRuntimeEngine`].
//! CLI still owns Win32.

use mida_core::{
    ContinueStatus, DebugEvent, DumpAdvice, EngineEvent, HostLoopFacts, IdentifyInput,
    IdentifyResult, PackerPlugin, PluginAdvice, PluginCtx, RuntimeBase, UnpackPhase,
};

/// Oreans/Themida family plugin.
#[derive(Debug, Default, Clone)]
pub struct ThemidaPlugin {
    /// Last phase transition requested (tests / diagnostics).
    pub last_phase: Option<UnpackPhase>,
    /// Last identify confidence (0 if never matched).
    pub last_identify_confidence: u8,
}

impl ThemidaPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply Themida host timeout / threshold defaults into a fresh session ctx.
    pub fn apply_session_defaults(&self, ctx: &mut PluginCtx) {
        ctx.text_poll_idle_timeout_secs = 30;
        ctx.iat_monitor_timeout_secs = 5;
        ctx.short_wait_ms = 100;
        // Historical CLI constants (behavior-preserving).
        ctx.virtualized_oep_max_retries = 1000;
        ctx.unrelated_av_storm_threshold = 32;
        ctx.unrelated_av_null_storm_threshold = 8;
        ctx.text_poll_min_nonzero = 8;
    }

    /// Identify and record [`last_identify_confidence`] for diagnostics / R3 prep.
    pub fn identify_record(&mut self, input: &IdentifyInput) -> IdentifyResult {
        let result = self.identify(input);
        self.last_identify_confidence = match &result {
            IdentifyResult::Match { confidence } => *confidence,
            IdentifyResult::Ambiguous => 1,
            IdentifyResult::NoMatch => 0,
        };
        result
    }

    /// Heuristic: known Oreans section names or blank-heavy layout.
    fn score_sections(names: &[String]) -> u8 {
        let mut score = 0u8;
        for n in names {
            let lower = n.to_ascii_lowercase();
            let trimmed = lower.trim();
            if trimmed == ".winlice" || trimmed.starts_with(".winlic") {
                score = score.saturating_add(40);
            } else if trimmed == ".boot" {
                score = score.saturating_add(25);
            } else if trimmed == ".themida" {
                score = score.saturating_add(40);
            } else if trimmed.is_empty() {
                score = score.saturating_add(2);
            }
        }
        score.min(100)
    }

    /// CreateProcess guard-path policy (mirrors prior cli/unpacker logic).
    fn apply_create_process_policy(ctx: &mut PluginCtx, image_base: u64) {
        ctx.runtime_base = Some(RuntimeBase(image_base));
        ctx.request_text_poll = false;
        ctx.request_close_handle_chain = false;

        if ctx.is_dotnet {
            ctx.phase = UnpackPhase::Observe;
            return;
        }

        if ctx.section0_is_plain_text {
            ctx.request_text_poll = true;
            ctx.phase = UnpackPhase::Observe;
        } else {
            ctx.request_close_handle_chain = true;
            ctx.phase = UnpackPhase::GuardActive;
        }
    }

    fn record_phase(&mut self, phase: UnpackPhase) {
        self.last_phase = Some(phase);
    }
}

impl PackerPlugin for ThemidaPlugin {
    fn family_id(&self) -> &'static str {
        "oreans_themida"
    }

    fn identify(&self, input: &IdentifyInput) -> IdentifyResult {
        let score = Self::score_sections(&input.section_names);
        if score >= 40 {
            IdentifyResult::Match {
                confidence: score.min(100),
            }
        } else if score > 0 {
            IdentifyResult::Ambiguous
        } else {
            IdentifyResult::NoMatch
        }
    }

    fn on_event(&mut self, ctx: &mut PluginCtx, event: &EngineEvent) -> PluginAdvice {
        match &event.event {
            DebugEvent::CreateProcess { image_base, .. } => {
                Self::apply_create_process_policy(ctx, *image_base);
                self.record_phase(ctx.phase);
                PluginAdvice::Continue(ContinueStatus::Continue)
            }
            DebugEvent::ExitProcess { .. } => {
                ctx.phase = UnpackPhase::Done;
                ctx.process_exited = true;
                // With OEP already known, dump with residual IAT; otherwise still leave.
                ctx.request_leave("exit_process");
                if ctx.oep_rva.is_some() {
                    ctx.skip_v3_iat_trace = true;
                }
                self.record_phase(UnpackPhase::Done);
                PluginAdvice::Transition(UnpackPhase::Done)
            }
            _ => PluginAdvice::Continue(ContinueStatus::Continue),
        }
    }

    fn dump_advice(&self, ctx: &PluginCtx) -> Option<DumpAdvice> {
        if matches!(
            ctx.phase,
            UnpackPhase::Dump | UnpackPhase::OepCandidate | UnpackPhase::IatTrace
        ) || ctx.oep_rva.is_some()
        {
            Some(DumpAdvice {
                entry_point_rva: ctx.oep_rva,
                prefer_pure_rebuild: false,
                note: "themida: host owns dump options; pure remains opt-in",
            })
        } else {
            None
        }
    }

    fn refresh_loop_policy(&mut self, ctx: &mut PluginCtx, facts: &HostLoopFacts) {
        // Shared default policy, then Themida-specific tweaks.
        // (Call default body inline — traits cannot easily super-call.)
        ctx.prefer_short_wait =
            facts.text_polling && !facts.oep_known && !facts.iat_trace_active;

        ctx.allow_close_handle_bp = ctx.request_close_handle_chain
            && !facts.guard_installed
            && !facts.text_polling
            && !ctx.is_dotnet
            && !facts.oep_known;

        if facts.process_exited {
            ctx.process_exited = true;
            // Dead debuggee: never hang in v3 single-step.
            ctx.skip_v3_iat_trace = true;
            ctx.request_leave("process_exited");
        }

        if facts.oep_known && facts.oep_via_scanning {
            // Frozen process dump (no ResumeThread after scan).
            ctx.request_leave("oep_via_scanning_frozen_dump");
        }

        if facts.iat_trace_complete {
            ctx.request_leave("iat_trace_complete");
        }

        // Once OEP is known via live path, short-wait is unnecessary.
        if facts.oep_known && !facts.oep_via_scanning {
            ctx.prefer_short_wait = false;
        }
    }

    fn note_guard_installed(&mut self, ctx: &mut PluginCtx) {
        ctx.guard_installed = true;
        if matches!(ctx.phase, UnpackPhase::Observe) {
            ctx.phase = UnpackPhase::GuardActive;
        }
        self.record_phase(ctx.phase);
    }

    fn note_oep_accepted(
        &mut self,
        ctx: &mut PluginCtx,
        oep_va: u64,
        via_scanning: bool,
    ) -> PluginAdvice {
        ctx.oep_found_via_scanning = via_scanning;
        if let Some(rva) = ctx.oep_va_to_rva(oep_va) {
            ctx.oep_rva = Some(rva);
        }
        ctx.phase = UnpackPhase::OepCandidate;
        ctx.request_text_poll = false;
        if via_scanning {
            ctx.request_leave("oep_via_scanning_frozen_dump");
        }
        self.record_phase(UnpackPhase::OepCandidate);
        PluginAdvice::Transition(UnpackPhase::OepCandidate)
    }

    fn note_iat_trace_enter(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        ctx.phase = UnpackPhase::IatTrace;
        self.record_phase(UnpackPhase::IatTrace);
        PluginAdvice::Transition(UnpackPhase::IatTrace)
    }

    fn note_iat_trace_complete(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        ctx.request_leave("iat_trace_complete");
        if !matches!(ctx.phase, UnpackPhase::Dump | UnpackPhase::Done) {
            ctx.phase = UnpackPhase::IatTrace;
        }
        self.record_phase(ctx.phase);
        PluginAdvice::Transition(UnpackPhase::IatTrace)
    }

    fn note_iat_trace_skipped(
        &mut self,
        ctx: &mut PluginCtx,
        reason: &'static str,
    ) -> PluginAdvice {
        ctx.skip_v3_iat_trace = true;
        ctx.request_leave(reason);
        if !matches!(
            ctx.phase,
            UnpackPhase::Dump | UnpackPhase::Done | UnpackPhase::IatTrace
        ) {
            ctx.phase = UnpackPhase::IatTrace;
        }
        self.record_phase(ctx.phase);
        PluginAdvice::Transition(UnpackPhase::IatTrace)
    }

    fn note_dump_enter(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        ctx.phase = UnpackPhase::Dump;
        ctx.request_leave("dump_enter");
        self.record_phase(UnpackPhase::Dump);
        PluginAdvice::Transition(UnpackPhase::Dump)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_core::{
        DebugEvent, EngineEvent, HostLoopFacts, IdentifyResult, PackerPlugin, PluginCtx,
        PreferredBase, RuntimeBase, Rva, UnpackPhase,
    };

    fn create_process_ev(image_base: u64) -> EngineEvent {
        EngineEvent {
            sequence: 1,
            event: DebugEvent::CreateProcess {
                process_id: 1,
                thread_id: 2,
                image_base,
                h_thread: windows::Win32::Foundation::HANDLE::default(),
                h_process: windows::Win32::Foundation::HANDLE::default(),
                h_file: windows::Win32::Foundation::HANDLE::default(),
            },
        }
    }

    #[test]
    fn identify_winlice_boot_is_match() {
        let p = ThemidaPlugin::new();
        let r = p.identify(&IdentifyInput {
            is_64bit: true,
            entry_point_rva: 0x13e0,
            size_of_image: 0xd1c000,
            section_names: vec![
                ".text".into(),
                ".winlice".into(),
                ".boot".into(),
                ".reloc".into(),
            ],
        });
        match r {
            IdentifyResult::Match { confidence } => assert!(confidence >= 40, "{confidence}"),
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn identify_plain_pe_no_match() {
        let p = ThemidaPlugin::new();
        let r = p.identify(&IdentifyInput {
            is_64bit: true,
            entry_point_rva: 0x1000,
            size_of_image: 0x10000,
            section_names: vec![".text".into(), ".rdata".into(), ".data".into()],
        });
        assert_eq!(r, IdentifyResult::NoMatch);
    }

    #[test]
    fn create_process_plain_text_requests_text_poll() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            section0_is_plain_text: true,
            is_dotnet: false,
            ..Default::default()
        };
        let advice = p.on_event(&mut ctx, &create_process_ev(0x7ff6_c050_0000));
        assert!(matches!(advice, PluginAdvice::Continue(_)));
        assert_eq!(ctx.runtime_base, Some(RuntimeBase(0x7ff6_c050_0000)));
        assert!(ctx.request_text_poll);
        assert!(!ctx.request_close_handle_chain);
        assert_eq!(ctx.phase, UnpackPhase::Observe);
    }

    #[test]
    fn create_process_non_text_requests_close_handle_chain() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            section0_is_plain_text: false,
            is_dotnet: false,
            ..Default::default()
        };
        let advice = p.on_event(&mut ctx, &create_process_ev(0x14000_0000));
        assert!(matches!(advice, PluginAdvice::Continue(_)));
        assert!(!ctx.request_text_poll);
        assert!(ctx.request_close_handle_chain);
        assert_eq!(ctx.phase, UnpackPhase::GuardActive);
    }

    #[test]
    fn create_process_dotnet_skips_both_paths() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            section0_is_plain_text: true,
            is_dotnet: true,
            ..Default::default()
        };
        p.on_event(&mut ctx, &create_process_ev(0x1000_0000));
        assert!(!ctx.request_text_poll);
        assert!(!ctx.request_close_handle_chain);
        assert_eq!(ctx.phase, UnpackPhase::Observe);
    }

    #[test]
    fn on_event_sets_runtime_base_and_continues() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx::default();
        let ev = EngineEvent {
            sequence: 1,
            event: DebugEvent::Breakpoint {
                thread_id: 1,
                address: 0x140001000,
            },
        };
        assert!(matches!(
            p.on_event(&mut ctx, &ev),
            PluginAdvice::Continue(_)
        ));

        p.on_event(&mut ctx, &create_process_ev(0x7ff6_c050_0000));
        assert_eq!(ctx.runtime_base, Some(RuntimeBase(0x7ff6_c050_0000)));
    }

    #[test]
    fn dump_advice_when_oep_set() {
        let p = ThemidaPlugin::new();
        let mut ctx = PluginCtx::default();
        assert!(p.dump_advice(&ctx).is_none());
        ctx.oep_rva = Some(Rva(0x13e0));
        let d = p.dump_advice(&ctx).expect("advice");
        assert_eq!(d.entry_point_rva, Some(Rva(0x13e0)));
        assert!(!d.prefer_pure_rebuild);
    }

    #[test]
    fn exit_process_transitions_done() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx::default();
        let ev = EngineEvent {
            sequence: 9,
            event: DebugEvent::ExitProcess { exit_code: 0 },
        };
        assert_eq!(
            p.on_event(&mut ctx, &ev),
            PluginAdvice::Transition(UnpackPhase::Done)
        );
        assert_eq!(ctx.phase, UnpackPhase::Done);
        assert!(ctx.process_exited);
        assert!(ctx.request_leave_debug_loop);
        assert_eq!(ctx.leave_reason, Some("exit_process"));
    }

    #[test]
    fn milestones_guard_oep_iat_dump() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            runtime_base: Some(RuntimeBase(0x7ff6_c050_0000)),
            preferred_base: Some(PreferredBase(0x14000_0000)),
            section0_is_plain_text: true,
            ..Default::default()
        };
        p.on_event(&mut ctx, &create_process_ev(0x7ff6_c050_0000));
        assert!(ctx.request_text_poll);

        p.note_guard_installed(&mut ctx);
        assert!(ctx.guard_installed);

        let advice = p.note_oep_accepted(&mut ctx, 0x7ff6_c050_13e0, false);
        assert_eq!(advice, PluginAdvice::Transition(UnpackPhase::OepCandidate));
        assert_eq!(ctx.oep_rva, Some(Rva(0x13e0)));
        assert!(!ctx.request_text_poll);
        assert_eq!(p.last_phase, Some(UnpackPhase::OepCandidate));

        p.note_iat_trace_enter(&mut ctx);
        assert_eq!(ctx.phase, UnpackPhase::IatTrace);

        p.note_dump_enter(&mut ctx);
        assert_eq!(ctx.phase, UnpackPhase::Dump);
        let d = p.dump_advice(&ctx).expect("dump advice");
        assert_eq!(d.entry_point_rva, Some(Rva(0x13e0)));
        assert!(!d.prefer_pure_rebuild);
    }

    #[test]
    fn oep_via_scanning_flag() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            runtime_base: Some(RuntimeBase(0x14000_0000)),
            ..Default::default()
        };
        p.note_oep_accepted(&mut ctx, 0x14000_2000, true);
        assert!(ctx.oep_found_via_scanning);
        assert_eq!(ctx.oep_rva, Some(Rva(0x2000)));
        assert_eq!(ctx.leave_reason, Some("oep_via_scanning_frozen_dump"));
    }

    #[test]
    fn loop_policy_close_handle_vs_text_poll() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx::default();
        p.apply_session_defaults(&mut ctx);
        ctx.section0_is_plain_text = false;
        p.on_event(&mut ctx, &create_process_ev(0x14000_0000));
        assert!(ctx.request_close_handle_chain);

        p.refresh_loop_policy(
            &mut ctx,
            &HostLoopFacts {
                text_polling: false,
                guard_installed: false,
                ..Default::default()
            },
        );
        assert!(ctx.allow_close_handle_bp);
        assert!(!ctx.prefer_short_wait);

        // After text-poll path CreateProcess
        let mut ctx2 = PluginCtx {
            section0_is_plain_text: true,
            ..Default::default()
        };
        p.apply_session_defaults(&mut ctx2);
        p.on_event(&mut ctx2, &create_process_ev(0x14000_0000));
        p.refresh_loop_policy(
            &mut ctx2,
            &HostLoopFacts {
                text_polling: true,
                ..Default::default()
            },
        );
        assert!(ctx2.prefer_short_wait);
        assert!(!ctx2.allow_close_handle_bp);
    }

    #[test]
    fn process_exited_skips_v3_and_leaves() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            oep_rva: Some(Rva(0x13e0)),
            phase: UnpackPhase::OepCandidate,
            ..Default::default()
        };
        p.refresh_loop_policy(
            &mut ctx,
            &HostLoopFacts {
                oep_known: true,
                process_exited: true,
                ..Default::default()
            },
        );
        assert!(ctx.skip_v3_iat_trace);
        assert!(ctx.request_leave_debug_loop);
    }

    #[test]
    fn note_iat_trace_skipped_records_phase() {
        let mut p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            oep_rva: Some(Rva(0x1656f4)),
            phase: UnpackPhase::OepCandidate,
            ..Default::default()
        };
        p.note_iat_trace_skipped(&mut ctx, "process_exited_skip_v3");
        assert!(ctx.skip_v3_iat_trace);
        assert_eq!(ctx.leave_reason, Some("process_exited_skip_v3"));
        assert_eq!(p.last_phase, Some(UnpackPhase::IatTrace));
    }

    #[test]
    fn session_defaults_include_3b4_thresholds() {
        let p = ThemidaPlugin::new();
        let mut ctx = PluginCtx {
            // Pretend something else mutated them first.
            virtualized_oep_max_retries: 1,
            unrelated_av_storm_threshold: 1,
            unrelated_av_null_storm_threshold: 1,
            text_poll_min_nonzero: 1,
            ..Default::default()
        };
        p.apply_session_defaults(&mut ctx);
        assert_eq!(ctx.virtualized_oep_max_retries, 1000);
        assert_eq!(ctx.unrelated_av_storm_threshold, 32);
        assert_eq!(ctx.unrelated_av_null_storm_threshold, 8);
        assert_eq!(ctx.text_poll_min_nonzero, 8);
        assert_eq!(ctx.text_poll_idle_timeout_secs, 30);
        assert_eq!(ctx.iat_monitor_timeout_secs, 5);
        assert_eq!(ctx.short_wait_ms, 100);
    }

    #[test]
    fn identify_record_stores_confidence() {
        let mut p = ThemidaPlugin::new();
        let r = p.identify_record(&IdentifyInput {
            is_64bit: true,
            entry_point_rva: 0x13e0,
            size_of_image: 0xd1c000,
            section_names: vec![".text".into(), ".winlice".into(), ".boot".into()],
        });
        assert!(matches!(r, IdentifyResult::Match { .. }));
        assert!(p.last_identify_confidence >= 40);
    }

    /// R3-prep: ThemidaPlugin + ReplayRuntimeEngine (no Win32) through
    /// create → LoadDll → guard AV → OEP → exit, with scripted memory.
    #[test]
    fn offline_replay_guard_oep_themida_plugin() {
        use mida_core::{
            guard_oep_event_script, ContinueStatus, DebugEvent, HostLoopFacts, PackerPlugin,
            PluginAdvice, PluginCtx, PreferredBase, ReplayMemory, ReplayRuntimeEngine,
            RuntimeEngine, Rva, UnpackPhase,
        };

        let base = 0x7ff6_c050_0000u64;
        let oep_rva = 0x13e0u32;
        let mut mem = ReplayMemory::new();
        mem.map(base + 0x1000, vec![0xcc; 16]);
        mem.map(
            base + u64::from(oep_rva),
            vec![0x48, 0x83, 0xec, 0x28, 0x90, 0x90, 0x90, 0x90],
        );

        let mut eng =
            ReplayRuntimeEngine::with_memory(guard_oep_event_script(base, oep_rva, 2), mem);
        let mut packer = ThemidaPlugin::new();
        let id = packer.identify_record(&IdentifyInput {
            is_64bit: true,
            entry_point_rva: oep_rva,
            size_of_image: 0xd1c000,
            section_names: vec![
                ".winlice".into(), // non-plain section0 → CloseHandle path
                ".boot".into(),
            ],
        });
        assert!(matches!(id, IdentifyResult::Match { .. }));
        assert!(packer.last_identify_confidence >= 40);

        let mut ctx = PluginCtx {
            preferred_base: Some(PreferredBase(0x14000_0000)),
            // Mirror identify layout: first section is Oreans virtualized, not plain .text.
            section0_is_plain_text: false,
            is_dotnet: false,
            ..Default::default()
        };
        packer.apply_session_defaults(&mut ctx);

        let mut phases = Vec::new();
        while eng.remaining() > 0 {
            let ev = eng.wait(None).unwrap();
            let advice = packer.on_event(&mut ctx, &ev);
            match &ev.event {
                DebugEvent::CreateProcess { .. } => {
                    phases.push("create");
                    assert!(matches!(advice, PluginAdvice::Continue(_)));
                    assert!(ctx.request_close_handle_chain);
                    assert!(!ctx.request_text_poll);
                    assert_eq!(ctx.runtime_base.map(|b| b.get()), Some(base));
                }
                DebugEvent::LoadDll { .. } => {
                    phases.push("load_dll");
                    packer.refresh_loop_policy(
                        &mut ctx,
                        &HostLoopFacts {
                            text_polling: false,
                            guard_installed: false,
                            ..Default::default()
                        },
                    );
                    assert!(ctx.allow_close_handle_bp);
                }
                DebugEvent::AccessViolation {
                    address,
                    exc_type: 8,
                    ..
                } => {
                    phases.push("guard_av");
                    let mut sample = [0u8; 4];
                    eng.read_memory(*address as usize, &mut sample).unwrap();
                    assert_eq!(sample, [0xcc; 4]);
                    packer.note_guard_installed(&mut ctx);
                }
                DebugEvent::Breakpoint { address, .. } => {
                    phases.push("oep_bp");
                    let advice = packer.note_oep_accepted(&mut ctx, *address, false);
                    assert_eq!(
                        advice,
                        PluginAdvice::Transition(UnpackPhase::OepCandidate)
                    );
                    assert_eq!(ctx.oep_rva, Some(Rva(oep_rva)));
                    let d = packer.dump_advice(&ctx).expect("dump advice after OEP");
                    assert_eq!(d.entry_point_rva, Some(Rva(oep_rva)));
                    assert!(!d.prefer_pure_rebuild);
                }
                DebugEvent::ExitProcess { .. } => {
                    phases.push("exit");
                    assert_eq!(
                        advice,
                        PluginAdvice::Transition(UnpackPhase::Done)
                    );
                    assert!(ctx.skip_v3_iat_trace);
                    assert!(ctx.request_leave_debug_loop);
                    assert_eq!(ctx.leave_reason, Some("exit_process"));
                }
                _ => phases.push("other"),
            }
            eng.continue_event(ContinueStatus::Continue).unwrap();
        }

        assert_eq!(
            phases,
            ["create", "load_dll", "guard_av", "oep_bp", "exit"]
        );
        assert_eq!(packer.last_phase, Some(UnpackPhase::Done));
        assert!(eng.process_exited());
    }

    /// R3-path: Lunlun-like — OEP via scanning + process exit → skip_v3 + dump.
    ///
    /// Mirrors live `note_iat_trace_skipped(process_exited_skip_v3)` without Win32.
    #[test]
    fn offline_replay_skip_v3_dump_after_scanned_oep() {
        use mida_core::{
            guard_oep_event_script, ContinueStatus, DebugEvent, HostLoopFacts, PackerPlugin,
            PluginAdvice, PluginCtx, PreferredBase, ReplayMemory, ReplayRuntimeEngine,
            RuntimeEngine, Rva, UnpackPhase,
        };

        // Lunlun-shaped EP from live smokes (not a PE claim — scripted VA only).
        let base = 0x14000_0000u64;
        let oep_rva = 0x1656f4u32;
        let mut mem = ReplayMemory::new();
        mem.map(base + 0x1000, vec![0xcc; 16]);
        mem.map(
            base + u64::from(oep_rva),
            vec![0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83],
        );

        let mut eng =
            ReplayRuntimeEngine::with_memory(guard_oep_event_script(base, oep_rva, 2), mem);
        let mut packer = ThemidaPlugin::new();
        let id = packer.identify_record(&IdentifyInput {
            is_64bit: true,
            entry_point_rva: oep_rva,
            size_of_image: 0xc60000,
            section_names: vec![".text".into(), ".themida".into(), ".boot".into()],
        });
        assert!(matches!(id, IdentifyResult::Match { .. }));

        let mut ctx = PluginCtx {
            preferred_base: Some(PreferredBase(base)),
            section0_is_plain_text: true,
            ..Default::default()
        };
        packer.apply_session_defaults(&mut ctx);

        // Drive create → guard → OEP (via_scan=true) → exit.
        while eng.remaining() > 0 {
            let ev = eng.wait(None).unwrap();
            let _ = packer.on_event(&mut ctx, &ev);
            match &ev.event {
                DebugEvent::AccessViolation { .. } => {
                    packer.note_guard_installed(&mut ctx);
                }
                DebugEvent::Breakpoint { address, .. } => {
                    let advice = packer.note_oep_accepted(&mut ctx, *address, true);
                    assert_eq!(
                        advice,
                        PluginAdvice::Transition(UnpackPhase::OepCandidate)
                    );
                    assert!(ctx.oep_found_via_scanning);
                    assert_eq!(ctx.oep_rva, Some(Rva(oep_rva)));
                }
                DebugEvent::ExitProcess { .. } => {
                    // Host would call note_iat_trace_skipped after dead process.
                    let skip = packer.note_iat_trace_skipped(&mut ctx, "process_exited_skip_v3");
                    assert_eq!(skip, PluginAdvice::Transition(UnpackPhase::IatTrace));
                    assert!(ctx.skip_v3_iat_trace);
                    packer.refresh_loop_policy(
                        &mut ctx,
                        &HostLoopFacts {
                            oep_known: true,
                            oep_via_scanning: true,
                            process_exited: true,
                            ..Default::default()
                        },
                    );
                    assert!(ctx.request_leave_debug_loop);
                    let dump = packer.note_dump_enter(&mut ctx);
                    assert_eq!(dump, PluginAdvice::Transition(UnpackPhase::Dump));
                    let advice = packer.dump_advice(&ctx).expect("dump after skip");
                    assert_eq!(advice.entry_point_rva, Some(Rva(oep_rva)));
                    assert!(!advice.prefer_pure_rebuild);
                }
                _ => {}
            }
            eng.continue_event(ContinueStatus::Continue).unwrap();
        }

        assert_eq!(ctx.phase, UnpackPhase::Dump);
        assert!(eng.process_exited());
        assert_eq!(packer.last_phase, Some(UnpackPhase::Dump));
    }
}
