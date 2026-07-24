//! Packer plugin boundary (R2 Slice 3 / 3b).
//!
//! Family strategy lives behind [`PackerPlugin`]. Host (CLI) still owns Win32
//! operations; plugins mutate [`PluginCtx`] policy flags and return
//! [`PluginAdvice`] so the unpack loop can apply side-effects gradually.
//!
//! Boundaries (architecture contract):
//! - Plugins must not import `mida-acceptance` or set product verdicts.
//! - Plugins must not own process lifetime outside [`PluginAdvice`].
//! - Pure PE rebuild stays outside packer crates (host dump adapters only).
//! - `mida-core` stays free of `mida-pe` / packer crates: identify uses
//!   host-prepared [`IdentifyInput`], not PE parsers.

use crate::addr::{PreferredBase, RuntimeBase, Rva, Va};
use crate::debugger::ContinueStatus;
use crate::runtime_engine::EngineEvent;

/// Host-prepared static PE hints for plugin selection (no PE crate dependency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifyInput {
    pub is_64bit: bool,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    /// Section names as reported by the host PE model (may be blank post-Themida).
    pub section_names: Vec<String>,
}

/// Result of family identification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifyResult {
    /// Plugin claims this sample; `confidence` is 0..=100 (advisory only).
    Match { confidence: u8 },
    /// Explicit non-match.
    NoMatch,
    /// Incomplete hints; host may try another plugin or fall back.
    Ambiguous,
}

/// High-level unpack phase for transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnpackPhase {
    Observe,
    GuardActive,
    OepCandidate,
    IatTrace,
    Dump,
    Done,
}

/// Host-observed loop facts for policy refresh (no Win32, no PE).
///
/// Filled each iteration by CLI from [`LoopState`]-equivalent state; plugin
/// writes decision flags on [`PluginCtx`] via
/// [`PackerPlugin::refresh_loop_policy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostLoopFacts {
    pub text_polling: bool,
    pub guard_installed: bool,
    pub oep_known: bool,
    pub oep_via_scanning: bool,
    pub iat_trace_active: bool,
    /// v3 per-slot trace finished (`current_slot >= total_slots`).
    pub iat_trace_complete: bool,
    pub process_exited: bool,
}

/// Mutable context shared with a plugin across events.
///
/// Host fills **session hints** once before the loop. Plugin updates **policy
/// outputs** from [`PackerPlugin::on_event`], milestones, and
/// [`PackerPlugin::refresh_loop_policy`]. Host applies Win32.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCtx {
    pub runtime_base: Option<RuntimeBase>,
    pub preferred_base: Option<PreferredBase>,
    pub phase: UnpackPhase,
    pub oep_rva: Option<Rva>,
    // --- session hints (host → plugin) ---
    /// Target is a .NET assembly (COM descriptor present).
    pub is_dotnet: bool,
    /// Section 0 name is plain `.text` (not a virtualized Oreans section).
    pub section0_is_plain_text: bool,
    // --- path policy (plugin → host, CreateProcess) ---
    /// After CreateProcess: host should poll .text stability and defer guard.
    pub request_text_poll: bool,
    /// After CreateProcess: host should use CloseHandle HW-BP → guard chain.
    pub request_close_handle_chain: bool,
    // --- lifecycle ---
    /// ExitProcess (or equivalent) observed by plugin policy.
    pub process_exited: bool,
    /// Host reported code-section guard is live.
    pub guard_installed: bool,
    /// OEP came from memory scan / PE EP fallback (not live RIP/AV).
    pub oep_found_via_scanning: bool,
    // --- Slice 3b-3 loop decision flags (plugin → host) ---
    /// Prefer finite wait (see [`short_wait_ms`]) so text poll can run.
    pub prefer_short_wait: bool,
    /// Host may install CloseHandle HW BP on LoadDll (CloseHandle chain path).
    pub allow_close_handle_bp: bool,
    /// Host should exit the debug loop after current work (sticky once set).
    pub request_leave_debug_loop: bool,
    /// Why leave was requested (`None` if not leaving).
    pub leave_reason: Option<&'static str>,
    /// Skip v3 single-step IAT tracing (e.g. process already dead).
    pub skip_v3_iat_trace: bool,
    /// Idle timeout for .text poll (seconds after last debug event).
    pub text_poll_idle_timeout_secs: u64,
    /// IAT PAGE_NOACCESS monitor window after OEP (seconds).
    pub iat_monitor_timeout_secs: u64,
    /// Short wait used when [`prefer_short_wait`] is true (milliseconds).
    pub short_wait_ms: u32,
    // --- Slice 3b-4 AV / text-poll thresholds (plugin → host) ---
    /// Max virtualized-OEP redirects before accepting last PossibleOEP.
    pub virtualized_oep_max_retries: u32,
    /// Unrelated (non-guard) AV streak that counts as a storm escape.
    pub unrelated_av_storm_threshold: u32,
    /// Null-fault AV streak that counts as a storm (with `target_address == 0`).
    pub unrelated_av_null_storm_threshold: u32,
    /// Min non-zero bytes in a 16-byte .text sample before stability checks.
    pub text_poll_min_nonzero: u8,
}

impl Default for PluginCtx {
    fn default() -> Self {
        Self {
            runtime_base: None,
            preferred_base: None,
            phase: UnpackPhase::Observe,
            oep_rva: None,
            is_dotnet: false,
            section0_is_plain_text: false,
            request_text_poll: false,
            request_close_handle_chain: false,
            process_exited: false,
            guard_installed: false,
            oep_found_via_scanning: false,
            prefer_short_wait: false,
            allow_close_handle_bp: false,
            request_leave_debug_loop: false,
            leave_reason: None,
            skip_v3_iat_trace: false,
            // Themida/Oreans host defaults (historical CLI values).
            text_poll_idle_timeout_secs: 30,
            iat_monitor_timeout_secs: 5,
            short_wait_ms: 100,
            virtualized_oep_max_retries: 1000,
            unrelated_av_storm_threshold: 32,
            unrelated_av_null_storm_threshold: 8,
            text_poll_min_nonzero: 8,
        }
    }
}

impl PluginCtx {
    /// Ensure runtime base is recorded (CreateProcess or host image_base).
    pub fn ensure_runtime_base(&mut self, image_base: u64) {
        if self.runtime_base.is_none() && image_base != 0 {
            self.runtime_base = Some(RuntimeBase(image_base));
        }
    }

    /// Convert a live OEP VA to RVA using runtime base, then preferred base.
    pub fn oep_va_to_rva(&self, oep_va: u64) -> Option<Rva> {
        let va = Va(oep_va);
        if let Some(base) = self.runtime_base {
            if let Some(rva) = va.to_rva(base) {
                return Some(rva);
            }
        }
        if let Some(pref) = self.preferred_base {
            return va.to_rva_preferred(pref);
        }
        None
    }

    /// Sticky leave request with a static reason string.
    pub fn request_leave(&mut self, reason: &'static str) {
        self.request_leave_debug_loop = true;
        if self.leave_reason.is_none() {
            self.leave_reason = Some(reason);
        }
    }
}

/// Advice returned after an event (or for pump control later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginAdvice {
    /// Resume the target with this continue status.
    /// Host still runs its event handlers unless phase/flags already settled.
    Continue(ContinueStatus),
    /// Request a phase transition (IAT / dump / done).
    Transition(UnpackPhase),
    /// Abort unpack with a plugin-local message (not an acceptance verdict).
    Abort { message: String },
}

/// Optional heap-capture knobs from a plugin (host maps into dump options).
///
/// Keeps sample-private RVAs out of `mida-core`: plugins either request the
/// built-in AHK/GTO preset (`prefer_ahk_gto_defaults`) or pass explicit RVAs.
/// Host still owns profile gating (`AhkGtoExperimental` vs `OreansClassic`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CapturePolicyHint {
    /// Prefer host-side built-in AHK/GTO hot-root defaults when roots are empty.
    pub prefer_ahk_gto_defaults: bool,
    /// Explicit hot-root image RVAs (empty → leave for preset / profile resolve).
    pub hot_root_rvas: Vec<u32>,
    /// Subset allowed large size probes (empty → host default intersection).
    pub large_table_rvas: Vec<u32>,
    /// Primary script object root (None → host default when preset applies).
    pub gscript_root_rva: Option<u32>,
    /// Soft cap on gscript root content (0 → host default).
    pub gscript_root_content_cap: usize,
    /// Bytes of gscript blob scanned for first-hop edges (0 → host default).
    pub gscript_first_hop_span: usize,
    /// Size probe for first-hop children (0 → host default).
    pub gscript_first_hop_probe: usize,
    /// Multi-hop expand seed RVAs (empty → host default).
    pub hot_expand_seed_rvas: Vec<u32>,
}

/// Optional dump-time hints from the plugin (host still owns dump options).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpAdvice {
    pub entry_point_rva: Option<Rva>,
    /// Host may ignore; default dump path remains legacy unless CLI opts in.
    pub prefer_pure_rebuild: bool,
    pub note: &'static str,
    /// Heap/hot-root capture hint. `None` = host profile defaults only.
    pub capture_policy: Option<CapturePolicyHint>,
}

/// Family strategy surface for the runtime engine / thin CLI.
///
/// **3b-1:** `on_event` CreateProcess path. **3b-2:** milestones.
/// **3b-3:** [`refresh_loop_policy`] decision flags (leave / short-wait / BP).
/// **3b-4:** AV/text thresholds + dump-boundary `addr` types on host dump path.
/// **3b-5:** [`note_iat_trace_skipped`] for skip-v3 paths (vs full complete).
/// **3b-6:** host `plugin_host` unifies IAT-complete + dump-enter call sites.
/// Handler bodies remain in `cli/unpacker`.
pub trait PackerPlugin {
    /// Stable family id (e.g. `"oreans_themida"`).
    fn family_id(&self) -> &'static str;

    /// Static identification from host-prepared hints.
    fn identify(&self, input: &IdentifyInput) -> IdentifyResult;

    /// React to a delivered engine event.
    fn on_event(&mut self, ctx: &mut PluginCtx, event: &EngineEvent) -> PluginAdvice;

    /// Advise dump parameters when phase reaches dump (optional).
    fn dump_advice(&self, ctx: &PluginCtx) -> Option<DumpAdvice>;

    /// Recompute loop decision flags from host facts (call each iteration).
    ///
    /// Default: short-wait while text-polling; leave on scanned OEP / IAT done /
    /// process exit; CloseHandle BP when close-handle path and not text-polling.
    fn refresh_loop_policy(&mut self, ctx: &mut PluginCtx, facts: &HostLoopFacts) {
        ctx.prefer_short_wait =
            facts.text_polling && !facts.oep_known && !facts.iat_trace_active;

        ctx.allow_close_handle_bp = ctx.request_close_handle_chain
            && !facts.guard_installed
            && !facts.text_polling
            && !ctx.is_dotnet
            && !facts.oep_known;

        if facts.process_exited {
            ctx.process_exited = true;
            if facts.oep_known || facts.iat_trace_active {
                ctx.skip_v3_iat_trace = true;
            }
            ctx.request_leave("process_exited");
        }

        if facts.oep_known && facts.oep_via_scanning {
            ctx.request_leave("oep_via_scanning_frozen_dump");
        }

        if facts.iat_trace_complete {
            ctx.request_leave("iat_trace_complete");
        }
    }

    /// Host installed code-section guard (PAGE_NOACCESS / equivalent).
    fn note_guard_installed(&mut self, ctx: &mut PluginCtx) {
        ctx.guard_installed = true;
        if matches!(ctx.phase, UnpackPhase::Observe) {
            ctx.phase = UnpackPhase::GuardActive;
        }
    }

    /// Host accepted an OEP virtual address (live RIP, AV, or scan).
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
        PluginAdvice::Transition(UnpackPhase::OepCandidate)
    }

    /// Host entered v3 single-step IAT tracing.
    fn note_iat_trace_enter(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        ctx.phase = UnpackPhase::IatTrace;
        PluginAdvice::Transition(UnpackPhase::IatTrace)
    }

    /// Host finished IAT slot tracing (or skipped it) and should leave soon.
    fn note_iat_trace_complete(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        ctx.request_leave("iat_trace_complete");
        if !matches!(ctx.phase, UnpackPhase::Dump | UnpackPhase::Done) {
            ctx.phase = UnpackPhase::IatTrace;
        }
        PluginAdvice::Transition(UnpackPhase::IatTrace)
    }

    /// Host skipped v3 IAT single-step (dead process, context fail, no IAT, …).
    ///
    /// Sets [`PluginCtx::skip_v3_iat_trace`] and sticky leave. Distinct from
    /// [`note_iat_trace_complete`] so diagnostics can tell skip vs full trace.
    fn note_iat_trace_skipped(
        &mut self,
        ctx: &mut PluginCtx,
        reason: &'static str,
    ) -> PluginAdvice {
        ctx.skip_v3_iat_trace = true;
        ctx.request_leave(reason);
        if !matches!(ctx.phase, UnpackPhase::Dump | UnpackPhase::Done | UnpackPhase::IatTrace)
        {
            ctx.phase = UnpackPhase::IatTrace;
        }
        PluginAdvice::Transition(UnpackPhase::IatTrace)
    }

    /// Host is leaving the debug loop for IAT repair + dump emit.
    fn note_dump_enter(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        ctx.phase = UnpackPhase::Dump;
        ctx.request_leave("dump_enter");
        PluginAdvice::Transition(UnpackPhase::Dump)
    }
}

/// Default plugin: never matches, always continues. Useful as a null object.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullPackerPlugin;

impl PackerPlugin for NullPackerPlugin {
    fn family_id(&self) -> &'static str {
        "null"
    }

    fn identify(&self, _input: &IdentifyInput) -> IdentifyResult {
        IdentifyResult::NoMatch
    }

    fn on_event(&mut self, _ctx: &mut PluginCtx, _event: &EngineEvent) -> PluginAdvice {
        PluginAdvice::Continue(ContinueStatus::Continue)
    }

    fn dump_advice(&self, _ctx: &PluginCtx) -> Option<DumpAdvice> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debugger::DebugEvent;
    use crate::runtime_engine::{ReplayRuntimeEngine, RuntimeEngine};

    #[test]
    fn null_plugin_never_matches_always_continues() {
        let mut p = NullPackerPlugin;
        let input = IdentifyInput {
            is_64bit: true,
            entry_point_rva: 0x1000,
            size_of_image: 0x10000,
            section_names: vec![".text".into(), ".winlice".into()],
        };
        assert_eq!(p.identify(&input), IdentifyResult::NoMatch);
        assert_eq!(p.family_id(), "null");

        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 1 }]);
        let ev = eng.wait(None).unwrap();
        let mut ctx = PluginCtx::default();
        assert_eq!(
            p.on_event(&mut ctx, &ev),
            PluginAdvice::Continue(ContinueStatus::Continue)
        );
        assert!(p.dump_advice(&ctx).is_none());
    }

    #[test]
    fn dyn_plugin_object_safe() {
        let p: Box<dyn PackerPlugin> = Box::new(NullPackerPlugin);
        assert_eq!(p.family_id(), "null");
        let _ = p.identify(&IdentifyInput {
            is_64bit: false,
            entry_point_rva: 0,
            size_of_image: 0,
            section_names: vec![],
        });
    }

    #[test]
    fn plugin_ctx_session_hints_default_off() {
        let ctx = PluginCtx::default();
        assert!(!ctx.is_dotnet);
        assert!(!ctx.section0_is_plain_text);
        assert!(!ctx.request_text_poll);
        assert!(!ctx.request_close_handle_chain);
        assert!(!ctx.process_exited);
        assert!(!ctx.guard_installed);
        assert!(!ctx.oep_found_via_scanning);
        assert!(!ctx.prefer_short_wait);
        assert!(!ctx.allow_close_handle_bp);
        assert!(!ctx.request_leave_debug_loop);
        assert!(!ctx.skip_v3_iat_trace);
        assert_eq!(ctx.text_poll_idle_timeout_secs, 30);
        assert_eq!(ctx.iat_monitor_timeout_secs, 5);
        assert_eq!(ctx.short_wait_ms, 100);
        assert_eq!(ctx.virtualized_oep_max_retries, 1000);
        assert_eq!(ctx.unrelated_av_storm_threshold, 32);
        assert_eq!(ctx.unrelated_av_null_storm_threshold, 8);
        assert_eq!(ctx.text_poll_min_nonzero, 8);
    }

    #[test]
    fn milestone_helpers_advance_phase() {
        let mut p = NullPackerPlugin;
        let mut ctx = PluginCtx {
            runtime_base: Some(RuntimeBase(0x14000_0000)),
            preferred_base: Some(PreferredBase(0x14000_0000)),
            ..Default::default()
        };
        p.note_guard_installed(&mut ctx);
        assert!(ctx.guard_installed);
        assert_eq!(ctx.phase, UnpackPhase::GuardActive);

        let advice = p.note_oep_accepted(&mut ctx, 0x14000_13e0, false);
        assert_eq!(advice, PluginAdvice::Transition(UnpackPhase::OepCandidate));
        assert_eq!(ctx.oep_rva, Some(Rva(0x13e0)));
        assert_eq!(ctx.phase, UnpackPhase::OepCandidate);
        assert!(!ctx.request_leave_debug_loop);

        assert_eq!(
            p.note_iat_trace_enter(&mut ctx),
            PluginAdvice::Transition(UnpackPhase::IatTrace)
        );
        assert_eq!(
            p.note_dump_enter(&mut ctx),
            PluginAdvice::Transition(UnpackPhase::Dump)
        );
        assert_eq!(ctx.phase, UnpackPhase::Dump);
        assert!(ctx.request_leave_debug_loop);
    }

    #[test]
    fn note_iat_trace_skipped_sets_skip_and_leave() {
        let mut p = NullPackerPlugin;
        let mut ctx = PluginCtx {
            runtime_base: Some(RuntimeBase(0x14000_0000)),
            oep_rva: Some(Rva(0x13e0)),
            phase: UnpackPhase::OepCandidate,
            ..Default::default()
        };
        let advice = p.note_iat_trace_skipped(&mut ctx, "process_exited_skip_v3");
        assert_eq!(advice, PluginAdvice::Transition(UnpackPhase::IatTrace));
        assert!(ctx.skip_v3_iat_trace);
        assert!(ctx.request_leave_debug_loop);
        assert_eq!(ctx.leave_reason, Some("process_exited_skip_v3"));
        assert_eq!(ctx.phase, UnpackPhase::IatTrace);
    }

    #[test]
    fn oep_via_scan_requests_leave() {
        let mut p = NullPackerPlugin;
        let mut ctx = PluginCtx {
            runtime_base: Some(RuntimeBase(0x14000_0000)),
            ..Default::default()
        };
        p.note_oep_accepted(&mut ctx, 0x14000_2000, true);
        assert!(ctx.request_leave_debug_loop);
        assert_eq!(ctx.leave_reason, Some("oep_via_scanning_frozen_dump"));
    }

    #[test]
    fn refresh_loop_policy_short_wait_and_close_handle() {
        let mut p = NullPackerPlugin;
        let mut ctx = PluginCtx {
            request_close_handle_chain: true,
            ..Default::default()
        };
        p.refresh_loop_policy(
            &mut ctx,
            &HostLoopFacts {
                text_polling: true,
                ..Default::default()
            },
        );
        assert!(ctx.prefer_short_wait);
        assert!(!ctx.allow_close_handle_bp);

        p.refresh_loop_policy(
            &mut ctx,
            &HostLoopFacts {
                text_polling: false,
                guard_installed: false,
                ..Default::default()
            },
        );
        assert!(!ctx.prefer_short_wait);
        assert!(ctx.allow_close_handle_bp);
    }

    #[test]
    fn refresh_loop_policy_iat_complete_leaves() {
        let mut p = NullPackerPlugin;
        let mut ctx = PluginCtx::default();
        p.refresh_loop_policy(
            &mut ctx,
            &HostLoopFacts {
                iat_trace_complete: true,
                iat_trace_active: true,
                oep_known: true,
                ..Default::default()
            },
        );
        assert!(ctx.request_leave_debug_loop);
        assert_eq!(ctx.leave_reason, Some("iat_trace_complete"));
    }

    #[test]
    fn oep_va_to_rva_prefers_runtime_base() {
        let ctx = PluginCtx {
            runtime_base: Some(RuntimeBase(0x7ff6_c050_0000)),
            preferred_base: Some(PreferredBase(0x14000_0000)),
            ..Default::default()
        };
        assert_eq!(
            ctx.oep_va_to_rva(0x7ff6_c050_13e0),
            Some(Rva(0x13e0))
        );
    }
}
