//! AHK/GTO [`PackerPlugin`] (R4-A0).
//!
//! Identify fingerprints from vault `gto_launcher` static layout (entry
//! section `.KI3`, scrambled section names, numbered `.dataN` payloads).
//! Identification and routing are available in the default build (G0): a
//! `gto_launcher`-shaped layout is recognized and routed to the AHK/GTO host.
//! The heavyweight recovery route (`run_gto_host` in `mida-cli`) still requires
//! the `gto-product-recovery` feature / `--profile=ahk-gto-experimental`; that
//! gate is not touched here. Live dump always requires explicit
//! `--profile=ahk-gto-experimental` on the host.

use mida_core::{
    ContinueStatus, DebugEvent, DumpAdvice, EngineEvent, HostLoopFacts, IdentifyInput,
    IdentifyResult, PackerPlugin, PluginAdvice, PluginCtx, RuntimeBase, UnpackPhase,
};

/// AHK/GTO family plugin.
#[derive(Debug, Default, Clone)]
pub struct AhkGtoPlugin {
    /// Last phase transition requested (tests / diagnostics).
    pub last_phase: Option<UnpackPhase>,
    /// Last identify confidence (0 if never matched).
    pub last_identify_confidence: u8,
}

impl AhkGtoPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Session defaults for GTO-style samples (host still owns Win32).
    ///
    /// Slightly longer IAT monitor window; storm thresholds stay conservative.
    pub fn apply_session_defaults(&self, ctx: &mut PluginCtx) {
        ctx.text_poll_idle_timeout_secs = 30;
        ctx.iat_monitor_timeout_secs = 10;
        ctx.short_wait_ms = 100;
        ctx.virtualized_oep_max_retries = 1000;
        ctx.unrelated_av_storm_threshold = 32;
        ctx.unrelated_av_null_storm_threshold = 8;
        ctx.text_poll_min_nonzero = 8;
    }

    /// Identify and record [`last_identify_confidence`].
    pub fn identify_record(&mut self, input: &IdentifyInput) -> IdentifyResult {
        let result = self.identify(input);
        self.last_identify_confidence = match &result {
            IdentifyResult::Match { confidence } => *confidence,
            IdentifyResult::Ambiguous => 1,
            IdentifyResult::NoMatch => 0,
        };
        result
    }

    /// Heuristic score from section names (0..=100).
    ///
    /// Identification is part of the default surface (G0): it must never be
    /// gated so that a default build can select the GTO family. The
    /// `gto-product-recovery` feature only gates the heavyweight recovery
    /// route, not recognition.
    fn score_sections(names: &[String]) -> u8 {
        let mut score = 0u8;
        let mut scrambled = 0u8;
        // Newer GTO packs (2026+) may drop `.KI3` and use numbered `.dataN` blobs.
        let mut numbered_data = 0u8;
        for n in names {
            let lower = n.to_ascii_lowercase();
            let trimmed = lower.trim();
            if trimmed == ".ki3" || trimmed.starts_with(".ki3") {
                score = score.saturating_add(50);
            } else if is_gto_numbered_data_section(trimmed) {
                numbered_data = numbered_data.saturating_add(1);
                // Still count as scrambled for the multi-scrambled bonus path.
                scrambled = scrambled.saturating_add(1);
            } else if is_scrambled_section_name(trimmed) {
                scrambled = scrambled.saturating_add(1);
            } else if is_oreans_marker(trimmed) {
                // Strong Oreans signal → push away from AHK/GTO match.
                return 0;
            }
        }
        // Two+ `.data0`/`.data1`/… sections are a strong AHK/GTO family marker
        // on samples without `.KI3` (Route H new protected input layout).
        if numbered_data >= 2 {
            score = score.saturating_add(45);
        }
        if scrambled >= 2 {
            score = score.saturating_add(30);
        } else if scrambled == 1 {
            score = score.saturating_add(15);
        }
        score.min(100)
    }

    fn apply_create_process_policy(ctx: &mut PluginCtx, image_base: u64) {
        ctx.runtime_base = Some(RuntimeBase(image_base));
        ctx.request_text_poll = false;
        ctx.request_close_handle_chain = false;

        if ctx.is_dotnet {
            ctx.phase = UnpackPhase::Observe;
            return;
        }

        // GTO often presents section0 as `.text` → text-poll / post-attach style.
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

/// GTO/Oreans negative-signal marker. Oreans section names always score 0 so a
/// real Oreans binary is never claimed by the GTO family.
fn is_oreans_marker(name: &str) -> bool {
    name == ".themida" || name == ".boot" || name == ".winlice" || name.starts_with(".winlic")
}

/// GTO numbered data payload sections (e.g. `.data0`, `.data1`, `.data2`).
fn is_gto_numbered_data_section(name: &str) -> bool {
    let n = name.trim();
    if !n.starts_with(".data") || n == ".data" {
        return false;
    }
    // `.data0`, `.data1`, … (digit suffix after ".data")
    n.as_bytes().get(5).is_some_and(|c| c.is_ascii_digit())
}

/// Non-standard PE section names (scrambled / placeholder).
fn is_scrambled_section_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') && name.len() <= 1 {
        return false;
    }
    // Standard-ish PE section names we should not treat as scrambled.
    const STANDARD: &[&str] = &[
        ".text", ".data", ".rdata", ".pdata", ".rsrc", ".reloc", ".tls", ".edata", ".idata",
        ".bss", ".xdata", ".CRT", ".crt", ".gfids", ".00cfg",
    ];
    let lower = name.to_ascii_lowercase();
    if STANDARD.iter().any(|s| lower == s.to_ascii_lowercase()) {
        return false;
    }
    if is_oreans_marker(&lower) {
        return false;
    }
    // Short alphanumeric packer names (e.g. .KI3) count as family markers via
    // the explicit .ki3 branch; other non-standard names count as scrambled.
    if lower == ".ki3" {
        return false;
    }
    true
}

impl PackerPlugin for AhkGtoPlugin {
    fn family_id(&self) -> &'static str {
        "ahk_gto"
    }

    fn identify(&self, input: &IdentifyInput) -> IdentifyResult {
        // Identification is always available (G0): a GTO-shaped layout can be
        // recognized and routed in the default build. The `gto-product-recovery`
        // feature gates the heavyweight recovery route only, not this match.
        let score = Self::score_sections(&input.section_names);
        if score >= 40 {
            return IdentifyResult::Match {
                confidence: score.min(100),
            };
        }
        if score > 0 {
            return IdentifyResult::Ambiguous;
        }
        IdentifyResult::NoMatch
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
                note: "ahk_gto: host must pass --profile=ahk-gto-experimental for heap/container stages",
                // Plugin owns the request for AHK capture defaults; host still
                // gates experimental stages on DumpProfile.
                capture_policy: Some(mida_core::CapturePolicyHint {
                    prefer_ahk_gto_defaults: true,
                    ..Default::default()
                }),
            })
        } else {
            None
        }
    }

    fn refresh_loop_policy(&mut self, ctx: &mut PluginCtx, facts: &HostLoopFacts) {
        ctx.prefer_short_wait = facts.text_polling && !facts.oep_known && !facts.iat_trace_active;

        ctx.allow_close_handle_bp = ctx.request_close_handle_chain
            && !facts.guard_installed
            && !facts.text_polling
            && !ctx.is_dotnet
            && !facts.oep_known;

        if facts.process_exited {
            ctx.process_exited = true;
            ctx.skip_v3_iat_trace = true;
            ctx.request_leave("process_exited");
        }

        if facts.oep_known && facts.oep_via_scanning {
            ctx.request_leave("oep_via_scanning_frozen_dump");
        }

        if facts.iat_trace_complete {
            ctx.request_leave("iat_trace_complete");
        }

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
    use mida_core::IdentifyResult;

    fn input(names: &[&str]) -> IdentifyInput {
        IdentifyInput {
            is_64bit: true,
            entry_point_rva: 0xbd5807,
            size_of_image: 0x1000000,
            section_names: names.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn family_id_is_ahk_gto() {
        assert_eq!(AhkGtoPlugin::new().family_id(), "ahk_gto");
    }

    // --- G0: identification is available in the default build ---

    #[test]
    fn gto_ki3_layout_matches() {
        // Vault gto_launcher section set (simplified).
        let r = AhkGtoPlugin::new().identify(&input(&[
            ".text", ".rdata", ".data", ".pdata", ".,\\W", ".|lT", ".KI3", ".rsrc",
        ]));
        match r {
            IdentifyResult::Match { confidence } => assert!(confidence >= 40, "conf={confidence}"),
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn ki3_alone_matches() {
        let r = AhkGtoPlugin::new().identify(&input(&[".text", ".KI3", ".rsrc"]));
        assert!(matches!(r, IdentifyResult::Match { confidence } if confidence >= 40));
    }

    #[test]
    fn numbered_data_sections_match_without_ki3() {
        // 2026-07-30 updated 启动器.exe layout (sha256 46539ea7…): no .KI3.
        let r = AhkGtoPlugin::new().identify(&input(&[
            ".text", ".rdata", ".data", ".pdata", "_RDATA", ".data0", ".data1", ".data2", ".rsrc",
        ]));
        match r {
            IdentifyResult::Match { confidence } => assert!(confidence >= 40, "conf={confidence}"),
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn identify_record_stores_confidence() {
        let mut p = AhkGtoPlugin::new();
        let _ = p.identify_record(&input(&[".KI3"]));
        assert!(p.last_identify_confidence >= 40);
        let _ = p.identify_record(&input(&[".text"]));
        assert_eq!(p.last_identify_confidence, 0);
    }

    #[test]
    fn oreans_themida_is_no_match() {
        let r = AhkGtoPlugin::new().identify(&input(&[".text", ".themida", ".boot"]));
        assert_eq!(r, IdentifyResult::NoMatch);
    }

    #[test]
    fn plain_pe_is_no_match() {
        let r = AhkGtoPlugin::new().identify(&input(&[".text", ".rdata", ".data", ".rsrc"]));
        assert_eq!(r, IdentifyResult::NoMatch);
    }

    /// G3-R1: a `.rdataN` numbered-payload layout (e.g. the current
    /// `启动器.exe` with `.rdata0/.rdata1/.rdata2` but NO `.KI3` and NO
    /// `.dataN`) is NOT a strong GTO match. It is Ambiguous at most, so a plain
    /// PE or an unrelated binary is never claimed as GTO from a section name
    /// alone. Extending `.rdataN` into a strong GTO signal requires
    /// characteristics/entropy/raw-virtual-size evidence, which `IdentifyInput`
    /// does not carry; that is a governance-gated change, not a silent one.
    #[test]
    fn rdata_numbered_payload_without_ki3_is_ambiguous_not_match() {
        // Mirrors the current real sample section set (no .KI3, no .dataN).
        let r = AhkGtoPlugin::new().identify(&input(&[
            ".text", ".rdata", ".data", ".pdata", ".fptable", ".rdata0", ".rdata1", ".rdata2",
            ".rsrc",
        ]));
        assert_eq!(
            r,
            IdentifyResult::Ambiguous,
            "a .rdataN payload with no .KI3/.dataN must stay Ambiguous (conservative)"
        );
        // A plain PE with a lone non-standard section is also not a Match.
        let plain = AhkGtoPlugin::new().identify(&input(&[".text", ".rdata", ".rdata1", ".rsrc"]));
        assert_eq!(plain, IdentifyResult::Ambiguous);
        assert!(!matches!(plain, IdentifyResult::Match { .. }));
    }

    /// G3-R1: `.dataN` numbered payload sections remain a strong GTO signal
    /// (existing behavior preserved) even without `.KI3`.
    #[test]
    fn data_numbered_payload_remains_match_without_ki3() {
        let r = AhkGtoPlugin::new().identify(&input(&[
            ".text", ".rdata", ".data", ".pdata", ".data0", ".data1", ".data2", ".rsrc",
        ]));
        assert!(matches!(r, IdentifyResult::Match { confidence } if confidence >= 40));
    }

    // --- gto-product-recovery: heavyweight recovery route tests only ---

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn dump_advice_notes_experimental_profile() {
        let p = AhkGtoPlugin::new();
        let mut ctx = PluginCtx::default();
        ctx.phase = UnpackPhase::Dump;
        let a = p.dump_advice(&ctx).expect("advice");
        assert!(a.note.contains("ahk-gto-experimental"));
        assert!(!a.prefer_pure_rebuild);
        let cap = a.capture_policy.expect("ahk capture hint");
        assert!(cap.prefer_ahk_gto_defaults);
        assert!(cap.hot_root_rvas.is_empty()); // host maps preset → built-in RVAs
    }

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn session_defaults_set_iat_monitor() {
        let p = AhkGtoPlugin::new();
        let mut ctx = PluginCtx::default();
        p.apply_session_defaults(&mut ctx);
        assert_eq!(ctx.iat_monitor_timeout_secs, 10);
    }
}
