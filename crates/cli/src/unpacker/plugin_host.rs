//! PackerPlugin host helpers (R2 3b + 3b-5/3b-6 + R4-A1).
//!
//! Mirrors [`LoopState`] into [`PluginCtx`] and recomputes loop decision flags.
//! Win32 / AV / IAT handler bodies stay in sibling modules.
//!
//! **3b-6:** unify IAT-complete + dump-enter so `mod.rs` call sites share one
//! milestone path (still no Win32).
//!
//! **R4-A1:** host holds a [`SelectedPacker`] (Oreans or AHK/GTO) and drives
//! milestones through the trait — not Themida-only.

use tracing::{debug, info};

use mida_core::{
    ContinueStatus, DumpAdvice, EngineEvent, HostLoopFacts, OepSource, PackerPlugin, PluginAdvice,
    PluginCtx, UnpackPhase,
};
#[cfg(feature = "gto-product-recovery")]
use mida_packers_ahk_gto::AhkGtoPlugin;
use mida_packers_themida::ThemidaPlugin;

use super::loop_state::LoopState;

/// Active family plugin for one unpack session (R4-A1).
///
/// Built after dual identify; dump experimental stages remain gated by CLI
/// [`mida_pe::DumpProfile`], not by this enum alone.
#[derive(Debug, Clone)]
pub(super) enum SelectedPacker {
    Oreans(ThemidaPlugin),
    #[cfg(feature = "gto-product-recovery")]
    AhkGto(AhkGtoPlugin),
}

impl SelectedPacker {
    #[must_use]
    pub(super) fn family_id(&self) -> &'static str {
        match self {
            Self::Oreans(p) => p.family_id(),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.family_id(),
        }
    }

    /// Whether this session should run Oreans V3-style IAT single-step fix.
    ///
    /// AHK/GTO uses live IAT rebuild at dump time (no Themida wrapper trace).
    #[must_use]
    pub(super) fn uses_oreans_iat_trace(&self) -> bool {
        matches!(self, Self::Oreans(_))
    }

    /// Apply family-specific session timeouts / thresholds.
    pub(super) fn apply_session_defaults(&self, ctx: &mut PluginCtx) {
        match self {
            Self::Oreans(p) => p.apply_session_defaults(ctx),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.apply_session_defaults(ctx),
        }
    }

    /// Last identify confidence recorded on the inner plugin (0 if unused).
    #[must_use]
    pub(super) fn last_identify_confidence(&self) -> u8 {
        match self {
            Self::Oreans(p) => p.last_identify_confidence,
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.last_identify_confidence,
        }
    }
}

/// Dual-identify Oreans vs AHK/GTO and build the session packer (R4-A1 / P1).
///
/// Call **before** process create so family selection is not after-the-fact.
/// Prefer Oreans on a clear Match; otherwise AHK/GTO Match; else default
/// Oreans host path. Identify never enables GTO dump stages by itself.
#[must_use]
pub(super) fn dual_select_packer(
    is_64bit: bool,
    entry_point_rva: u32,
    size_of_image: u32,
    section_names: Vec<String>,
) -> (
    SelectedPacker,
    mida_core::IdentifyResult,
    mida_core::IdentifyResult,
    &'static str,
) {
    let mut oreans_probe = ThemidaPlugin::new();
    #[cfg(feature = "gto-product-recovery")]
    let mut gto_probe = AhkGtoPlugin::new();
    let identify_input = mida_core::IdentifyInput {
        is_64bit,
        entry_point_rva,
        size_of_image,
        section_names,
    };
    let oreans_id = oreans_probe.identify_record(&identify_input);
    let gto_id = {
        #[cfg(feature = "gto-product-recovery")]
        {
            gto_probe.identify_record(&identify_input)
        }
        #[cfg(not(feature = "gto-product-recovery"))]
        {
            mida_core::IdentifyResult::NoMatch
        }
    };
    let family = select_packer_family(&oreans_id, &gto_id);
    let packer = match family {
        #[cfg(feature = "gto-product-recovery")]
        "ahk_gto" => SelectedPacker::AhkGto(gto_probe),
        _ => SelectedPacker::Oreans(oreans_probe),
    };
    (packer, oreans_id, gto_id, family)
}

/// Pick family id from dual identify results.
#[must_use]
pub(super) fn select_packer_family(
    oreans: &mida_core::IdentifyResult,
    gto: &mida_core::IdentifyResult,
) -> &'static str {
    let oreans_conf = match oreans {
        mida_core::IdentifyResult::Match { confidence } => *confidence,
        mida_core::IdentifyResult::Ambiguous => 1,
        mida_core::IdentifyResult::NoMatch => 0,
    };
    let gto_conf = match gto {
        mida_core::IdentifyResult::Match { confidence } => *confidence,
        mida_core::IdentifyResult::Ambiguous => 1,
        mida_core::IdentifyResult::NoMatch => 0,
    };
    if oreans_conf >= 40 && oreans_conf >= gto_conf {
        return "oreans_themida";
    }
    #[cfg(feature = "gto-product-recovery")]
    if gto_conf >= 40 {
        return "ahk_gto";
    }
    "oreans_themida"
}

impl PackerPlugin for SelectedPacker {
    fn family_id(&self) -> &'static str {
        SelectedPacker::family_id(self)
    }

    fn identify(&self, input: &mida_core::IdentifyInput) -> mida_core::IdentifyResult {
        match self {
            Self::Oreans(p) => p.identify(input),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.identify(input),
        }
    }

    fn on_event(&mut self, ctx: &mut PluginCtx, event: &EngineEvent) -> PluginAdvice {
        match self {
            Self::Oreans(p) => p.on_event(ctx, event),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.on_event(ctx, event),
        }
    }

    fn dump_advice(&self, ctx: &PluginCtx) -> Option<DumpAdvice> {
        match self {
            Self::Oreans(p) => p.dump_advice(ctx),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.dump_advice(ctx),
        }
    }

    fn refresh_loop_policy(&mut self, ctx: &mut PluginCtx, facts: &HostLoopFacts) {
        match self {
            Self::Oreans(p) => p.refresh_loop_policy(ctx, facts),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.refresh_loop_policy(ctx, facts),
        }
    }

    fn note_guard_installed(&mut self, ctx: &mut PluginCtx) {
        match self {
            Self::Oreans(p) => p.note_guard_installed(ctx),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.note_guard_installed(ctx),
        }
    }

    fn note_oep_accepted(
        &mut self,
        ctx: &mut PluginCtx,
        oep_va: u64,
        via_scanning: bool,
    ) -> PluginAdvice {
        match self {
            Self::Oreans(p) => p.note_oep_accepted(ctx, oep_va, via_scanning),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.note_oep_accepted(ctx, oep_va, via_scanning),
        }
    }

    fn note_iat_trace_enter(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        match self {
            Self::Oreans(p) => p.note_iat_trace_enter(ctx),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.note_iat_trace_enter(ctx),
        }
    }

    fn note_iat_trace_complete(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        match self {
            Self::Oreans(p) => p.note_iat_trace_complete(ctx),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.note_iat_trace_complete(ctx),
        }
    }

    fn note_iat_trace_skipped(
        &mut self,
        ctx: &mut PluginCtx,
        reason: &'static str,
    ) -> PluginAdvice {
        match self {
            Self::Oreans(p) => p.note_iat_trace_skipped(ctx, reason),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.note_iat_trace_skipped(ctx, reason),
        }
    }

    fn note_dump_enter(&mut self, ctx: &mut PluginCtx) -> PluginAdvice {
        match self {
            Self::Oreans(p) => p.note_dump_enter(ctx),
            #[cfg(feature = "gto-product-recovery")]
            Self::AhkGto(p) => p.note_dump_enter(ctx),
        }
    }
}

// Silence unused ContinueStatus when only re-exported via trait paths.
const _: ContinueStatus = ContinueStatus::Continue;

/// Build [`HostLoopFacts`] from current host loop state.
pub(super) fn host_loop_facts(ls: &LoopState) -> HostLoopFacts {
    // Product-complete only (resolved+failed+skipped==total, no abort, no fails).
    // Walking current_slot to total alone is NOT complete (audit residual P1).
    let iat_trace_complete = ls.iat_trace.as_ref().is_some_and(|t| t.product_complete());
    HostLoopFacts {
        text_polling: ls.text_polling,
        guard_installed: ls.guard_installed,
        oep_known: ls.oep.is_some(),
        oep_via_scanning: matches!(ls.oep_provenance.source, OepSource::ScanFallback),
        iat_trace_active: ls.iat_trace.is_some(),
        iat_trace_complete,
        process_exited: ls.process_exited,
    }
}

/// Recompute leave / short-wait / CloseHandle flags from current [`LoopState`].
pub(super) fn refresh_plugin_loop_policy(
    packer: &mut SelectedPacker,
    plugin_ctx: &mut PluginCtx,
    ls: &LoopState,
) {
    packer.refresh_loop_policy(plugin_ctx, &host_loop_facts(ls));
}

/// Mirror host [`LoopState`] milestones into [`PluginCtx`] without moving Win32.
///
/// Idempotent: only advances phase when host has new evidence (guard / OEP / IAT).
pub(super) fn sync_plugin_milestones(
    packer: &mut SelectedPacker,
    plugin_ctx: &mut PluginCtx,
    ls: &LoopState,
    image_base: u64,
) {
    plugin_ctx.ensure_runtime_base(image_base);

    if ls.guard_installed && !plugin_ctx.guard_installed {
        packer.note_guard_installed(plugin_ctx);
        debug!(
            phase = ?plugin_ctx.phase,
            family = packer.family_id(),
            "PackerPlugin: guard_installed"
        );
    }

    if let Some(oep_va) = ls.oep {
        let need_oep = plugin_ctx.oep_rva.is_none()
            || matches!(
                plugin_ctx.phase,
                UnpackPhase::Observe | UnpackPhase::GuardActive
            )
            || plugin_ctx.oep_provenance != ls.oep_provenance;
        if need_oep {
            let advice =
                packer.note_oep_accepted(plugin_ctx, oep_va as u64, ls.oep_found_via_scanning);
            // The packer hook remains backward-compatible; the provenance contract
            // is host-owned and must be recorded independently of that hook.
            plugin_ctx.record_oep_provenance(ls.oep_provenance.clone());
            debug!(
                ?advice,
                oep_rva = ?plugin_ctx.oep_rva,
                via_scan = ls.oep_found_via_scanning,
                family = packer.family_id(),
                "PackerPlugin: OEP accepted"
            );
        } else if plugin_ctx.oep_provenance != ls.oep_provenance {
            plugin_ctx.record_oep_provenance(ls.oep_provenance.clone());
        }
    }

    if ls.iat_trace.is_some()
        && !matches!(
            plugin_ctx.phase,
            UnpackPhase::IatTrace | UnpackPhase::Dump | UnpackPhase::Done
        )
    {
        let advice = packer.note_iat_trace_enter(plugin_ctx);
        debug!(
            ?advice,
            family = packer.family_id(),
            "PackerPlugin: IAT trace enter"
        );
    }

    // Keep process_exited flag aligned if host saw exit outside plugin consult.
    if ls.process_exited {
        plugin_ctx.process_exited = true;
        if ls.oep.is_some() {
            plugin_ctx.skip_v3_iat_trace = true;
        }
    }

    // 3b-3: refresh decision flags after milestone updates.
    refresh_plugin_loop_policy(packer, plugin_ctx, ls);
}

/// After [`AvAction::Break`]: record IAT complete vs skip, then ensure leave.
///
/// Does not run Win32 — only PackerPlugin milestones / leave flags.
pub(super) fn note_plugin_av_break(
    packer: &mut SelectedPacker,
    plugin_ctx: &mut PluginCtx,
    ls: &LoopState,
    image_base: u64,
) {
    sync_plugin_milestones(packer, plugin_ctx, ls, image_base);

    let iat_done = ls.iat_trace.as_ref().is_some_and(|t| t.product_complete());

    if iat_done {
        let advice = packer.note_iat_trace_complete(plugin_ctx);
        debug!(
            ?advice,
            family = packer.family_id(),
            "PackerPlugin: IAT product-complete (av break)"
        );
    } else if ls.oep.is_some() && ls.storm_escape_freeze && !ls.process_exited {
        // Process still alive after null-AV storm freeze: do not set
        // skip_v3_iat_trace — post-loop fix_iat_v3 will run on live slots.
        info!(
            oep = ?ls.oep.map(|a| format!("{a:#x}")),
            family = packer.family_id(),
            "PackerPlugin: storm_escape_freeze — defer IAT v3 to post-loop (live process)"
        );
    } else if ls.oep.is_some() {
        // OEP known but v3 not finished: skipped (dead process / fail / no IAT).
        let reason = if ls.process_exited {
            "process_exited_skip_v3"
        } else if ls.iat_trace.is_none() {
            "iat_not_started_or_detection_failed"
        } else {
            "iat_trace_aborted"
        };
        let advice = packer.note_iat_trace_skipped(plugin_ctx, reason);
        info!(
            ?advice,
            reason,
            process_exited = ls.process_exited,
            family = packer.family_id(),
            "PackerPlugin: IAT v3 skipped"
        );
    }

    refresh_plugin_loop_policy(packer, plugin_ctx, ls);
    if !plugin_ctx.request_leave_debug_loop {
        plugin_ctx.request_leave("av_handler_break");
    }
}

/// Host finished v3 IAT single-step (all slots done). Sticky leave via complete.
///
/// Call from SingleStep path when `current_slot >= total_slots`. Does not Win32.
pub(super) fn note_plugin_iat_complete(packer: &mut SelectedPacker, plugin_ctx: &mut PluginCtx) {
    let advice = packer.note_iat_trace_complete(plugin_ctx);
    debug!(
        ?advice,
        family = packer.family_id(),
        "PackerPlugin: IAT trace complete"
    );
}

/// Enter dump phase and log [`DumpAdvice`] (post-attach / post-loop shared path).
///
/// Returns the advice for callers that still need it at dump emit boundary.
pub(super) fn enter_dump_phase(
    packer: &mut SelectedPacker,
    plugin_ctx: &mut PluginCtx,
    log_label: &'static str,
) -> Option<DumpAdvice> {
    let phase_advice = packer.note_dump_enter(plugin_ctx);
    debug!(
        ?phase_advice,
        label = log_label,
        family = packer.family_id(),
        "PackerPlugin: dump enter"
    );
    let advice = packer.dump_advice(plugin_ctx);
    if let Some(ref a) = advice {
        info!(
            oep_rva = ?a.entry_point_rva,
            pure = a.prefer_pure_rebuild,
            via_scan = plugin_ctx.oep_found_via_scanning,
            note = a.note,
            family = packer.family_id(),
            "{log_label}"
        );
    }
    advice
}

/// Sticky leave reason if plugin already requested leave (`None` = stay).
#[must_use]
pub(super) fn plugin_leave_reason(plugin_ctx: &PluginCtx) -> Option<&'static str> {
    if plugin_ctx.request_leave_debug_loop {
        Some(plugin_ctx.leave_reason.unwrap_or("unspecified"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_core::IdentifyResult;

    #[test]
    fn selected_oreans_family_id() {
        let p = SelectedPacker::Oreans(ThemidaPlugin::new());
        assert_eq!(p.family_id(), "oreans_themida");
    }

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn selected_gto_family_id() {
        let p = SelectedPacker::AhkGto(AhkGtoPlugin::new());
        assert_eq!(p.family_id(), "ahk_gto");
    }

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn selected_gto_dump_advice_notes_profile() {
        let p = SelectedPacker::AhkGto(AhkGtoPlugin::new());
        let mut ctx = PluginCtx::default();
        ctx.phase = UnpackPhase::Dump;
        let a = p.dump_advice(&ctx).expect("advice");
        assert!(a.note.contains("ahk-gto-experimental"));
    }

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn selected_dispatches_identify() {
        let p = SelectedPacker::AhkGto(AhkGtoPlugin::new());
        let r = p.identify(&mida_core::IdentifyInput {
            is_64bit: true,
            entry_point_rva: 0x1,
            size_of_image: 0x1000,
            section_names: vec![".KI3".into()],
        });
        assert!(matches!(r, IdentifyResult::Match { confidence } if confidence >= 40));
    }

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn dual_select_gto_from_ki3_sections() {
        let (packer, _o, g, fam) = dual_select_packer(
            true,
            0x1000,
            0x200_0000,
            vec![".text".into(), ".KI3".into(), ".,\\W".into(), ".|lT".into()],
        );
        assert_eq!(fam, "ahk_gto");
        assert_eq!(packer.family_id(), "ahk_gto");
        assert!(!packer.uses_oreans_iat_trace());
        assert!(matches!(g, IdentifyResult::Match { confidence } if confidence >= 40));
    }

    #[cfg(not(feature = "gto-product-recovery"))]
    #[test]
    fn selected_gto_identify_is_disabled_by_default() {
        let (packer, _o, g, fam) = dual_select_packer(
            true,
            0x1000,
            0x200_0000,
            vec![".text".into(), ".KI3".into(), ".,\\W".into(), ".|lT".into()],
        );
        assert_eq!(fam, "oreans_themida");
        assert_eq!(packer.family_id(), "oreans_themida");
        assert_eq!(g, IdentifyResult::NoMatch);
    }

    #[cfg(not(feature = "gto-product-recovery"))]
    #[test]
    fn dual_select_ki3_defaults_to_oreans_when_gto_disabled() {
        let (packer, _o, g, fam) = dual_select_packer(
            true,
            0x1000,
            0x200_0000,
            vec![".text".into(), ".KI3".into(), ".,\\W".into(), ".|lT".into()],
        );
        assert_eq!(fam, "oreans_themida");
        assert_eq!(packer.family_id(), "oreans_themida");
        assert!(packer.uses_oreans_iat_trace());
        assert_eq!(g, IdentifyResult::NoMatch);
    }

    #[test]
    fn dual_select_oreans_from_themida_marker() {
        let (packer, o, _g, fam) = dual_select_packer(
            true,
            0x1000,
            0x100_0000,
            vec![".text".into(), ".themida".into(), ".boot".into()],
        );
        assert_eq!(fam, "oreans_themida");
        assert_eq!(packer.family_id(), "oreans_themida");
        assert!(packer.uses_oreans_iat_trace());
        assert!(matches!(o, IdentifyResult::Match { confidence } if confidence >= 40));
    }

    #[test]
    fn select_prefers_oreans_when_both_match_higher() {
        assert_eq!(
            select_packer_family(
                &IdentifyResult::Match { confidence: 80 },
                &IdentifyResult::Match { confidence: 50 },
            ),
            "oreans_themida"
        );
    }

    #[cfg(feature = "gto-product-recovery")]
    #[test]
    fn select_gto_when_only_gto_matches() {
        assert_eq!(
            select_packer_family(
                &IdentifyResult::NoMatch,
                &IdentifyResult::Match { confidence: 80 },
            ),
            "ahk_gto"
        );
    }

    #[test]
    fn sync_plugin_milestones_propagates_runtime_oep_provenance() {
        // P8-B: the host must propagate the runtime OEP provenance from the
        // loop state into the plugin context (source/VA/RVA), and must not let
        // a later sync overwrite a confirmed provenance with an unknown one.
        use crate::unpacker::loop_state::LoopState;
        use mida_core::{OepProvenance, RuntimeBase, Rva};

        let mut packer = SelectedPacker::Oreans(ThemidaPlugin::new());
        let mut ctx = PluginCtx::default();
        let mut ls = LoopState::default();
        ls.oep = Some(0x14000_13e0usize);
        ls.oep_provenance = OepProvenance::trace(
            0x14000_13e0,
            "runtime PossibleOEP confirmed as application prologue",
        );
        ls.oep_found_via_scanning = false;

        sync_plugin_milestones(&mut packer, &mut ctx, &ls, 0x14000_0000);

        assert_eq!(ctx.oep_provenance.source, mida_core::OepSource::Trace);
        assert_eq!(ctx.oep_provenance.va, Some(0x14000_13e0));
        assert_eq!(ctx.oep_provenance.rva, Some(0x13e0));
        assert_eq!(ctx.oep_rva, Some(Rva(0x13e0)));
        assert!(!ctx.oep_found_via_scanning);
        assert!(ctx.oep_provenance.application_oep);

        // A second sync with an identical provenance must not clobber it.
        sync_plugin_milestones(&mut packer, &mut ctx, &ls, 0x14000_0000);
        assert_eq!(ctx.oep_provenance.source, mida_core::OepSource::Trace);
        assert_eq!(ctx.oep_provenance.rva, Some(0x13e0));

        // The runtime_base helper must be set so the RVA derivation holds.
        assert_eq!(ctx.runtime_base, Some(RuntimeBase(0x14000_0000)));
    }

    #[test]
    fn sync_plugin_milestones_does_not_downgrade_unknown_to_fabricated_rva() {
        // A provenance that never established a runtime VA must not gain a
        // fabricated RVA just because the image base is known.
        use crate::unpacker::loop_state::LoopState;
        use mida_core::OepProvenance;

        let mut packer = SelectedPacker::Oreans(ThemidaPlugin::new());
        let mut ctx = PluginCtx::default();
        let mut ls = LoopState::default();
        ls.oep = Some(0x14000_13e0usize);
        ls.oep_provenance = OepProvenance::unknown("no trustworthy OEP");
        ls.oep_found_via_scanning = true;

        sync_plugin_milestones(&mut packer, &mut ctx, &ls, 0x14000_0000);

        assert_eq!(ctx.oep_provenance.source, mida_core::OepSource::Unknown);
        assert_eq!(ctx.oep_provenance.va, None);
        assert_eq!(ctx.oep_provenance.rva, None);
    }
}
