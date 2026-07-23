//! Themida / Oreans [`PackerPlugin`] stub (R2 Slice 3).
//!
//! Offline identify only. The live unpacker in `mida-cli` still owns the debug
//! loop; this type does **not** drive OEP/IAT/dump yet.

use mida_core::{
    DumpAdvice, EngineEvent, IdentifyInput, IdentifyResult, PackerPlugin, PluginAdvice,
    PluginCtx, UnpackPhase, ContinueStatus,
};

/// Oreans/Themida family plugin stub.
#[derive(Debug, Default, Clone)]
pub struct ThemidaPlugin {
    /// Last phase transition requested via [`PackerPlugin::on_event`] (tests).
    pub last_phase: Option<UnpackPhase>,
}

impl ThemidaPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Heuristic: known Oreans section names or blank-heavy layout with EP in first section range.
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
                // Themida often wipes names; weak signal only.
                score = score.saturating_add(2);
            }
        }
        score.min(100)
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
        // Stub: record CreateProcess runtime base; always continue.
        // Live policy remains in cli/unpacker until Slice 3 migration.
        if let mida_core::DebugEvent::CreateProcess { image_base, .. } = &event.event {
            ctx.runtime_base = Some(mida_core::RuntimeBase(*image_base));
        }
        if let mida_core::DebugEvent::ExitProcess { .. } = &event.event {
            ctx.phase = UnpackPhase::Done;
            self.last_phase = Some(UnpackPhase::Done);
            return PluginAdvice::Transition(UnpackPhase::Done);
        }
        PluginAdvice::Continue(ContinueStatus::Continue)
    }

    fn dump_advice(&self, ctx: &PluginCtx) -> Option<DumpAdvice> {
        if ctx.phase == UnpackPhase::Dump || ctx.oep_rva.is_some() {
            Some(DumpAdvice {
                entry_point_rva: ctx.oep_rva,
                prefer_pure_rebuild: false,
                note: "themida stub: host owns dump options; pure remains opt-in",
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_core::{DebugEvent, IdentifyResult, PackerPlugin, PluginCtx, UnpackPhase, Rva};
    use mida_core::{EngineEvent, RuntimeBase};

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
        // No CreateProcess yet
        assert!(matches!(
            p.on_event(&mut ctx, &ev),
            PluginAdvice::Continue(_)
        ));

        let create = EngineEvent {
            sequence: 2,
            event: DebugEvent::CreateProcess {
                process_id: 1,
                thread_id: 2,
                image_base: 0x7ff6_c050_0000,
                h_thread: windows::Win32::Foundation::HANDLE::default(),
                h_process: windows::Win32::Foundation::HANDLE::default(),
                h_file: windows::Win32::Foundation::HANDLE::default(),
            },
        };
        p.on_event(&mut ctx, &create);
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
    }
}
