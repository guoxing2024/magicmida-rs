//! Packer plugin boundary (R2 Slice 3 stub).
//!
//! Family strategy will live behind [`PackerPlugin`]. This module defines the
//! trait and shared types only — **no live unpacker is driven by plugins yet**.
//!
//! Boundaries (architecture contract):
//! - Plugins must not import `mida-acceptance` or set product verdicts.
//! - Plugins must not own process lifetime outside [`PluginAdvice`].
//! - Pure PE rebuild stays outside packer crates (host dump adapters only).
//! - `mida-core` stays free of `mida-pe` / packer crates: identify uses
//!   host-prepared [`IdentifyInput`], not PE parsers.

use crate::addr::{PreferredBase, RuntimeBase, Rva};
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

/// High-level unpack phase for transitions (stub vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnpackPhase {
    Observe,
    GuardActive,
    OepCandidate,
    IatTrace,
    Dump,
    Done,
}

/// Mutable context shared with a plugin across events (engine-owned later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCtx {
    pub runtime_base: Option<RuntimeBase>,
    pub preferred_base: Option<PreferredBase>,
    pub phase: UnpackPhase,
    pub oep_rva: Option<Rva>,
}

impl Default for PluginCtx {
    fn default() -> Self {
        Self {
            runtime_base: None,
            preferred_base: None,
            phase: UnpackPhase::Observe,
            oep_rva: None,
        }
    }
}

/// Advice returned after an event (or for pump control later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginAdvice {
    /// Resume the target with this continue status.
    Continue(ContinueStatus),
    /// Request a phase transition (IAT / dump / done).
    Transition(UnpackPhase),
    /// Abort unpack with a plugin-local message (not an acceptance verdict).
    Abort { message: String },
}

/// Optional dump-time hints from the plugin (host still owns dump options).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpAdvice {
    pub entry_point_rva: Option<Rva>,
    /// Host may ignore; default dump path remains legacy unless CLI opts in.
    pub prefer_pure_rebuild: bool,
    pub note: &'static str,
}

/// Family strategy surface for the runtime engine / thin CLI.
///
/// **Stub status:** CLI does not call this for control flow yet. Implementations
/// may exist for offline identify tests and future migration.
pub trait PackerPlugin {
    /// Stable family id (e.g. `"oreans_themida"`).
    fn family_id(&self) -> &'static str;

    /// Static identification from host-prepared hints.
    fn identify(&self, input: &IdentifyInput) -> IdentifyResult;

    /// React to a delivered engine event.
    ///
    /// Stub implementations typically return [`PluginAdvice::Continue`].
    fn on_event(&mut self, ctx: &mut PluginCtx, event: &EngineEvent) -> PluginAdvice;

    /// Advise dump parameters when phase reaches dump (optional).
    fn dump_advice(&self, ctx: &PluginCtx) -> Option<DumpAdvice>;
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
}
