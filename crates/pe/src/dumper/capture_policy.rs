//! Externalizable dump capture policy for heap-global / AHK-style roots.
//!
//! Hot RVAs and probe knobs used to be module-private constants. They remain
//! available as [`DumpCapturePolicy::ahk_gto_default`], but callers can pass a
//! custom policy via [`super::types::DumpOptions::capture_policy`] or map a
//! plugin [`mida_core::CapturePolicyHint`] with [`Self::from_plugin_hint`].
//! Empty policy + AhkGtoExperimental still resolves to the built-in AHK/GTO
//! defaults so behaviour stays stable.

use mida_core::CapturePolicyHint;

use super::types::DumpProfile;

/// Capture knobs for heap-global detection (xref seeds, size probes, gscript).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpCapturePolicy {
    /// Image RVAs force-seeded / preferred as hot roots (gscript, string tables…).
    pub hot_root_rvas: Vec<u32>,
    /// Subset allowed to use the large (hot) size probe ladder.
    pub large_table_rvas: Vec<u32>,
    /// Primary script object root (first-hop exhaust source).
    pub gscript_root_rva: Option<u32>,
    /// Soft cap on gscript root content after capture (0 → default 0x2000).
    pub gscript_root_content_cap: usize,
    /// Bytes of gscript blob scanned for first-hop edges (0 → default 0x200).
    pub gscript_first_hop_span: usize,
    /// Size probe for first-hop children (0 → default 0x800).
    pub gscript_first_hop_probe: usize,
    /// Image roots used as multi-hop expand seeds (empty → gscript + hot pair defaults).
    pub hot_expand_seed_rvas: Vec<u32>,
    /// `.data` RVAs of `RTL_CRITICAL_SECTION` objects to re-initialize in the
    /// dumped image (set `LockCount = -1`, zero `OwningThread`/`RecursionCount`/
    /// `LockSemaphore`). Captured CS bytes carry stale/zero lock state from the
    /// dumped process; a fresh loader enter would AV/deadlock. R-GTO-UI round 5.
    pub cs_reinit_rvas: Vec<u32>,
}

impl Default for DumpCapturePolicy {
    fn default() -> Self {
        Self {
            hot_root_rvas: Vec::new(),
            large_table_rvas: Vec::new(),
            gscript_root_rva: None,
            gscript_root_content_cap: 0,
            gscript_first_hop_span: 0,
            gscript_first_hop_probe: 0,
            hot_expand_seed_rvas: Vec::new(),
            cs_reinit_rvas: Vec::new(),
        }
    }
}

impl DumpCapturePolicy {
    /// Built-in AHK/GTO research defaults (former module constants).
    pub fn ahk_gto_default() -> Self {
        Self {
            hot_root_rvas: vec![
                0x149d50, // gscript / main script object
                0x18a898, // hot fill root (title path)
                0x141bf0, // AHK global object
                0x148bf8, // large table
                0x148cb8, // string capacity (pair with 0x148cc0)
                0x148cc0, // string table base
                0x148cb0, 0x148ca8, 0x148c98, 0x148c00,
            ],
            large_table_rvas: vec![0x149d50, 0x141bf0, 0x148bf8, 0x148c00, 0x148c98],
            gscript_root_rva: Some(0x149d50),
            // R-GTO-UI: 0x2000 truncated the live script object while GUI was up
            // (readable ≥0x20000). Cold restart then ExitProcess(0) without
            // NewClassName. 0x10000 keeps first-hop + more body; still under
            // MAX_HEAP_GLOBAL_BYTES (32 KiB) free-list swallow ceiling.
            gscript_root_content_cap: 0x20000,
            gscript_first_hop_span: 0x200,
            gscript_first_hop_probe: 0x800,
            hot_expand_seed_rvas: vec![0x149d50, 0x18a898, 0x148cb8, 0x148cc0],
            // R-GTO-UI round 5/7: WinMain enters a CRITICAL_SECTION at
            // `.data` RVA 0x145db0 that is zeroed in the dump; LockCount=0
            // (not -1) makes RtlEnterCriticalSection treat it as contended
            // and wait on a NULL LockSemaphore -> AV. Re-init to unlocked.
            cs_reinit_rvas: vec![0x145db0],
        }
    }

    /// Map a plugin [`CapturePolicyHint`] into a dump policy (pre-profile resolve).
    ///
    /// - Explicit RVAs always win.
    /// - `prefer_ahk_gto_defaults` with empty hot roots → full built-in preset.
    /// - Otherwise knobs copy through for later [`Self::resolve_for_profile`].
    pub fn from_plugin_hint(hint: &CapturePolicyHint) -> Self {
        if !hint.hot_root_rvas.is_empty() {
            return Self {
                hot_root_rvas: hint.hot_root_rvas.clone(),
                large_table_rvas: hint.large_table_rvas.clone(),
                gscript_root_rva: hint.gscript_root_rva,
                gscript_root_content_cap: hint.gscript_root_content_cap,
                gscript_first_hop_span: hint.gscript_first_hop_span,
                gscript_first_hop_probe: hint.gscript_first_hop_probe,
                hot_expand_seed_rvas: hint.hot_expand_seed_rvas.clone(),
                cs_reinit_rvas: Vec::new(),
            };
        }
        if hint.prefer_ahk_gto_defaults {
            let mut p = Self::ahk_gto_default();
            // Optional knob overrides on top of the preset.
            if hint.gscript_root_rva.is_some() {
                p.gscript_root_rva = hint.gscript_root_rva;
            }
            if hint.gscript_root_content_cap != 0 {
                p.gscript_root_content_cap = hint.gscript_root_content_cap;
            }
            if hint.gscript_first_hop_span != 0 {
                p.gscript_first_hop_span = hint.gscript_first_hop_span;
            }
            if hint.gscript_first_hop_probe != 0 {
                p.gscript_first_hop_probe = hint.gscript_first_hop_probe;
            }
            if !hint.large_table_rvas.is_empty() {
                p.large_table_rvas = hint.large_table_rvas.clone();
            }
            if !hint.hot_expand_seed_rvas.is_empty() {
                p.hot_expand_seed_rvas = hint.hot_expand_seed_rvas.clone();
            }
            return p;
        }
        Self {
            hot_root_rvas: Vec::new(),
            large_table_rvas: hint.large_table_rvas.clone(),
            gscript_root_rva: hint.gscript_root_rva,
            gscript_root_content_cap: hint.gscript_root_content_cap,
            gscript_first_hop_span: hint.gscript_first_hop_span,
            gscript_first_hop_probe: hint.gscript_first_hop_probe,
            hot_expand_seed_rvas: hint.hot_expand_seed_rvas.clone(),
            cs_reinit_rvas: Vec::new(),
        }
    }

    /// Host convenience: optional plugin hint + profile resolve.
    ///
    /// When `hint` is `None`, behaves like empty policy + profile (M2 path).
    /// When present, maps via [`Self::from_plugin_hint`] then resolves.
    pub fn resolve_with_plugin_hint(
        base: Self,
        hint: Option<&CapturePolicyHint>,
        profile: DumpProfile,
    ) -> Self {
        let policy = match hint {
            Some(h) => {
                // Explicit caller roots on DumpOptions win over plugin preset.
                if !base.hot_root_rvas.is_empty() {
                    base
                } else {
                    Self::from_plugin_hint(h)
                }
            }
            None => base,
        };
        policy.resolve_for_profile(profile)
    }

    /// Short label for snapshot sidecar / logs.
    pub fn source_label(&self) -> &'static str {
        if self.hot_root_rvas.is_empty() {
            "empty"
        } else if self == &Self::ahk_gto_default() {
            "ahk_gto_defaults"
        } else {
            "custom"
        }
    }

    /// Resolve empty / partial policy for the active dump profile.
    ///
    /// - `AhkGtoExperimental` + empty hot roots → full AHK/GTO defaults.
    /// - Otherwise fill zero knobs with AHK defaults only when those fields are 0
    ///   but hot roots are already set (partial override).
    pub fn resolve_for_profile(mut self, profile: DumpProfile) -> Self {
        if self.hot_root_rvas.is_empty() {
            return match profile {
                DumpProfile::AhkGtoExperimental => Self::ahk_gto_default(),
                DumpProfile::OreansClassic => self,
            };
        }
        let def = Self::ahk_gto_default();
        if self.gscript_root_rva.is_none() {
            self.gscript_root_rva = def.gscript_root_rva;
        }
        if self.gscript_root_content_cap == 0 {
            self.gscript_root_content_cap = def.gscript_root_content_cap;
        }
        if self.gscript_first_hop_span == 0 {
            self.gscript_first_hop_span = def.gscript_first_hop_span;
        }
        if self.gscript_first_hop_probe == 0 {
            self.gscript_first_hop_probe = def.gscript_first_hop_probe;
        }
        if self.hot_expand_seed_rvas.is_empty() {
            self.hot_expand_seed_rvas = def.hot_expand_seed_rvas;
        }
        if self.large_table_rvas.is_empty() {
            // Prefer intersection of hot roots with default large tables.
            self.large_table_rvas = def
                .large_table_rvas
                .into_iter()
                .filter(|r| self.hot_root_rvas.contains(r))
                .collect();
        }
        self
    }

    pub fn is_hot_root(&self, rva: u32) -> bool {
        self.hot_root_rvas.contains(&rva)
    }

    pub fn is_large_table(&self, rva: u32) -> bool {
        self.large_table_rvas.contains(&rva)
    }

    pub fn gscript_root(&self) -> Option<u32> {
        self.gscript_root_rva
    }

    pub fn gscript_content_cap(&self) -> usize {
        if self.gscript_root_content_cap == 0 {
            0x2000
        } else {
            self.gscript_root_content_cap
        }
    }

    pub fn first_hop_span(&self) -> usize {
        if self.gscript_first_hop_span == 0 {
            0x200
        } else {
            self.gscript_first_hop_span
        }
    }

    pub fn first_hop_probe(&self) -> usize {
        if self.gscript_first_hop_probe == 0 {
            0x800
        } else {
            self.gscript_first_hop_probe
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plus_ahk_profile_resolves_defaults() {
        let p = DumpCapturePolicy::default().resolve_for_profile(DumpProfile::AhkGtoExperimental);
        assert!(p.is_hot_root(0x149d50));
        assert!(p.is_large_table(0x141bf0));
        assert_eq!(p.gscript_root(), Some(0x149d50));
    }

    #[test]
    fn empty_plus_oreans_stays_empty() {
        let p = DumpCapturePolicy::default().resolve_for_profile(DumpProfile::OreansClassic);
        assert!(p.hot_root_rvas.is_empty());
    }

    #[test]
    fn custom_hot_roots_preserved() {
        let p = DumpCapturePolicy {
            hot_root_rvas: vec![0x1000],
            ..Default::default()
        }
        .resolve_for_profile(DumpProfile::AhkGtoExperimental);
        assert_eq!(p.hot_root_rvas, vec![0x1000]);
        assert_eq!(p.gscript_root(), Some(0x149d50)); // filled from defaults
    }

    #[test]
    fn plugin_hint_prefer_defaults_maps_preset() {
        let hint = CapturePolicyHint {
            prefer_ahk_gto_defaults: true,
            ..Default::default()
        };
        let p = DumpCapturePolicy::from_plugin_hint(&hint);
        assert_eq!(p, DumpCapturePolicy::ahk_gto_default());
        assert_eq!(p.source_label(), "ahk_gto_defaults");
    }

    #[test]
    fn plugin_hint_explicit_roots_win() {
        let hint = CapturePolicyHint {
            prefer_ahk_gto_defaults: true,
            hot_root_rvas: vec![0x2000, 0x3000],
            gscript_root_rva: Some(0x2000),
            ..Default::default()
        };
        let p = DumpCapturePolicy::from_plugin_hint(&hint)
            .resolve_for_profile(DumpProfile::AhkGtoExperimental);
        assert_eq!(p.hot_root_rvas, vec![0x2000, 0x3000]);
        assert_eq!(p.gscript_root(), Some(0x2000));
        assert_eq!(p.source_label(), "custom");
    }

    #[test]
    fn resolve_with_plugin_hint_none_matches_profile() {
        let p = DumpCapturePolicy::resolve_with_plugin_hint(
            DumpCapturePolicy::default(),
            None,
            DumpProfile::AhkGtoExperimental,
        );
        assert_eq!(p, DumpCapturePolicy::ahk_gto_default());
    }

    #[test]
    fn base_roots_override_plugin_preset() {
        let hint = CapturePolicyHint {
            prefer_ahk_gto_defaults: true,
            ..Default::default()
        };
        let base = DumpCapturePolicy {
            hot_root_rvas: vec![0x42],
            ..Default::default()
        };
        let p = DumpCapturePolicy::resolve_with_plugin_hint(
            base,
            Some(&hint),
            DumpProfile::AhkGtoExperimental,
        );
        assert_eq!(p.hot_root_rvas, vec![0x42]);
    }
}
