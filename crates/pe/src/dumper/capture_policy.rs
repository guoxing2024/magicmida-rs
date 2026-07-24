//! Externalizable dump capture policy for heap-global / AHK-style roots.
//!
//! Hot RVAs and probe knobs used to be module-private constants. They remain
//! available as [`DumpCapturePolicy::ahk_gto_default`], but callers can pass a
//! custom policy via [`super::types::DumpOptions::capture_policy`] (future:
//! case manifest / plugin). Empty policy + AhkGtoExperimental still resolves
//! to the built-in AHK/GTO defaults so behaviour stays stable.

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
                0x148cb0,
                0x148ca8,
                0x148c98,
                0x148c00,
            ],
            large_table_rvas: vec![0x149d50, 0x141bf0, 0x148bf8, 0x148c00, 0x148c98],
            gscript_root_rva: Some(0x149d50),
            gscript_root_content_cap: 0x2000,
            gscript_first_hop_span: 0x200,
            gscript_first_hop_probe: 0x800,
            hot_expand_seed_rvas: vec![0x149d50, 0x18a898, 0x148cb8, 0x148cc0],
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
}
