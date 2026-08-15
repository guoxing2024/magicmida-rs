//! Externalizable dump capture policy for heap-global / AHK-style roots.
//! Route B R1: minimal changes for CS re-init, per-object hot-root additions, label-name exact-graph, path allocator cold-init.
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
    /// Optional runtime cookie mirror: before OEP transfer, copy QWORD at
    /// `cookie_mirror_src_rva` → `cookie_mirror_dst_rva` (both image RVAs).
    /// R-GTO-UI round 9: AHK call-obfuscation cookie @0x1454b8 must match the
    /// live MSVC `__security_cookie` (LOAD_CONFIG randomizes 0x141020 before
    /// any code runs). Dump plant of DEFAULT is not enough.
    pub cookie_mirror_src_rva: Option<u32>,
    pub cookie_mirror_dst_rva: Option<u32>,

    // MIDA-SERIAL-14: identity-bound policy gate. `None` binding means the
    // sample-specific RVA fields below are inert (generic behavior only).
    /// Optional module binding: when `Some`, sample-specific RVAs may activate
    /// only for an exactly matching [`ModuleIdentity`].
    pub module_binding: Option<super::module_identity::ModuleIdentity>,
    /// Explicit policy revision (integer). Mismatch rejects sample-specific
    /// activation; `0` is the unversioned default.
    pub policy_revision: u32,
    /// SHA-256 (hex) over the canonical policy content (revision + binding +
    /// all sample-specific + behavior-affecting generic fields). Empty string
    /// means "not computed". An externally supplied digest that differs from
    /// the recomputed value fails closed.
    pub policy_digest: String,
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
            cookie_mirror_src_rva: None,
            cookie_mirror_dst_rva: None,
            module_binding: None,
            policy_revision: 0,
            policy_digest: String::new(),
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
                // R-GTO-UI r19: DO NOT hot-capture 0x148cb0/cb8/cc0 — those are
                // AHK SimpleHeap bump-allocator control slots (0xb9410). Dump-time
                // exhausted arenas make WinMain path copy (0xb9360) fail → error
                // reporter AV. Leave NULL so cold start runs 0xb94a0 init.
                0x148ca8, 0x148c98, 0x148c00,
                // Route B R2: per-object hot-root addition for cmd/dispatch table (label-name exact-graph completion)
                0x147868,
                // R-GTO-UI r12: WinMain cmd/dispatch pointer table (store @0x36d0a).
                // Null → AV at 0x5747a `mov rcx,[rax+rcx*8]` after MessageBox path.
            ],
            // 0x147868: cmd/dispatch table (count @0x147888); needs large probe.
            large_table_rvas: vec![0x149d50, 0x141bf0, 0x148bf8, 0x148c00, 0x148c98, 0x147868],
            gscript_root_rva: Some(0x149d50),
            // R-GTO-UI: 0x2000 truncated the live script object while GUI was up
            // (readable ≥0x20000). Cold restart then ExitProcess(0) without
            // NewClassName. 0x10000 keeps first-hop + more body; still under
            // MAX_HEAP_GLOBAL_BYTES (32 KiB) free-list swallow ceiling.
            gscript_root_content_cap: 0x20000,
            gscript_first_hop_span: 0x200,
            gscript_first_hop_probe: 0x800,
            hot_expand_seed_rvas: vec![0x149d50, 0x18a898],
            // R-GTO-UI round 5/7: WinMain enters a CRITICAL_SECTION at
            // `.data` RVA 0x145db0 that is zeroed in the dump; LockCount=0
            // (not -1) makes RtlEnterCriticalSection treat it as contended
            // and wait on a NULL LockSemaphore -> AV. Re-init to unlocked.
            // R-GTO-UI r24: after RegisterClass, CreateWindow path takes
            // MSVC locale/MT lock via 0xe1e18 table @0x141040 (stride 0x58,
            // CS at +0x30). Slot1 CS @0x1410c8 had LockCount=0 → RtlEnter CS AV.
            // Keep 0x145db0 (WinMain) and re-init locale table locks.
            cs_reinit_rvas: vec![
                0x145db0, 0x141070, 0x1410c8, 0x141120, 0x141178, 0x1411d0, 0x141228, 0x141280,
                0x1412d8, 0x141330, 0x141388, 0x1413e0, 0x141438, 0x141490, 0x1414e8, 0x141540,
                0x141598, 0x1415f0, 0x141648, 0x1416a0, 0x1416f8, 0x141750, 0x1417a8, 0x141800,
                0x141858, 0x1418b0, 0x141908, 0x141960, 0x1419b8, 0x141a10, 0x141a68, 0x141ac0,
                0x141b18,
            ],
            // R-GTO-UI round 9: mirror live MSVC security cookie → AHK
            // call-obfuscation cookie so the decrypt skip path is taken.
            cookie_mirror_src_rva: Some(0x141020),
            cookie_mirror_dst_rva: Some(0x1454b8),
            // MIDA-SERIAL-14: the built-in preset is sample-specific; without
            // a module binding it MUST NOT activate. Callers that want the
            // preset must bind it to a verified ModuleIdentity first.
            module_binding: None,
            policy_revision: 0,
            policy_digest: String::new(),
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
                cookie_mirror_src_rva: None,
                cookie_mirror_dst_rva: None,
                module_binding: None,
                policy_revision: 0,
                policy_digest: String::new(),
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
            cookie_mirror_src_rva: None,
            cookie_mirror_dst_rva: None,
            module_binding: None,
            policy_revision: 0,
            policy_digest: String::new(),
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
        // Cookie mirror is AHK/GTO-only. Fill when both slots are unset so a
        // partial custom policy still gets the call-obfuscation fix; callers
        // who set either slot keep full control.
        if matches!(profile, DumpProfile::AhkGtoExperimental)
            && self.cookie_mirror_src_rva.is_none()
            && self.cookie_mirror_dst_rva.is_none()
        {
            self.cookie_mirror_src_rva = def.cookie_mirror_src_rva;
            self.cookie_mirror_dst_rva = def.cookie_mirror_dst_rva;
        }
        self
    }

    // ================= MIDA-SERIAL-14 identity-bound policy gate =================

    /// Bind this policy to a verified module identity (consumes self).
    pub fn with_module_binding(mut self, module: super::module_identity::ModuleIdentity) -> Self {
        self.module_binding = Some(module);
        self
    }

    /// Explicitly set the policy revision (consumes self).
    pub fn with_policy_revision(mut self, revision: u32) -> Self {
        self.policy_revision = revision;
        self
    }

    /// Explicitly stamp an externally supplied policy digest (consumes self).
    /// The digest is validated against [`Self::policy_digest_value`] by
    /// [`Self::validate_for_module`]; a mismatch fails closed.
    pub fn with_external_policy_digest(mut self, digest: String) -> Self {
        self.policy_digest = digest;
        self
    }

    /// Canonical policy digest (SHA-256 hex) over revision + module binding +
    /// every sample-specific field + behavior-affecting generic fields.
    /// Does NOT include `policy_digest` itself (no self-reference).
    pub fn policy_digest_value(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"mida.policy-digest/v1\0");
        h.update(&self.policy_revision.to_le_bytes());
        match &self.module_binding {
            Some(m) => {
                h.update(b"binding\0");
                h.update(m.digest_hex().as_bytes());
            }
            None => {
                h.update(b"unbound\0");
            }
        }
        h.update(b"hot_root_rvas\0");
        for rva in &self.hot_root_rvas {
            h.update(&rva.to_le_bytes());
        }
        h.update(b"large_table_rvas\0");
        for rva in &self.large_table_rvas {
            h.update(&rva.to_le_bytes());
        }
        h.update(b"gscript_root_rva\0");
        match self.gscript_root_rva {
            Some(r) => h.update(&r.to_le_bytes()),
            None => h.update(b"none\0"),
        }
        h.update(b"cs_reinit_rvas\0");
        for rva in &self.cs_reinit_rvas {
            h.update(&rva.to_le_bytes());
        }
        h.update(b"cookie_mirror\0");
        match (self.cookie_mirror_src_rva, self.cookie_mirror_dst_rva) {
            (Some(s), Some(d)) => {
                h.update(&s.to_le_bytes());
                h.update(&d.to_le_bytes());
            }
            _ => h.update(b"none\0"),
        }
        h.update(b"hot_expand_seed_rvas\0");
        for rva in &self.hot_expand_seed_rvas {
            h.update(&rva.to_le_bytes());
        }
        h.update(b"gscript_content_cap\0");
        h.update(&self.gscript_root_content_cap.to_le_bytes());
        h.update(b"first_hop_span\0");
        h.update(&self.gscript_first_hop_span.to_le_bytes());
        h.update(b"first_hop_probe\0");
        h.update(&self.gscript_first_hop_probe.to_le_bytes());
        format!("{:x}", h.finalize())
    }

    /// Whether the digest (if any) matches the recomputed value.
    pub fn digest_matches(&self) -> bool {
        if self.policy_digest.is_empty() {
            return true; // not stamped; gate treats unstamped as unverified
        }
        self.policy_digest == self.policy_digest_value()
    }

    /// Validate this policy against a module identity:
    /// - no binding        -> Err (sample-specific must not activate);
    /// - binding mismatch  -> Err;
    /// - digest mismatch   -> Err;
    /// - revision unset(0) -> Err;
    /// - matching binding  -> Ok(ActivationAllowed).
    pub fn validate_for_module(
        &self,
        module: &super::module_identity::ModuleIdentity,
    ) -> Result<PolicyValidation, PolicyGateError> {
        match &self.module_binding {
            None => Err(PolicyGateError::UnboundPolicy),
            Some(bound) => {
                if bound != module {
                    return Err(PolicyGateError::ModuleMismatch);
                }
                if !self.digest_matches() {
                    return Err(PolicyGateError::DigestMismatch);
                }
                if self.policy_revision == 0 {
                    return Err(PolicyGateError::UnversionedPolicy);
                }
                Ok(PolicyValidation::ActivationAllowed)
            }
        }
    }

    /// True iff sample-specific fields may activate for this module.
    pub fn sample_specific_activation(
        &self,
        module: &super::module_identity::ModuleIdentity,
    ) -> bool {
        matches!(
            self.validate_for_module(module),
            Ok(PolicyValidation::ActivationAllowed)
        )
    }

    /// Whether a specific sample transform/action is allowed for this module.
    /// `action` is a symbolic name; the RVA alone is never sufficient. Reserved
    /// for MIDA-SERIAL-15 wiring.
    pub fn allows_sample_transform(
        &self,
        module: &super::module_identity::ModuleIdentity,
        _action: &str,
    ) -> bool {
        self.sample_specific_activation(module)
    }

    /// Produce a copy with all sample-specific RVA fields stripped (generic
    /// knobs retained). Used when no binding / mismatch occurs so the dump
    /// proceeds on the safe generic path.
    pub fn strip_sample_specific(&self) -> Self {
        Self {
            hot_root_rvas: Vec::new(),
            large_table_rvas: Vec::new(),
            gscript_root_rva: None,
            gscript_root_content_cap: self.gscript_root_content_cap,
            gscript_first_hop_span: self.gscript_first_hop_span,
            gscript_first_hop_probe: self.gscript_first_hop_probe,
            hot_expand_seed_rvas: Vec::new(),
            cs_reinit_rvas: Vec::new(),
            cookie_mirror_src_rva: None,
            cookie_mirror_dst_rva: None,
            module_binding: self.module_binding.clone(),
            policy_revision: self.policy_revision,
            policy_digest: self.policy_digest.clone(),
        }
    }

    /// True iff this policy currently has any sample-specific field set.
    pub fn has_sample_specific(&self) -> bool {
        !self.hot_root_rvas.is_empty()
            || !self.large_table_rvas.is_empty()
            || self.gscript_root_rva.is_some()
            || !self.cs_reinit_rvas.is_empty()
            || self.cookie_mirror_src_rva.is_some()
            || self.cookie_mirror_dst_rva.is_some()
            || !self.hot_expand_seed_rvas.is_empty()
    }

    /// True iff this policy is generic-only (no sample-specific fields).
    pub fn is_generic_only(&self) -> bool {
        !self.has_sample_specific()
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

/// Outcome of [`DumpCapturePolicy::validate_for_module`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyValidation {
    /// Binding matches, digest valid, revision set — sample-specific allowed.
    ActivationAllowed,
}

/// Fail-closed reasons from the policy gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyGateError {
    /// No module binding on the policy.
    UnboundPolicy,
    /// Binding identity does not match the given module.
    ModuleMismatch,
    /// Stamped policy digest does not match the recomputed value.
    DigestMismatch,
    /// Policy revision is 0 (unversioned) — sample-specific denied.
    UnversionedPolicy,
}

impl std::fmt::Display for PolicyGateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyGateError::UnboundPolicy => write!(f, "policy has no module binding"),
            PolicyGateError::ModuleMismatch => write!(f, "policy module binding mismatch"),
            PolicyGateError::DigestMismatch => write!(f, "policy digest mismatch"),
            PolicyGateError::UnversionedPolicy => write!(f, "policy revision unset (0)"),
        }
    }
}

impl std::error::Error for PolicyGateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plus_ahk_profile_resolves_defaults() {
        let p = DumpCapturePolicy::default().resolve_for_profile(DumpProfile::AhkGtoExperimental);
        assert!(p.is_hot_root(0x149d50));
        assert!(p.is_large_table(0x141bf0));
        assert_eq!(p.gscript_root(), Some(0x149d50));
        assert_eq!(p.cookie_mirror_src_rva, Some(0x141020));
        assert_eq!(p.cookie_mirror_dst_rva, Some(0x1454b8));
    }

    #[test]
    fn partial_ahk_hot_roots_fill_cookie_mirror() {
        let p = DumpCapturePolicy {
            hot_root_rvas: vec![0x149d50],
            ..Default::default()
        }
        .resolve_for_profile(DumpProfile::AhkGtoExperimental);
        assert_eq!(p.cookie_mirror_src_rva, Some(0x141020));
        assert_eq!(p.cookie_mirror_dst_rva, Some(0x1454b8));
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

    // ============ MIDA-SERIAL-14 policy gate tests ============

    /// Build a ModuleIdentity from a minimal hand-constructed PeHeader.
    fn test_module_identity(
        machine: u16,
        stamp: u32,
        size_image: u32,
    ) -> super::super::module_identity::ModuleIdentity {
        let pe = crate::header::PeHeader {
            dos_header: crate::header::ImageDosHeader {
                e_magic: 0x5a4d,
                e_lfanew: 0x40,
            },
            nt_headers: crate::header::ImageNtHeaders {
                signature: 0x4550,
                file_header: crate::header::ImageFileHeader {
                    machine,
                    number_of_sections: 1,
                    time_date_stamp: stamp,
                    size_of_optional_header: 0xf0,
                    characteristics: 0x102,
                },
                optional_header: crate::header::ImageOptionalHeader {
                    magic: 0x20b,
                    major_linker_version: 0,
                    minor_linker_version: 0,
                    size_of_code: 0x1000,
                    size_of_initialized_data: 0x2000,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0x1000,
                    base_of_code: 0x1000,
                    base_of_data: None,
                    image_base: 0x140000000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: size_image,
                    size_of_headers: 0x400,
                    check_sum: 0,
                    subsystem: 3,
                    dll_characteristics: 0,
                    size_of_stack_reserve: 0x100000,
                    size_of_stack_commit: 0x1000,
                    size_of_heap_reserve: 0x100000,
                    size_of_heap_commit: 0x1000,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [crate::header::ImageDataDirectory::default(); 16],
                },
            },
            sections: vec![crate::header::PeSection {
                header: crate::header::ImageSectionHeader {
                    name: *b".text\0\0\0",
                    virtual_size: 0x100,
                    virtual_address: 0x1000,
                    size_of_raw_data: 0x200,
                    pointer_to_raw_data: 0x400,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: 0x60000020,
                },
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x100,
                raw_offset: 0x400,
                raw_size: 0x200,
                characteristics: 0x60000020,
                extra_data: None,
            }],
            image_base: 0x140000000,
            entry_point: 0x1000,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        };
        super::super::module_identity::ModuleIdentity::from_pe_header(&pe).unwrap()
    }

    #[test]
    fn unbound_policy_denies_activation() {
        let module = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        let p = DumpCapturePolicy::ahk_gto_default();
        assert!(!p.sample_specific_activation(&module));
        assert_eq!(
            p.validate_for_module(&module),
            Err(PolicyGateError::UnboundPolicy)
        );
    }

    #[test]
    fn matching_binding_permits_activation() {
        let module = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        let p = DumpCapturePolicy::ahk_gto_default()
            .with_module_binding(module.clone())
            .with_policy_revision(1)
            .with_external_policy_digest(
                DumpCapturePolicy::ahk_gto_default()
                    .with_module_binding(module.clone())
                    .with_policy_revision(1)
                    .policy_digest_value(),
            );
        assert!(p.sample_specific_activation(&module));
        assert!(p.allows_sample_transform(&module, "sanitize_ahk_runtime_global"));
    }

    #[test]
    fn mismatching_binding_denies_activation() {
        let m1 = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        let m2 = test_module_identity(0x8664, 0x5f5e101, 0x3000); // different stamp
        let p = DumpCapturePolicy::ahk_gto_default()
            .with_module_binding(m1)
            .with_policy_revision(1)
            .with_external_policy_digest(String::new());
        assert!(!p.sample_specific_activation(&m2));
        assert_eq!(
            p.validate_for_module(&m2),
            Err(PolicyGateError::ModuleMismatch)
        );
    }

    #[test]
    fn revision_zero_denies_activation() {
        let module = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        let p = DumpCapturePolicy::ahk_gto_default().with_module_binding(module.clone());
        assert!(!p.sample_specific_activation(&module));
        assert_eq!(
            p.validate_for_module(&module),
            Err(PolicyGateError::UnversionedPolicy)
        );
    }

    #[test]
    fn digest_tampering_denies_activation() {
        let module = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        let p = DumpCapturePolicy::ahk_gto_default()
            .with_module_binding(module.clone())
            .with_policy_revision(1)
            .with_external_policy_digest("deadbeef".to_string()); // tampered
        assert!(!p.digest_matches());
        assert!(!p.sample_specific_activation(&module));
        assert_eq!(
            p.validate_for_module(&module),
            Err(PolicyGateError::DigestMismatch)
        );
    }

    #[test]
    fn strip_sample_specific_leaves_generic_only() {
        let p = DumpCapturePolicy::ahk_gto_default();
        let stripped = p.strip_sample_specific();
        assert!(stripped.is_generic_only());
        assert!(stripped.hot_root_rvas.is_empty());
        assert!(stripped.cs_reinit_rvas.is_empty());
        assert_eq!(stripped.gscript_first_hop_span, p.gscript_first_hop_span);
    }

    #[test]
    fn generic_only_policy_without_binding_stays_safe() {
        let p = DumpCapturePolicy::default();
        assert!(p.is_generic_only());
        assert!(!p.has_sample_specific());
        let module = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        assert!(!p.sample_specific_activation(&module));
    }

    #[test]
    fn explicit_rva_without_binding_does_not_bypass_gate() {
        let module = test_module_identity(0x8664, 0x5f5e100, 0x3000);
        let p = DumpCapturePolicy {
            hot_root_rvas: vec![0x1000, 0x2000],
            ..Default::default()
        };
        assert!(!p.sample_specific_activation(&module));
        let stripped = p.strip_sample_specific();
        assert!(stripped.is_generic_only());
    }
}
