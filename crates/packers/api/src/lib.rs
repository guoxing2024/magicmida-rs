//! # mida-packer-api
//!
//! Packer-neutral detection vocabulary shared by every packer front-end.
//!
//! ## Why this crate exists
//!
//! Before this crate the workspace had exactly one real abstraction
//! (`mida_core::DebuggerCore`) and one packer crate
//! ([`mida-packers-themida`]).  `mida-cli` hard-referenced that packer, so
//! "which packer is this?" had no home and every front-end that needed an
//! answer grew its own copy of the section-name check.
//!
//! That is not merely untidy — it produced a measured defect.  On
//! 2026-10-25 `mida-cli /unpack D:\Projects\zz_test.exe` printed
//! `Themida version: V3` and created the debuggee for a **VMProtect** sample,
//! because Themida's `is_themida_section` heuristic (an executable section
//! with `raw_size == 0` and a large virtual size) is also satisfied by that
//! sample's `.rdata0`.  Measured over 87 protected samples on this machine,
//! the heuristic fires on 6 genuine Themida samples *and* on that
//! VMProtect one: it cannot be tightened into correctness, so the packer
//! decision has to become an explicit, evidence-carrying step that runs
//! *before* any per-packer heuristic.
//!
//! ## Shape
//!
//! - [`PackerKind`] / [`Family`] — who built the protection.
//! - [`VmProtectMode`] — *how much* was protected.  The mode matters more
//!   than the family: the two measured VMProtect modes need different
//!   pipelines (see `mida-packers-vmprotect`).
//! - [`Evidence`] — one machine-checkable reason, so a wrong verdict is
//!   diagnosable instead of a bare `false`.
//! - [`Detection`] — the verdict plus its evidence.
//! - [`Packer`] — the contract a packer crate implements.  Only
//!   `mida-packers-vmprotect` implements it so far; migrating
//!   `mida-packers-themida` onto it is deliberately left as a follow-up so
//!   this change cannot perturb the 281 existing tests.

use mida_pe::PeHeader;

/// Which non-standard packer produced this image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Oreans Themida / WinLicense.
    Themida,
    /// VMProtect (any 2.x/3.x build).
    VmProtect,
    /// UPX (the NRV/LZMA packer; static layout, no runtime secret).
    Upx,
    /// No packer we recognise.
    Unknown,
}

impl Family {
    /// Short human label used in log lines.
    pub fn label(self) -> &'static str {
        match self {
            Family::Themida => "Themida",
            Family::VmProtect => "VMProtect",
            Family::Upx => "UPX",
            Family::Unknown => "unknown",
        }
    }
}

/// How much of the image VMProtect actually protected.
///
/// The two measured modes need different pipelines, so the family alone is
/// not a usable verdict:
///
/// | mode | file carries | pipeline |
/// |---|---|---|
/// | [`VmProtectMode::MinProtection`] | `.text` intact, IAT intact, one `.vmp*` section | static report + payload extraction |
/// | [`VmProtectMode::Packed`] | no code bytes at all (`raw_size == 0`) | runtime image dump + payload carve |
///
/// `MinProtection` is measured on `D:\Projects\lunlun\伦伦软件.exe`
/// (19,005,952 B) and `Packed` on `D:\Projects\zz_test.exe` (21,415,936 B);
/// both are VMProtect 2.XX–3.XX per DIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmProtectMode {
    /// Original sections are present in the file; only selected functions
    /// were virtualised into `.vmp0`/`.vmp1`.
    MinProtection,
    /// Executable sections have `SizeOfRawData == 0`: the original image is
    /// reconstructed in memory by the VMProtect loader.
    Packed,
}

impl VmProtectMode {
    /// Short human label.
    pub fn label(self) -> &'static str {
        match self {
            VmProtectMode::MinProtection => "min-protection",
            VmProtectMode::Packed => "packed",
        }
    }
}

/// A packer verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackerKind {
    Themida,
    VmProtect(VmProtectMode),
    Upx,
    Unknown,
}

impl PackerKind {
    /// The family this kind belongs to.
    pub fn family(self) -> Family {
        match self {
            PackerKind::Themida => Family::Themida,
            PackerKind::VmProtect(_) => Family::VmProtect,
            PackerKind::Upx => Family::Upx,
            PackerKind::Unknown => Family::Unknown,
        }
    }

    /// The VMProtect mode, when this verdict is VMProtect.
    pub fn vmprotect_mode(self) -> Option<VmProtectMode> {
        match self {
            PackerKind::VmProtect(m) => Some(m),
            _ => None,
        }
    }

    /// Name of the ScyllaHide profile to use for this packer.
    ///
    /// The injector takes **no ini argument** — measured:
    /// `InjectorCLIx64.exe pid:<pid> <HookLibraryx64.dll> nowait`.  The only
    /// way to select a profile is the `CurrentProfile` key inside the
    /// `scylla_hide.ini` the injector finds beside itself, so profile
    /// selection is a property of the packer rather than of the injector
    /// command line.
    ///
    /// `"Magicmida"` is the historical hand-written Themida profile and is
    /// kept verbatim so the three existing e2e golden gates keep producing
    /// the same bytes.  `"VMProtect x86/x64"` is the preset ScyllaHide itself
    /// ships (`D:\Tools\ScyllaHide\scylla_hide.ini`), used verbatim rather
    /// than invented, because its option set is the vendor's, not a guess.
    pub fn scylla_profile(self) -> &'static str {
        match self {
            PackerKind::Themida => "Magicmida",
            PackerKind::VmProtect(_) => "VMProtect x86/x64",
            // UPX does no anti-debug work at all; and it currently has no live
            // pipeline in this project, so no injector is ever started for it.
            PackerKind::Upx => "Disabled",
            PackerKind::Unknown => "Disabled",
        }
    }
}

/// One machine-checkable reason behind a verdict.
///
/// `code` is a stable identifier (safe to assert on in tests and to grep in
/// logs); `detail` is the measured value that triggered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /// Stable identifier, e.g. `notpaged-executable-section`.
    pub code: &'static str,
    /// The measured value, e.g. `sections [".vmp0"]`.
    pub detail: String,
}

impl Evidence {
    /// Build an evidence item.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// `code: detail`
    pub fn render(&self) -> String {
        format!("{}: {}", self.code, self.detail)
    }
}

/// A verdict plus the evidence that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// The verdict.
    pub kind: PackerKind,
    /// Why.  Never empty for a non-[`PackerKind::Unknown`] verdict.
    pub evidence: Vec<Evidence>,
    /// Facts that were looked for but not found — useful when a verdict is
    /// surprising, because "we checked and it was absent" is different from
    /// "we did not check".
    pub absent: Vec<Evidence>,
}

impl Detection {
    /// The "nothing matched" verdict, with no evidence.
    pub fn unknown() -> Self {
        Self {
            kind: PackerKind::Unknown,
            evidence: Vec::new(),
            absent: Vec::new(),
        }
    }

    /// Family shortcut.
    pub fn family(&self) -> Family {
        self.kind.family()
    }

    /// `true` for any Themida verdict.
    pub fn is_themida(&self) -> bool {
        matches!(self.kind, PackerKind::Themida)
    }

    /// `true` for any VMProtect verdict.
    pub fn is_vmprotect(&self) -> bool {
        matches!(self.kind, PackerKind::VmProtect(_))
    }

    /// `true` for any UPX verdict.
    pub fn is_upx(&self) -> bool {
        matches!(self.kind, PackerKind::Upx)
    }

    /// `true` when nothing matched.
    pub fn is_unknown(&self) -> bool {
        matches!(self.kind, PackerKind::Unknown)
    }

    /// One-line summary suitable for a log line or an error message.
    pub fn summary(&self) -> String {
        match self.kind {
            PackerKind::Themida => "Themida".to_string(),
            PackerKind::VmProtect(m) => format!("VMProtect ({})", m.label()),
            PackerKind::Upx => "UPX".to_string(),
            PackerKind::Unknown => "no recognised packer".to_string(),
        }
    }

    /// Every evidence line, rendered, prefixed with `+ ` for present and
    /// `- ` for absent.
    pub fn render_evidence(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .evidence
            .iter()
            .map(|e| format!("+ {}", e.render()))
            .collect();
        out.extend(self.absent.iter().map(|e| format!("- {}", e.render())));
        out
    }
}

/// The contract a packer crate implements.
///
/// `detect` returns `Some(evidence)` **only** when the image really belongs
/// to this packer, and that evidence must be sufficient on its own to
/// justify the claim — a caller may print it to a user who is about to
/// spend minutes on the wrong pipeline.
pub trait Packer {
    /// Human name, e.g. `"VMProtect"`.
    fn name(&self) -> &'static str;

    /// Family this packer belongs to.
    fn family(&self) -> Family;

    /// Evidence that `pe`/`image` was produced by this packer, or `None`.
    ///
    /// `image` is the whole file; it is needed because
    /// [`mida_pe::PeSection`] does not carry its own bytes.
    fn detect(&self, pe: &PeHeader, image: &[u8]) -> Option<Vec<Evidence>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_and_mode_round_trip() {
        let k = PackerKind::VmProtect(VmProtectMode::Packed);
        assert_eq!(k.family(), Family::VmProtect);
        assert_eq!(k.vmprotect_mode(), Some(VmProtectMode::Packed));
        assert_eq!(k.family().label(), "VMProtect");
        assert_eq!(VmProtectMode::Packed.label(), "packed");
        assert_eq!(PackerKind::Themida.family(), Family::Themida);
        assert_eq!(PackerKind::Upx.family(), Family::Upx);
        assert_eq!(PackerKind::Upx.family().label(), "UPX");
        assert_eq!(PackerKind::Upx.vmprotect_mode(), None);
        assert_eq!(PackerKind::Themida.family(), Family::Themida);
        assert_eq!(PackerKind::Unknown.family(), Family::Unknown);
        assert_eq!(PackerKind::Themida.vmprotect_mode(), None);
    }

    #[test]
    fn summary_names_the_mode_not_just_the_family() {
        let d = Detection {
            kind: PackerKind::VmProtect(VmProtectMode::MinProtection),
            evidence: vec![Evidence::new("vmp-section", "sections [\".vmp0\"]")],
            absent: Vec::new(),
        };
        // The mode is the load-bearing part of the verdict: the two modes
        // need different pipelines, so a summary that omits it is useless.
        assert_eq!(d.summary(), "VMProtect (min-protection)");
        assert!(d.is_vmprotect());
        assert!(!d.is_themida());
        assert!(!d.is_unknown());
        assert_eq!(d.render_evidence(), vec!["+ vmp-section: sections [\".vmp0\"]"]);
    }

    #[test]
    fn scylla_profile_is_per_packer_and_names_the_shipped_ones() {
        // The injector has no ini argument, so this name is the only lever.
        assert_eq!(PackerKind::Themida.scylla_profile(), "Magicmida");
        assert_eq!(
            PackerKind::VmProtect(VmProtectMode::MinProtection).scylla_profile(),
            "VMProtect x86/x64"
        );
        // Both modes share the profile: the mode changes the *pipeline*, not
        // the anti-anti-debug option set.
        assert_eq!(
            PackerKind::VmProtect(VmProtectMode::Packed).scylla_profile(),
            PackerKind::VmProtect(VmProtectMode::MinProtection).scylla_profile()
        );
        assert_eq!(PackerKind::Unknown.scylla_profile(), "Disabled");
    }

    #[test]
    fn absent_evidence_is_rendered_distinctly_from_present() {
        let d = Detection {
            kind: PackerKind::Unknown,
            evidence: vec![Evidence::new("a", "yes")],
            absent: vec![Evidence::new("b", "no")],
        };
        assert_eq!(d.render_evidence(), vec!["+ a: yes", "- b: no"]);
        assert_eq!(Detection::unknown().summary(), "no recognised packer");
        assert!(Detection::unknown().evidence.is_empty());
    }
}
