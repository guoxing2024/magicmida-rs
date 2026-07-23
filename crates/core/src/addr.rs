//! Explicit PE / process address types (R2-Slice1).
//!
//! Live and dump code historically mixed preferred ImageBase with ASLR runtime
//! base as raw `u64`. These newtypes make the conversion rules explicit.
//!
//! Rules (see `docs/VNEXT_R2_RUNTIME_API.md`):
//! - Live map: `Va = RuntimeBase + Rva`
//! - Dump emit ImageBase uses [`PreferredBase`], not [`RuntimeBase`]
//! - Hardcoded fix: `preferred_va = runtime_va - RuntimeBase + PreferredBase`
//!
//! This module is pure (no Win32). Existing call sites may adopt types
//! incrementally; Slice 1 does not rewrite unpacker/dumper.

use core::fmt;

/// Preferred load address from the PE optional header (on-disk / header_patch).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct PreferredBase(pub u64);

/// Actual process image base after load (ASLR / CreateProcess / PEB).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RuntimeBase(pub u64);

/// Relative virtual address (offset from an image base).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rva(pub u32);

/// Absolute virtual address in a process address space.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Va(pub u64);

/// Byte offset into a PE file image (on disk / serialized buffer).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileOffset(pub u32);

impl PreferredBase {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Absolute VA as if the image were loaded at the preferred base.
    #[must_use]
    pub fn va(self, rva: Rva) -> Va {
        Va(self.0.wrapping_add(rva.0 as u64))
    }
}

impl RuntimeBase {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Live map: absolute VA from runtime base + RVA.
    #[must_use]
    pub fn va(self, rva: Rva) -> Va {
        Va::from_runtime(self, rva)
    }
}

impl Rva {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Va {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// `Va = RuntimeBase + Rva` (wrapping add, matching typical PE tooling).
    #[must_use]
    pub fn from_runtime(base: RuntimeBase, rva: Rva) -> Self {
        Self(base.0.wrapping_add(u64::from(rva.0)))
    }

    /// `Va = PreferredBase + Rva` (emit / preferred layout).
    #[must_use]
    pub fn from_preferred(base: PreferredBase, rva: Rva) -> Self {
        Self(base.0.wrapping_add(u64::from(rva.0)))
    }

    /// Inverse of [`from_runtime`]; `None` if below base or RVA does not fit `u32`.
    #[must_use]
    pub fn to_rva(self, base: RuntimeBase) -> Option<Rva> {
        self.0
            .checked_sub(base.0)
            .and_then(|d| u32::try_from(d).ok())
            .map(Rva)
    }

    /// Inverse of [`from_preferred`].
    #[must_use]
    pub fn to_rva_preferred(self, base: PreferredBase) -> Option<Rva> {
        self.0
            .checked_sub(base.0)
            .and_then(|d| u32::try_from(d).ok())
            .map(Rva)
    }

    /// Rebase a live absolute pointer from runtime base into preferred layout.
    ///
    /// Used by hardcoded-address fix after dump: content still holds runtime
    /// VAs while the file ImageBase is restored to preferred.
    ///
    /// ```text
    /// preferred_va = runtime_va - RuntimeBase + PreferredBase
    /// ```
    #[must_use]
    pub fn rebase_to_preferred(self, runtime: RuntimeBase, preferred: PreferredBase) -> Self {
        Self(self.0.wrapping_sub(runtime.0).wrapping_add(preferred.0))
    }
}

impl FileOffset {
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

// --- Display / Debug ---

macro_rules! impl_fmt_hex {
    ($t:ty, $name:literal) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($name, "({:#x})"), self.0)
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }
    };
}

impl_fmt_hex!(PreferredBase, "PreferredBase");
impl_fmt_hex!(RuntimeBase, "RuntimeBase");
impl_fmt_hex!(Rva, "Rva");
impl_fmt_hex!(Va, "Va");
impl_fmt_hex!(FileOffset, "FileOffset");

#[cfg(test)]
mod tests {
    use super::*;

    const PREFERRED: PreferredBase = PreferredBase(0x0000_0140_0000_0000);
    // Typical Win11 ASLR-ish high base (not a real sample base).
    const RUNTIME: RuntimeBase = RuntimeBase(0x0000_7ff6_c050_0000);

    #[test]
    fn live_map_roundtrip() {
        let rva = Rva(0x13e0);
        let va = Va::from_runtime(RUNTIME, rva);
        assert_eq!(va.0, RUNTIME.0 + 0x13e0);
        assert_eq!(va.to_rva(RUNTIME), Some(rva));
        assert_eq!(RUNTIME.va(rva), va);
    }

    #[test]
    fn preferred_map_roundtrip() {
        let rva = Rva(0x13e0);
        let va = Va::from_preferred(PREFERRED, rva);
        assert_eq!(va.0, 0x0000_0140_0000_13e0);
        assert_eq!(va.to_rva_preferred(PREFERRED), Some(rva));
        assert_eq!(PREFERRED.va(rva), va);
    }

    #[test]
    fn to_rva_rejects_below_base() {
        let va = Va(RUNTIME.0 - 1);
        assert_eq!(va.to_rva(RUNTIME), None);
    }

    #[test]
    fn to_rva_rejects_overflow_u32() {
        let va = Va(RUNTIME.0 + u64::from(u32::MAX) + 1);
        assert_eq!(va.to_rva(RUNTIME), None);
    }

    /// Phase2 bug class: pure emit must not use RuntimeBase as ImageBase.
    #[test]
    fn preferred_and_runtime_are_distinct_for_emit() {
        assert_ne!(PREFERRED.0, RUNTIME.0);
        let rva = Rva(0x1000);
        let live = Va::from_runtime(RUNTIME, rva);
        let emit = Va::from_preferred(PREFERRED, rva);
        assert_ne!(live, emit);
        // Same RVA, different absolute forms.
        assert_eq!(live.to_rva(RUNTIME), emit.to_rva_preferred(PREFERRED));
    }

    #[test]
    fn rebase_runtime_pointer_to_preferred_layout() {
        let rva = Rva(0x1a_5000);
        let live_ptr = Va::from_runtime(RUNTIME, rva);
        let fixed = live_ptr.rebase_to_preferred(RUNTIME, PREFERRED);
        assert_eq!(fixed, Va::from_preferred(PREFERRED, rva));
        // Identity when bases match (Lunlun-style no-ASLR or already preferred).
        let same = Va::from_runtime(RuntimeBase(PREFERRED.0), rva);
        assert_eq!(
            same.rebase_to_preferred(RuntimeBase(PREFERRED.0), PREFERRED),
            same
        );
    }

    #[test]
    fn file_offset_is_plain_newtype() {
        let off = FileOffset::new(0x400);
        assert_eq!(off.get(), 0x400);
        assert_eq!(format!("{off}"), "0x400");
        assert!(format!("{off:?}").contains("FileOffset"));
    }
}
