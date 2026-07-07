//! Miscellaneous PE helper functions.

/// Align `value` upward to the nearest multiple of `alignment`.
///
/// Returns `value` unchanged if it is already aligned.
///
/// # Examples
///
/// ```
/// use mida_pe::align_up;
/// assert_eq!(align_up(37, 16), 48);
/// assert_eq!(align_up(32, 16), 32);
/// ```
#[inline]
#[must_use]
pub fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    let delta = value % alignment;
    if delta > 0 {
        value + alignment - delta
    } else {
        value
    }
}

/// Returns `true` if `IMAGE_FILE_DLL` is set in the file characteristics.
///
/// # Examples
///
/// ```
/// use mida_pe::is_dll;
/// const IMAGE_FILE_DLL: u16 = 0x2000;
/// assert!(is_dll(IMAGE_FILE_DLL));
/// assert!(!is_dll(0));
/// ```
#[inline]
#[must_use]
pub fn is_dll(characteristics: u16) -> bool {
    characteristics & 0x2000 != 0
}

/// Returns `true` if `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` is set.
///
/// # Examples
///
/// ```
/// use mida_pe::has_force_integrity;
/// const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
/// assert!(has_force_integrity(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY));
/// ```
#[inline]
#[must_use]
pub fn has_force_integrity(characteristics: u16) -> bool {
    characteristics & 0x0080 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up_already_aligned() {
        assert_eq!(align_up(32, 16), 32);
    }

    #[test]
    fn test_align_up_needs_padding() {
        assert_eq!(align_up(37, 16), 48);
    }

    #[test]
    fn test_align_up_zero() {
        assert_eq!(align_up(0, 16), 0);
    }

    #[test]
    fn test_align_up_alignment_one() {
        assert_eq!(align_up(37, 1), 37);
    }

    #[test]
    fn test_align_up_zero_alignment() {
        assert_eq!(align_up(100, 0), 100);
    }

    #[test]
    fn test_is_dll_true() {
        const IMAGE_FILE_DLL: u16 = 0x2000;
        assert!(is_dll(IMAGE_FILE_DLL));
        // Mix of flags
        assert!(is_dll(IMAGE_FILE_DLL | 0x0002));
    }

    #[test]
    fn test_is_dll_false() {
        assert!(!is_dll(0));
        assert!(!is_dll(0x0002));
    }

    #[test]
    fn test_has_force_integrity() {
        const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
        assert!(has_force_integrity(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY));
        assert!(!has_force_integrity(0));
    }
}
