//! # mida-packers-vmprotect
//!
//! VMProtect detection, mode classification and a static structure report.
//!
//! ## What this crate is, and is not
//!
//! It is **not** a devirtualiser.  VMProtect's VM bytecode is randomised per
//! build; recovering original x86 from it is a research problem, not a
//! pipeline stage.  What this crate does is everything that *is*
//! deterministic and testable without a running process:
//!
//! - classify a sample as VMProtect and, more importantly, as one of two
//!   measured **modes** ([`VmProtectMode`]) that need different pipelines;
//! - report the structure that matters (`runtime` section, relocated
//!   exception directory, scrambled `.pdata`, in-file `.vmp*` trampolines);
//! - locate the encrypted resource payload (`RT_RCDATA`, > 1 MiB) with its
//!   size, file offset, SHA-256, entropy and printable magic.
//!
//! ## Measured ground truth
//!
//! Two samples, both VMProtect 2.XX–3.XX per DIE:
//!
//! | | `lunlun\伦伦软件.exe` | `zz_test.exe` |
//! |---|---|---|
//! | size | 19,005,952 | 21,415,936 |
//! | mode | `MinProtection` | `Packed` |
//! | `.text` | `raw_size 0x72400`, decodes 100 % | `raw_size 0` — absent |
//! | entry point | `0x4b274` in `.text` | `0x130bbfb` in `.rdata2` |
//! | runtime section | `.vmp0` `raw 0x217e00` | `.rdata2` `raw 0x1466400` |
//! | exception dir | in `.vmp0`, 64/64 triples | in `.rdata2`, 64/64 triples |
//! | `.pdata` | `raw 0x4e00`, **0/64** triples | `raw 0` |
//! | payload | `RT_RCDATA` id 101, 16,102,969 B in file | id 131, 12,782,080 B **memory-only** |
//!
//! The discriminator was chosen by measurement, not inspection: over 87
//! protected samples on this machine, `MEM_NOT_PAGED` on an executable
//! section fires on **19 of the 24** `.fptable`-family samples and on
//! **0 of the 63** Themida samples.  See [`detect`] for how it is used.

pub mod detect;
pub mod payload_xor;
pub mod report;
pub mod resources;

#[cfg(test)]
mod test_support;

pub use detect::{
    body_lost_sections, classify_mode, detect, fptable_section, is_executable, is_not_paged,
    is_template_named_section,
    is_vmp_named_section, notpaged_executable_sections, packed_sections,
    plausible_runtime_function_triples, runtime_sections, scrambled_pdata, section_bytes,
    section_name, shannon_entropy, VmProtectDetector, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_NOT_PAGED, PACKED_MIN_VIRTUAL_SIZE,
};
pub use report::{
    analyze, exception_directory, section_of, trampolines, ExceptionDirectory, Trampoline,
    VmProtectReport,
};
pub use resources::{large_resources, walk_resources, LargeResource, ResourceEntry, LARGE_RESOURCE_MIN, RT_RCDATA};
pub use payload_xor::{
    looks_like_pe_image, transform_for, PayloadTransform, KNOWN_TRANSFORMS,
};
