//! UPX packer front-end: detection, pack-header parsing, a static structure
//! report, and — since this increment — a **static unpacker**.
//!
//! ## Why UPX is measured differently from the other two packers
//!
//! Themida and VMProtect keep secrets at runtime — the code appears in memory
//! only after the packer's own loader runs, which is why those pipelines need
//! a debugger or a live capture.  UPX does not: the *whole* original image is
//! one statically-decodable stream, and the file records everything needed to
//! decode it in a 32-byte `PackHeader`.  Measured on UPX **5.2.1** (the
//! version installed here), cross-checked against `src/packhead.cpp` and
//! `src/pefile.cpp` of the same tag:
//!
//! | fact | measured |
//! |---|---|
//! | PackHeader size / fields | 32 B: `'UPX!'`, version, format, method, level, u_adler, c_adler, u_len, c_len, u_file_size, filter, filter_cto, n_mru, checksum |
//! | header checksum | `sum(bytes[+4..+32]) mod 251` at `+31` |
//! | format ids | PE32 = 9, PE32+/AMD64 = 36 |
//! | method ids | 2 = NRV2B_LE32, 5 = NRV2D_LE32, 8 = NRV2E_LE32 (the default), 14 = LZMA |
//! | compressed stream | **one** block (no `b_info` chain), `c_len` bytes, `c_adler` = standard Adler-32 seeded 1 (4/4 samples) |
//! | stream placement | `UPX1` raw start + `ic`, where `ic` is the part of the ident (version string + PackHeader) that did not fit into the PE header slack — i.e. always directly after the PackHeader |
//! | structural invariant | `UPX1_raw + align_up(ic + c_len, 16)` == the file offset of the entry point (the unpacker stub), verified 4/4 |
//! | overlay | the input's tail (e.g. a GNU COFF symbol table) is copied verbatim after the last section |
//!
//! `l_info`/`p_info` — present in the DOS and ELF formats — do **not** appear
//! in UPX 5.2.1 PE output; the first measurement pass went looking for them at
//! `UPX1`'s raw start and found nothing, which is itself a recorded result.
//!
//! ## The static unpacker
//!
//! [`unpack_static`] ports `PeFile::unpack0` of the same tag: decode
//! (NRV2E `le32` per UCL `n2e_d.c`, or LZMA with UPX's 2-byte property
//! header per `compress_lzma.cpp`), undo the call-trick filter
//! (`cto.h` / `ctok.h`), rebuild imports, relocations and resources from the
//! reconstruction data the decoded image carries at its tail, and reassemble
//! the file.  Verified **byte-for-byte against `upx -d`** on all four corpus
//! samples — with the recorded caveat that `upx -d`'s output is the ground
//! truth, not the pre-pack original (UPX rewrites the DOS stub area when
//! packing and never restores it).  See `unpack.rs` for the port and its
//! three traps.

mod detect;
mod error;
mod filter;
mod header;
mod lzma;
mod nrv2e;
mod reloc;
mod report;
mod unpack;

#[cfg(test)]
pub(crate) mod test_support;

pub use detect::{detect, UpxDetector};
pub use error::UpxUnpackError;
pub use header::{adler32, find_pack_header, PackHeader};
pub use report::{analyze, UpxReport};
pub use unpack::unpack_static;
