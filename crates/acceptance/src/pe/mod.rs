//! Independent byte-level PE view (no Win32, no production crate coupling).

pub mod read;
pub mod view;

pub use view::{
    try_parse, DataDirectory, OptionalHeaderView, PeImage, SectionView,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
};
