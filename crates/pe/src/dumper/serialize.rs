//! Compatibility shim: header serialization lives on pure [PeHeader].
//!
//! R1-B moved serialize_headers into crate::header so dump adapters call the
//! pure PE model without owning PE layout emit.

// Method is defined in header::PeHeader; this module remains for historical path.
