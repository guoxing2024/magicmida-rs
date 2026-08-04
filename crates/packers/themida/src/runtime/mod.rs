//! Runtime handler decisions extracted from the CLI host (P3-B/C).
//!
//! The CLI host keeps only capability execution: it implements the query
//! seams, performs the returned actions, and drives the event pump. All
//! business decisions live here as pure functions.

pub mod av_oep_handler;
