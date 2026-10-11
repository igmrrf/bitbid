//! Shared native/WASM library. No filesystem, process, HTTP, wallet store or signing I/O.
//! Production crypto uses OS/browser entropy; deterministic material is private to tests.
pub mod address;
pub mod crypto;
pub mod legacy_seal;
pub mod protocol;
pub mod registry;
pub mod token;
