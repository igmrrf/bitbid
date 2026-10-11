//! Pure, host-testable core for the bitbid web console.
//!
//! This crate owns all cryptography (seal/unseal) and all on-chain JSON-RPC
//! decoding so that both can be exercised from the host target without a browser.
//! It has no `wasm`, `web-sys`, or `js-sys` dependencies.

pub mod address;
pub mod registry;
pub mod seal;

pub use registry::{DecodeError, RegistryRecord};
pub use seal::{SealError, SealedEnvelope};
