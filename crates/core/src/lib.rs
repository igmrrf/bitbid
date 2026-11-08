//! Browser-facing namespace for the shared native/WASM BitSec core.
//! Transport and UI stay in the app crate; protocol/crypto/registry codecs are shared.
pub mod address;
pub mod registry;
pub mod seal;
/// Canonical payload schema and wire encoding, shared with the native CLI.
pub use bitbid_core::protocol;
pub use registry::{DecodeError, RegistryRecord};
pub use seal::TokenError;
