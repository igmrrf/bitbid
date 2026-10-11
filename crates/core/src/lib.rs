//! Browser-facing namespace for the shared native/WASM BitSec core.
//! Transport and UI stay in the app crate; protocol/crypto/registry codecs are shared.
pub mod address;
pub mod registry;
pub mod seal;
pub use registry::{DecodeError, RegistryRecord};
pub use seal::TokenError;
