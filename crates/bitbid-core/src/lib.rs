//! Shared native/WASM library. No filesystem, process, HTTP, wallet store or signing I/O.
//! Production crypto uses OS/browser entropy; deterministic material is private to tests.
pub mod address;
pub mod crypto;
pub mod legacy_seal;
pub mod ports;
pub mod protocol;
pub mod registry;
pub mod registry_read;
pub mod registry_list;
pub mod token;

pub mod error;
pub use error::{Error, ErrorKind, IpfsError, RpcError, StoreError};
pub use ports::{Clock, Host, Ipfs, RandomSource, Rpc, Store, StoreKey, WriteOpts};
pub mod wallet_codec;
pub mod wallet_read;

/// Versioned client-encrypted team-vault protocol.
pub mod team_vault;
