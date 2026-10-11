//! Pure domain + orchestration + port traits for the proposed split.
//!
//! This is a skeleton: module bodies are intentionally empty so the shape of
//! the partition is visible. Port traits and their types match the spec.

use std::sync::Arc;
use std::time::Duration;

mod error;
pub use error::*;

/// Logical keys for app-owned blobs; hides all path layout from core.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StoreKey {
    Wallet,
    NetworkConfig,
    SecretIndex,
    ProjectConfig,
    IpfsCache(String),
}

/// Write semantics carried by the store (0600/0700 + no-clobber).
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteOpts {
    pub private: bool,
    pub create_new: bool,
}

/// Time source. Infallible. Replaces `current_timestamp` / receipt-poll sleeps.
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
    fn sleep(&self, d: Duration);
}

/// Randomness source. Infallible. Replaces every `OsRng` / `rand` call.
pub trait RandomSource: Send + Sync {
    fn fill_bytes(&self, dest: &mut [u8]);
    // real: k256::SecretKey
    fn gen_key(&self) -> [u8; 32];
}

/// Logical repository for app-owned blobs.
pub trait Store: Send + Sync {
    fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError>;
    fn write(&self, key: &StoreKey, bytes: &[u8], opts: WriteOpts) -> Result<(), StoreError>;
    fn exists(&self, key: &StoreKey) -> Result<bool, StoreError>;
    fn remove(&self, key: &StoreKey) -> Result<(), StoreError>;
}

/// IPFS access; adapter encapsulates Pinata/Kubo/gateway + JWT.
pub trait Ipfs: Send + Sync {
    fn add(&self, bytes: &[u8], name: &str) -> Result<String, IpfsError>;
    fn cat(&self, cid: &str) -> Result<Vec<u8>, IpfsError>;
}

/// A single JSON-RPC round trip; ABI/RLP/signing stays pure in core.
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError>;
}

/// Bundle of port trait objects handed to core entry points.
#[derive(Clone)]
pub struct Host {
    pub store: Arc<dyn Store>,
    pub ipfs: Arc<dyn Ipfs>,
    pub rpc: Arc<dyn Rpc>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn RandomSource>,
}

// --- Module stubs implied by the partition -------------------------------

pub mod bip39_words {}
pub mod blockchain {}
pub mod env_file {}
pub mod errors {}
pub mod eth {}
pub mod ipfs {}
pub mod materialize {}
pub mod network_config {}
pub mod project_config {}
pub mod secrets {}
pub mod wallet {}

/// One stub core use-case, called from the composition root.
pub fn bipplaceholder() -> String {
    "bitbid-core placeholder".to_string()
}
