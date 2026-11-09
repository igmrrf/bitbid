//! Synchronous host boundaries. Implementations own configuration and I/O policy.
use std::{sync::Arc, time::Duration};

use serde_json::Value;

use crate::{IpfsError, RpcError, StoreError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StoreKey {
    Wallet,
    NetworkConfig,
    SecretIndex,
    ProjectConfig,
    IpfsCache(String),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WriteOpts {
    /// Request private storage permissions from implementations supporting them.
    pub private: bool,
    /// Reject replacement of an existing key with `StoreError::AlreadyExists`.
    pub create_new: bool,
}

pub trait Store: Send + Sync {
    /// Absence is `Ok(None)`, consistent with `exists`.
    fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError>;
    fn write(&self, key: &StoreKey, bytes: &[u8], opts: WriteOpts) -> Result<(), StoreError>;
    fn exists(&self, key: &StoreKey) -> Result<bool, StoreError>;
    /// Removing an absent key succeeds.
    fn remove(&self, key: &StoreKey) -> Result<(), StoreError>;
}

pub trait Ipfs: Send + Sync {
    fn add(&self, bytes: &[u8], name: &str) -> Result<String, IpfsError>;
    fn cat(&self, cid: &str) -> Result<Vec<u8>, IpfsError>;
}

pub trait Rpc: Send + Sync {
    /// Return the JSON-RPC `result`, with missing results represented as Null.
    /// Transport/JSON failures are Request/Decode. Any provider `error` member,
    /// including null, is Provider. Implementations do not introduce retries.
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
    fn sleep(&self, duration: Duration);
}

/// Infallible entropy boundary: implementations must supply valid material or
/// follow their fail-stop policy. Deterministic implementations belong in tests.
pub trait RandomSource: Send + Sync {
    fn fill_bytes(&self, dest: &mut [u8]);
    fn gen_key(&self) -> k256::SecretKey;
}

#[derive(Clone)]
pub struct Host {
    pub store: Arc<dyn Store>,
    pub ipfs: Arc<dyn Ipfs>,
    pub rpc: Arc<dyn Rpc>,
    pub clock: Arc<dyn Clock>,
    pub random: Arc<dyn RandomSource>,
}
