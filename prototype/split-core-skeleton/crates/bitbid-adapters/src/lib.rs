//! Native implementations of the core ports plus CLI-only facilities.
//! Bodies are `todo!()` stubs: they typecheck and satisfy the traits.

use std::time::Duration;

use bitbid_core::{Clock, Ipfs, IpfsError, RandomSource, Rpc, RpcError, Store, StoreError, StoreKey, WriteOpts};

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        todo!()
    }
    fn sleep(&self, _d: Duration) {
        todo!()
    }
}

pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill_bytes(&self, _dest: &mut [u8]) {
        todo!()
    }
    fn gen_key(&self) -> [u8; 32] {
        todo!()
    }
}

pub struct NativeStore;

impl Store for NativeStore {
    fn read(&self, _key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
        todo!()
    }
    fn write(&self, _key: &StoreKey, _bytes: &[u8], _opts: WriteOpts) -> Result<(), StoreError> {
        todo!()
    }
    fn exists(&self, _key: &StoreKey) -> Result<bool, StoreError> {
        todo!()
    }
    fn remove(&self, _key: &StoreKey) -> Result<(), StoreError> {
        todo!()
    }
}

pub struct BlockingIpfs;

impl Ipfs for BlockingIpfs {
    fn add(&self, _bytes: &[u8], _name: &str) -> Result<String, IpfsError> {
        todo!()
    }
    fn cat(&self, _cid: &str) -> Result<Vec<u8>, IpfsError> {
        todo!()
    }
}

pub struct BlockingRpc;

impl Rpc for BlockingRpc {
    fn call(&self, _method: &str, _params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        todo!()
    }
}

// --- CLI-only stub modules ----------------------------------------------

pub mod terminal {}
pub mod process {}
pub mod env {}
pub mod print {}

// --- Native-only facility (gated out of wasm) ----------------------------

/// Proves the `cfg(not(target_arch = "wasm32"))` gating pattern: `libc` is
/// declared only for non-wasm targets and is actually referenced here.
#[cfg(not(target_arch = "wasm32"))]
pub fn staging_pid() -> libc::pid_t {
    // real: signal/staging cleanup for materialize
    unsafe { libc::getpid() }
}
