//! CLI composition for the selected registry list read. Other operations retain
//! the legacy Ethereum path. No storage, IPFS, time, or entropy port is supplied.
use std::{sync::Arc, time::Duration};

use anyhow::Result;
use bitbid_adapters::rpc::BlockingRpc;
use bitbid_core::registry_read::read_registry_info;
use bitbid_core::{
    Clock, Host, Ipfs, IpfsError, RandomSource, Store, StoreError, StoreKey, WriteOpts,
};

use super::{OnChainSecretInfo, bytes_to_checksum_address, index_is_hidden, registry_address};
use crate::network_config::load_network_config;

pub(super) fn read(secret_id: &str) -> Result<OnChainSecretInfo> {
    let conf = load_network_config()?;
    let registry = registry_address(&conf)?;
    let unused = Arc::new(UnusedForRegistryRead);
    let host = Host {
        store: unused.clone(),
        ipfs: unused.clone(),
        rpc: Arc::new(BlockingRpc::new(conf.rpc_url)),
        clock: unused.clone(),
        random: unused,
    };
    // Project the new core boundary through its payload-free public message.
    // List retains its legacy per-record skip policy and successful exit.
    let info = read_registry_info(&host, &registry, secret_id)
        .map_err(|error| anyhow::anyhow!(error.public_message()))?;
    Ok(OnChainSecretInfo {
        sender: bytes_to_checksum_address(&info.sender),
        recipient: if info.is_public {
            "public".into()
        } else {
            bytes_to_checksum_address(&info.recipient)
        },
        ipfs_cid: info.ipfs_cid,
        created_at: info.created_at,
        expires_at: info.expires_at,
        max_reads: info.max_reads,
        read_count: info.read_count,
        revoked: info.revoked,
        is_public: info.is_public,
        is_expired: info.is_expired,
        limit_reached: info.limit_reached,
        hidden: index_is_hidden(secret_id)?,
    })
}

// Intentionally private and fail-stop: this composition supports Rpc only.
// A future read requiring other ports must explicitly supply real adapters.
struct UnusedForRegistryRead;
impl Store for UnusedForRegistryRead {
    fn read(&self, _: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
        panic!("registry list must not access Store")
    }
    fn write(&self, _: &StoreKey, _: &[u8], _: WriteOpts) -> Result<(), StoreError> {
        panic!("registry list must not access Store")
    }
    fn exists(&self, _: &StoreKey) -> Result<bool, StoreError> {
        panic!("registry list must not access Store")
    }
    fn remove(&self, _: &StoreKey) -> Result<(), StoreError> {
        panic!("registry list must not access Store")
    }
}
impl Ipfs for UnusedForRegistryRead {
    fn add(&self, _: &[u8], _: &str) -> Result<String, IpfsError> {
        panic!("registry list must not access Ipfs")
    }
    fn cat(&self, _: &str) -> Result<Vec<u8>, IpfsError> {
        panic!("registry list must not access Ipfs")
    }
}
impl Clock for UnusedForRegistryRead {
    fn now_unix(&self) -> i64 {
        panic!("registry list must not access Clock")
    }
    fn sleep(&self, _: Duration) {
        panic!("registry list must not access Clock")
    }
}
impl RandomSource for UnusedForRegistryRead {
    fn fill_bytes(&self, _: &mut [u8]) {
        panic!("registry list must not access RandomSource")
    }
    fn gen_key(&self) -> k256::SecretKey {
        panic!("registry list must not access RandomSource")
    }
}
