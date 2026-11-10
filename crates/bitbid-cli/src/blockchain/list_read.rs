//! CLI composition for the selected registry list read. Other operations retain
//! the legacy Ethereum path. Native Store reads stay outside registry_read; its
//! unused storage, IPFS, time, and entropy capabilities remain fail-stop.
use std::{sync::Arc, time::Duration};

use anyhow::Result;
use bitbid_adapters::{rpc::BlockingRpc, store::FileStore};
use bitbid_core::registry_read::{RegistryInfo, read_registry_info};
use bitbid_core::{
    Clock, Host, Ipfs, IpfsError, RandomSource, Store, StoreError, StoreKey, WriteOpts,
};

use super::{Index, OnChainSecretInfo, bytes_to_checksum_address, registry_address};
use crate::network_config::NetworkConfig;

// Select each path only when the original accessor is reached. Store errors and
// decode failures retain the old fallback; path-selection ConfigError does not.
pub(super) fn load_index() -> Result<Index> {
    let path = super::index_path()?;
    let store = FileStore::new([(StoreKey::SecretIndex, path)]);
    Ok(decode_or_default(&store, &StoreKey::SecretIndex))
}

fn load_network_config() -> Result<NetworkConfig> {
    let path = crate::network_config::get_config_path()?;
    let store = FileStore::new([(StoreKey::NetworkConfig, path)]);
    Ok(decode_or_default(&store, &StoreKey::NetworkConfig))
}

fn decode_or_default<T: serde::de::DeserializeOwned + Default>(
    store: &dyn Store,
    key: &StoreKey,
) -> T {
    store
        .read(key)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_str(std::str::from_utf8(&bytes).ok()?).ok())
        .unwrap_or_default()
}

pub(super) fn read(secret_id: &str) -> Result<RegistryInfo> {
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
    // The late reload retains fallback and fatal path-selection effects even
    // though policy uses the enumeration-time hidden flag.
    let _ = load_index()?;
    Ok(info)
}

pub(super) fn project(info: RegistryInfo) -> OnChainSecretInfo {
    OnChainSecretInfo {
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
        hidden: false,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // This decoder has exactly one capability: reading its explicit key. Any
    // eager exists/write/remove operation fails the test immediately.
    struct ReadOnly {
        bytes: Option<Vec<u8>>,
        denied: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Store for ReadOnly {
        fn read(&self, key: &StoreKey) -> std::result::Result<Option<Vec<u8>>, StoreError> {
            assert_eq!(*key, StoreKey::SecretIndex);
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.denied {
                Err(StoreError::PermissionDenied("safe".into()))
            } else {
                Ok(self.bytes.clone())
            }
        }
        fn write(
            &self,
            _: &StoreKey,
            _: &[u8],
            _: WriteOpts,
        ) -> std::result::Result<(), StoreError> {
            panic!("list decoder wrote")
        }
        fn exists(&self, _: &StoreKey) -> std::result::Result<bool, StoreError> {
            panic!("list decoder probed exists")
        }
        fn remove(&self, _: &StoreKey) -> std::result::Result<(), StoreError> {
            panic!("list decoder removed")
        }
    }
    #[test]
    fn store_decoder_reads_only_and_preserves_all_native_fallbacks() {
        for (bytes, denied) in [
            (None, false),
            (Some(vec![255]), false),
            (Some(b"{no".to_vec()), false),
            (Some(b"[]".to_vec()), false),
            // Unknown JSON fields must not bypass the original whole-file UTF-8 check.
            (Some(b"{\"id\":{\"unknown\":\"\xff\"}}".to_vec()), false),
            (None, true),
        ] {
            let store = ReadOnly {
                bytes,
                denied,
                calls: 0.into(),
            };
            let index: Index = decode_or_default(&store, &StoreKey::SecretIndex);
            assert!(index.is_empty());
            assert_eq!(store.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
        let store = ReadOnly {
            bytes: Some(br#"{"original-ID":{"hidden":true}}"#.to_vec()),
            denied: false,
            calls: 0.into(),
        };
        let index: Index = decode_or_default(&store, &StoreKey::SecretIndex);
        assert!(index["original-ID"].hidden);
    }
    #[test]
    fn empty_enumeration_never_invokes_the_network_reader() {
        let calls = Cell::new(0);
        let result =
            super::super::list_index_with(Index::new(), "me", None, false, false, false, |_| {
                calls.set(calls.get() + 1);
                panic!("empty list resolved config/RPC")
            })
            .unwrap();
        assert!(result.is_empty());
        assert_eq!(calls.get(), 0);
    }
}
