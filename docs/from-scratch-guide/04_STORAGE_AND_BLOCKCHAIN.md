# Part 4: Storage & Blockchain Integration

This module details constructing the IPFS decentralised file storage engine and EVM RPC blockchain client with offline local registry fallback logic.

---

## 1. Concepts & Documentation Links

- **IPFS InterPlanetary File System**: Content-addressed storage for encrypted payloads ([IPFS Docs](https://docs.ipfs.tech/)).
- **Keccak-256**: SHA-3 cryptographic hash function used in Ethereum ([sha3 crate](https://docs.rs/sha3/latest/sha3/)).
- **EIP-55 Checksum Encoding**: Mixed-case checksum address standard for EVM addresses ([EIP-55 Spec](https://eips.ethereum.org/EIPS/eip-55)).
- **JSON-RPC 2.0**: Standard protocol for interacting with EVM RPC nodes ([reqwest crate](https://docs.rs/reqwest/latest/reqwest/)).

---

## 2. Network Config Module ([`src/network_config.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/network_config.rs))

Create `src/network_config.rs`:

```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpfsConfig {
    pub gateway: String,
    pub pinning_service: Option<String>,
    /// Kubo RPC API endpoint (local daemon or self-hosted node).
    #[serde(default = "default_ipfs_api_url")]
    pub api_url: String,
    /// Pinata JWT for hosted pinning. Falls back to the BSEC_PINATA_JWT env var.
    #[serde(default)]
    pub pinning_jwt: Option<String>,
}

fn default_ipfs_api_url() -> String {
    "http://127.0.0.1:5001".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub network: String,
    pub chain_id: u32,
    pub rpc_url: String,
    pub registry_address: String,
    pub ipfs: IpfsConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network: "amoy".to_string(),
            chain_id: 80002,
            rpc_url: "https://rpc-amoy.polygon.technology".to_string(),
            registry_address: "0x39a13aC4081076bEDdA4cCdC8b8E8d8f07F3bA49".to_string(),
            ipfs: IpfsConfig {
                gateway: "https://ipfs.io/ipfs/".to_string(),
                pinning_service: None,
                api_url: default_ipfs_api_url(),
                pinning_jwt: None,
            },
        }
    }
}

pub fn get_config_path() -> PathBuf {
    crate::wallet::get_app_dir().join("network-config.json")
}

pub fn load_network_config() -> NetworkConfig {
    let path = get_config_path();
    if let Ok(content) = fs::read_to_string(&path)
        && let Ok(config) = serde_json::from_str(&content) {
            return config;
        }
    NetworkConfig::default()
}

pub fn save_network_config(config: &NetworkConfig) -> Result<()> {
    let path = get_config_path();
    let content = serde_json::to_string_pretty(config)?;
    crate::wallet::write_secure_file(&path, content.as_bytes())?;
    Ok(())
}

pub fn update_network_config(
    network: Option<String>,
    rpc: Option<String>,
    registry: Option<String>,
    ipfs_gateway: Option<String>,
    ipfs_pinning: Option<String>,
) -> Result<NetworkConfig> {
    let mut config = load_network_config();

    if let Some(net) = network {
        match net.to_lowercase().as_str() {
            "polygon" => {
                config.network = "polygon".to_string();
                config.chain_id = 137;
                if rpc.is_none() {
                    config.rpc_url = "https://polygon-rpc.com".to_string();
                }
            }
            "base" => {
                config.network = "base".to_string();
                config.chain_id = 8453;
                if rpc.is_none() {
                    config.rpc_url = "https://mainnet.base.org".to_string();
                }
            }
            "local" | "anvil" | "hardhat" => {
                config.network = "local".to_string();
                config.chain_id = 31337;
                if rpc.is_none() {
                    config.rpc_url = "http://localhost:8545".to_string();
                }
            }
            "amoy" => {
                config.network = "amoy".to_string();
                config.chain_id = 80002;
                if rpc.is_none() {
                    config.rpc_url = "https://rpc-amoy.polygon.technology".to_string();
                }
            }
            "sepolia" => {
                config.network = "sepolia".to_string();
                config.chain_id = 11155111;
                if rpc.is_none() {
                    config.rpc_url = "https://rpc.sepolia.org".to_string();
                }
            }
            "base-sepolia" => {
                config.network = "base-sepolia".to_string();
                config.chain_id = 84532;
                if rpc.is_none() {
                    config.rpc_url = "https://sepolia.base.org".to_string();
                }
            }
            "ethereum" => {
                config.network = "ethereum".to_string();
                config.chain_id = 1;
                if rpc.is_none() {
                    config.rpc_url = "https://mainnet.infura.io/v3/your-infura-key".to_string();
                }
            }
            custom => {
                config.network = custom.to_string();
            }
        }
    }

    if let Some(r) = rpc {
        config.rpc_url = r;
    }

    if let Some(reg) = registry {
        config.registry_address = reg;
    }

    if let Some(g) = ipfs_gateway {
        config.ipfs.gateway = g;
    }

    if let Some(p) = ipfs_pinning {
        config.ipfs.pinning_service = Some(p);
    }

    save_network_config(&config)?;
    Ok(config)
}
```

---

## 3. IPFS Engine ([`src/ipfs.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/ipfs.rs))

Create `src/ipfs.rs`:

```rust
//! Real IPFS storage.
//!
//! Upload: Pinata `pinFileToIPFS` when a JWT is configured, otherwise a Kubo RPC daemon
//! (`/api/v0/add`). Fetch: local cache, then Kubo `cat`, then the configured and public
//! gateways. No mock CIDs, no fabricated success — an unreachable backend returns an error.
//!
//! Integrity: payloads are AES-256-GCM encrypted, so a tampered or substituted blob fails
//! AEAD authentication (or JSON parsing) downstream rather than silently compromising the
//! secret. Reproducing IPFS dag-pb chunking to recompute the CID is therefore unnecessary.

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use crate::network_config::NetworkConfig;

const IPFS_TIMEOUT_SECS: u64 = 15;

pub fn get_ipfs_cache_dir() -> PathBuf {
    let dir = crate::wallet::get_app_dir().join("ipfs_cache");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(IPFS_TIMEOUT_SECS))
        .build()
        .map_err(|e| anyhow!("failed to build IPFS HTTP client: {}", e))
}

fn resolve_pinning_jwt(conf: &NetworkConfig) -> Option<String> {
    conf.ipfs
        .pinning_jwt
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("BSEC_PINATA_JWT").ok().filter(|s| !s.trim().is_empty()))
}

/// Accept only well-formed CID strings: length in 2..=64 and every byte
/// ASCII-alphanumeric (base58btc / base32 charset). Rejects '/', '.', '\0',
/// whitespace, and any other separator that could enable path traversal.
fn valid_cid(cid: &str) -> bool {
    let len = cid.len();
    (2..=64).contains(&len) && cid.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Derive the on-disk cache filename from a SHA-256 hash of the CID so the
/// path is ALWAYS contained within the cache dir, even if `valid_cid` is ever
/// bypassed. Both write (upload) and read (fetch) MUST use this same
/// derivation so the same CID maps to the same file.
fn cache_file_for(cid: &str) -> PathBuf {
    get_ipfs_cache_dir().join(format!(
        "{}.json",
        crate::wallet::bytes_to_hex(&crate::wallet::hash_digest(cid.as_bytes()))
    ))
}

fn cache_payload(cid: &str, payload_json: &str) {
    let cache_file = cache_file_for(cid);
    let _ = crate::wallet::write_secure_file(&cache_file, payload_json.as_bytes());
}

fn pin_via_pinata(client: &Client, jwt: &str, payload_json: &str) -> Result<String> {
    let form = reqwest::blocking::multipart::Form::new()
        .text("file", payload_json.to_string());
    let res = client
        .post("https://api.pinata.cloud/pinning/pinFileToIPFS")
        .bearer_auth(jwt)
        .multipart(form)
        .send()
        .map_err(|e| anyhow!("Pinata request failed: {}", e))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().unwrap_or_default();
        return Err(anyhow!("Pinata pinning failed ({}): {}", status, body));
    }
    let json: serde_json::Value = res.json().map_err(|e| anyhow!("Pinata response decode error: {}", e))?;
    let cid = json
        .get("IpfsHash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("Pinata response missing IpfsHash"))?;
    Ok(cid.to_string())
}

fn add_via_kubo(client: &Client, api_url: &str, payload_json: &str) -> Result<String> {
    let url = format!("{}/api/v0/add", api_url.trim_end_matches('/'));
    let form = reqwest::blocking::multipart::Form::new()
        .text("file", payload_json.to_string());
    let res = client
        .post(&url)
        .multipart(form)
        .send()
        .map_err(|e| anyhow!("IPFS daemon request to {} failed: {}", url, e))?;
    if !res.status().is_success() {
        return Err(anyhow!("IPFS daemon add failed ({})", res.status()));
    }
    let json: serde_json::Value = res.json().map_err(|e| anyhow!("IPFS add response decode error: {}", e))?;
    let cid = json
        .get("Hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("IPFS add response missing Hash"))?;
    Ok(cid.to_string())
}

/// Upload a payload to IPFS. Returns a real CID. Errors if no backend is reachable.
pub fn upload_to_ipfs(payload_json: &str) -> Result<String> {
    let conf = crate::network_config::load_network_config();
    let client = client()?;

    // 1. Hosted pinning (Pinata) if a JWT is configured — persists across machines.
    if let Some(jwt) = resolve_pinning_jwt(&conf) {
        match pin_via_pinata(&client, &jwt, payload_json) {
            Ok(cid) => {
                if !valid_cid(&cid) {
                    return Err(anyhow!("invalid IPFS CID {:?}", cid));
                }
                cache_payload(&cid, payload_json);
                return Ok(cid);
            }
            Err(e) => log::warn!("Pinata pinning failed, trying local IPFS daemon: {}", e),
        }
    }

    // 2. Local / self-hosted Kubo daemon.
    match add_via_kubo(&client, &conf.ipfs.api_url, payload_json) {
        Ok(cid) => {
            if !valid_cid(&cid) {
                return Err(anyhow!("invalid IPFS CID {:?}", cid));
            }
            cache_payload(&cid, payload_json);
            Ok(cid)
        }
        Err(e) => Err(anyhow!(
            "No IPFS backend available. Configure a Pinata JWT (ipfs.pinning_jwt or \
             BSEC_PINATA_JWT) or run a local IPFS daemon reachable at {}. Last error: {}",
            conf.ipfs.api_url,
            e
        )),
    }
}

fn cat_via_kubo(client: &Client, api_url: &str, cid: &str) -> Option<String> {
    let url = format!("{}/api/v0/cat?arg={}", api_url.trim_end_matches('/'), cid);
    match client.post(&url).send() {
        Ok(res) if res.status().is_success() => res.text().ok(),
        _ => None,
    }
}

/// Fetch a payload by CID: local cache, then Kubo daemon, then gateways.
pub fn fetch_from_ipfs(cid: &str) -> Result<String> {
    // Reject attacker-controlled, malformed CIDs before any filesystem or
    // network use.
    if !valid_cid(cid) {
        return Err(anyhow!("invalid IPFS CID {:?}", cid));
    }

    let conf = crate::network_config::load_network_config();

    // 1. Local cache. Path is hash-derived so it is always contained in the
    //    cache dir regardless of the CID contents.
    let cache_file = cache_file_for(cid);
    if let Ok(cached) = fs::read_to_string(&cache_file) {
        return Ok(cached);
    }

    let client = client()?;

    // 2. Kubo daemon cat.
    if let Some(text) = cat_via_kubo(&client, &conf.ipfs.api_url, cid) {
        let _ = crate::wallet::write_secure_file(&cache_file, text.as_bytes());
        return Ok(text);
    }

    // 3. Configured + public gateways.
    let configured = format!(
        "{}{}",
        conf.ipfs.gateway.trim_end_matches('/'),
        "/",
    );
    let gateways = [
        configured,
        "https://ipfs.io/ipfs/".to_string(),
        "https://dweb.link/ipfs/".to_string(),
    ];

    for gw in gateways {
        let url = format!("{}{}", gw, cid);
        if let Ok(res) = client.get(&url).send()
            && res.status().is_success()
            && let Ok(text) = res.text()
        {
            let _ = crate::wallet::write_secure_file(&cache_file, text.as_bytes());
            return Ok(text);
        }
    }

    Err(anyhow!(
        "Failed to fetch payload for IPFS CID '{}' from daemon or gateways.",
        cid
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_cid_accepts_cidv0() {
        // Realistic CIDv0 (base58btc, starts with "Qm").
        assert!(valid_cid("QmXwF1ttoPek9x6Qq7bZ9k4x4mS4Lq9uH8dF6yZ2aB3cD4"));
    }

    #[test]
    fn valid_cid_accepts_cidv1_base32() {
        // Realistic CIDv1 (base32, starts with "bafy").
        assert!(valid_cid(
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        ));
    }

    #[test]
    fn valid_cid_rejects_traversal_and_malformed() {
        assert!(!valid_cid("../etc"));
        assert!(!valid_cid("/etc/passwd"));
        assert!(!valid_cid("a/b"));
        assert!(!valid_cid(""));
        assert!(!valid_cid("x\0y"));
        // Over-long: 100 chars exceeds the 64 upper bound.
        assert!(!valid_cid(&"a".repeat(100)));
    }

    #[test]
    fn cache_file_for_stays_inside_cache_dir() {
        let malicious = "/etc/passwd";
        let path = cache_file_for(malicious);
        assert!(
            path.starts_with(get_ipfs_cache_dir()),
            "hash-derived cache path {:?} escaped cache dir",
            path
        );
    }
}
```

---

## 4. Blockchain Client Module ([`src/blockchain.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/blockchain.rs))

Create `src/blockchain.rs`:

```rust
//! On-chain registry access for BsecSecretRegistry.
//!
//! All state-changing operations are real signed transactions; all reads are real
//! `eth_call`s against the configured RPC node (remote or local anvil). A local index
//! (`~/.bsec/secret_index.json`) only enumerates the secret IDs this wallet has created or
//! viewed and tracks a local-only `hidden` flag — the authoritative state (reads, revocation,
//! expiry, recipient) always comes from the chain.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::eth;
use crate::network_config::{load_network_config, NetworkConfig};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OnChainSecretInfo {
    pub sender: String,
    pub recipient: String,
    pub ipfs_cid: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_reads: u32,
    pub read_count: u32,
    pub revoked: bool,
    pub is_public: bool,
    pub is_expired: bool,
    pub limit_reached: bool,
    #[serde(default)]
    pub hidden: bool,
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn bytes_to_checksum_address(bytes: &[u8; 20]) -> String {
    let hex_lower = crate::wallet::bytes_to_hex(bytes);
    let hash = keccak256(hex_lower.as_bytes());
    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");

    for (i, ch) in hex_lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            checksummed.push(ch);
        } else {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                checksummed.push(ch.to_ascii_uppercase());
            } else {
                checksummed.push(ch.to_ascii_lowercase());
            }
        }
    }
    checksummed
}

/// Encode a secret ID string into a bytes32 contract key. Only two shapes are accepted,
/// both mapped losslessly and left-aligned:
///
/// - a "0x"-prefixed hex string that decodes to AT MOST 32 bytes, or
/// - a non-hex ID whose raw UTF-8 is AT MOST 32 bytes.
///
/// Anything longer is rejected rather than silently truncated — silent truncation let
/// distinct IDs collide on the same on-chain bytes32 key.
pub fn encode_bytes32_hex(id_str: &str) -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    if id_str.starts_with("0x") {
        let b = crate::wallet::hex_to_bytes(id_str)?;
        if b.len() > 32 {
            return Err(anyhow!("secret ID {:?} decodes to {} bytes; max 32", id_str, b.len()));
        }
        bytes[..b.len()].copy_from_slice(&b);
        return Ok(bytes);
    }
    let raw = id_str.as_bytes();
    if raw.len() > 32 {
        return Err(anyhow!("secret ID {:?} is {} bytes; max 32", id_str, raw.len()));
    }
    bytes[..raw.len()].copy_from_slice(raw);
    Ok(bytes)
}

fn registry_address(conf: &NetworkConfig) -> Result<[u8; 20]> {
    eth::parse_address(&conf.registry_address).map_err(|e| {
        anyhow!(
            "Invalid registry_address '{}' in network config: {}",
            conf.registry_address,
            e
        )
    })
}

// ---------------------------------------------------------------------------
// Local index (enumeration + hidden flag only)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct IndexEntry {
    #[serde(default)]
    hidden: bool,
    #[serde(default)]
    role: String,
}

type Index = BTreeMap<String, IndexEntry>;

fn index_path() -> PathBuf {
    crate::wallet::get_app_dir().join("secret_index.json")
}

fn load_index() -> Index {
    match fs::read_to_string(index_path()) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Index::new(),
    }
}

fn save_index(index: &Index) -> Result<()> {
    let content = serde_json::to_string_pretty(index)?;
    crate::wallet::write_secure_file(&index_path(), content.as_bytes())
}

/// Record that this wallet knows about a secret (created or received), for `list`.
pub fn index_note(secret_id: &str, role: &str) {
    let mut index = load_index();
    let entry = index.entry(secret_id.to_string()).or_default();
    if entry.role.is_empty() {
        entry.role = role.to_string();
    }
    let _ = save_index(&index);
}

fn index_set_hidden(secret_id: &str, hidden: bool) {
    let mut index = load_index();
    index.entry(secret_id.to_string()).or_default().hidden = hidden;
    let _ = save_index(&index);
}

fn index_is_hidden(secret_id: &str) -> bool {
    load_index().get(secret_id).map(|e| e.hidden).unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Contract operations
// ---------------------------------------------------------------------------

/// Register a secret on-chain via a signed shareSecret transaction. Returns the tx hash.
pub fn register_secret_on_chain(
    priv_bytes: &[u8],
    secret_id: &str,
    recipient_addr: &[u8; 20],
    ipfs_cid: &str,
    expires_at: u64,
    max_reads: u32,
    is_public: bool,
) -> Result<String> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id)?;
    let data = eth::encode_share_secret(&id32, recipient_addr, ipfs_cid, expires_at, max_reads, is_public);
    let tx_hash = eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    index_note(secret_id, "sender");
    Ok(tx_hash)
}

pub fn get_secret_info_on_chain(secret_id: &str) -> Result<OnChainSecretInfo> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id)?;
    let data = eth::encode_bytes32_call("getSecretInfo(bytes32)", &id32);

    let ret = eth::eth_call(&conf, &to, &data).map_err(|e| {
        anyhow!("Secret ID '{}' not found on-chain (or RPC error): {}", secret_id, e)
    })?;
    if ret.is_empty() {
        return Err(anyhow!("Secret ID '{}' not found on blockchain registry.", secret_id));
    }
    let d = eth::decode_secret_info(&ret)?;

    let recipient = if d.is_public {
        "public".to_string()
    } else {
        bytes_to_checksum_address(&d.recipient)
    };

    Ok(OnChainSecretInfo {
        sender: bytes_to_checksum_address(&d.sender),
        recipient,
        ipfs_cid: d.ipfs_cid,
        created_at: d.created_at,
        expires_at: d.expires_at,
        max_reads: d.max_reads,
        read_count: d.read_count,
        revoked: d.revoked,
        is_public: d.is_public,
        is_expired: d.is_expired,
        limit_reached: d.limit_reached,
        hidden: index_is_hidden(secret_id),
    })
}

pub fn record_read_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id)?;
    let data = eth::encode_bytes32_call("recordRead(bytes32)", &id32);
    eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    Ok(())
}

pub fn revoke_secret_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    let conf = load_network_config();
    let to = registry_address(&conf)?;
    let id32 = encode_bytes32_hex(secret_id)?;
    let data = eth::encode_bytes32_call("revokeSecret(bytes32)", &id32);
    eth::send_contract_tx(&conf, priv_bytes, &to, &data)?;
    Ok(())
}

/// Hide a secret locally (contract has no hidden state) and best-effort revoke on-chain.
pub fn hide_secret_on_chain(priv_bytes: &[u8], secret_id: &str) -> Result<()> {
    index_set_hidden(secret_id, true);
    if let Err(e) = revoke_secret_on_chain(priv_bytes, secret_id) {
        log::warn!(
            "On-chain revocation not performed for secret '{}' during hide (kept local hide): {}",
            secret_id,
            e
        );
    }
    Ok(())
}

pub fn list_secrets_on_chain(
    user_address: &str,
    filter_user: Option<&str>,
    all: bool,
    expired_only: bool,
    active_only: bool,
) -> Result<Vec<(String, OnChainSecretInfo)>> {
    let index = load_index();
    let mut results = Vec::new();

    for (sec_id, entry) in index.iter() {
        let rec = match get_secret_info_on_chain(sec_id) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Skipping secret '{}' in listing (chain read failed): {}", sec_id, e);
                continue;
            }
        };

        let is_expired = rec.is_expired || rec.limit_reached || rec.revoked;
        let is_mine = rec.is_public
            || rec.sender.to_lowercase() == user_address.to_lowercase()
            || rec.recipient.to_lowercase() == user_address.to_lowercase();

        if entry.hidden && !all {
            continue;
        }

        if let Some(target) = filter_user {
            if rec.recipient.to_lowercase() != target.to_lowercase()
                && rec.sender.to_lowercase() != target.to_lowercase()
            {
                continue;
            }
        } else if !all && !is_mine {
            continue;
        }

        if expired_only && !is_expired {
            continue;
        }
        if active_only && is_expired {
            continue;
        }

        results.push((sec_id.clone(), rec));
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_0x_64hex_decodes_to_32_bytes() {
        let id = format!("0x{}", "ab".repeat(32)); // 0x + 64 hex chars = 32 bytes
        let out = encode_bytes32_hex(&id).expect("valid 32-byte hex id must encode");
        assert_eq!(out, [0xabu8; 32]);
    }

    #[test]
    fn oversized_0x_hex_is_rejected() {
        let id = format!("0x{}", "cd".repeat(33)); // decodes to 33 bytes > 32
        assert!(encode_bytes32_hex(&id).is_err());
    }

    #[test]
    fn oversized_raw_id_is_rejected() {
        let id = "z".repeat(33); // non-hex raw id, 33 bytes > 32
        assert!(encode_bytes32_hex(&id).is_err());
    }

    #[test]
    fn short_raw_id_is_left_aligned() {
        let out = encode_bytes32_hex("hello").expect("short raw id must encode");
        let mut expected = [0u8; 32];
        expected[..5].copy_from_slice(b"hello");
        assert_eq!(out, expected);
    }

    #[test]
    fn checksum_address_eip55_known_vectors() {
        // Parse a 40-hex string into a fixed 20-byte address.
        fn addr(hex: &str) -> [u8; 20] {
            let bytes = crate::wallet::hex_to_bytes(hex).expect("valid 40-hex address");
            let mut out = [0u8; 20];
            out.copy_from_slice(&bytes);
            out
        }

        // Official EIP-55 checksum vectors.
        assert_eq!(
            bytes_to_checksum_address(&addr("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert_eq!(
            bytes_to_checksum_address(&addr("fb6916095ca1df60bb79ce92ce3ea74c37c5d359")),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(
            bytes_to_checksum_address(&addr("dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb")),
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        );
    }
}
```

---

## 5. Verification

Build modules:
```bash
cargo check
```


## 4. Ethereum Interoperability ([`src/eth.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/eth.rs))

```rust
//! Ethereum JSON-RPC + transaction layer.
//!
//! Real on-chain interaction: ABI encode/decode for the BsecSecretRegistry contract,
//! transaction signing (secp256k1 via k256), and receipt polling. Chains that report a
//! `baseFeePerGas` (post-London) are sent EIP-1559 type-2 transactions; chains without one
//! fall back to EIP-155 legacy signing.
//! No fabricated results: every call hits the configured RPC endpoint or returns an error.

use anyhow::{anyhow, Result};
use k256::SecretKey;
use k256::ecdsa::SigningKey;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::time::Duration;

use crate::blockchain::keccak256;
use crate::network_config::NetworkConfig;
use crate::wallet::{bytes_to_hex, hex_to_bytes};

const RPC_TIMEOUT_SECS: u64 = 20;
const RECEIPT_POLL_ATTEMPTS: u32 = 60;
const RECEIPT_POLL_INTERVAL_SECS: u64 = 2;

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(RPC_TIMEOUT_SECS))
        .build()
        .map_err(|e| anyhow!("failed to build HTTP client: {}", e))
}

/// Perform a JSON-RPC 2.0 call against the configured node. Surfaces RPC-level errors.
pub fn rpc(conf: &NetworkConfig, method: &str, params: Value) -> Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let res = http_client()?
        .post(&conf.rpc_url)
        .json(&body)
        .send()
        .map_err(|e| anyhow!("RPC connection error to {}: {}", conf.rpc_url, e))?;
    let parsed: Value = res
        .json()
        .map_err(|e| anyhow!("RPC response decode error from {}: {}", conf.rpc_url, e))?;
    if let Some(err) = parsed.get("error") {
        return Err(anyhow!("RPC error from {}: {}", conf.rpc_url, err));
    }
    Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
}

fn hex_to_u128(s: &str) -> Result<u128> {
    let t = s.trim().trim_start_matches("0x");
    let t = if t.is_empty() { "0" } else { t };
    u128::from_str_radix(t, 16).map_err(|e| anyhow!("invalid hex integer '{}': {}", s, e))
}

// ---------------------------------------------------------------------------
// Minimal RLP encoder (subset: a transaction is a list of byte-strings).
// Integers are big-endian with no leading zeros; 0 encodes as the empty string.
// ---------------------------------------------------------------------------

fn be_trim(bytes: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    bytes[i..].to_vec()
}

fn be_trim_u128(v: u128) -> Vec<u8> {
    be_trim(&v.to_be_bytes())
}

fn len_bytes(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.insert(0, (n & 0xff) as u8);
        n >>= 8;
    }
    out
}

fn encode_len(len: usize, short_base: u8, long_base: u8) -> Vec<u8> {
    if len <= 55 {
        vec![short_base + len as u8]
    } else {
        let lb = len_bytes(len);
        let mut out = vec![long_base + lb.len() as u8];
        out.extend_from_slice(&lb);
        out
    }
}

/// RLP-encode a single byte-string item.
fn rlp_str(s: &[u8]) -> Vec<u8> {
    if s.len() == 1 && s[0] < 0x80 {
        vec![s[0]]
    } else {
        let mut out = encode_len(s.len(), 0x80, 0xb7);
        out.extend_from_slice(s);
        out
    }
}

/// RLP-encode a list whose every element is a raw byte-string field.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for it in items {
        payload.extend_from_slice(&rlp_str(it));
    }
    let mut out = encode_len(payload.len(), 0xc0, 0xf7);
    out.extend_from_slice(&payload);
    out
}

// ---------------------------------------------------------------------------
// Addressing
// ---------------------------------------------------------------------------

pub fn address_bytes_from_secret(priv_bytes: &[u8]) -> Result<[u8; 20]> {
    let sk = SecretKey::from_slice(priv_bytes).map_err(|e| anyhow!("invalid private key: {}", e))?;
    let pk = sk.public_key();
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let ep = pk.to_encoded_point(false);
    let hash = keccak256(&ep.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

/// Parse a hex "0x..." address into 20 bytes.
pub fn parse_address(addr: &str) -> Result<[u8; 20]> {
    let bytes = hex_to_bytes(addr)?;
    if bytes.len() != 20 {
        return Err(anyhow!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn addr_hex(addr: &[u8; 20]) -> String {
    format!("0x{}", bytes_to_hex(addr))
}

// ---------------------------------------------------------------------------
// ABI encoding
// ---------------------------------------------------------------------------

fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn word_from_right(bytes: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let n = bytes.len().min(32);
    w[32 - n..].copy_from_slice(&bytes[bytes.len() - n..]);
    w
}

fn word_u128(v: u128) -> [u8; 32] {
    word_from_right(&v.to_be_bytes())
}

fn word_addr(addr: &[u8; 20]) -> [u8; 32] {
    word_from_right(addr)
}

fn word_bool(b: bool) -> [u8; 32] {
    word_u128(if b { 1 } else { 0 })
}

/// ABI-encode shareSecret(bytes32,address,string,uint64,uint32,bool).
pub fn encode_share_secret(
    secret_id: &[u8; 32],
    recipient: &[u8; 20],
    ipfs_cid: &str,
    expires_at: u64,
    max_reads: u32,
    is_public: bool,
) -> Vec<u8> {
    let sel = selector("shareSecret(bytes32,address,string,uint64,uint32,bool)");
    let mut out = Vec::new();
    out.extend_from_slice(&sel);

    // 6 head words; the string is dynamic, its head slot holds the tail offset.
    let head_words = 6usize;
    out.extend_from_slice(secret_id);
    out.extend_from_slice(&word_addr(recipient));
    out.extend_from_slice(&word_u128((head_words * 32) as u128)); // offset to string
    out.extend_from_slice(&word_u128(expires_at as u128));
    out.extend_from_slice(&word_u128(max_reads as u128));
    out.extend_from_slice(&word_bool(is_public));

    // tail: string length + padded bytes
    let cid_bytes = ipfs_cid.as_bytes();
    out.extend_from_slice(&word_u128(cid_bytes.len() as u128));
    out.extend_from_slice(cid_bytes);
    let pad = (32 - (cid_bytes.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// ABI-encode a single-bytes32-arg call (recordRead / revokeSecret / getSecretInfo).
pub fn encode_bytes32_call(signature: &str, secret_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&selector(signature));
    out.extend_from_slice(secret_id);
    out
}

// ---------------------------------------------------------------------------
// ABI decoding for getSecretInfo return tuple
// ---------------------------------------------------------------------------

/// Decoded getSecretInfo() return values.
pub struct DecodedSecretInfo {
    pub sender: [u8; 20],
    pub recipient: [u8; 20],
    pub ipfs_cid: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_reads: u32,
    pub read_count: u32,
    pub revoked: bool,
    pub is_public: bool,
    pub is_expired: bool,
    pub limit_reached: bool,
}

fn word_at(data: &[u8], idx: usize) -> Result<&[u8]> {
    let start = idx * 32;
    data.get(start..start + 32).ok_or_else(|| anyhow!("ABI decode: word {} out of range", idx))
}

fn word_to_u64(w: &[u8]) -> u64 {
    let mut acc = 0u64;
    for &b in &w[24..32] {
        acc = (acc << 8) | b as u64;
    }
    acc
}

fn word_to_u32(w: &[u8]) -> u32 {
    let mut acc = 0u32;
    for &b in &w[28..32] {
        acc = (acc << 8) | b as u32;
    }
    acc
}

fn word_to_addr(w: &[u8]) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..32]);
    a
}

pub fn decode_secret_info(data: &[u8]) -> Result<DecodedSecretInfo> {
    if data.len() < 32 * 11 {
        return Err(anyhow!("ABI decode: return data too short ({} bytes)", data.len()));
    }
    let sender = word_to_addr(word_at(data, 0)?);
    let recipient = word_to_addr(word_at(data, 1)?);
    let str_offset = word_to_u64(word_at(data, 2)?) as usize;
    let created_at = word_to_u64(word_at(data, 3)?);
    let expires_at = word_to_u64(word_at(data, 4)?);
    let max_reads = word_to_u32(word_at(data, 5)?);
    let read_count = word_to_u32(word_at(data, 6)?);
    let revoked = word_to_u64(word_at(data, 7)?) != 0;
    let is_public = word_to_u64(word_at(data, 8)?) != 0;
    let is_expired = word_to_u64(word_at(data, 9)?) != 0;
    let limit_reached = word_to_u64(word_at(data, 10)?) != 0;

    let len_pos = str_offset;
    let str_len = word_to_u64(
        data.get(len_pos..len_pos + 32).ok_or_else(|| anyhow!("ABI decode: string length out of range"))?,
    ) as usize;
    let str_start = len_pos + 32;
    let cid_bytes = data
        .get(str_start..str_start + str_len)
        .ok_or_else(|| anyhow!("ABI decode: string body out of range"))?;
    let ipfs_cid = String::from_utf8(cid_bytes.to_vec()).map_err(|e| anyhow!("ABI decode: cid not utf8: {}", e))?;

    Ok(DecodedSecretInfo {
        sender,
        recipient,
        ipfs_cid,
        created_at,
        expires_at,
        max_reads,
        read_count,
        revoked,
        is_public,
        is_expired,
        limit_reached,
    })
}

// ---------------------------------------------------------------------------
// Read (eth_call) and write (signed tx) paths
// ---------------------------------------------------------------------------

/// eth_call against the registry; returns raw return bytes.
pub fn eth_call(conf: &NetworkConfig, to: &[u8; 20], data: &[u8]) -> Result<Vec<u8>> {
    let obj = json!({ "to": addr_hex(to), "data": format!("0x{}", bytes_to_hex(data)) });
    let res = rpc(conf, "eth_call", json!([obj, "latest"]))?;
    let s = res.as_str().ok_or_else(|| anyhow!("eth_call returned non-string result"))?;
    hex_to_bytes(s)
}

/// Sign an EIP-155 legacy transaction and return the 0x-prefixed raw tx.
// A legacy tx has nine RLP fields; passing them individually is clearer than a wrapper struct.
#[allow(clippy::too_many_arguments)]
fn sign_legacy_tx(
    priv_bytes: &[u8],
    nonce: u128,
    gas_price: u128,
    gas_limit: u128,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Result<String> {
    let unsigned = rlp_list(&[
        be_trim_u128(nonce),
        be_trim_u128(gas_price),
        be_trim_u128(gas_limit),
        to.to_vec(),
        be_trim_u128(value),
        data.to_vec(),
        be_trim_u128(chain_id as u128),
        Vec::new(),
        Vec::new(),
    ]);
    let hash = keccak256(&unsigned);

    let signing_key = SigningKey::from_slice(priv_bytes).map_err(|e| anyhow!("invalid signing key: {}", e))?;
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| anyhow!("transaction signing failed: {}", e))?;
    let sig_bytes = sig.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..64];
    let v = chain_id * 2 + 35 + recid.to_byte() as u64;

    let signed = rlp_list(&[
        be_trim_u128(nonce),
        be_trim_u128(gas_price),
        be_trim_u128(gas_limit),
        to.to_vec(),
        be_trim_u128(value),
        data.to_vec(),
        be_trim_u128(v as u128),
        be_trim(r),
        be_trim(s),
    ]);
    Ok(format!("0x{}", bytes_to_hex(&signed)))
}

/// Default tip if the node does not expose `eth_maxPriorityFeePerGas` (1.5 gwei).
const DEFAULT_PRIORITY_FEE_WEI: u128 = 1_500_000_000;

/// Fetch `baseFeePerGas` of the latest block. `None` means the chain is pre-London
/// (no base fee) and must be sent a legacy transaction.
fn latest_base_fee(conf: &NetworkConfig) -> Result<Option<u128>> {
    let block = rpc(conf, "eth_getBlockByNumber", json!(["latest", false]))?;
    match block.get("baseFeePerGas").and_then(|v| v.as_str()) {
        Some(s) => Ok(Some(hex_to_u128(s)?)),
        None => Ok(None),
    }
}

/// Suggested priority fee (tip) from the node, falling back to a fixed default.
fn suggested_priority_fee(conf: &NetworkConfig) -> u128 {
    match rpc(conf, "eth_maxPriorityFeePerGas", json!([])) {
        Ok(v) => v
            .as_str()
            .and_then(|s| hex_to_u128(s).ok())
            .unwrap_or(DEFAULT_PRIORITY_FEE_WEI),
        Err(_) => DEFAULT_PRIORITY_FEE_WEI,
    }
}

/// RLP-encode the EIP-1559 type-2 field list (without the 0x02 type byte).
/// `access_list` is always the empty list (0xc0); signature fields are appended when present.
#[allow(clippy::too_many_arguments)]
fn eip1559_field_list(
    chain_id: u64,
    nonce: u128,
    max_priority_fee: u128,
    max_fee: u128,
    gas_limit: u128,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    sig: Option<(u8, &[u8], &[u8])>,
) -> Vec<u8> {
    let mut items: Vec<Vec<u8>> = vec![
        rlp_str(&be_trim_u128(chain_id as u128)),
        rlp_str(&be_trim_u128(nonce)),
        rlp_str(&be_trim_u128(max_priority_fee)),
        rlp_str(&be_trim_u128(max_fee)),
        rlp_str(&be_trim_u128(gas_limit)),
        rlp_str(to),
        rlp_str(&be_trim_u128(value)),
        rlp_str(data),
        vec![0xc0], // access_list: empty RLP list
    ];
    if let Some((y_parity, r, s)) = sig {
        items.push(rlp_str(&be_trim_u128(y_parity as u128)));
        items.push(rlp_str(&be_trim(r)));
        items.push(rlp_str(&be_trim(s)));
    }
    let mut payload = Vec::new();
    for it in &items {
        payload.extend_from_slice(it);
    }
    let mut out = encode_len(payload.len(), 0xc0, 0xf7);
    out.extend_from_slice(&payload);
    out
}

/// Sign an EIP-1559 (type-2) transaction and return the 0x-prefixed raw tx.
#[allow(clippy::too_many_arguments)]
fn sign_eip1559_tx(
    priv_bytes: &[u8],
    chain_id: u64,
    nonce: u128,
    max_priority_fee: u128,
    max_fee: u128,
    gas_limit: u128,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
) -> Result<String> {
    let unsigned = eip1559_field_list(
        chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, None,
    );
    let mut to_hash = Vec::with_capacity(1 + unsigned.len());
    to_hash.push(0x02);
    to_hash.extend_from_slice(&unsigned);
    let hash = keccak256(&to_hash);

    let signing_key = SigningKey::from_slice(priv_bytes).map_err(|e| anyhow!("invalid signing key: {}", e))?;
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(&hash)
        .map_err(|e| anyhow!("transaction signing failed: {}", e))?;
    let sig_bytes = sig.to_bytes();
    // For type-2 txs the signature's v is the raw y-parity (0 or 1), not the EIP-155 form.
    let signed = eip1559_field_list(
        chain_id,
        nonce,
        max_priority_fee,
        max_fee,
        gas_limit,
        to,
        value,
        data,
        Some((recid.to_byte(), &sig_bytes[..32], &sig_bytes[32..64])),
    );
    let mut tx = Vec::with_capacity(1 + signed.len());
    tx.push(0x02);
    tx.extend_from_slice(&signed);
    Ok(format!("0x{}", bytes_to_hex(&tx)))
}

/// Build, sign, and broadcast a contract-call transaction; wait for a successful receipt.
/// Returns the transaction hash.
pub fn send_contract_tx(
    conf: &NetworkConfig,
    priv_bytes: &[u8],
    to: &[u8; 20],
    data: &[u8],
) -> Result<String> {
    let from = address_bytes_from_secret(priv_bytes)?;
    let from_hex = addr_hex(&from);

    let nonce = hex_to_u128(
        rpc(conf, "eth_getTransactionCount", json!([from_hex, "pending"]))?
            .as_str()
            .ok_or_else(|| anyhow!("eth_getTransactionCount returned non-string"))?,
    )?;

    let call_obj = json!({
        "from": from_hex,
        "to": addr_hex(to),
        "data": format!("0x{}", bytes_to_hex(data)),
    });
    let gas_limit = match rpc(conf, "eth_estimateGas", json!([call_obj])) {
        Ok(v) => match v.as_str() {
            Some(s) => hex_to_u128(s)?.saturating_mul(12) / 10, // +20% headroom
            None => 300_000,
        },
        Err(e) => {
            // estimateGas reverting usually means the tx itself would revert on-chain.
            return Err(anyhow!("gas estimation failed (transaction would revert): {}", e));
        }
    };

    let chain_id = conf.chain_id as u64;
    // Post-London chains report a base fee -> send EIP-1559 type-2. Pre-London chains have
    // none -> fall back to EIP-155 legacy signing.
    let raw = match latest_base_fee(conf)? {
        Some(base_fee) => {
            let priority = suggested_priority_fee(conf);
            // Standard headroom: cover up to a doubling of the base fee before the tip.
            let max_fee = base_fee.saturating_mul(2).saturating_add(priority);
            sign_eip1559_tx(priv_bytes, chain_id, nonce, priority, max_fee, gas_limit, to, 0, data)?
        }
        None => {
            let gas_price = hex_to_u128(
                rpc(conf, "eth_gasPrice", json!([]))?
                    .as_str()
                    .ok_or_else(|| anyhow!("eth_gasPrice returned non-string"))?,
            )?;
            sign_legacy_tx(priv_bytes, nonce, gas_price, gas_limit, to, 0, data, chain_id)?
        }
    };

    let tx_hash = rpc(conf, "eth_sendRawTransaction", json!([raw]))?
        .as_str()
        .ok_or_else(|| anyhow!("eth_sendRawTransaction returned non-string"))?
        .to_string();

    wait_for_receipt(conf, &tx_hash)?;
    Ok(tx_hash)
}

fn wait_for_receipt(conf: &NetworkConfig, tx_hash: &str) -> Result<()> {
    for _ in 0..RECEIPT_POLL_ATTEMPTS {
        let receipt = rpc(conf, "eth_getTransactionReceipt", json!([tx_hash]))?;
        if !receipt.is_null() {
            let status = receipt.get("status").and_then(|s| s.as_str()).unwrap_or("0x1");
            if status == "0x0" {
                return Err(anyhow!("transaction {} reverted on-chain", tx_hash));
            }
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(RECEIPT_POLL_INTERVAL_SECS));
    }
    Err(anyhow!("timed out waiting for receipt of transaction {}", tx_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_single_byte() {
        assert_eq!(rlp_str(&[0x00]), vec![0x00]);
        assert_eq!(rlp_str(&[0x7f]), vec![0x7f]);
        assert_eq!(rlp_str(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn rlp_empty_is_0x80() {
        assert_eq!(rlp_str(&[]), vec![0x80]);
        assert_eq!(be_trim_u128(0), Vec::<u8>::new());
    }

    #[test]
    fn rlp_short_string() {
        // "dog" -> 0x83 'd' 'o' 'g'
        assert_eq!(rlp_str(b"dog"), vec![0x83, b'd', b'o', b'g']);
    }

    #[test]
    fn rlp_list_of_two() {
        // ["cat","dog"] -> 0xc8 0x83 cat 0x83 dog
        let l = rlp_list(&[b"cat".to_vec(), b"dog".to_vec()]);
        assert_eq!(l, vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']);
    }

    #[test]
    fn selector_transfer() {
        // keccak256("transfer(address,uint256)")[..4] = 0xa9059cbb
        assert_eq!(selector("transfer(address,uint256)"), [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn eip1559_type_byte_and_determinism() {
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let to = [0x11u8; 20];
        let raw1 = sign_eip1559_tx(&pk, 1, 0, 1_000_000_000, 30_000_000_000, 21000, &to, 0, b"").unwrap();
        let raw2 = sign_eip1559_tx(&pk, 1, 0, 1_000_000_000, 30_000_000_000, 21000, &to, 0, b"").unwrap();
        // Type-2 envelope: first byte after 0x is the 0x02 type marker.
        assert!(raw1.starts_with("0x02"));
        // RFC6979 deterministic signing -> identical inputs yield identical raw tx.
        assert_eq!(raw1, raw2);
    }

    #[test]
    fn eip1559_empty_access_list_encoding() {
        // The access_list field is the RLP empty list, a single 0xc0 byte.
        let list = eip1559_field_list(1, 0, 0, 0, 0, &[0u8; 20], 0, b"", None);
        assert!(list.contains(&0xc0));
    }

    #[test]
    fn address_from_known_key() {
        // Well-known test vector: private key 0x0000...0001
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let addr = address_bytes_from_secret(&pk).unwrap();
        assert_eq!(
            format!("0x{}", bytes_to_hex(&addr)),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn hex_to_u128_cases() {
        // Standard 0x-prefixed and bare hex.
        assert_eq!(hex_to_u128("0x10").unwrap(), 16);
        assert_eq!(hex_to_u128("ff").unwrap(), 255);
        // Empty and lone "0x" are treated as zero.
        assert_eq!(hex_to_u128("").unwrap(), 0);
        assert_eq!(hex_to_u128("0x").unwrap(), 0);
        // Surrounding whitespace is trimmed before parsing.
        assert_eq!(hex_to_u128("  0x10  ").unwrap(), 16);
        // Non-hex digits surface as an error.
        assert!(hex_to_u128("0xZZ").is_err());
    }

    #[test]
    fn legacy_tx_structural_and_deterministic() {
        use crate::wallet::hex_to_bytes;
        let mut pk = [0u8; 32];
        pk[31] = 1;
        let to = [0x11u8; 20];
        let raw1 = sign_legacy_tx(&pk, 0, 1_000_000_000, 21000, &to, 0, b"", 1).unwrap();
        let raw2 = sign_legacy_tx(&pk, 0, 1_000_000_000, 21000, &to, 0, b"", 1).unwrap();

        // (a) 0x-prefixed raw tx.
        assert!(raw1.starts_with("0x"));
        // (b) RFC6979 deterministic signing -> identical inputs, identical output.
        assert_eq!(raw1, raw2);
        // (c) NOT an EIP-1559 type-2 envelope; a legacy RLP list starts with a byte
        // >= 0xc0, so the first hex char after 0x is in c/d/e/f.
        assert!(!raw1.starts_with("0x02"));
        let first = raw1.as_bytes()[2] as char;
        assert!(matches!(first, 'c' | 'd' | 'e' | 'f'));
        // (d) Even-length body that round-trips through the crate's hex decoder.
        let body = &raw1[2..];
        assert_eq!(body.len() % 2, 0);
        assert!(hex_to_bytes(body).is_ok());
    }

    #[test]
    fn decode_secret_info_roundtrip() {
        // Push a right-aligned 32-byte word carrying a big-endian integer.
        fn push_word_u128(buf: &mut Vec<u8>, v: u128) {
            let mut w = [0u8; 32];
            w[16..32].copy_from_slice(&v.to_be_bytes());
            buf.extend_from_slice(&w);
        }
        // Push a bool as a right-aligned word (non-zero in the last 8 bytes).
        fn push_word_bool(buf: &mut Vec<u8>, b: bool) {
            push_word_u128(buf, if b { 1 } else { 0 });
        }
        // Push an address into the low 20 bytes (bytes 12..32) of a word.
        fn push_word_addr(buf: &mut Vec<u8>, addr: &[u8; 20]) {
            let mut w = [0u8; 32];
            w[12..32].copy_from_slice(addr);
            buf.extend_from_slice(&w);
        }

        let sender = [0xAAu8; 20];
        let recipient = [0xBBu8; 20];
        let cid = "QmTestCid123";

        let mut buf: Vec<u8> = Vec::new();
        push_word_addr(&mut buf, &sender); // word 0
        push_word_addr(&mut buf, &recipient); // word 1
        push_word_u128(&mut buf, 11 * 32); // word 2: string tail offset = 352
        push_word_u128(&mut buf, 1000); // word 3: created_at
        push_word_u128(&mut buf, 2000); // word 4: expires_at
        push_word_u128(&mut buf, 5); // word 5: max_reads
        push_word_u128(&mut buf, 2); // word 6: read_count
        push_word_bool(&mut buf, false); // word 7: revoked
        push_word_bool(&mut buf, true); // word 8: is_public
        push_word_bool(&mut buf, false); // word 9: is_expired
        push_word_bool(&mut buf, false); // word 10: limit_reached
        assert_eq!(buf.len(), 11 * 32);

        // Dynamic string tail at offset 352: length word, then padded CID bytes.
        push_word_u128(&mut buf, cid.len() as u128);
        buf.extend_from_slice(cid.as_bytes());
        let pad = (32 - (cid.len() % 32)) % 32;
        buf.extend(std::iter::repeat_n(0u8, pad));

        let d = decode_secret_info(&buf).unwrap();
        assert_eq!(d.sender, sender);
        assert_eq!(d.recipient, recipient);
        assert_eq!(d.ipfs_cid, cid);
        assert_eq!(d.created_at, 1000);
        assert_eq!(d.expires_at, 2000);
        assert_eq!(d.max_reads, 5);
        assert_eq!(d.read_count, 2);
        assert!(!d.revoked);
        assert!(d.is_public);
        assert!(!d.is_expired);
        assert!(!d.limit_reached);
    }

    #[test]
    fn decode_secret_info_rejects_short_buffer() {
        assert!(decode_secret_info(&[0u8; 100]).is_err());
    }
}
```
