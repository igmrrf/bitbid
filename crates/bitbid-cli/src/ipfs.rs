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

pub fn get_ipfs_cache_dir() -> Result<PathBuf> {
    let dir = crate::wallet::get_app_dir()?.join("ipfs_cache");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    Ok(dir)
}

fn client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(IPFS_TIMEOUT_SECS))
        .build()
        .map_err(|e| anyhow!("failed to build IPFS HTTP client: {}", e))
}

pub(crate) fn resolve_pinning_jwt(conf: &NetworkConfig) -> Result<Option<String>> {
    let selected = if let Some(value) = conf
        .ipfs
        .pinning_jwt
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(value.clone())
    } else {
        std::env::var_os("BITBID_PINATA_JWT")
            .map(|value| {
                value
                    .into_string()
                    .map_err(|_| crate::compat::error("invalid Pinata credential."))
            })
            .transpose()?
    };
    let Some(value) = selected.filter(|s| !s.trim().is_empty()) else {
        return Ok(None);
    };
    // Validate the actual bearer header boundary before constructing/sending a request.
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(crate::compat::error("invalid Pinata credential."));
    }
    reqwest::header::HeaderValue::from_str(&format!("Bearer {value}"))
        .map_err(|_| crate::compat::error("invalid Pinata credential."))?;
    Ok(Some(value))
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
fn cache_file_for(cid: &str) -> Result<PathBuf> {
    Ok(get_ipfs_cache_dir()?.join(format!(
        "{}.json",
        crate::wallet::bytes_to_hex(&crate::wallet::hash_digest(cid.as_bytes()))
    )))
}

fn cache_payload(cid: &str, payload_json: &str) -> Result<()> {
    let cache_file = cache_file_for(cid)?;
    let _ = crate::wallet::write_secure_file(&cache_file, payload_json.as_bytes());
    Ok(())
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
    let conf = crate::network_config::load_network_config()?;
    let jwt = resolve_pinning_jwt(&conf)?;
    let client = client()?;

    // 1. Hosted pinning (Pinata) if a JWT is configured — persists across machines.
    if let Some(jwt) = jwt {
        match pin_via_pinata(&client, &jwt, payload_json) {
            Ok(cid) => {
                if !valid_cid(&cid) {
                    return Err(anyhow!("invalid IPFS CID {:?}", cid));
                }
                cache_payload(&cid, payload_json)?;
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
            cache_payload(&cid, payload_json)?;
            Ok(cid)
        }
        Err(e) => Err(anyhow!(
            "No IPFS backend available. Configure a Pinata JWT (ipfs.pinning_jwt or \
             BITBID_PINATA_JWT) or run a local IPFS daemon reachable at {}. Last error: {}",
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

    let conf = crate::network_config::load_network_config()?;

    // 1. Local cache. Path is hash-derived so it is always contained in the
    //    cache dir regardless of the CID contents.
    let cache_file = cache_file_for(cid)?;
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
pub(super) fn assert_cache_file_containment() {
    let malicious = "/etc/passwd";
    let path = cache_file_for(malicious).unwrap();
    assert!(path.starts_with(get_ipfs_cache_dir().unwrap()), "hash-derived cache path escaped cache dir");
}

/// Exercise the exact production Pinata request builder against an isolated TLS
/// trap. Trust and proxy injection exist only in the test executable.
#[cfg(test)]
pub(super) fn pinata_transport_fixture(
    jwt: &str,
    certificate: &[u8],
    proxy: &str,
) -> Result<String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .add_root_certificate(reqwest::Certificate::from_pem(certificate)?)
        .proxy(reqwest::Proxy::https(proxy)?)
        .build()?;
    pin_via_pinata(&client, jwt, "{\"synthetic\":true}")
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
        // Run the resolver boundary in an isolated process: never select the test user's home.
        crate::compatibility_tests::cache_path_fixture();
    }
}
