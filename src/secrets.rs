use anyhow::{anyhow, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::blockchain::{
    get_secret_info_on_chain, hide_secret_on_chain, list_secrets_on_chain, record_read_on_chain, register_secret_on_chain,
    revoke_secret_on_chain,
};
use crate::ipfs::{fetch_from_ipfs, upload_to_ipfs};
use crate::wallet::{bytes_to_hex, hash_digest, hex_to_bytes};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecretRecord {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub content: String,
    pub content_key: String,
    pub ephemeral_pubkey: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_reads: u32,
    pub read_count: u32,
    pub hidden: bool,
}

pub use bitbid_core::protocol::{BundleMember, IpfsPayload, SecretKind};
#[cfg(test)]
use bitbid_core::crypto::{decrypt_text, encrypt_text};

pub fn parse_duration(ttl_str: &str) -> Result<u64> {
    let ttl_str = ttl_str.trim();
    if ttl_str.is_empty() {
        return Ok(86400 * 7);
    }
    let split_pos = ttl_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(ttl_str.len());
    let (num_part, unit_part) = ttl_str.split_at(split_pos);
    let val: u64 = num_part
        .parse()
        .map_err(|_| anyhow!("Invalid TTL number format"))?;
    let unit = unit_part.trim().to_lowercase();
    let secs = match unit.as_str() {
        "" | "s" | "sec" | "second" | "seconds" => val,
        "m" | "min" | "minute" | "minutes" => {
            val.checked_mul(60).ok_or_else(|| anyhow!("TTL value too large"))?
        }
        "h" | "hr" | "hour" | "hours" => {
            val.checked_mul(3600).ok_or_else(|| anyhow!("TTL value too large"))?
        }
        "d" | "day" | "days" => {
            val.checked_mul(86400).ok_or_else(|| anyhow!("TTL value too large"))?
        }
        "w" | "week" | "weeks" => val
            .checked_mul(86400)
            .ok_or_else(|| anyhow!("TTL value too large"))?
            .checked_mul(7)
            .ok_or_else(|| anyhow!("TTL value too large"))?,
        _ => return Err(anyhow!("Invalid TTL unit (use s, m, h, d, w)")),
    };
    // Enforce a sane upper cap of 100 years.
    if secs > 100 * 365 * 86400 {
        return Err(anyhow!("TTL exceeds maximum (100 years)"));
    }
    Ok(secs)
}

/// Encrypt each bundle member's plaintext body in place with the content key. The IPFS
/// payload JSON is stored cleartext except for these AES-256-GCM ciphertext fields, so
/// member bodies MUST be sealed before upload or they would leak on IPFS.
#[cfg(test)]
fn seal_member_bodies(members: &mut [BundleMember], key: &[u8; 32]) -> Result<()> {
    for m in members.iter_mut() {
        m.content = encrypt_text(&m.content, key)?;
    }
    Ok(())
}

/// Decrypt each bundle member's body in place (inverse of `seal_member_bodies`).
#[cfg(test)]
fn open_member_bodies(members: &mut [BundleMember], key: &[u8; 32]) -> Result<()> {
    for m in members.iter_mut() {
        m.content = decrypt_text(&m.content, key)?;
    }
    Ok(())
}

/// Metadata describing how a shared secret should be materialized to file(s).
#[derive(Default)]
pub struct ShareMeta {
    pub kind: Option<SecretKind>,
    pub filename: Option<String>,
    pub no_export: bool,
    pub content_encoding: Option<String>,
    /// Plaintext bundle members; their bodies are sealed before upload.
    pub members: Option<Vec<BundleMember>>,
}

fn resolve_recipient_pubkey(to_address: &str, sender_info: &crate::wallet::WalletInfo) -> Result<Option<PublicKey>> {
    if to_address.to_lowercase() == sender_info.address.to_lowercase() || to_address == sender_info.public_key {
        let pub_bytes = hex_to_bytes(&sender_info.public_key)?;
        return PublicKey::from_sec1_bytes(&pub_bytes)
            .map(Some)
            .map_err(|e| anyhow!("Invalid sender public key: {}", e));
    }

    if to_address == "public" {
        return Ok(None);
    }

    if to_address.starts_with("0x04") || to_address.starts_with("04") || to_address.starts_with("0x02") || to_address.starts_with("0x03") {
        let pub_bytes = hex_to_bytes(to_address)?;
        return PublicKey::from_sec1_bytes(&pub_bytes)
            .map(Some)
            .map_err(|e| anyhow!("Invalid recipient public key: {}", e));
    }

    Err(crate::errors::BsecError::InvalidRecipient(
        "Recipient must be a valid SEC1 public key (0x04...), your own wallet address, or 'public'. \
         EVM addresses (0x...) of external users cannot be used for ECDH key exchange without their public key."
            .into(),
    )
    .into())
}

pub fn share_secret(
    content: &str,
    ttl_str: &str,
    max_reads: u32,
    to_address: &str,
    sender_address: &str,
    password: Option<&str>,
    meta: ShareMeta,
) -> Result<SecretRecord> {
    let members_size: usize = meta
        .members
        .as_ref()
        .map(|ms| ms.iter().map(|m| m.content.len()).sum())
        .unwrap_or(0);
    if content.len() + members_size > 10 * 1024 * 1024 {
        return Err(anyhow!("Secret content size exceeds maximum limit of 10MB."));
    }

    let ttl_secs = parse_duration(ttl_str)?;
    let now = crate::wallet::current_timestamp();
    let expires_at = now.checked_add(ttl_secs).ok_or_else(|| anyhow!("expiry timestamp overflow"))?;

    let sender_info = crate::wallet::get_wallet_info(password)?;
    let recipient_pubkey_opt = resolve_recipient_pubkey(to_address, &sender_info)?;

    let payload = bitbid_core::crypto::seal_payload(IpfsPayload {
        content: content.to_owned(), content_key: String::new(), ephemeral_pubkey: None,
        kind: meta.kind, filename: meta.filename, no_export: meta.no_export,
        members: meta.members, content_encoding: meta.content_encoding,
    }, recipient_pubkey_opt.as_ref())?;
    let payload_json = String::from_utf8(bitbid_core::protocol::canonical_bytes(&payload)?)?;

    let ipfs_cid = upload_to_ipfs(&payload_json)?;

    // Full 256-bit id (0x + 64 hex) so encode_bytes32_hex maps it losslessly onto the
    // contract's bytes32 key. The previous 16-hex-char id was only 64 bits and, being
    // non-hex-prefixed, was packed as ASCII bytes — inviting collisions on the on-chain key.
    let random_nonce: u64 = rand::random();
    let id_seed = format!("{}:{}:{}:{}", sender_address, to_address, now, random_nonce);
    let secret_id = format!("0x{}", bytes_to_hex(&hash_digest(id_seed.as_bytes())));

    let is_public = to_address == "public";

    // On-chain recipient is an EVM address: zero for public, else derived from the
    // recipient's public key (real ECDH confidentiality is enforced separately).
    let recipient_addr: [u8; 20] = if is_public {
        [0u8; 20]
    } else if let Some(ref pk) = recipient_pubkey_opt {
        let ep = pk.to_encoded_point(false);
        let hash = crate::blockchain::keccak256(&ep.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        addr
    } else {
        [0u8; 20]
    };

    let priv_bytes = Zeroizing::new(hex_to_bytes(&sender_info.private_key)?);

    register_secret_on_chain(
        &priv_bytes,
        &secret_id,
        &recipient_addr,
        &ipfs_cid,
        expires_at,
        max_reads,
        is_public,
    )?;

    let record = SecretRecord {
        id: secret_id.clone(),
        sender: sender_address.to_string(),
        recipient: to_address.to_string(),
        content: payload.content,
        content_key: payload.content_key,
        ephemeral_pubkey: payload.ephemeral_pubkey,
        created_at: now,
        expires_at,
        max_reads,
        read_count: 0,
        hidden: false,
    };

    Ok(record)
}

pub fn view_secret(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<String> {
    Ok(view_payload(secret_id, user_address, password)?.content)
}

/// Decrypt a secret and return the WHOLE payload (metadata + plaintext content + plaintext
/// member bodies). Performs authorization, expiry/read-limit checks, and consumes exactly
/// one on-chain read — a bundle counts as one read, not N. Materialize needs this instead
/// of the flattened `view_secret` string because it must see kind/filename/members/no_export.
pub fn view_payload(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<IpfsPayload> {
    let onchain_info = get_secret_info_on_chain(secret_id)?;

    let wallet_info = crate::wallet::get_wallet_info(password)?;

    let is_recipient = onchain_info.is_public
        || onchain_info.recipient.to_lowercase() == wallet_info.address.to_lowercase()
        || onchain_info.recipient == wallet_info.public_key
        || onchain_info.recipient.to_lowercase() == user_address.to_lowercase();

    let is_sender = onchain_info.sender.to_lowercase() == wallet_info.address.to_lowercase()
        || onchain_info.sender == wallet_info.public_key
        || onchain_info.sender.to_lowercase() == user_address.to_lowercase();

    if !is_recipient && !is_sender {
        return Err(crate::errors::BsecError::PermissionDenied("you may not view this secret".into()).into());
    }

    if onchain_info.revoked {
        return Err(anyhow!("Secret with ID '{}' has been revoked.", secret_id));
    }

    let now = crate::wallet::current_timestamp();
    if now > onchain_info.expires_at {
        return Err(crate::errors::BsecError::SecretExpired.into());
    }

    // Public secrets are not read-limited (the contract does not enforce maxReads for them).
    if !onchain_info.is_public && onchain_info.read_count >= onchain_info.max_reads {
        return Err(crate::errors::BsecError::SecretExpired.into());
    }

    let payload_str = fetch_from_ipfs(&onchain_info.ipfs_cid)?;
    let payload = bitbid_core::protocol::decode_payload(payload_str.as_bytes())?;
    let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);
    let payload = bitbid_core::crypto::open_payload(
        payload, Some(&priv_bytes), onchain_info.is_public || onchain_info.recipient == "public",
    )?;

    record_read_on_chain(&priv_bytes, secret_id)?;
    crate::blockchain::index_note(secret_id, "recipient");

    Ok(payload)
}

/// Decrypt a secret and flatten it into a KEY=VALUE map (env or JSON object). Retained helper
/// for env-style consumers; `run --secret` uses `view_payload` directly so it can also stage
/// file-kind and bundle secrets (calling this would double-count the on-chain read).
#[allow(dead_code)]
pub fn load_secret_as_env(secret_id: &str, user_address: &str, password: Option<&str>) -> Result<std::collections::BTreeMap<String, String>> {
    let decrypted_content = view_secret(secret_id, user_address, password)?;
    if decrypted_content.trim().starts_with('{') {
        crate::env_file::parse_json_content(&decrypted_content)
    } else {
        Ok(crate::env_file::parse_env_content(&decrypted_content))
    }
}

pub fn list_secrets(
    user_address: &str,
    filter_user: Option<&str>,
    all: bool,
    expired_only: bool,
    active_only: bool,
) -> Result<Vec<SecretRecord>> {
    let onchain_list = list_secrets_on_chain(user_address, filter_user, all, expired_only, active_only)?;
    let mut results = Vec::new();

    for (sec_id, info) in onchain_list {
        results.push(SecretRecord {
            id: sec_id,
            sender: info.sender,
            recipient: info.recipient,
            content: "[Encrypted Payload on IPFS]".to_string(),
            content_key: "[Encrypted Key]".to_string(),
            ephemeral_pubkey: None,
            created_at: info.created_at,
            expires_at: info.expires_at,
            max_reads: info.max_reads,
            read_count: info.read_count,
            hidden: false,
        });
    }

    Ok(results)
}

pub fn revoke_secret(secret_id: &str, password: Option<&str>) -> Result<()> {
    let wallet_info = crate::wallet::get_wallet_info(password)?;
    let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);
    revoke_secret_on_chain(&priv_bytes, secret_id)
}

pub fn hide_secret(
    secret_id: Option<&str>,
    user_filter: Option<&str>,
    user_address: &str,
    password: Option<&str>,
) -> Result<usize> {
    let wallet_info = crate::wallet::get_wallet_info(password)?;
    let priv_bytes = Zeroizing::new(hex_to_bytes(&wallet_info.private_key)?);

    let onchain_list = list_secrets_on_chain(user_address, user_filter, true, false, false)?;
    let mut hidden_count = 0;

    for (id, rec) in onchain_list {
        let matches_id = secret_id.is_none_or(|target| id == target);
        let matches_filter = user_filter.is_none_or(|target| {
            rec.recipient.to_lowercase() == target.to_lowercase()
                || rec.sender.to_lowercase() == target.to_lowercase()
        });

        if matches_id && matches_filter {
            // Hiding sets local visibility (`hidden = true`) and best-effort revokes on-chain
            // if this wallet is the creator; revocation failure is logged, local hide still applies.
            if hide_secret_on_chain(&priv_bytes, &id).is_ok() {
                hidden_count += 1;
            }
        }
    }

    Ok(hidden_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Backward compat: a payload serialized before this feature has only the three
    // original fields. It MUST still deserialize, with new fields defaulting.
    #[test]
    fn old_payload_json_deserializes_with_defaults() {
        let old_json = r#"{
            "content": "nonce:cipher",
            "content_key": "nonce:wrapped",
            "ephemeral_pubkey": "0x04abcd"
        }"#;
        let p: IpfsPayload = serde_json::from_str(old_json).unwrap();
        assert_eq!(p.content, "nonce:cipher");
        assert_eq!(p.kind, None);
        assert_eq!(p.filename, None);
        assert!(!p.no_export);
        assert!(p.members.is_none());
        assert_eq!(p.content_encoding, None);
    }

    // A single-file secret with no new metadata omits every new field from the wire form,
    // keeping bytes identical to a pre-feature payload.
    #[test]
    fn plain_payload_omits_all_new_fields() {
        let p = IpfsPayload {
            content: "c".to_string(),
            content_key: "k".to_string(),
            ephemeral_pubkey: Some("0x04".to_string()),
            kind: None,
            filename: None,
            no_export: false,
            members: None,
            content_encoding: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("kind"));
        assert!(!json.contains("filename"));
        assert!(!json.contains("no_export"));
        assert!(!json.contains("members"));
        assert!(!json.contains("content_encoding"));
    }

    // A bundle payload survives serialize -> deserialize intact.
    #[test]
    fn bundle_payload_roundtrips() {
        let p = IpfsPayload {
            content: String::new(),
            content_key: "k".to_string(),
            ephemeral_pubkey: None,
            kind: None,
            filename: None,
            no_export: true,
            members: Some(vec![BundleMember {
                kind: SecretKind::Pem,
                filename: "cert.pem".to_string(),
                content: "LS0t".to_string(),
                encoding: "base64".to_string(),
                env: Some("TLS_CERT".to_string()),
            }]),
            content_encoding: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: IpfsPayload = serde_json::from_str(&json).unwrap();
        assert!(back.no_export);
        let m = back.members.unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].kind, SecretKind::Pem);
        assert_eq!(m[0].filename, "cert.pem");
        assert_eq!(m[0].encoding, "base64");
        assert_eq!(m[0].env.as_deref(), Some("TLS_CERT"));
    }

    #[test]
    fn member_bodies_seal_open_roundtrip() {
        let key = [7u8; 32];
        let mut members = vec![
            BundleMember { kind: SecretKind::Pem, filename: "cert.pem".into(), content: "PEM BODY".into(), encoding: "utf8".into(), env: None },
            BundleMember { kind: SecretKind::Env, filename: ".env".into(), content: "K=V".into(), encoding: "utf8".into(), env: None },
        ];
        seal_member_bodies(&mut members, &key).unwrap();
        // sealed bodies are ciphertext, not the original plaintext
        assert_ne!(members[0].content, "PEM BODY");
        assert!(members[0].content.contains(':'));
        open_member_bodies(&mut members, &key).unwrap();
        assert_eq!(members[0].content, "PEM BODY");
        assert_eq!(members[1].content, "K=V");
    }

    #[test]
    fn secret_kind_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&SecretKind::Json).unwrap(), "\"json\"");
        assert_eq!(serde_json::to_string(&SecretKind::Cred).unwrap(), "\"cred\"");
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
    }

    #[test]
    fn parse_duration_empty_defaults_to_one_week() {
        assert_eq!(parse_duration("").unwrap(), 86400 * 7);
    }

    #[test]
    fn parse_duration_multiplication_overflow_is_error() {
        // A number that overflows u64 seconds once multiplied by the week factor.
        assert!(parse_duration("99999999999999999999w").is_err());
        // u64::MAX with a unit that multiplies also overflows.
        assert!(parse_duration(&format!("{}w", u64::MAX)).is_err());
    }

    #[test]
    fn parse_duration_beyond_100_year_cap_is_error() {
        // 101 years in seconds is within u64 but exceeds the 100-year cap.
        let one_hundred_one_years = 101u64 * 365 * 86400;
        assert!(parse_duration(&format!("{}s", one_hundred_one_years)).is_err());
        // Also via a unit-based value clearly beyond the cap.
        assert!(parse_duration("6000w").is_err());
    }
}
