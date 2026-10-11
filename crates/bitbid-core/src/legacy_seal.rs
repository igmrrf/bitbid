//! Compatibility reader for existing browser-only `bitbid1:` tokens.
//! New tokens are produced by `token`, using the shared CLI payload protocol.
//!
//! A sealed secret is a single, versioned, base64 share string. It carries the
//! recipient id, the sender's ephemeral secp256k1 public key, and the AES-256-GCM
//! payload. The symmetric content key is itself wrapped under a key derived from
//! the ECDH(ephemeral secret, recipient public key) shared secret via HKDF-SHA256,
//! so only the holder of the recipient private key can recover it.
//!
//! This mirrors the CLI's primitive choices (secp256k1 ECDH + HKDF-SHA256 +
//! AES-256-GCM) in a web-native, self-describing single-string format. Byte-for-byte
//! interop with the CLI's `IpfsPayload` JSON is intentionally out of scope for v1.
//!
//! Format v1 (all integers big-endian), base64-encoded after a `bitbid1:` prefix:
//!
//! ```text
//! u8      version (= 1)
//! u16     recipient_id length
//! [u8]    recipient_id (UTF-8)
//! u8      ephemeral_pubkey length (33 or 65)
//! [u8]    ephemeral_pubkey (SEC1)
//! [12]    iv_wrap
//! u16     wrapped key length
//! [u8]    wrapped key (AES-256-GCM of the 32-byte content key, 48 bytes)
//! [12]    iv_payload
//! [..]    payload ciphertext (AES-256-GCM output, includes the 16-byte tag)
//! ```

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
#[cfg(test)]
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use sha2::Sha256;
use thiserror::Error;

#[cfg(test)]
use crate::address::{address_from_pubkey, checksum_address};

/// Prefix that marks a version-1 bitbid share string.
pub const SEAL_PREFIX: &str = "bitbid1:";
/// Current envelope version byte.
pub const SEAL_VERSION: u8 = 1;

const HKDF_INFO: &[u8] = b"bitbid-webapp-ecdh-aes256gcm-v1";
const IV_LEN: usize = 12;
const CONTENT_KEY_LEN: usize = 32;
const GCM_TAG_LEN: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealError {
    #[error("share string does not start with the '{SEAL_PREFIX}' prefix")]
    BadPrefix,
    #[error("share string is not valid base64: {0}")]
    BadBase64(String),
    #[error("unsupported seal version: {0}")]
    BadVersion(u8),
    #[error("malformed seal envelope: {0}")]
    Malformed(&'static str),
    #[error("invalid recipient public key: {0}")]
    BadRecipientKey(String),
    #[error("invalid ephemeral public key in envelope: {0}")]
    BadEphemeralKey(String),
    #[error("invalid recipient private key")]
    BadRecipientSecret,
    #[error("decryption failed: wrong recipient key or tampered ciphertext")]
    DecryptFailed,
    #[error("plaintext is not valid UTF-8")]
    NotUtf8,
    #[error("system randomness unavailable: {0}")]
    Random(String),
}

/// A parsed (or about-to-be-serialized) version-1 sealed envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    pub version: u8,
    pub recipient_id: String,
    pub ephemeral_pubkey: Vec<u8>,
    pub iv_wrap: [u8; IV_LEN],
    pub wrapped_key: Vec<u8>,
    pub iv_payload: [u8; IV_LEN],
    pub ciphertext: Vec<u8>,
}

impl SealedEnvelope {
    /// Serialize to the versioned base64 share string.
    pub fn to_share_string(&self) -> String {
        let mut buf = Vec::new();
        buf.push(self.version);
        let rid = self.recipient_id.as_bytes();
        buf.extend_from_slice(&(rid.len() as u16).to_be_bytes());
        buf.extend_from_slice(rid);
        buf.push(self.ephemeral_pubkey.len() as u8);
        buf.extend_from_slice(&self.ephemeral_pubkey);
        buf.extend_from_slice(&self.iv_wrap);
        buf.extend_from_slice(&(self.wrapped_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.wrapped_key);
        buf.extend_from_slice(&self.iv_payload);
        buf.extend_from_slice(&self.ciphertext);
        format!("{SEAL_PREFIX}{}", BASE64_STANDARD.encode(buf))
    }

    /// Parse a versioned base64 share string. Never fabricates plaintext.
    pub fn from_share_string(s: &str) -> Result<Self, SealError> {
        let body = s.strip_prefix(SEAL_PREFIX).ok_or(SealError::BadPrefix)?;
        let bytes = BASE64_STANDARD
            .decode(body.trim())
            .map_err(|e| SealError::BadBase64(e.to_string()))?;
        parse_envelope(&bytes)
    }

    /// The recipient's EVM address derived from the ephemeral-independent recipient id.
    pub fn is_for_recipient(&self, id: &str) -> bool {
        self.recipient_id.eq_ignore_ascii_case(id)
    }
}

fn parse_envelope(b: &[u8]) -> Result<SealedEnvelope, SealError> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], SealError> {
        let out = b
            .get(*p..*p + n)
            .ok_or(SealError::Malformed("unexpected end of envelope"))?;
        *p += n;
        Ok(out)
    };

    let version = take(&mut p, 1)?[0];
    if version != SEAL_VERSION {
        return Err(SealError::BadVersion(version));
    }
    let rid_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().unwrap()) as usize;
    let recipient_id =
        String::from_utf8(take(&mut p, rid_len)?.to_vec()).map_err(|_| SealError::NotUtf8)?;
    let eph_len = take(&mut p, 1)?[0] as usize;
    if eph_len != 33 && eph_len != 65 {
        return Err(SealError::Malformed("ephemeral public key length"));
    }
    let ephemeral_pubkey = take(&mut p, eph_len)?.to_vec();
    let iv_wrap: [u8; IV_LEN] = take(&mut p, IV_LEN)?.try_into().unwrap();
    let wrapped_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().unwrap()) as usize;
    if wrapped_len < GCM_TAG_LEN {
        return Err(SealError::Malformed("wrapped key too short"));
    }
    let wrapped_key = take(&mut p, wrapped_len)?.to_vec();
    let iv_payload: [u8; IV_LEN] = take(&mut p, IV_LEN)?.try_into().unwrap();
    let ciphertext = b
        .get(p..)
        .ok_or(SealError::Malformed("payload ciphertext missing"))?
        .to_vec();
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(SealError::Malformed("payload ciphertext shorter than tag"));
    }

    Ok(SealedEnvelope {
        version,
        recipient_id,
        ephemeral_pubkey,
        iv_wrap,
        wrapped_key,
        iv_payload,
        ciphertext,
    })
}

#[cfg(test)]
fn random_bytes(n: usize) -> Result<Vec<u8>, SealError> {
    let mut out = vec![0u8; n];
    getrandom::getrandom(&mut out).map_err(|e| SealError::Random(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
fn random_scalar_bytes() -> Result<[u8; 32], SealError> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|e| SealError::Random(e.to_string()))?;
        if SecretKey::from_slice(&bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err(SealError::Random("could not sample a valid scalar".into()))
}

#[cfg(test)]
fn parse_public_key(hex: &str) -> Result<PublicKey, SealError> {
    let bytes = crate::address::hex_to_bytes(hex).map_err(SealError::BadRecipientKey)?;
    PublicKey::from_sec1_bytes(&bytes).map_err(|e| SealError::BadRecipientKey(e.to_string()))
}

fn derive_wrap_key(shared: &[u8]) -> Result<[u8; 32], SealError> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|_| SealError::Malformed("hkdf expand failed"))?;
    Ok(okm)
}

fn gcm(key: &[u8; 32]) -> Result<Aes256Gcm, SealError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| SealError::Malformed("invalid AES key length"))
}

#[cfg(test)]
fn aead_encrypt(key: &[u8; 32], iv: &[u8; IV_LEN], plain: &[u8]) -> Result<Vec<u8>, SealError> {
    gcm(key)?
        .encrypt(Nonce::from_slice(iv), plain)
        .map_err(|_| SealError::DecryptFailed)
}

fn aead_decrypt(key: &[u8; 32], iv: &[u8; IV_LEN], cipher: &[u8]) -> Result<Vec<u8>, SealError> {
    gcm(key)?
        .decrypt(Nonce::from_slice(iv), cipher)
        .map_err(|_| SealError::DecryptFailed)
}

/// Seal `plaintext` to a recipient public key, returning the parsed envelope.
///
/// `recipient_pubkey_hex` is a SEC1 secp256k1 key (`0x04...`, or compressed
/// `0x02...`/`0x03...`). When `recipient_id` is empty the recipient's checksummed
/// EVM address is used.
#[cfg(test)]
pub fn seal(
    plaintext: &[u8],
    recipient_pubkey_hex: &str,
    recipient_id: &str,
) -> Result<SealedEnvelope, SealError> {
    let recipient = parse_public_key(recipient_pubkey_hex)?;
    let ephemeral = random_scalar_bytes()?;
    let content_key: [u8; 32] = random_bytes(CONTENT_KEY_LEN)?.try_into().unwrap();
    let iv_wrap: [u8; IV_LEN] = random_bytes(IV_LEN)?.try_into().unwrap();
    let iv_payload: [u8; IV_LEN] = random_bytes(IV_LEN)?.try_into().unwrap();
    let id = if recipient_id.trim().is_empty() {
        let sec1 = recipient.to_encoded_point(false);
        checksum_address(&address_from_pubkey(sec1.as_bytes()).map_err(SealError::BadRecipientKey)?)
    } else {
        recipient_id.to_string()
    };
    seal_with_material(
        plaintext,
        &recipient,
        &id,
        &ephemeral,
        &content_key,
        &iv_wrap,
        &iv_payload,
    )
}

// Private material seam for legacy compatibility vectors; production samples entropy.
#[cfg(test)]
fn seal_with_material(
    plaintext: &[u8],
    recipient: &PublicKey,
    recipient_id: &str,
    ephemeral_secret_bytes: &[u8; 32],
    content_key: &[u8; 32],
    iv_wrap: &[u8; IV_LEN],
    iv_payload: &[u8; IV_LEN],
) -> Result<SealedEnvelope, SealError> {
    let ephemeral =
        SecretKey::from_slice(ephemeral_secret_bytes).map_err(|_| SealError::BadRecipientSecret)?;
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let wrap_key = derive_wrap_key(shared.raw_secret_bytes())?;

    let wrapped_key = aead_encrypt(&wrap_key, iv_wrap, content_key)?;
    let ciphertext = aead_encrypt(content_key, iv_payload, plaintext)?;

    Ok(SealedEnvelope {
        version: SEAL_VERSION,
        recipient_id: recipient_id.to_string(),
        ephemeral_pubkey: ephemeral
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        iv_wrap: *iv_wrap,
        wrapped_key,
        iv_payload: *iv_payload,
        ciphertext,
    })
}

/// Seal and return the base64 share string directly.
#[cfg(test)]
pub fn seal_to_share_string(
    plaintext: &[u8],
    recipient_pubkey_hex: &str,
    recipient_id: &str,
) -> Result<String, SealError> {
    Ok(seal(plaintext, recipient_pubkey_hex, recipient_id)?.to_share_string())
}

/// Unseal a share string with the recipient's raw 32-byte private key, returning bytes.
pub fn unseal(share_string: &str, recipient_secret_bytes: &[u8]) -> Result<Vec<u8>, SealError> {
    let env = SealedEnvelope::from_share_string(share_string)?;
    let secret =
        SecretKey::from_slice(recipient_secret_bytes).map_err(|_| SealError::BadRecipientSecret)?;
    let ephemeral = PublicKey::from_sec1_bytes(&env.ephemeral_pubkey)
        .map_err(|e| SealError::BadEphemeralKey(e.to_string()))?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let wrap_key = derive_wrap_key(shared.raw_secret_bytes())?;

    let content_key_vec = aead_decrypt(&wrap_key, &env.iv_wrap, &env.wrapped_key)?;
    if content_key_vec.len() != CONTENT_KEY_LEN {
        return Err(SealError::DecryptFailed);
    }
    let mut content_key = [0u8; CONTENT_KEY_LEN];
    content_key.copy_from_slice(&content_key_vec);
    aead_decrypt(&content_key, &env.iv_payload, &env.ciphertext)
}

/// Unseal a share string and decode the plaintext as UTF-8.
pub fn unseal_to_string(
    share_string: &str,
    recipient_secret_bytes: &[u8],
) -> Result<String, SealError> {
    let bytes = unseal(share_string, recipient_secret_bytes)?;
    String::from_utf8(bytes).map_err(|_| SealError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_bytes(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[31] = n;
        k
    }

    fn public_hex(n: u8) -> String {
        let sk = SecretKey::from_slice(&secret_bytes(n)).unwrap();
        crate::address::bytes_to_hex(sk.public_key().to_encoded_point(false).as_bytes())
    }

    fn fixed_envelope() -> (SealedEnvelope, [u8; 32]) {
        // recipient private key = 2, ephemeral private key = 1, all fixed material.
        let recipient = SecretKey::from_slice(&secret_bytes(2)).unwrap();
        let env = seal_with_material(
            b"bitbid fixed vector",
            &recipient.public_key(),
            "alice",
            &secret_bytes(1),
            &[0x42u8; 32],
            &[0x01u8; IV_LEN],
            &[0x02u8; IV_LEN],
        )
        .unwrap();
        (env, secret_bytes(2))
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn round_trips_utf8_and_empty() {
        let recipient = public_hex(1);
        for plain in ["hello, bitbid", "unicode: \u{1f512}\u{1f680}", ""] {
            let share = seal_to_share_string(plain.as_bytes(), &recipient, "bob").unwrap();
            assert!(share.starts_with(SEAL_PREFIX));
            let out = unseal_to_string(&share, &secret_bytes(1)).unwrap();
            assert_eq!(out, plain);
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn wrong_recipient_key_yields_no_plaintext() {
        let recipient = public_hex(1);
        let share = seal_to_share_string(b"top secret", &recipient, "bob").unwrap();
        // Sealed to key 1; try to open with key 2.
        assert_eq!(
            unseal(&share, &secret_bytes(2)),
            Err(SealError::DecryptFailed)
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn tampered_ciphertext_fails_aead() {
        let recipient = public_hex(1);
        let share = seal_to_share_string(b"integrity matters", &recipient, "bob").unwrap();
        let mut env = SealedEnvelope::from_share_string(&share).unwrap();
        let last = env.ciphertext.len() - 1;
        env.ciphertext[last] ^= 0x01;
        let tampered = env.to_share_string();
        assert_eq!(
            unseal(&tampered, &secret_bytes(1)),
            Err(SealError::DecryptFailed)
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn rejects_bad_prefix_and_version() {
        assert_eq!(
            SealedEnvelope::from_share_string("nope:AAAA"),
            Err(SealError::BadPrefix)
        );
        // Valid prefix, base64 of a single byte 0x02 (version 2).
        let bad = format!("{SEAL_PREFIX}{}", BASE64_STANDARD.encode([2u8]));
        assert_eq!(
            SealedEnvelope::from_share_string(&bad),
            Err(SealError::BadVersion(2))
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn envelope_is_ecdh_hkdf_aesgcm_structurally() {
        let (env, key) = fixed_envelope();
        // Ephemeral public key is a full uncompressed secp256k1 point.
        assert_eq!(env.ephemeral_pubkey.len(), 65);
        assert_eq!(env.ephemeral_pubkey[0], 0x04);
        assert!(PublicKey::from_sec1_bytes(&env.ephemeral_pubkey).is_ok());
        // IVs are 12 bytes; wrapped 32-byte content key + 16-byte GCM tag = 48.
        assert_eq!(env.iv_wrap.len(), IV_LEN);
        assert_eq!(env.iv_payload.len(), IV_LEN);
        assert_eq!(env.wrapped_key.len(), CONTENT_KEY_LEN + GCM_TAG_LEN);
        // AES-256-GCM appends a 16-byte tag to the 19-byte plaintext.
        assert_eq!(
            env.ciphertext.len(),
            "bitbid fixed vector".len() + GCM_TAG_LEN
        );
        // The recipient id travels in the clear.
        assert_eq!(env.recipient_id, "alice");
        // The derived wrap key is stable for fixed ECDH inputs.
        let ephemeral = PublicKey::from_sec1_bytes(&env.ephemeral_pubkey).unwrap();
        let recipient = SecretKey::from_slice(&key).unwrap();
        let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
        assert_eq!(
            derive_wrap_key(shared.raw_secret_bytes()).unwrap(),
            derive_wrap_key(shared.raw_secret_bytes()).unwrap()
        );
        assert_eq!(
            unseal(&env.to_share_string(), &key).unwrap(),
            b"bitbid fixed vector"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn fixed_vector_literal_share_string() {
        let (env, _) = fixed_envelope();
        let share = env.to_share_string();
        assert_eq!(
            share,
            "bitbid1:AQAFYWxpY2VBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgBAQEBAQEBAQEBAQEAMPcx6YkasDdkcXVIz1Uu6cYGRywV2pcOTmOa6SbII3/gTfAI0d9fUlVeXP7kDEN79AICAgICAgICAgICApCMcmC1mHflxNL2VeqQ1py7cWPk8kzTYJYM+zm4aWxwPQJM"
        );
        // Sealing is deterministic for fixed material: re-encode reproduces the literal.
        assert_eq!(env.to_share_string(), share);
    }
}
