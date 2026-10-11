//! Existing CLI cryptographic suite and ciphertext field format.
use crate::{address::bytes_to_hex, protocol::IpfsPayload};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const HKDF_INFO: &[u8] = b"bsec-ecdh-aes256gcm-v1";
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("malformed encrypted payload: {0}")]
    Malformed(&'static str),
    #[error("decryption failed: wrong recipient key or tampered ciphertext")]
    DecryptFailed,
    #[error("encryption failed")]
    EncryptFailed,
    #[error("invalid secp256k1 key")]
    Key,
    #[error("plaintext is not valid UTF-8")]
    Utf8,
    #[error("system randomness unavailable")]
    Random,
}

pub fn derive_ecdh_key(shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = hkdf::Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|_| CryptoError::Malformed("HKDF"))?;
    Ok(key)
}
fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(bytes)
}
fn ephemeral_key() -> Result<SecretKey, CryptoError> {
    for _ in 0..16 {
        let bytes = Zeroizing::new(random::<32>()?);
        if let Ok(key) = SecretKey::from_slice(bytes.as_ref()) {
            return Ok(key);
        }
    }
    Err(CryptoError::Random)
}
fn public_wrapper_key() -> [u8; 32] {
    Sha256::digest(b"bsec_public_secret_wrapper_key_v1").into()
}

pub fn encrypt_text(plain: &str, key: &[u8; 32]) -> Result<String, CryptoError> {
    encrypt_with_nonce(plain, key, &random::<12>()?)
}
// Caller-supplied nonces never appear in the public production API.
fn encrypt_with_nonce(
    plain: &str,
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Key)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plain.as_bytes())
        .map_err(|_| CryptoError::EncryptFailed)?;
    Ok(format!(
        "{}:{}",
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(ciphertext)
    ))
}
pub fn decrypt_text(ciphertext: &str, key: &[u8; 32]) -> Result<String, CryptoError> {
    let (nonce, body) = ciphertext
        .split_once(':')
        .ok_or(CryptoError::Malformed("cipher format"))?;
    let nonce = BASE64_STANDARD
        .decode(nonce)
        .map_err(|_| CryptoError::Malformed("nonce encoding"))?;
    if nonce.len() != 12 {
        return Err(CryptoError::Malformed("nonce must be 12 bytes"));
    }
    let body = BASE64_STANDARD
        .decode(body)
        .map_err(|_| CryptoError::Malformed("cipher encoding"))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Key)?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), body.as_slice())
        .map_err(|_| CryptoError::DecryptFailed)?;
    String::from_utf8(plain).map_err(|_| CryptoError::Utf8)
}

/// `None` retains the CLI's explicitly public (non-confidential) sharing mode.
pub fn seal_payload(
    mut payload: IpfsPayload,
    recipient: Option<&PublicKey>,
) -> Result<IpfsPayload, CryptoError> {
    let ephemeral = ephemeral_key()?;
    let wrapper = Zeroizing::new(match recipient {
        Some(recipient) => {
            let shared =
                k256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
            derive_ecdh_key(shared.raw_secret_bytes())?
        }
        None => public_wrapper_key(),
    });
    let content_key = Zeroizing::new(random::<32>()?);
    payload.content = encrypt_text(&payload.content, &content_key)?;
    payload.content_key = encrypt_text(&BASE64_STANDARD.encode(content_key.as_ref()), &wrapper)?;
    payload.ephemeral_pubkey = Some(bytes_to_hex(
        ephemeral.public_key().to_encoded_point(false).as_bytes(),
    ));
    if let Some(members) = &mut payload.members {
        for member in members {
            member.content = encrypt_text(&member.content, &content_key)?;
        }
    }
    Ok(payload)
}

/// Public mode must be explicitly supplied by the host's registry policy.
/// Decrypts every member before returning any plaintext; performs no chain/storage I/O.
pub fn open_payload(
    mut payload: IpfsPayload,
    recipient_secret: Option<&[u8]>,
    is_public: bool,
) -> Result<IpfsPayload, CryptoError> {
    let wrapper = Zeroizing::new(if is_public {
        public_wrapper_key()
    } else {
        let eph_hex = payload
            .ephemeral_pubkey
            .as_ref()
            .ok_or(CryptoError::Malformed("missing ephemeral key"))?;
        let eph_bytes = crate::address::hex_to_bytes(eph_hex).map_err(|_| CryptoError::Key)?;
        let ephemeral = PublicKey::from_sec1_bytes(&eph_bytes).map_err(|_| CryptoError::Key)?;
        let secret = SecretKey::from_slice(recipient_secret.ok_or(CryptoError::Key)?)
            .map_err(|_| CryptoError::Key)?;
        let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
        derive_ecdh_key(shared.raw_secret_bytes())?
    });
    let key_text = Zeroizing::new(decrypt_text(&payload.content_key, &wrapper)?);
    let key_bytes = Zeroizing::new(
        BASE64_STANDARD
            .decode(key_text.as_bytes())
            .map_err(|_| CryptoError::Malformed("content key encoding"))?,
    );
    let key = Zeroizing::new(
        <[u8; 32]>::try_from(key_bytes.as_slice())
            .map_err(|_| CryptoError::Malformed("content key length"))?,
    );
    if payload.content.is_empty() && payload.members.is_none() {
        return Err(CryptoError::Malformed("missing content ciphertext"));
    }
    if !payload.content.is_empty() {
        payload.content = decrypt_text(&payload.content, &key)?;
    }
    if let Some(members) = &mut payload.members {
        for member in members {
            member.content = decrypt_text(&member.content, &key)?;
        }
    }
    payload.content_key.clear();
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn fixed_material_matches_independent_node_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/ipfs-v1.json")).unwrap();
        let mut ephemeral_bytes = [0; 32];
        ephemeral_bytes[31] = 1;
        let mut recipient_bytes = [0; 32];
        recipient_bytes[31] = 2;
        let ephemeral = SecretKey::from_slice(&ephemeral_bytes).unwrap();
        let recipient = SecretKey::from_slice(&recipient_bytes).unwrap();
        let shared = k256::ecdh::diffie_hellman(
            ephemeral.to_nonzero_scalar(),
            recipient.public_key().as_affine(),
        );
        let wrapper = derive_ecdh_key(shared.raw_secret_bytes()).unwrap();
        let mut payload = IpfsPayload::text(
            encrypt_with_nonce(
                vector["plaintext"].as_str().unwrap(),
                &[0x42; 32],
                &[0x02; 12],
            )
            .unwrap(),
        );
        payload.content_key =
            encrypt_with_nonce(&BASE64_STANDARD.encode([0x42; 32]), &wrapper, &[0x01; 12]).unwrap();
        payload.ephemeral_pubkey = Some(bytes_to_hex(
            ephemeral.public_key().to_encoded_point(false).as_bytes(),
        ));
        assert_eq!(
            String::from_utf8(crate::protocol::canonical_bytes(&payload).unwrap()).unwrap(),
            vector["canonical_payload"].as_str().unwrap()
        );
        assert_eq!(
            crate::protocol::to_share_string(&payload).unwrap(),
            vector["token"].as_str().unwrap()
        );
    }
}
