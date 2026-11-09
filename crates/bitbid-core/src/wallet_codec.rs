//! Pure codecs for the existing native wallet format. No storage, clock, or OS entropy.
//!
//! This is the legacy wallet profile, independent of the team-vault qualification.
//! Secret output buffers are guarded; this is not a claim of complete process-memory erasure.
use crate::{RandomSource, address};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::prelude::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

/// Payload-free diagnostics, except for library errors which contain no input secrets.
#[derive(Debug, Error)]
pub enum WalletCodecError {
    #[error("Argon2 key derivation failed: {0}")]
    KeyDerivation(argon2::Error),
    #[error("Invalid encrypted wallet format")]
    Format,
    #[error("Invalid salt base64")]
    SaltBase64,
    #[error("Invalid nonce base64")]
    NonceBase64,
    #[error("Invalid wallet nonce length")]
    NonceLength,
    #[error("Invalid ciphertext base64")]
    CiphertextBase64,
    #[error("Invalid password or wallet data corrupted.")]
    InvalidPassword,
    #[error("wallet encryption failed")]
    Encryption,
    #[error("UTF8 decode error: {0}")]
    Utf8(std::str::Utf8Error),
    #[error("mnemonic generation failed: {0}")]
    MnemonicGeneration(bip39::Error),
    #[error("Failed to parse mnemonic: {0}")]
    Mnemonic(bip39::Error),
    #[error("BIP-32 HD key derivation failed for path m/44'/60'/0'/0/0: {0}")]
    Derivation(bip32::Error),
    #[error("Invalid secp256k1 private key length")]
    PrivateKeyLength,
    #[error("Failed to derive secp256k1 key: {0}")]
    PrivateKey(k256::elliptic_curve::Error),
}

/// Legacy Argon2id19 m19456/t2/p1/output32; salts shorter than eight bytes use SHA256.
/// The returned array remains compatible with the native env-file callers.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], WalletCodecError> {
    let mut key = Zeroizing::new([0u8; 32]);
    let expanded;
    let effective_salt = if salt.len() < 8 {
        expanded = Sha256::digest(salt);
        expanded.as_slice()
    } else {
        salt
    };
    let params = Params::new(19456, 2, 1, Some(32)).map_err(WalletCodecError::KeyDerivation)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), effective_salt, &mut *key)
        .map_err(WalletCodecError::KeyDerivation)?;
    Ok(*key)
}

/// Consume exactly sixteen salt bytes, then twelve nonce bytes from the injected source.
pub fn encrypt_wallet(
    data: &str,
    password: &str,
    random: &dyn RandomSource,
) -> Result<String, WalletCodecError> {
    let mut salt = [0; 16];
    random.fill_bytes(&mut salt);
    let key = Zeroizing::new(derive_key(password, &salt)?);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("fixed 32-byte key");
    let mut nonce = [0; 12];
    random.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), data.as_bytes())
        .map_err(|_| WalletCodecError::Encryption)?;
    Ok(format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(ciphertext)
    ))
}

pub fn decrypt_wallet(
    encrypted: &str,
    password: &str,
) -> Result<Zeroizing<String>, WalletCodecError> {
    let parts: Vec<_> = encrypted.split(':').collect();
    if parts.len() != 3 {
        return Err(WalletCodecError::Format);
    }
    let salt = BASE64_STANDARD
        .decode(parts[0])
        .map_err(|_| WalletCodecError::SaltBase64)?;
    let key = Zeroizing::new(derive_key(password, &salt)?);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("fixed 32-byte key");
    let nonce = BASE64_STANDARD
        .decode(parts[1])
        .map_err(|_| WalletCodecError::NonceBase64)?;
    // generic-array's from_slice panics for any other length (release panic=abort).
    if nonce.len() != 12 {
        return Err(WalletCodecError::NonceLength);
    }
    let ciphertext = BASE64_STANDARD
        .decode(parts[2])
        .map_err(|_| WalletCodecError::CiphertextBase64)?;
    let mut plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| WalletCodecError::InvalidPassword)?,
    );
    if let Err(error) = std::str::from_utf8(&plaintext) {
        return Err(WalletCodecError::Utf8(error));
    }
    // Move the checked allocation into a guarded String; no plaintext clone.
    let bytes = std::mem::take(&mut *plaintext);
    Ok(Zeroizing::new(
        String::from_utf8(bytes).expect("UTF8 checked above"),
    ))
}

/// Borrowed fields avoid a second owning copy of native wallet secrets.
pub struct WalletFields<'a> {
    pub address: &'a str,
    pub public_key: &'a str,
    pub private_key: &'a str,
    pub mnemonic: &'a str,
    pub created_at: u64,
    pub last_accessed: u64,
    pub user_id: Option<&'a str>,
}

/// Append `s` as a JSON string literal (quoted + escaped) directly into `out`.
/// Writes byte-by-byte into the caller's buffer so a secret value never lands in a
/// separate, un-zeroized allocation (as `format!`/`serde_json::Value` would).
fn json_escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str("\\u");
                for shift in [12u32, 8, 4, 0] {
                    let nib = (c as u32 >> shift) & 0xf;
                    out.push(char::from_digit(nib, 16).unwrap_or('0'));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Render a wallet as a pretty JSON object into a `Zeroizing<String>`, optionally including
/// the private key and/or mnemonic. Secrets are written straight into a single pre-sized
/// buffer — never routed through `serde_json::Value` or `serde_json::to_string` (whose
/// internal buffer growth leaves freed, un-zeroized plaintext copies). The buffer is reserved
/// once for worst-case JSON escaping. This rendered allocation is wiped on drop; the
/// borrowed input fields and cryptographic-library internals have their own lifetimes.
///
/// With both flags set the output carries every legacy wallet field, in its original order.
pub fn render_wallet_json(
    info: &WalletFields<'_>,
    include_private_key: bool,
    include_mnemonic: bool,
) -> Zeroizing<String> {
    let cap = 1024
        + 6 * (info.address.len()
            + info.public_key.len()
            + info.user_id.map_or(0, str::len)
            + if include_private_key {
                info.private_key.len()
            } else {
                0
            }
            + if include_mnemonic {
                info.mnemonic.len()
            } else {
                0
            });
    let mut out = Zeroizing::new(String::with_capacity(cap));
    let o: &mut String = &mut out;

    o.push_str("{\n");
    o.push_str("  \"address\": ");
    json_escape_into(o, info.address);
    o.push_str(",\n  \"public_key\": ");
    json_escape_into(o, info.public_key);
    o.push_str(",\n  \"created_at\": ");
    o.push_str(&info.created_at.to_string());
    o.push_str(",\n  \"last_accessed\": ");
    o.push_str(&info.last_accessed.to_string());
    o.push_str(",\n  \"user_id\": ");
    match info.user_id {
        Some(uid) => json_escape_into(o, uid),
        None => o.push_str("null"),
    }
    if include_private_key {
        o.push_str(",\n  \"private_key\": ");
        json_escape_into(o, info.private_key);
    }
    if include_mnemonic {
        o.push_str(",\n  \"mnemonic\": ");
        json_escape_into(o, info.mnemonic);
    }
    o.push_str("\n}");
    out
}

/// Exactly sixteen entropy bytes; production hosts must supply OS randomness or fail-stop.
pub fn generate_mnemonic(random: &dyn RandomSource) -> Result<Zeroizing<String>, WalletCodecError> {
    let mut entropy = Zeroizing::new([0; 16]);
    random.fill_bytes(&mut *entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())
        .map_err(WalletCodecError::MnemonicGeneration)?;
    Ok(Zeroizing::new(mnemonic.to_string()))
}

pub fn validate_mnemonic(mnemonic: &str) -> Result<(), bip39::Error> {
    bip39::Mnemonic::parse(mnemonic).map(|_| ())
}

/// Deliberately has no Debug/Clone; private output is wiped when its owner drops it.
pub struct WalletKeyPair {
    pub private_key: Zeroizing<String>,
    pub public_key: String,
    pub address: String,
}

pub fn key_pair_from_private_key(private_key: &[u8]) -> Result<WalletKeyPair, WalletCodecError> {
    if private_key.len() != 32 {
        return Err(WalletCodecError::PrivateKeyLength);
    }
    let key = k256::SecretKey::from_slice(private_key).map_err(WalletCodecError::PrivateKey)?;
    let private_bytes = Zeroizing::new(key.to_bytes());
    let public = key.public_key().to_encoded_point(false);
    let hash = address::keccak256(&public.as_bytes()[1..]);
    let mut addr = [0; 20];
    addr.copy_from_slice(&hash[12..]);
    let mut private = Zeroizing::new(String::with_capacity(66));
    private.push_str("0x");
    for b in private_bytes.iter() {
        private.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        private.push(char::from_digit((b & 15) as u32, 16).unwrap());
    }
    Ok(WalletKeyPair {
        private_key: private,
        public_key: address::bytes_to_hex(public.as_bytes()),
        address: address::checksum_address(&addr),
    })
}

pub fn derive_wallet_keys(mnemonic: &str) -> Result<WalletKeyPair, WalletCodecError> {
    let mnemonic = bip39::Mnemonic::parse(mnemonic).map_err(WalletCodecError::Mnemonic)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let path = DERIVATION_PATH
        .parse::<bip32::DerivationPath>()
        .expect("fixed BIP44 path");
    let xprv = bip32::XPrv::derive_from_path(seed.as_ref(), &path)
        .map_err(WalletCodecError::Derivation)?;
    let private = Zeroizing::new(xprv.private_key().to_bytes());
    key_pair_from_private_key(private.as_ref())
}
