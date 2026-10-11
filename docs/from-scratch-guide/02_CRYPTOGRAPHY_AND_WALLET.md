# Part 2: Cryptography & Wallet Engine

This module details building the self-sovereign HD wallet manager, key derivation pipeline, AES-256-GCM encryption engine, zeroization memory protection, and secure POSIX file permission handling.

---

## 1. Cryptographic Principles & Crate Documentation

- **Key Derivation (Argon2)**: Password-based KDF configured with salt to derive 256-bit AES keys ([argon2 crate](https://docs.rs/argon2/latest/argon2/)).
- **Symmetric Cipher (AES-256-GCM)**: Authenticated cipher offering confidentiality and integrity protection ([aes-gcm crate](https://docs.rs/aes-gcm/latest/aes_gcm/)).
- **Elliptic Curve (Secp256k1 / k256)**: Standard Koblitz curve used for EVM address derivation and ECDH key agreement ([k256 crate](https://docs.rs/k256/latest/k256/)).
- **Mnemonic Key Derivation (BIP-39 & BIP-32)**: HD wallet seed derivation according to BIP-44 path (`m/44'/60'/0'/0/0`) ([bip39 crate](https://docs.rs/bip39/latest/bip39/), [bip32 crate](https://docs.rs/bip32/latest/bip32/)).
- **Memory Hygiene (Zeroize)**: Automatic wiping of sensitive buffers on drop ([zeroize crate](https://docs.rs/zeroize/latest/zeroize/)).

---

## 2. Wallet Core Implementation ([`src/wallet.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/wallet.rs))

Create `src/wallet.rs`:

```rust
use anyhow::{anyhow, Result};
use crate::errors::BsecError;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::prelude::*;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct WalletInfo {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub mnemonic: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletInfoPublic {
    pub address: String,
    pub public_key: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub user_id: Option<String>,
}

impl From<&WalletInfo> for WalletInfoPublic {
    fn from(w: &WalletInfo) -> Self {
        Self {
            address: w.address.clone(),
            public_key: w.public_key.clone(),
            created_at: w.created_at,
            last_accessed: w.last_accessed,
            user_id: w.user_id.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletConfig {
    pub address: String,
    pub created_at: u64,
    pub user_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WalletFile {
    pub encrypted: bool,
    pub data: String,
    pub last_accessed: u64,
}

pub fn get_app_dir() -> PathBuf {
    if let Ok(bsec_home) = std::env::var("BSEC_HOME") {
        let path = PathBuf::from(bsec_home);
        if !path.exists() {
            let _ = fs::create_dir_all(&path);
        }
        return path;
    }
    let mut dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push(".bsec");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn set_private_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

pub fn write_secure_file(path: &Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        // O_NOFOLLOW: refuse to open the final path component if it is a symlink. Without this
        // an attacker who can plant a symlink at the target between an existence check and the
        // write (TOCTOU, CWE-59/CWE-367) could redirect a plaintext-secret write elsewhere, or
        // clobber a victim-owned file. Opening a symlink now fails with ELOOP instead.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(content)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, content)?;
    }
    set_private_file_permissions(path);
    Ok(())
}

/// Like `write_secure_file` but fails (AlreadyExists) if the path already exists.
/// O_EXCL (via `create_new`) makes the "do not overwrite" decision atomic (no TOCTOU,
/// CWE-367): an existence check followed by a separate open can race a planted file, but a
/// single exclusive-create open cannot. O_NOFOLLOW still refuses a symlink at the final
/// component. Use this for the non-force write path; `write_secure_file` (create+truncate)
/// remains for the force path and all existing callers.
pub fn write_secure_file_new(path: &Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(content)?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(content)?;
    }
    set_private_file_permissions(path);
    Ok(())
}


pub fn hash_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("Invalid hex length"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| anyhow!("Invalid hex byte: {}", e)))
        .collect()
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    let effective_salt = if salt.len() < 8 {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.finalize().to_vec()
    } else {
        salt.to_vec()
    };
    argon2
        .hash_password_into(password.as_bytes(), &effective_salt, &mut key)
        .map_err(|e| anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}

pub fn encrypt_wallet(data_str: &str, password: &str) -> Result<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| anyhow!("invalid cipher key length"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, data_str.as_bytes())
        .map_err(|_| anyhow!("wallet encryption failed"))?;
    Ok(format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(cipher_text)
    ))
}

pub fn decrypt_wallet(encrypted_str: &str, password: &str) -> Result<String> {
    let parts: Vec<&str> = encrypted_str.split(':').collect();
    if parts.len() == 3 {
        let salt = BASE64_STANDARD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid salt base64"))?;
        let key = derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid cipher key"))?;
        let decoded_nonce = BASE64_STANDARD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid nonce base64"))?;
        let nonce = Nonce::from_slice(&decoded_nonce);
        let cipher_text = BASE64_STANDARD
            .decode(parts[2])
            .map_err(|_| anyhow!("Invalid ciphertext base64"))?;
        let plaintext = cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(|_| BsecError::InvalidPassword)?;
        let text_str = String::from_utf8(plaintext).map_err(|e| anyhow!("UTF8 decode error: {}", e))?;
        Ok(text_str)
    } else {
        Err(anyhow!("Invalid encrypted wallet format"))
    }
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
/// once with enough headroom that no reallocation occurs, so the only heap residence of the
/// plaintext is this buffer, which is wiped on drop.
///
/// With both flags set the output carries every `WalletInfo` field, so it round-trips through
/// `serde_json::from_str::<WalletInfo>` — this is also the on-disk serialization used at init.
pub fn render_wallet_json(
    info: &WalletInfo,
    include_private_key: bool,
    include_mnemonic: bool,
) -> Zeroizing<String> {
    let cap = 1024
        + info.address.len()
        + info.public_key.len()
        + info.user_id.as_deref().map_or(0, str::len)
        + if include_private_key { info.private_key.len() } else { 0 }
        + if include_mnemonic { info.mnemonic.len() } else { 0 };
    let mut out = Zeroizing::new(String::with_capacity(cap));
    let o: &mut String = &mut out;

    o.push_str("{\n");
    o.push_str("  \"address\": ");
    json_escape_into(o, &info.address);
    o.push_str(",\n  \"public_key\": ");
    json_escape_into(o, &info.public_key);
    o.push_str(",\n  \"created_at\": ");
    o.push_str(&info.created_at.to_string());
    o.push_str(",\n  \"last_accessed\": ");
    o.push_str(&info.last_accessed.to_string());
    o.push_str(",\n  \"user_id\": ");
    match &info.user_id {
        Some(uid) => json_escape_into(o, uid),
        None => o.push_str("null"),
    }
    if include_private_key {
        o.push_str(",\n  \"private_key\": ");
        json_escape_into(o, &info.private_key);
    }
    if include_mnemonic {
        o.push_str(",\n  \"mnemonic\": ");
        json_escape_into(o, &info.mnemonic);
    }
    o.push_str("\n}");
    out
}

pub fn generate_mnemonic() -> Result<String> {
    let mut entropy = [0u8; 16];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| anyhow!("mnemonic generation failed: {}", e))?;
    Ok(mnemonic.to_string())
}

pub fn init_wallet(
    import_mnemonic: Option<String>,
    password: Option<String>,
    user_id: Option<String>,
    overwrite: bool,
    allow_plaintext: bool,
) -> Result<WalletInfo> {
    // Encryption is the default. Storing the private key and mnemonic in cleartext (CWE-312)
    // is only permitted when the caller explicitly opts in via `allow_plaintext`; otherwise a
    // missing password is a hard error rather than a silent plaintext write.
    if password.is_none() && !allow_plaintext {
        return Err(anyhow!(
            "A wallet password is required to encrypt the private key and mnemonic at rest. \
             Provide one interactively or via --password, or pass --no-encryption to explicitly \
             store the wallet UNENCRYPTED (not recommended)."
        ));
    }
    let app_dir = get_app_dir();
    let config_path = app_dir.join("config.json");
    let wallet_path = app_dir.join("wallet.json");

    if config_path.exists() && !overwrite {
        return Err(anyhow!(
            "Wallet already exists. Use overwrite option or provide new credentials."
        ));
    }

    let mnemonic_str = match import_mnemonic {
        Some(m) => {
            let _parsed = bip39::Mnemonic::parse(&m)
                .map_err(|e| BsecError::InvalidMnemonic(e.to_string()))?;
            m
        }
        None => generate_mnemonic()?,
    };

    let parsed_mnemonic = bip39::Mnemonic::parse(&mnemonic_str)
        .map_err(|e| anyhow!("Failed to parse mnemonic: {}", e))?;
    let seed = parsed_mnemonic.to_seed("");

    // Standard BIP-44 Ethereum path. Any derivation failure is a hard error: silently
    // falling back to a raw seed slice would produce a DIFFERENT (non-standard) key/address
    // than the mnemonic implies, stranding funds and making secrets un-decryptable.
    let derivation_path = "m/44'/60'/0'/0/0";
    let path = derivation_path
        .parse::<bip32::DerivationPath>()
        .map_err(|e| anyhow!("Invalid derivation path '{}': {}", derivation_path, e))?;
    let xprv = bip32::XPrv::derive_from_path(seed, &path)
        .map_err(|e| anyhow!("BIP-32 HD key derivation failed for path {}: {}", derivation_path, e))?;
    let secret_key = k256::SecretKey::from_slice(&xprv.private_key().to_bytes())
        .map_err(|e| anyhow!("Failed to derive secp256k1 key: {}", e))?;

    let public_key = secret_key.public_key();

    let priv_bytes = secret_key.to_bytes();
    let pub_bytes = public_key.to_encoded_point(false);

    let private_key = format!("0x{}", bytes_to_hex(&priv_bytes));
    let public_key_str = format!("0x{}", bytes_to_hex(pub_bytes.as_bytes()));

    let uncompressed_pub = &pub_bytes.as_bytes()[1..];
    let pub_hash = crate::blockchain::keccak256(uncompressed_pub);
    let mut addr_bytes = [0u8; 20];
    addr_bytes.copy_from_slice(&pub_hash[12..32]);
    let address = crate::blockchain::bytes_to_checksum_address(&addr_bytes);
    let now = current_timestamp();

    let wallet_info = WalletInfo {
        address: address.clone(),
        public_key: public_key_str,
        private_key,
        mnemonic: mnemonic_str,
        created_at: now,
        last_accessed: now,
        user_id: user_id.clone(),
    };

    // The serialized blob contains the plaintext private key and mnemonic. Build it with the
    // manual writer (not serde_json::to_string, whose buffer growth leaves freed un-zeroized
    // copies) into a single pre-sized Zeroizing buffer, so the only plaintext residence is this
    // buffer — wiped on drop. It carries every field, so it round-trips via serde on read.
    let raw_data = render_wallet_json(&wallet_info, true, true);

    let wallet_file = if let Some(ref pwd) = password {
        let encrypted_data = encrypt_wallet(raw_data.as_str(), pwd)?;
        WalletFile {
            encrypted: true,
            data: encrypted_data,
            last_accessed: now,
        }
    } else {
        eprintln!(
            "WARNING: wallet created WITHOUT a password. The private key and mnemonic are stored \
             UNENCRYPTED at {}. Anyone with read access to this file controls the wallet. \
             Re-run with --password to encrypt it.",
            wallet_path.display()
        );
        WalletFile {
            encrypted: false,
            data: raw_data.as_str().to_string(),
            last_accessed: now,
        }
    };

    write_secure_file(&wallet_path, serde_json::to_string_pretty(&wallet_file)?.as_bytes())?;

    let config = WalletConfig {
        address: address.clone(),
        created_at: now,
        user_id,
    };
    write_secure_file(&config_path, serde_json::to_string_pretty(&config)?.as_bytes())?;

    Ok(wallet_info)
}

pub fn get_wallet_info(password: Option<&str>) -> Result<WalletInfo> {
    let app_dir = get_app_dir();
    let wallet_path = app_dir.join("wallet.json");

    if !wallet_path.exists() {
        return Err(BsecError::WalletNotFound.into());
    }

    let content = fs::read_to_string(&wallet_path)?;
    let wallet_file: WalletFile = serde_json::from_str(&content)?;

    // Read-only: do NOT rewrite wallet.json here. The previous write-on-read updated
    // `last_accessed` on every read, which raced under concurrent invocations (unsynchronized
    // read-modify-write) and rewrote the plaintext key for unencrypted wallets. The marginal
    // value of a read timestamp does not justify either hazard.
    let info = if wallet_file.encrypted {
        let pwd = password.ok_or_else(|| anyhow!("Wallet is encrypted. Password is required."))?;
        let decrypted_json = Zeroizing::new(decrypt_wallet(&wallet_file.data, pwd)?);
        serde_json::from_str::<WalletInfo>(&decrypted_json)?
    } else {
        serde_json::from_str::<WalletInfo>(&wallet_file.data)?
    };

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_secure_file_new_creates_0600_then_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");

        write_secure_file_new(&p, b"data").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Exclusive create (O_EXCL): a second write to the same path must fail with
        // AlreadyExists, atomically — never a silent truncating overwrite.
        let err = write_secure_file_new(&p, b"other").unwrap_err();
        let io = err
            .downcast_ref::<std::io::Error>()
            .expect("error should wrap an io::Error");
        assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists);
        // Original content is intact.
        assert_eq!(std::fs::read(&p).unwrap(), b"data");
    }

    // O_NOFOLLOW + O_EXCL: a symlink planted at the target must not be written through, so the
    // symlink's target file is left untouched (anti-TOCTOU / CWE-59).
    #[cfg(unix)]
    #[test]
    fn write_secure_file_new_refuses_symlink_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let link = dir.path().join("link");
        std::fs::write(&real, b"orig").unwrap();
        symlink(&real, &link).unwrap();

        let res = write_secure_file_new(&link, b"pwned");
        assert!(res.is_err(), "must refuse to write through a symlink at the target path");
        assert_eq!(
            std::fs::read(&real).unwrap(),
            b"orig",
            "the symlink's target must be untouched"
        );
    }

    // Round-trip the hardened writer used everywhere else, plus its permission guarantee.
    #[test]
    fn write_secure_file_roundtrip_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        write_secure_file(&p, b"hello").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // write_secure_file DOES overwrite (create+truncate), unlike the _new variant.
        write_secure_file(&p, b"z").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"z");
    }
}
```

---

## 3. Verification

Build module:
```bash
cargo check
```


## 3. BIP-39 Word List ([`src/bip39_words.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/bip39_words.rs))

```rust
#[allow(dead_code)]
pub static BIP39_WORDS: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien",
    "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always",
    "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
    "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety",
    "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area",
    "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive",
    "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
    "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
    "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware",
    "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag",
    "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel",
    "base", "basic", "basket", "battle", "beach", "beacon", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call",
    "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry",
    "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category",
    "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century",
    "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle",
    "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
    "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coal", "coast",
    "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyot", "crack",
    "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd",
    "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture",
    "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle",
    "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day",
    "deal", "debate", "debris", "decade", "december", "decide", "decline", "decor", "decrease", "deer",
    "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist",
    "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design",
    "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial",
    "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner",
    "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display",
    "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin",
    "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon",
    "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive",
    "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
    "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark",
    "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end",
    "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist",
    "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal",
    "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence",
    "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess",
    "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist",
    "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra",
    "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
    "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal",
    "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel",
    "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure",
    "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm",
    "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat",
    "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush",
    "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force",
    "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox",
    "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown",
    "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain",
    "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas",
    "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine",
    "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad",
    "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow",
    "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern",
    "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green",
    "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide",
    "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
    "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head",
    "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero",
    "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold",
    "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse",
    "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor",
    "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon",
    "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense",
    "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject",
    "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire",
    "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate",
    "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly",
    "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle",
    "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid",
    "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee",
    "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp",
    "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn",
    "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg",
    "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter",
    "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb",
    "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan",
    "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine",
    "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man",
    "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter",
    "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody",
    "melon", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh",
    "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum",
    "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture",
    "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon",
    "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move",
    "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must",
    "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation",
    "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest",
    "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise",
    "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel",
    "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure",
    "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office",
    "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion",
    "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
    "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer",
    "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone",
    "pack", "packet", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic",
    "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path",
    "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant",
    "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet",
    "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon",
    "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet",
    "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet",
    "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position",
    "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict",
    "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote",
    "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp",
    "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push",
    "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
    "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise",
    "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven",
    "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe",
    "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject",
    "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew",
    "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist",
    "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward",
    "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot",
    "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round",
    "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad",
    "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan",
    "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap",
    "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section",
    "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share",
    "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe",
    "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling",
    "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch",
    "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice",
    "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile",
    "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song",
    "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare",
    "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider",
    "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray",
    "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage",
    "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step",
    "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove",
    "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
    "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer",
    "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise",
    "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet",
    "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table",
    "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term",
    "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing",
    "think", "third", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket",
    "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title",
    "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow",
    "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado",
    "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade",
    "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree",
    "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck",
    "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna",
    "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two",
    "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo",
    "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until",
    "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge",
    "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran",
    "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual",
    "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano",
    "volume", "vote", "vowel", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut",
    "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
    "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome",
    "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper",
    "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "winner",
    "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood",
    "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
    "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero",
    "zone", "zoo",
];
```
