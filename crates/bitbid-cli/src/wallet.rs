use anyhow::{anyhow, Result};
use crate::errors::BsecError;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;
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

pub fn get_app_dir() -> Result<PathBuf> {
    crate::compat::app_dir()
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

/// Native fail-stop entropy adapter; never substitutes deterministic bytes.
struct WalletOsRandom;
impl bitbid_core::RandomSource for WalletOsRandom {
    fn fill_bytes(&self, dest: &mut [u8]) { OsRng.fill_bytes(dest); }
    fn gen_key(&self) -> k256::SecretKey { k256::SecretKey::random(&mut OsRng) }
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    Ok(bitbid_core::wallet_codec::derive_key(password, salt)?)
}

pub fn encrypt_wallet(data_str: &str, password: &str) -> Result<String> {
    Ok(bitbid_core::wallet_codec::encrypt_wallet(data_str, password, &WalletOsRandom)?)
}

#[allow(dead_code)] // Retained native compatibility wrapper; reader uses the guarded core result.
pub fn decrypt_wallet(encrypted_str: &str, password: &str) -> Result<String> {
    let mut plaintext = bitbid_core::wallet_codec::decrypt_wallet(encrypted_str, password)
        .map_err(|error| match error {
            bitbid_core::wallet_codec::WalletCodecError::InvalidPassword => anyhow!(BsecError::InvalidPassword),
            other => anyhow!(other),
        })?;
    Ok(std::mem::take(&mut *plaintext))
}

/// Render into one guarded buffer without cloning the native wallet's secret fields.
pub fn render_wallet_json(info: &WalletInfo, include_private_key: bool, include_mnemonic: bool) -> Zeroizing<String> {
    bitbid_core::wallet_codec::render_wallet_json(&bitbid_core::wallet_codec::WalletFields {
        address: &info.address,
        public_key: &info.public_key,
        private_key: &info.private_key,
        mnemonic: &info.mnemonic,
        created_at: info.created_at,
        last_accessed: info.last_accessed,
        user_id: info.user_id.as_deref(),
    }, include_private_key, include_mnemonic)
}

pub fn generate_mnemonic() -> Result<String> {
    let mut mnemonic = bitbid_core::wallet_codec::generate_mnemonic(&WalletOsRandom)?;
    Ok(std::mem::take(&mut *mnemonic))
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
    let app_dir = get_app_dir()?;
    let config_path = app_dir.join("config.json");
    let wallet_path = app_dir.join("wallet.json");

    if config_path.exists() && !overwrite {
        return Err(anyhow!(
            "Wallet already exists. Use overwrite option or provide new credentials."
        ));
    }

    let mnemonic_str = match import_mnemonic {
        Some(m) => {
            bitbid_core::wallet_codec::validate_mnemonic(&m)
                .map_err(|e| BsecError::InvalidMnemonic(e.to_string()))?;
            m
        }
        None => generate_mnemonic()?,
    };

    let mut keys = bitbid_core::wallet_codec::derive_wallet_keys(&mnemonic_str)?;
    let private_key = std::mem::take(&mut *keys.private_key);
    let public_key_str = keys.public_key;
    let address = keys.address;
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
    // Keep native path selection/revalidation at the original lazy access point.
    let app_dir = get_app_dir()?;
    let wallet_path = app_dir.join("wallet.json");
    // Retain the original metadata check: it intentionally classifies inaccessible
    // symlink targets and loops as missing before the Store's readable-file check.
    if !wallet_path.exists() {
        return Err(BsecError::WalletNotFound.into());
    }
    let store = bitbid_adapters::store::FileStore::new([
        (bitbid_core::StoreKey::Wallet, wallet_path),
    ]);
    let mut info = bitbid_core::wallet_read::read_wallet(&store, password)
        .map_err(|error| match error {
            bitbid_core::wallet_read::WalletReadError::Missing => anyhow!(BsecError::WalletNotFound),
            bitbid_core::wallet_read::WalletReadError::Codec(bitbid_core::wallet_codec::WalletCodecError::InvalidPassword) => anyhow!(BsecError::InvalidPassword),
            other => anyhow!(other),
        })?;
    // Move, rather than clone, the guarded result into the existing native guard.
    Ok(WalletInfo {
        address: std::mem::take(&mut info.address),
        public_key: std::mem::take(&mut info.public_key),
        private_key: std::mem::take(&mut info.private_key),
        mnemonic: std::mem::take(&mut info.mnemonic),
        created_at: info.created_at,
        last_accessed: info.last_accessed,
        user_id: info.user_id.take(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_codec_wrappers_preserve_kdf_json_and_invalid_password_type() {
        let vector: serde_json::Value = serde_json::from_str(include_str!("../../bitbid-core/tests/vectors/wallet-codec-v1.json")).unwrap();
        let password = vector["password"].as_str().unwrap();
        let encrypted = vector["encrypted"].as_str().unwrap();
        let raw = vector["plaintext"].as_str().unwrap();
        assert_eq!(decrypt_wallet(encrypted, password).unwrap(), raw);
        let info: WalletInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(*render_wallet_json(&info, true, true), raw);
        let error = decrypt_wallet(encrypted, "wrong PUBLIC password").unwrap_err();
        assert!(matches!(error.downcast_ref::<BsecError>(), Some(BsecError::InvalidPassword)));
        for case in vector["kdf"].as_array().unwrap() {
            let salt = hex_to_bytes(case["salt_hex"].as_str().unwrap()).unwrap();
            assert_eq!(bytes_to_hex(&derive_key(password, &salt).unwrap()), case["key_hex"].as_str().unwrap());
        }
    }

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
