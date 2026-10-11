# Part 1: Prerequisites, Dependencies & Error Architecture

This module covers initializing the Rust project, configuring `Cargo.toml` with modern dependencies, establishing the directory structure, and implementing custom error handling with CLI exit codes.

---

## 1. Environment Setup

Ensure you have Rust (2024 edition supported) installed:
```bash
rustc --version
cargo --version
```

Create a new binary project:
```bash
cargo new bsec --bin
cd bsec
```

---

## 2. Configuration: `Cargo.toml`

Replace `Cargo.toml` with the following configuration:

```toml
[package]
name = "bsec"
version = "0.1.0"
authors = ["Developer <developer@example.com>"]
license = "MIT OR Apache-2.0"
description = "A tool to manage environment variables and share secrets securely"
readme = "README.md"
edition = "2024"

[dependencies]
# CLI Parsing & Formatting
clap = { version = "4.5.31", features = ["derive"] }
clap_complete = "4.5.44"
rpassword = "7.3.0"
log = "0.4.26"
thiserror = "2.0.12"
anyhow = "1.0.97"

# Serialization & Formats
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0.140"
yaml_serde = "0.10"

# Cryptography & Memory Safety
argon2 = "0.5.3"
aes-gcm = "0.10.3"
k256 = { version = "0.13.4", features = ["ecdsa", "arithmetic", "ecdh"] }
bip39 = "2.1.0"
bip32 = "0.5.3"
zeroize = { version = "1.8.1", features = ["derive"] }
sha2 = "0.10.8"
sha3 = "0.10.8"
base64 = "0.22.1"
rand = "0.8.5"

# Networking & System Helpers
reqwest = { version = "0.12", features = ["blocking", "json", "multipart"] }
tempfile = "3.19.0"
dirs = "6.0.0"
lazy_static = "1.5.0"

[dev-dependencies]
assert_cmd = "2.0.16"
assert_fs = "1.1.2"
predicates = "3.1.3"
proptest = "1.6.0"
```

### Key Crates Documentation Links

- [clap](https://docs.rs/clap/latest/clap/): Command Line Argument Parser for Rust.
- [argon2](https://docs.rs/argon2/latest/argon2/): Password hashing & Key Derivation Function (KDF).
- [aes-gcm](https://docs.rs/aes-gcm/latest/aes_gcm/): AES-256-GCM authenticated symmetric encryption.
- [k256](https://docs.rs/k256/latest/k256/): Secp256k1 elliptic curve library with ECDH support.
- [bip39](https://docs.rs/bip39/latest/bip39/): Mnemonic code for deterministic key generation.
- [bip32](https://docs.rs/bip32/latest/bip32/): Hierarchical Deterministic (HD) wallets derivation.
- [zeroize](https://docs.rs/zeroize/latest/zeroize/): Securely clearing memory buffers on drop.
- [thiserror](https://docs.rs/thiserror/latest/thiserror/): Custom derive macro for `std::error::Error`.

---

## 3. Project Directory Structure

Create the required directories:
```bash
mkdir -p src contracts tests docs
```

Expected project structure:
```
.
├── Cargo.toml
├── contracts/
│   └── BsecSecretRegistry.sol
├── src/
│   ├── bip39_words.rs
│   ├── blockchain.rs
│   ├── config.rs
│   ├── env_file.rs
│   ├── errors.rs
│   ├── helpers.rs
│   ├── ipfs.rs
│   ├── main.rs
│   ├── manager.rs
│   ├── network_config.rs
│   ├── project_config.rs
│   ├── secrets.rs
│   └── wallet.rs
└── tests/
    ├── config_and_cli_tests.rs
    ├── encryption_tests.rs
    ├── env_file_tests.rs
    ├── secrets_tests.rs
    └── wallet_tests.rs
```

---

## 4. Error Handling Module ([`src/errors.rs`](file:///Users/igmrrf/Desktop/tmp/bitsec/src/errors.rs))

Create `src/errors.rs` to define structured domain error types and map them to explicit process exit codes:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum BsecError {
    #[error("Wallet not found. Please run 'bsec init' first.")]
    WalletNotFound,

    #[error("Invalid password or wallet data corrupted.")]
    InvalidPassword,

    #[error("Secret with ID '{0}' not found.")]
    SecretNotFound(String),

    #[error("Secret has expired or maximum read count exceeded.")]
    SecretExpired,

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid BIP-39 mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid recipient or public key: {0}")]
    InvalidRecipient(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Format parsing error: {0}")]
    ParseError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("{0}")]
    Generic(String),
}

impl BsecError {
    #[allow(dead_code)]
    pub fn exit_code(&self) -> i32 {
        match self {
            BsecError::InvalidPassword => 2,
            BsecError::SecretExpired
            | BsecError::SecretNotFound(_)
            | BsecError::PermissionDenied(_) => 3,
            BsecError::IoError(_) | BsecError::ParseError(_) | BsecError::ConfigError(_) => 4,
            BsecError::InvalidMnemonic(_) | BsecError::InvalidRecipient(_) => 5,
            _ => 1,
        }
    }
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, BsecError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_exit_codes() {
        assert_eq!(BsecError::InvalidPassword.exit_code(), 2);
        assert_eq!(BsecError::SecretExpired.exit_code(), 3);
        assert_eq!(BsecError::SecretNotFound("id".into()).exit_code(), 3);
        assert_eq!(BsecError::PermissionDenied("denied".into()).exit_code(), 3);
        assert_eq!(BsecError::ParseError("parse".into()).exit_code(), 4);
        assert_eq!(BsecError::ConfigError("cfg".into()).exit_code(), 4);
        assert_eq!(BsecError::InvalidMnemonic("mnem".into()).exit_code(), 5);
        assert_eq!(BsecError::InvalidRecipient("recip".into()).exit_code(), 5);
        assert_eq!(BsecError::WalletNotFound.exit_code(), 1);
        assert_eq!(BsecError::CryptoError("crypto".into()).exit_code(), 1);
        assert_eq!(BsecError::Generic("gen".into()).exit_code(), 1);
    }
}
```

---

## 5. Verification

Run compiler checks to ensure `src/errors.rs` compiles without issues:
```bash
cargo check
```
