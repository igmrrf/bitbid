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

// This classification is additive; legacy process exits remain independent.
impl From<&BsecError> for bitbid_core::ErrorKind {
    fn from(error: &BsecError) -> Self {
        match error {
            BsecError::InvalidPassword => Self::Wallet,
            BsecError::WalletNotFound | BsecError::SecretNotFound(_) => Self::NotFound,
            BsecError::SecretExpired | BsecError::PermissionDenied(_) | BsecError::Generic(_) => {
                Self::Secret
            }
            BsecError::InvalidMnemonic(_) | BsecError::InvalidRecipient(_) => Self::Invalid,
            BsecError::IoError(_) => Self::Store,
            BsecError::ParseError(_) => Self::Decode,
            BsecError::ConfigError(_) => Self::Config,
            BsecError::CryptoError(_) => Self::Crypto,
        }
    }
}

/// Preserve the legacy untyped CLI fallback precedence, independently of kind.
pub fn fallback_exit_code(message: &str) -> i32 {
    let msg = message.to_lowercase();
    if msg.contains("password") || msg.contains("corrupted") {
        2
    } else if msg.contains("not found") || msg.contains("expired") || msg.contains("permission") {
        3
    } else if msg.contains("io")
        || msg.contains("parse")
        || msg.contains("config")
        || msg.contains("file")
    {
        4
    } else if msg.contains("mnemonic") || msg.contains("recipient") {
        5
    } else {
        1
    }
}

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, BsecError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_exit_and_additive_kind_table() {
        use bitbid_core::ErrorKind as K;
        for (error, code, kind) in [
            (BsecError::WalletNotFound, 1, K::NotFound),
            (BsecError::InvalidPassword, 2, K::Wallet),
            (BsecError::SecretNotFound("id".into()), 3, K::NotFound),
            (BsecError::SecretExpired, 3, K::Secret),
            (BsecError::PermissionDenied("denied".into()), 3, K::Secret),
            (BsecError::InvalidMnemonic("mnem".into()), 5, K::Invalid),
            (BsecError::InvalidRecipient("recip".into()), 5, K::Invalid),
            (BsecError::CryptoError("crypto".into()), 1, K::Crypto),
            (BsecError::IoError(std::io::Error::other("io")), 4, K::Store),
            (BsecError::ParseError("parse".into()), 4, K::Decode),
            (BsecError::ConfigError("cfg".into()), 4, K::Config),
            (BsecError::Generic("gen".into()), 1, K::Secret),
        ] {
            assert_eq!(error.exit_code(), code);
            assert_eq!(K::from(&error), kind);
        }
    }

    #[test]
    fn fallback_preserves_original_precedence_and_case_folding() {
        for (message, code) in [
            ("PASSWORD permission io mnemonic", 2),
            ("corrupted file recipient", 2),
            ("not found config", 3),
            ("expired parse", 3),
            ("permission mnemonic", 3),
            ("io recipient", 4),
            ("parse mnemonic", 4),
            ("config recipient", 4),
            ("file mnemonic", 4),
            ("mnemonic recipient", 5),
            ("recipient", 5),
            ("unclassified", 1),
            ("IO", 4),
            ("configuration", 4),
        ] {
            assert_eq!(fallback_exit_code(message), code, "{message}");
        }
    }
}
