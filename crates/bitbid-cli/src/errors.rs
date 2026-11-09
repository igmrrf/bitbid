use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum BitbidError {
    #[error("Wallet not found. Please run 'bitbid init' first.")]
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

impl BitbidError {
    #[allow(dead_code)]
    pub fn exit_code(&self) -> i32 {
        match self {
            BitbidError::InvalidPassword => 2,
            BitbidError::SecretExpired
            | BitbidError::SecretNotFound(_)
            | BitbidError::PermissionDenied(_) => 3,
            BitbidError::IoError(_) | BitbidError::ParseError(_) | BitbidError::ConfigError(_) => 4,
            BitbidError::InvalidMnemonic(_) | BitbidError::InvalidRecipient(_) => 5,
            _ => 1,
        }
    }
}

/// Legacy source-inclusion compatibility alias, retained through all 0.x releases.
#[allow(dead_code)]
pub type BsecError = BitbidError;

// This classification is additive; legacy process exits remain independent.
impl From<&BitbidError> for bitbid_core::ErrorKind {
    fn from(error: &BitbidError) -> Self {
        match error {
            BitbidError::InvalidPassword => Self::Wallet,
            BitbidError::WalletNotFound | BitbidError::SecretNotFound(_) => Self::NotFound,
            BitbidError::SecretExpired | BitbidError::PermissionDenied(_) | BitbidError::Generic(_) => {
                Self::Secret
            }
            BitbidError::InvalidMnemonic(_) | BitbidError::InvalidRecipient(_) => Self::Invalid,
            BitbidError::IoError(_) => Self::Store,
            BitbidError::ParseError(_) => Self::Decode,
            BitbidError::ConfigError(_) => Self::Config,
            BitbidError::CryptoError(_) => Self::Crypto,
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
pub type Result<T> = std::result::Result<T, BitbidError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_alias_preserves_variants_results_conversions_and_downcasts() {
        fn legacy_result(error: BsecError) -> Result<()> {
            Err(error)
        }
        let legacy: BsecError = BsecError::InvalidRecipient("recipient".into());
        let canonical: BitbidError = legacy;
        let result = legacy_result(canonical);
        let erased = anyhow::Error::new(result.unwrap_err());
        assert!(matches!(
            erased.downcast_ref::<BsecError>(),
            Some(BsecError::InvalidRecipient(_))
        ));
        assert!(matches!(
            erased.downcast_ref::<BitbidError>(),
            Some(BitbidError::InvalidRecipient(_))
        ));
        let converted: BsecError = std::io::Error::other("synthetic").into();
        assert!(matches!(converted, BitbidError::IoError(_)));
        assert_eq!(converted.exit_code(), 4);
        assert_eq!(bitbid_core::ErrorKind::from(&converted), bitbid_core::ErrorKind::Store);
    }

    #[test]
    fn legacy_exit_and_additive_kind_table() {
        use bitbid_core::ErrorKind as K;
        for (error, code, kind) in [
            (BitbidError::WalletNotFound, 1, K::NotFound),
            (BitbidError::InvalidPassword, 2, K::Wallet),
            (BitbidError::SecretNotFound("id".into()), 3, K::NotFound),
            (BitbidError::SecretExpired, 3, K::Secret),
            (BitbidError::PermissionDenied("denied".into()), 3, K::Secret),
            (BitbidError::InvalidMnemonic("mnem".into()), 5, K::Invalid),
            (BitbidError::InvalidRecipient("recip".into()), 5, K::Invalid),
            (BitbidError::CryptoError("crypto".into()), 1, K::Crypto),
            (BitbidError::IoError(std::io::Error::other("io")), 4, K::Store),
            (BitbidError::ParseError("parse".into()), 4, K::Decode),
            (BitbidError::ConfigError("cfg".into()), 4, K::Config),
            (BitbidError::Generic("gen".into()), 1, K::Secret),
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
