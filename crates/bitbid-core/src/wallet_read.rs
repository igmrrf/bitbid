//! Read-only unlock of the legacy wallet format through one explicitly mapped Store key.
//!
//! Returned strings are stored values, not validated or rederived keys. Secret-owning
//! records have wiping Drop and no Debug/Clone. Serde/library temporary allocations
//! retain their own lifetimes; this does not promise complete memory erasure.
use crate::{
    Store, StoreError, StoreKey,
    wallet_codec::{self, WalletCodecError},
};
use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// The exact stored wallet fields. Ownership can be moved with `mem::take`; Drop
/// wipes fields still owned by this record. Deliberately not Debug or Clone.
///
/// ```compile_fail
/// # fn secret(wallet: bitbid_core::wallet_read::WalletInfo) {
/// println!("{wallet:?}");
/// # }
/// ```
/// ```compile_fail
/// # fn secret(wallet: bitbid_core::wallet_read::WalletInfo) {
/// let copy = wallet.clone();
/// # }
/// ```
#[derive(Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub mnemonic: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub user_id: Option<String>,
}
impl Drop for WalletInfo {
    fn drop(&mut self) {
        self.address.zeroize();
        self.public_key.zeroize();
        self.private_key.zeroize();
        self.mnemonic.zeroize();
        self.created_at.zeroize();
        self.last_accessed.zeroize();
        self.user_id.zeroize();
    }
}

#[derive(Deserialize)]
struct WalletFile {
    encrypted: bool,
    data: String,
    #[serde(rename = "last_accessed")]
    _last_accessed: u64,
}
impl Drop for WalletFile {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Contains only constructed, payload-free diagnostics and the historical exit
/// classification. Neither the original serde error nor its source is retained.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct WalletJsonError {
    message: String,
    legacy_exit: i32,
}

/// Safe errors from the reader. Arbitrary Store payloads are never retained.
#[derive(Debug, Error)]
pub enum WalletReadError {
    #[error("Wallet not found. Please run 'bitbid init' first.")]
    Missing,
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Wallet storage read failed")]
    Read,
    #[error("stream did not contain valid UTF-8")]
    Utf8,
    #[error("Wallet is encrypted. Password is required.")]
    PasswordRequired,
    #[error(transparent)]
    Json(WalletJsonError),
    #[error(transparent)]
    Codec(WalletCodecError),
}
impl WalletReadError {
    /// Preserve the native 0.x exit classification independently of redaction.
    /// In particular, malformed JSON text historically influenced its exit.
    pub fn legacy_exit_code(&self) -> i32 {
        match self {
            Self::PermissionDenied => 3,
            Self::PasswordRequired => 2,
            Self::Json(error) => error.legacy_exit,
            Self::Codec(error) => legacy_exit(&error.to_string()),
            Self::Missing | Self::Read | Self::Utf8 => 1,
        }
    }
}

fn legacy_exit(message: &str) -> i32 {
    // This guarded copy preserves the native fallback's Unicode case folding
    // without leaving an additional unguarded payload-bearing allocation.
    let lower = Zeroizing::new(message.to_lowercase());
    if lower.contains("password") || lower.contains("corrupted") {
        2
    } else if lower.contains("not found")
        || lower.contains("expired")
        || lower.contains("permission")
    {
        3
    } else if lower.contains("io")
        || lower.contains("parse")
        || lower.contains("config")
        || lower.contains("file")
    {
        4
    } else if lower.contains("mnemonic") || lower.contains("recipient") {
        5
    } else {
        1
    }
}

const FIELDS: &[&str] = &[
    "encrypted",
    "data",
    "last_accessed",
    "address",
    "public_key",
    "private_key",
    "mnemonic",
    "created_at",
    "user_id",
];
const EXPECTED: &[&str] = &[
    "a boolean",
    "a string",
    "u64",
    "struct WalletFile",
    "struct WalletInfo",
];

fn safe_data_message(raw: &str, line: usize, column: usize) -> String {
    let suffix = format!(" at line {line} column {column}");
    if let Some(body) = raw.strip_suffix(&suffix) {
        for field in FIELDS {
            for kind in ["missing field", "duplicate field"] {
                if body == format!("{kind} `{field}`") {
                    return format!("{body}{suffix}");
                }
            }
        }
        for prefix in ["invalid type: ", "invalid value: "] {
            if let Some((unexpected, expected)) = body
                .strip_prefix(prefix)
                .and_then(|s| s.rsplit_once(", expected "))
            {
                if !EXPECTED.contains(&expected) {
                    continue;
                }
                let safe = if unexpected.starts_with("string \"") {
                    Some("string [redacted]")
                } else if unexpected.starts_with("integer `") {
                    Some("integer [redacted]")
                } else if unexpected.starts_with("floating point `") {
                    Some("floating point [redacted]")
                } else if unexpected.starts_with("boolean `") {
                    Some("boolean [redacted]")
                } else if ["unit value", "sequence", "map"].contains(&unexpected) {
                    Some(unexpected)
                } else {
                    None
                };
                if let Some(safe) = safe {
                    return format!("{prefix}{safe}, expected {expected}{suffix}");
                }
            }
        }
    }
    format!("Invalid wallet JSON data{suffix}")
}

fn json_error(error: serde_json::Error) -> WalletReadError {
    let raw = Zeroizing::new(error.to_string());
    let legacy_exit = legacy_exit(&raw);
    let message = match error.classify() {
        // Syntax/EOF messages are parser-static. Data messages may quote input.
        serde_json::error::Category::Syntax | serde_json::error::Category::Eof => raw.to_string(),
        _ => safe_data_message(&raw, error.line(), error.column()),
    };
    WalletReadError::Json(WalletJsonError {
        message,
        legacy_exit,
    })
}

/// Read Wallet exactly once, parse the outer record, then unlock and parse its
/// stored fields. Never checks existence separately or writes/accesses other ports.
pub fn read_wallet(
    store: &dyn Store,
    password: Option<&str>,
) -> Result<WalletInfo, WalletReadError> {
    let bytes = Zeroizing::new(
        store
            .read(&StoreKey::Wallet)
            .map_err(|error| match error {
                StoreError::NotFound(_) => WalletReadError::Missing,
                StoreError::PermissionDenied(_) => WalletReadError::PermissionDenied,
                StoreError::AlreadyExists(_) | StoreError::Io(_) => WalletReadError::Read,
            })?
            .ok_or(WalletReadError::Missing)?,
    );
    let text = std::str::from_utf8(&bytes).map_err(|_| WalletReadError::Utf8)?;
    let file: WalletFile = serde_json::from_str(text).map_err(json_error)?;
    if file.encrypted {
        let password = password.ok_or(WalletReadError::PasswordRequired)?;
        let plaintext =
            wallet_codec::decrypt_wallet(&file.data, password).map_err(WalletReadError::Codec)?;
        serde_json::from_str(&plaintext).map_err(json_error)
    } else {
        serde_json::from_str(&file.data).map_err(json_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrecognized_data_messages_do_not_admit_untrusted_fields_or_expected_types() {
        for raw in [
            "missing field `PUBLIC password` at line 1 column 2",
            "invalid type: string \"PUBLIC password\", expected PUBLIC secret at line 1 column 2",
            "PUBLIC secret at line 1 column 2",
        ] {
            assert_eq!(
                safe_data_message(raw, 1, 2),
                "Invalid wallet JSON data at line 1 column 2"
            );
        }
        let error = json_error(<serde_json::Error as serde::de::Error>::custom(
            "PUBLIC password",
        ));
        assert_eq!(error.legacy_exit_code(), 2);
        assert_eq!(
            error.to_string(),
            "Invalid wallet JSON data at line 0 column 0"
        );
        assert!(!format!("{error:?}").contains("PUBLIC"));
    }
}
