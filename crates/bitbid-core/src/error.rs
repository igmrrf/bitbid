//! Additive error taxonomy. Existing APIs retain their concrete error types.
//!
//! Use [`Error::public_message`] at host/client boundaries. `Display` and `Debug`
//! contain diagnostic payloads and are not public-safe renderings.
use crate::{
    crypto::CryptoError, legacy_seal::SealError, protocol::ProtocolError, registry,
    token::TokenError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("storage I/O: {0}")]
    Io(String),
}

#[derive(Debug, Error)]
pub enum IpfsError {
    #[error("invalid CID: {0}")]
    InvalidCid(String),
    #[error("IPFS request: {0}")]
    Request(String),
    #[error("IPFS decode: {0}")]
    Decode(String),
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC request: {0}")]
    Request(String),
    #[error("RPC provider: {0}")]
    Provider(String),
    #[error("RPC decode: {0}")]
    Decode(String),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Ipfs(#[from] IpfsError),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("wallet: {0}")]
    Wallet(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("config: {0}")]
    Config(String),
    #[error("secret: {0}")]
    Secret(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("decode: {0}")]
    Decode(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Store,
    Transport,
    Chain,
    Wallet,
    Crypto,
    Config,
    Secret,
    NotFound,
    Invalid,
    Decode,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Store(_) => ErrorKind::Store,
            Self::Ipfs(_) => ErrorKind::Transport,
            Self::Rpc(_) => ErrorKind::Chain,
            Self::Wallet(_) => ErrorKind::Wallet,
            Self::Crypto(_) => ErrorKind::Crypto,
            Self::Config(_) => ErrorKind::Config,
            Self::Secret(_) => ErrorKind::Secret,
            Self::NotFound(_) => ErrorKind::NotFound,
            Self::Invalid(_) => ErrorKind::Invalid,
            Self::Decode(_) => ErrorKind::Decode,
        }
    }

    /// Fixed, payload-free text suitable for a public host/client boundary.
    pub fn public_message(&self) -> String {
        match self.kind() {
            ErrorKind::Store => "storage operation failed",
            ErrorKind::Transport => "IPFS operation failed",
            ErrorKind::Chain => "RPC operation failed",
            ErrorKind::Wallet => "wallet operation failed",
            ErrorKind::Crypto => "cryptographic operation failed",
            ErrorKind::Config => "configuration error",
            ErrorKind::Secret => "secret operation failed",
            ErrorKind::NotFound => "not found",
            ErrorKind::Invalid => "invalid input",
            ErrorKind::Decode => "decode failed",
        }
        .into()
    }
}

impl From<&Error> for ErrorKind {
    fn from(error: &Error) -> Self {
        error.kind()
    }
}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Decode(error.to_string())
    }
}
impl From<CryptoError> for Error {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error.to_string())
    }
}
impl From<TokenError> for Error {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::Crypto(error) => error.into(),
            TokenError::Protocol(error) => error.into(),
            TokenError::Legacy(_) | TokenError::Encoding => Self::Decode(error.to_string()),
            TokenError::Bundle => Self::Invalid(error.to_string()),
        }
    }
}
impl From<SealError> for Error {
    fn from(error: SealError) -> Self {
        match error {
            SealError::BadRecipientKey(_) | SealError::BadRecipientSecret => {
                Self::Invalid(error.to_string())
            }
            SealError::DecryptFailed | SealError::Random(_) => Self::Crypto(error.to_string()),
            SealError::BadPrefix
            | SealError::BadBase64(_)
            | SealError::BadVersion(_)
            | SealError::Malformed(_)
            | SealError::BadEphemeralKey(_)
            | SealError::NotUtf8 => Self::Decode(error.to_string()),
        }
    }
}
impl From<registry::DecodeError> for Error {
    fn from(error: registry::DecodeError) -> Self {
        match error {
            registry::DecodeError::Rpc(_) => RpcError::Provider(error.to_string()).into(),
            registry::DecodeError::Json(_)
            | registry::DecodeError::NoResult
            | registry::DecodeError::Shape(_)
            | registry::DecodeError::Abi(_) => Self::Decode(error.to_string()),
        }
    }
}
