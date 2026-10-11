//! Versioned canonical encoding of the existing CLI IPFS payload.
use base64::prelude::{BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u8 = 1;
pub const TOKEN_PREFIX: &str = "bitbid2:";
pub const MAX_WIRE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IpfsPayload {
    pub content: String,
    pub content_key: String,
    pub ephemeral_pubkey: Option<String>,

    // --- file-materialization metadata, all optional for backward compat ---
    /// Intended file type of `content` (single-file secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SecretKind>,
    /// Suggested output basename (single-file secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Seal: when true, refuse all file materialization (terminal view only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_export: bool,
    /// Present => this secret is a bundle; materialization iterates members.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<BundleMember>>,
    /// Encoding of the single-file `content`: "utf8" (default) or "base64".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    Env,
    Pem,
    Json,
    Cred,
}

fn enc_utf8() -> String {
    "utf8".to_string()
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BundleMember {
    pub kind: SecretKind,
    /// Basename only, e.g. "creds.json".
    pub filename: String,
    /// The member's plaintext body (whole payload is still AEAD-encrypted at rest).
    pub content: String,
    /// "utf8" (default) or "base64" for binary member bodies.
    #[serde(default = "enc_utf8")]
    pub encoding: String,
    /// Optional explicit env var name to bind this member's staged path to under `run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid payload JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported payload protocol version: {0}")]
    Version(u8),
    #[error("invalid token base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("unsupported share token prefix")]
    Prefix,
    #[error("payload exceeds the wire size limit")]
    Size,
}

fn legacy_version() -> u8 {
    PROTOCOL_VERSION
}
#[derive(Serialize, Deserialize)]
struct WirePayload {
    #[serde(default = "legacy_version")]
    protocol_version: u8,
    #[serde(flatten)]
    payload: IpfsPayload,
}

/// Fixed field order, UTF-8 compact JSON, optional fields omitted per the CLI schema.
/// Canonical for this protocol; this is not a general JSON canonicalizer.
pub fn canonical_bytes(payload: &IpfsPayload) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(&WirePayload {
        protocol_version: PROTOCOL_VERSION,
        payload: payload.clone(),
    })?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(ProtocolError::Size);
    }
    Ok(bytes)
}

/// Missing version means legacy CLI v1; explicitly unsupported versions fail closed.
pub fn decode_payload(bytes: &[u8]) -> Result<IpfsPayload, ProtocolError> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(ProtocolError::Size);
    }
    let wire: WirePayload = serde_json::from_slice(bytes)?;
    if wire.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(wire.protocol_version));
    }
    Ok(wire.payload)
}

pub fn to_share_string(payload: &IpfsPayload) -> Result<String, ProtocolError> {
    Ok(format!(
        "{TOKEN_PREFIX}{}",
        BASE64_STANDARD.encode(canonical_bytes(payload)?)
    ))
}

/// Accept a new token or raw IPFS JSON. Legacy browser tokens use a separate reader.
pub fn from_share_string(token: &str) -> Result<IpfsPayload, ProtocolError> {
    let token = token.trim();
    if token.starts_with('{') {
        return decode_payload(token.as_bytes());
    }
    let body = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(ProtocolError::Prefix)?;
    if body.len() > MAX_WIRE_BYTES.div_ceil(3) * 4 {
        return Err(ProtocolError::Size);
    }
    decode_payload(&BASE64_STANDARD.decode(body)?)
}

impl IpfsPayload {
    pub fn text(content: String) -> Self {
        Self {
            content,
            content_key: String::new(),
            ephemeral_pubkey: None,
            kind: None,
            filename: None,
            no_export: false,
            members: None,
            content_encoding: None,
        }
    }
}

/// Output format for `materialize` / `view --file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Env,
    Pem,
    Json,
    Cred,
    Schema,
}

impl SecretKind {
    pub fn as_format(self) -> OutputFormat {
        match self {
            SecretKind::Env => OutputFormat::Env,
            SecretKind::Pem => OutputFormat::Pem,
            SecretKind::Json => OutputFormat::Json,
            SecretKind::Cred => OutputFormat::Cred,
        }
    }
}
