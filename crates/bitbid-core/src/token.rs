//! Offline share token boundary used by the native CLI and the browser console.
use crate::{
    crypto::{self, CryptoError},
    protocol::{self, IpfsPayload, ProtocolError},
};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use k256::PublicKey;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum TokenError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("invalid legacy browser token: {0}")]
    Legacy(String),
    #[error("bundle payload requires the file materialization interface")]
    Bundle,
    #[error("unsupported content encoding")]
    Encoding,
}
pub fn seal_to_share_string(
    plaintext: &[u8],
    recipient_pubkey_hex: &str,
) -> Result<String, TokenError> {
    let bytes = crate::address::hex_to_bytes(recipient_pubkey_hex).map_err(|_| CryptoError::Key)?;
    let recipient = PublicKey::from_sec1_bytes(&bytes).map_err(|_| CryptoError::Key)?;
    let mut payload = match std::str::from_utf8(plaintext) {
        Ok(text) => IpfsPayload::text(text.to_owned()),
        Err(_) => {
            let mut payload = IpfsPayload::text(BASE64_STANDARD.encode(plaintext));
            payload.content_encoding = Some("base64".into());
            payload
        }
    };
    payload = crypto::seal_payload(payload, Some(&recipient))?;
    Ok(protocol::to_share_string(&payload)?)
}
pub fn unseal(share: &str, recipient_secret: &[u8]) -> Result<Vec<u8>, TokenError> {
    let share = share.trim();
    if share.starts_with(crate::legacy_seal::SEAL_PREFIX) {
        return crate::legacy_seal::unseal(share, recipient_secret)
            .map_err(|e| TokenError::Legacy(e.to_string()));
    }
    let payload = protocol::from_share_string(share)?;
    if payload.members.is_some() {
        return Err(TokenError::Bundle);
    }
    let payload = crypto::open_payload(payload, Some(recipient_secret), false)?;
    match payload.content_encoding.as_deref() {
        None | Some("utf8") => Ok(payload.content.into_bytes()),
        Some("base64") => BASE64_STANDARD
            .decode(payload.content)
            .map_err(|_| TokenError::Encoding),
        _ => Err(TokenError::Encoding),
    }
}
pub fn unseal_to_string(share: &str, recipient_secret: &[u8]) -> Result<String, TokenError> {
    String::from_utf8(unseal(share, recipient_secret)?).map_err(|_| CryptoError::Utf8.into())
}
