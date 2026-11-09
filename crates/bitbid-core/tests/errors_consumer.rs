//! Public additive API and legacy concrete contracts, executed natively and in WASM.
use bitbid_core::{Error, ErrorKind, IpfsError, RpcError, StoreError};
use bitbid_core::{
    crypto::{self, CryptoError},
    legacy_seal::{self, SealError},
    protocol::{self, ProtocolError},
    registry::{self, DecodeError},
    token::{self, TokenError},
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

fn assert_safe(error: Error, kind: ErrorKind, message: &str) {
    assert_eq!(error.kind(), kind);
    assert_eq!(ErrorKind::from(&error), kind);
    assert_eq!(error.public_message(), message);
}
fn converted<T: Into<Error> + std::fmt::Display>(old: T, kind: ErrorKind, message: &str) {
    let diagnostic = old.to_string();
    let new = old.into();
    // Diagnostic payload remains available, but never becomes the public message.
    let payload = match &new {
        Error::Store(_) | Error::Ipfs(_) => panic!("unexpected conversion"),
        Error::Rpc(RpcError::Provider(s)) => s,
        Error::Rpc(RpcError::Request(_) | RpcError::Decode(_)) => panic!("wrong RPC variant"),
        Error::Wallet(s)
        | Error::Crypto(s)
        | Error::Config(s)
        | Error::Secret(s)
        | Error::NotFound(s)
        | Error::Invalid(s)
        | Error::Decode(s) => s,
    };
    assert_eq!(payload, &diagnostic);
    assert_safe(new, kind, message);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn public_root_module_and_thread_contracts() {
    fn transferable<T: Send + Sync + 'static>() {}
    transferable::<Error>();
    transferable::<StoreError>();
    transferable::<IpfsError>();
    transferable::<RpcError>();
    let root: Error = bitbid_core::error::Error::Secret("diagnostic".into());
    let _: bitbid_core::error::ErrorKind = root.kind();
    let _: bitbid_core::error::StoreError = StoreError::Io("diagnostic".into());
    let _: bitbid_core::error::IpfsError = IpfsError::Request("diagnostic".into());
    let _: bitbid_core::error::RpcError = RpcError::Request("diagnostic".into());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_new_variant_has_a_fixed_payload_free_message() {
    for payload in [
        "pw",
        "abandon",
        "/home/alice/wallet.json",
        r"C:\Users\alice\wallet.json",
        r"\\server\private",
        "https://rpc.test/token?password=pw",
        "provider body: abandon pw /secret 0x0123456789abcdef",
    ] {
        for error in [
            StoreError::NotFound(payload.into()),
            StoreError::PermissionDenied(payload.into()),
            StoreError::AlreadyExists(payload.into()),
            StoreError::Io(payload.into()),
        ] {
            assert_safe(error.into(), ErrorKind::Store, "storage operation failed");
        }
        for error in [
            IpfsError::InvalidCid(payload.into()),
            IpfsError::Request(payload.into()),
            IpfsError::Decode(payload.into()),
        ] {
            assert_safe(error.into(), ErrorKind::Transport, "IPFS operation failed");
        }
        for error in [
            RpcError::Request(payload.into()),
            RpcError::Provider(payload.into()),
            RpcError::Decode(payload.into()),
        ] {
            assert_safe(error.into(), ErrorKind::Chain, "RPC operation failed");
        }
        for (error, kind, message) in [
            (
                Error::Wallet(payload.into()),
                ErrorKind::Wallet,
                "wallet operation failed",
            ),
            (
                Error::Crypto(payload.into()),
                ErrorKind::Crypto,
                "cryptographic operation failed",
            ),
            (
                Error::Config(payload.into()),
                ErrorKind::Config,
                "configuration error",
            ),
            (
                Error::Secret(payload.into()),
                ErrorKind::Secret,
                "secret operation failed",
            ),
            (
                Error::NotFound(payload.into()),
                ErrorKind::NotFound,
                "not found",
            ),
            (
                Error::Invalid(payload.into()),
                ErrorKind::Invalid,
                "invalid input",
            ),
            (
                Error::Decode(payload.into()),
                ErrorKind::Decode,
                "decode failed",
            ),
        ] {
            assert_safe(error, kind, message);
        }
    }
}

// Exhaustive legacy matches make additions/removals and recursive routing visible
// to an external consumer without changing any existing concrete API.
fn protocol_kind(error: &ProtocolError) -> ErrorKind {
    match error {
        ProtocolError::Json(_)
        | ProtocolError::Version(_)
        | ProtocolError::Base64(_)
        | ProtocolError::Prefix
        | ProtocolError::Size => ErrorKind::Decode,
    }
}
fn crypto_kind(error: &CryptoError) -> ErrorKind {
    match error {
        CryptoError::Malformed(_)
        | CryptoError::DecryptFailed
        | CryptoError::EncryptFailed
        | CryptoError::Key
        | CryptoError::Utf8
        | CryptoError::Random => ErrorKind::Crypto,
    }
}
fn token_kind(error: &TokenError) -> ErrorKind {
    match error {
        TokenError::Crypto(e) => crypto_kind(e),
        TokenError::Protocol(e) => protocol_kind(e),
        TokenError::Legacy(_) | TokenError::Encoding => ErrorKind::Decode,
        TokenError::Bundle => ErrorKind::Invalid,
    }
}
fn protocols(payload: &str) -> Vec<ProtocolError> {
    vec![
        ProtocolError::Json(<serde_json::Error as serde::de::Error>::custom(payload)),
        ProtocolError::Version(255),
        ProtocolError::Base64(base64::DecodeError::InvalidByte(0, b'%')),
        ProtocolError::Prefix,
        ProtocolError::Size,
    ]
}
fn cryptos(payload: &'static str) -> Vec<CryptoError> {
    vec![
        CryptoError::Malformed(payload),
        CryptoError::DecryptFailed,
        CryptoError::EncryptFailed,
        CryptoError::Key,
        CryptoError::Utf8,
        CryptoError::Random,
    ]
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_legacy_variant_converts_without_changing_its_public_contract() {
    for payload in [
        "pw",
        "abandon",
        "/home/private",
        r"C:\private",
        "https://rpc.test/pw",
        "provider body abandon",
    ] {
        for e in protocols(payload) {
            let kind = protocol_kind(&e);
            converted(e, kind, "decode failed");
        }
        for e in cryptos(payload) {
            let kind = crypto_kind(&e);
            converted(e, kind, "cryptographic operation failed");
        }
        let mut tokens: Vec<_> = protocols(payload).into_iter().map(TokenError::Protocol).collect();
        tokens.extend(cryptos(payload).into_iter().map(TokenError::Crypto));
        tokens.extend([
            TokenError::Legacy(payload.into()),
            TokenError::Bundle,
            TokenError::Encoding,
        ]);
        for e in tokens {
            let kind = token_kind(&e);
            let message = match kind {
                ErrorKind::Crypto => "cryptographic operation failed",
                ErrorKind::Invalid => "invalid input",
                ErrorKind::Decode => "decode failed",
                _ => panic!("unexpected legacy class"),
            };
            converted(e, kind, message);
        }
        for e in [
            SealError::BadPrefix,
            SealError::BadBase64(payload.into()),
            SealError::BadVersion(255),
            SealError::Malformed(payload),
            SealError::BadRecipientKey(payload.into()),
            SealError::BadEphemeralKey(payload.into()),
            SealError::BadRecipientSecret,
            SealError::DecryptFailed,
            SealError::NotUtf8,
            SealError::Random(payload.into()),
        ] {
            let (kind, message) = match &e {
                SealError::BadRecipientKey(_) | SealError::BadRecipientSecret => {
                    (ErrorKind::Invalid, "invalid input")
                }
                SealError::DecryptFailed | SealError::Random(_) => {
                    (ErrorKind::Crypto, "cryptographic operation failed")
                }
                SealError::BadPrefix
                | SealError::BadBase64(_)
                | SealError::BadVersion(_)
                | SealError::Malformed(_)
                | SealError::BadEphemeralKey(_)
                | SealError::NotUtf8 => (ErrorKind::Decode, "decode failed"),
            };
            converted(e, kind, message);
        }
        for e in [
            DecodeError::Json(payload.into()),
            DecodeError::Rpc(payload.into()),
            DecodeError::NoResult,
            DecodeError::Shape(payload),
            DecodeError::Abi(payload.into()),
        ] {
            let (kind, message) = match &e {
                DecodeError::Rpc(_) => (ErrorKind::Chain, "RPC operation failed"),
                DecodeError::Json(_)
                | DecodeError::NoResult
                | DecodeError::Shape(_)
                | DecodeError::Abi(_) => (ErrorKind::Decode, "decode failed"),
            };
            converted(e, kind, message);
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn legacy_apis_still_return_their_concrete_result_types() {
    let _: Result<protocol::IpfsPayload, ProtocolError> = protocol::from_share_string("unknown:");
    let _: Result<String, CryptoError> = crypto::decrypt_text("invalid", &[0; 32]);
    let _: Result<Vec<u8>, TokenError> = token::unseal("unknown:", &[0; 32]);
    let _: Result<Vec<u8>, SealError> = legacy_seal::unseal("unknown:", &[0; 32]);
    let _: Result<registry::RegistryRecord, DecodeError> =
        registry::decode_get_secret_info_response("{}", "test");
}
