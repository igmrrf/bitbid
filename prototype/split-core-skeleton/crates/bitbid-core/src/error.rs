//! The single core error model for `bitbid-core`.
//!
//! Core owns one typed umbrella [`Error`] that unifies the three port errors
//! plus the pure-core failure classes. It intentionally depends on nothing
//! beyond `thiserror`: no `anyhow`, no `clap`, no `leptos`. CLI and web
//! projections are derived from [`ErrorKind`] plus [`Error::public_message`].

use thiserror::Error;

// --- Port errors (owned by their ports, moved here from lib.rs) -----------

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("i/o error: {0}")]
    Io(String),
}

#[derive(Debug, Error)]
pub enum IpfsError {
    #[error("invalid cid: {0}")]
    InvalidCid(String),
    #[error("ipfs request failed: {0}")]
    Request(String),
    #[error("ipfs decode failed: {0}")]
    Decode(String),
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("rpc request failed: {0}")]
    Request(String),
    #[error("rpc returned error: {0}")]
    Provider(String),
    #[error("rpc decode failed: {0}")]
    Decode(String),
}

// --- Umbrella error -------------------------------------------------------

/// One core error type, unified from the per-port errors via `#[from]`.
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

/// Coarse class of an [`Error`], used to compute the CLI exit code and the
/// web/`ServerFnError` projection without matching every variant at each site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// Local durable storage / filesystem failures.
    Store,
    /// IPFS transport failures.
    Transport,
    /// JSON-RPC / chain failures.
    Chain,
    /// Wallet lifecycle failures (auth, password, Keystore).
    Wallet,
    /// Cryptographic operation failures.
    Crypto,
    /// Configuration / environment parsing failures.
    Config,
    /// Secret lifecycle failures (expiry, read-count, ACL).
    Secret,
    /// A requested entity is absent.
    NotFound,
    /// Caller-supplied input is malformed or rejected.
    Invalid,
    /// A serialization / ABI / RLP decode step failed.
    Decode,
}

impl Error {
    /// Classify the error without exposing its payload.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Store(_) => ErrorKind::Store,
            Error::Ipfs(_) => ErrorKind::Transport,
            Error::Rpc(_) => ErrorKind::Chain,
            Error::Wallet(_) => ErrorKind::Wallet,
            Error::Crypto(_) => ErrorKind::Crypto,
            Error::Config(_) => ErrorKind::Config,
            Error::Secret(_) => ErrorKind::Secret,
            Error::NotFound(_) => ErrorKind::NotFound,
            Error::Invalid(_) => ErrorKind::Invalid,
            Error::Decode(_) => ErrorKind::Decode,
        }
    }

    /// A sanitized, user-facing message safe to cross the SSR boundary.
    ///
    /// Guarantees: the payload of secret-bearing classes ([`Error::Wallet`],
    /// [`Error::Crypto`], [`Error::Config`], [`Error::Secret`],
    /// [`Error::Invalid`]) is never emitted — a short mnemonic or password
    /// cannot be detected by inspection, so those classes are payload-free by
    /// construction. For the operational payloads that remain
    /// ([`Error::Store`], [`Error::Ipfs`], [`Error::Rpc`], [`Error::NotFound`],
    /// [`Error::Decode`]) every absolute-path substring is replaced with
    /// `<path>` and secret-looking tokens with `<redacted>`.
    pub fn public_message(&self) -> String {
        match self {
            Error::Store(e) => sanitize(&e.to_string()),
            Error::Ipfs(e) => sanitize(&e.to_string()),
            Error::Rpc(e) => sanitize(&e.to_string()),
            Error::Wallet(_) => "wallet: <redacted>".to_string(),
            Error::Crypto(_) => "crypto: <redacted>".to_string(),
            Error::Config(_) => "config: <redacted>".to_string(),
            Error::Secret(_) => "secret error".to_string(),
            Error::NotFound(m) => format!("not found: {}", sanitize(m)),
            Error::Invalid(_) => "invalid input: <redacted>".to_string(),
            Error::Decode(m) => format!("decode: {}", sanitize(m)),
        }
    }
}

impl From<&Error> for ErrorKind {
    fn from(e: &Error) -> Self {
        e.kind()
    }
}

// --- Sanitizer ------------------------------------------------------------

fn sanitize(msg: &str) -> String {
    let redacted = redact_paths(msg);
    let mut out = String::with_capacity(redacted.len());
    let mut first = true;
    for token in redacted.split_whitespace() {
        if !first {
            out.push(' ');
        }
        first = false;
        if looks_like_secret(token) {
            out.push_str("<redacted>");
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Replace every absolute-path substring with `<path>`, wherever it appears:
/// as its own token, after `=`, `:`, or whitespace, inside quotes/braces, or
/// with a Windows drive (`C:\…`) or a leading `\\` UNC prefix. A path ends at
/// whitespace or a delimiter, so embedded paths cannot leak.
fn redact_paths(msg: &str) -> String {
    let chars: Vec<char> = msg.chars().collect();
    let mut out = String::with_capacity(msg.len());
    let mut i = 0;
    while i < chars.len() {
        let prev = if i == 0 { None } else { Some(chars[i - 1]) };
        if let Some(prefix_len) = path_prefix_len(&chars, i, prev) {
            out.push_str("<path>");
            i += prefix_len;
            while i < chars.len() && !is_path_stop(chars[i]) {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Length of the absolute-path prefix starting at `chars[i]`, or `None` when
/// no path starts there. Requires a token boundary so `and/or` is untouched.
fn path_prefix_len(chars: &[char], i: usize, prev: Option<char>) -> Option<usize> {
    let at_boundary = prev.map_or(true, |p| !p.is_alphanumeric());
    if !at_boundary {
        return None;
    }
    let c = chars[i];
    if c == '/' || c == '\\' {
        return Some(1);
    }
    if c.is_ascii_alphabetic()
        && chars.get(i + 1) == Some(&':')
        && matches!(chars.get(i + 2), Some('/') | Some('\\'))
    {
        return Some(3);
    }
    None
}

fn is_path_stop(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ')' | '}' | ']' | ',' | ';' | '>' | ':')
}

fn looks_like_secret(token: &str) -> bool {
    let alnum = token.chars().all(|c| c.is_ascii_alphanumeric());
    let hexish = token.chars().all(|c| c.is_ascii_hexdigit());
    if token.len() >= 32 && (alnum || hexish) {
        return true;
    }
    if let Some(rest) = token.strip_prefix("0x") {
        if rest.len() >= 16 && hexish {
            return true;
        }
    }
    false
}

// --- SSR contract ---------------------------------------------------------

const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<Error>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_stable() {
        assert_eq!(Error::from(StoreError::NotFound("x".into())).kind(), ErrorKind::Store);
        assert_eq!(Error::from(IpfsError::Request("x".into())).kind(), ErrorKind::Transport);
        assert_eq!(Error::from(RpcError::Provider("x".into())).kind(), ErrorKind::Chain);
        assert_eq!(Error::Wallet("x".into()).kind(), ErrorKind::Wallet);
        assert_eq!(ErrorKind::from(&Error::Crypto("x".into())), ErrorKind::Crypto);
        assert_eq!(Error::Config("x".into()).kind(), ErrorKind::Config);
        assert_eq!(Error::Secret("x".into()).kind(), ErrorKind::Secret);
        assert_eq!(Error::NotFound("x".into()).kind(), ErrorKind::NotFound);
        assert_eq!(Error::Invalid("x".into()).kind(), ErrorKind::Invalid);
        assert_eq!(Error::Decode("x".into()).kind(), ErrorKind::Decode);
    }

    #[test]
    fn secret_payload_is_never_leaked() {
        let e = Error::Secret("mnemonic words here".into());
        let msg = e.public_message();
        assert!(!msg.contains("mnemonic"));
        assert_eq!(msg, "secret error");
    }

    #[test]
    fn short_secrets_are_never_leaked() {
        let mnemonic =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        let e = Error::Invalid(mnemonic.into());
        assert!(!e.public_message().contains("abandon"));
        assert_eq!(e.public_message(), "invalid input: <redacted>");

        let e = Error::Wallet("password=hunter2".into());
        assert!(!e.public_message().contains("hunter2"));
        assert_eq!(e.public_message(), "wallet: <redacted>");

        let e = Error::Crypto("key deadbeefcafe".into());
        assert!(!e.public_message().contains("deadbeefcafe"));
        assert_eq!(e.public_message(), "crypto: <redacted>");

        let e = Error::Config("api_key=abc123".into());
        assert!(!e.public_message().contains("abc123"));
        assert_eq!(e.public_message(), "config: <redacted>");
    }

    #[test]
    fn absolute_paths_are_redacted() {
        let isolated = Error::NotFound("failed to read /Users/me/.bsec/wallet.json".into());
        assert_eq!(
            isolated.public_message(),
            "not found: failed to read <path>"
        );

        let embedded = Error::NotFound("open failed path=/Users/me/.bsec/wallet.json: denied".into());
        assert_eq!(
            embedded.public_message(),
            "not found: open failed path=<path>: denied"
        );

        let quoted = Error::NotFound("cannot open \"/Users/me/.bsec/wallet.json\"".into());
        assert_eq!(quoted.public_message(), "not found: cannot open \"<path>\"");

        let windows = Error::NotFound("config={\"key\":\"C:\\Users\\me\\wallet.json\"}".into());
        assert_eq!(
            windows.public_message(),
            "not found: config={\"key\":\"<path>\"}"
        );
    }

    #[test]
    fn long_hex_is_redacted() {
        let e = Error::Decode("key 0x0123456789abcdef0123456789abcdef".into());
        assert_eq!(e.public_message(), "decode: key <redacted>");
    }
}
