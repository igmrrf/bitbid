# Core error model and its CLI/web projections

The [2026-11-08 rollout decision](migration-rollout.md#additive-error-interface-frozen-for-e)
governs the next production implementation: preserve legacy concrete errors and
CLI exits, add classifications/conversions, use constant payload-free public
messages, and retain Yew CSR. The enum/projection/redaction examples below are
historical planning; their proposed CLI reclassifications and SSR work are not
part of that implementation.

Checkpoint E is implemented locally under [#17](https://github.com/igmrrf/clienv/issues/17):
`bitbid_core::error` and its root exports add the frozen types, owned conversions,
classifications and fixed payload-free public messages. Legacy concrete APIs,
facade identity and CLI rendering/exits remain intact. Native/WASM public consumer
tests and CLI characterization cover these boundaries. Synchronous ports and
host/client wiring remain subsequent checkpoints.

Planning prototype for wayfinder #11. Records the decision: **`bitbid-core` owns
one typed error enum** built with `thiserror`, unifying the per-port errors. No
`anyhow` in core. Core never depends on `clap` or `leptos`; projections are
computed from a small `ErrorKind` plus a sanitized `public_message`. The real
split is not performed here; see
`prototype/split-core-skeleton/crates/bitbid-core/src/error.rs`.

## Enum shape

Per-port errors stay distinct and keep their current variants
(`StoreError`, `IpfsError`, `RpcError`). The umbrella enum unifies them via
`#[from]` and adds the pure-core failure classes:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)] Store(#[from] StoreError),
    #[error(transparent)] Ipfs(#[from] IpfsError),
    #[error(transparent)] Rpc(#[from] RpcError),
    #[error("wallet: {0}")]        Wallet(String),
    #[error("crypto: {0}")]        Crypto(String),
    #[error("config: {0}")]        Config(String),
    #[error("secret: {0}")]        Secret(String),
    #[error("not found: {0}")]     NotFound(String),
    #[error("invalid input: {0}")] Invalid(String),
    #[error("decode: {0}")]        Decode(String),
}
```

`ErrorKind` is a `Clone, Copy, Debug, PartialEq, Eq` classifier over the
classes `Store, Transport, Chain, Wallet, Crypto, Config, Secret, NotFound,
Invalid, Decode`:

| Variant | `ErrorKind` |
|---|---|
| `Store(_)` | `Store` |
| `Ipfs(_)` | `Transport` |
| `Rpc(_)` | `Chain` |
| `Wallet(_)` | `Wallet` |
| `Crypto(_)` | `Crypto` |
| `Config(_)` | `Config` |
| `Secret(_)` | `Secret` |
| `NotFound(_)` | `NotFound` |
| `Invalid(_)` | `Invalid` |
| `Decode(_)` | `Decode` |

`Error::kind(&self) -> ErrorKind` is the primary accessor; `From<&Error> for
ErrorKind` is provided as an ergonomic alias. `Error::public_message(&self) ->
String` is the only user-facing rendering. Because a short secret (a BIP-39
mnemonic, a password) is indistinguishable from ordinary text, the
secret-bearing classes are **payload-free by construction**: `Wallet`,
`Crypto`, `Config`, `Secret`, and `Invalid` never emit their `String`, only
`wallet: <redacted>` / `crypto: <redacted>` / `config: <redacted>` /
`secret error` / `invalid input: <redacted>`. The remaining operational
payloads (`Store`, `Ipfs`, `Rpc`, `NotFound`, `Decode`) are sanitized by
`public_message`: every absolute-path substring (`/…`, `\…`, `C:\…`, `\\…`)
is replaced with `<path>` wherever it occurs (its own token, after `=`, `:`,
or inside quotes/braces), and secret-looking tokens (≥32-char
alphanumeric/hex, or `0x` + ≥16 hex) with `<redacted>`. `Display`/`Debug`
remain for adapter-side logging only and MUST NOT be sent to a client.

A compile-time assertion fixes the SSR contract:
`const _: fn() = || { /* assert Error: Send + Sync + 'static */ };`.

## CLI projection — `ErrorKind -> i32` exit codes

The webapp/CLI owns this table; core exposes only `kind()`. It carries forward
the mapping in `bitsec/src/errors.rs::exit_code` against the new classes:

| Exit | Meaning | `ErrorKind` | Legacy equivalent |
|---|---|---|---|
| `0` | success | — | — |
| `2` | usage, parsed by `clap` **before** core runs; also wallet auth failures (wrong password) | `Wallet` | `InvalidPassword` |
| `3` | secret / not-found class | `Secret`, `NotFound` | `SecretExpired`, `SecretNotFound`, `PermissionDenied` |
| `4` | environment / storage / transport / chain / config / decode | `Store`, `Transport`, `Chain`, `Config`, `Decode` | `IoError`, `ParseError`, `ConfigError` |
| `5` | invalid caller input | `Invalid` | `InvalidMnemonic`, `InvalidRecipient` |
| `1` | generic fallback (incl. crypto) | `Crypto`, anything unmatched | `WalletNotFound`, `CryptoError`, `Generic` |

Reconciliation notes: legacy `WalletNotFound` returned `1`; in the new model a
missing wallet is `ErrorKind::NotFound` (→ `3`) for consistency with "requested
thing absent", while wrong-password stays `Wallet` (→ `2`). Legacy
`PermissionDenied` returned `3`; a store permission failure now surfaces as
`Store` (→ `4`) unless a use-case reclassifies it. `cargo check` is the
compile-time guarantee that no `clap` type reaches core.

## Web / SSR projection — `Error -> ServerFnError`

Core must not depend on `leptos`. The server function (owned by the webapp)
maps a core `Error` using `kind()` for coarse classification and
`public_message()` for the client-visible string — never `Display` of the raw
error:

```rust
// in the webapp crate, NOT in core
fn to_server_fn_error(e: bitbid_core::Error) -> ServerFnError {
    let msg = e.public_message(); // already sanitized
    match e.kind() {
        ErrorKind::NotFound  => ServerFnError::new(format!("not found: {msg}")),   // 404
        ErrorKind::Invalid   => ServerFnError::new(format!("invalid input: {msg}")), // 400
        ErrorKind::Secret    => ServerFnError::new(format!("forbidden: {msg}")),   // 403
        ErrorKind::Wallet    => ServerFnError::new(format!("unauthorized: {msg}")), // 401
        _                    => ServerFnError::new(format!("internal error: {msg}")), // 500
    }
}
```

## Boundary rules

- Errors that cross the server boundary must be `Send + Sync` (and `'static`);
  enforced by the compile-time assertion above.
- Messages that cross the boundary must be sanitized; use `public_message()`,
  never `Display`/`Debug`.
- Port errors remain distinct and unify through `#[from]`; adapters translate
  backend-specific failures into the port enums, and core never sees a
  `reqwest`/`libc` error type.
