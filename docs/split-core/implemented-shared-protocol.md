# Shared protocol implementation — 2026-10-11

## Reconciliation with the existing plans

The earlier topology/module/SSR documents describe a future full split and a
Leptos server with per-request key unlock. The implemented console is Yew CSR:
keys and cryptography run locally in browser WASM. This change retains that
platform and does not implement the deferred SSR key custody model.

One source library, `crates/bitbid-core`, compiles into the native `bsec` binary
and browser WASM. A browser cannot execute the native binary. `webapp` consumes
this library via a sibling path dependency and a thin compatibility namespace.
The static `web` landing page is a separate repository and has no crypto runtime.

This is the first bounded extraction: payload types, the established CLI crypto
suite, versioned token serialization, hex/EIP-55 helpers and registry codecs.
The CLI package/binary and native wallet, filesystem, process, IPFS, signing and
RPC orchestration retain their existing layout. The prototype remains a separate
workspace. The full virtual workspace, adapter crates, application rename and
SSR port/error model are future work.

## Payload protocol v1 and browser transport v2

The former web-only `bitbid1:` format uses a different HKDF label and wraps raw
content-key bytes. It never interoperated with CLI payloads. Its reader remains
available to both consumers; production code no longer writes that format.

New `bitbid2:` strings are standard padded base64 of exactly the bytes returned
by `protocol::canonical_bytes`. Those bytes are also the IPFS upload body used
by native `share`. Canonical JSON for this schema uses UTF-8, no whitespace,
fixed field order and no trailing newline:

1. `protocol_version` (integer `1`)
2. `content`, `content_key`, `ephemeral_pubkey`
3. `kind`, `filename`, `no_export`, `members`, `content_encoding`, when present
   (false `no_export` is omitted)

Members retain the original field order: kind, filename, content, encoding,
optional env. This is a schema-specific encoding, not a general JSON
canonicalization standard. Readers accept legacy CLI JSON with no version as v1,
reject explicitly unknown versions, and accept reordered/whitespace JSON while
writers always emit canonical bytes. Adding versions/fields must preserve the
frozen v1 vectors or introduce a new protocol version. New versioned JSON is
also readable by the former CLI's serde payload reader, which ignores the new
version field.

Encryption retains the established suite: secp256k1 ECDH, HKDF-SHA256 with
`bsec-ecdh-aes256gcm-v1`, AES-256-GCM with 12-byte nonces. Cipher fields remain
`base64(nonce):base64(ciphertext || tag)`. The wrapped plaintext is the standard
base64 string of the random 32-byte content key, matching the old CLI. Ephemeral
public keys use uncompressed SEC1 with lowercase `0x` hex. UTF-8 single bodies
retain their CLI representation; arbitrary bytes use base64 content encoding.
Bundle members are individually encrypted before storage. Public mode retains
the existing well-known wrapper key and requires an explicit host policy flag.

Fresh production entropy comes from the OS or browser `crypto.getRandomValues`
through getrandom. Equal plaintext does not imply equal ciphertext or equal CIDs.
The independent Node/OpenSSL test vector uses synthetic scalars 1/2, key `42`
and nonces `01`/`02` only in tests. No fixed-material API is public.

## Blockchain linkage and limits

The registry links `(chain, registry contract, secret bytes32 ID)` to an IPFS
CID and lifecycle metadata. `share` uploads the canonical encrypted payload,
then registers the existing randomly generated full 256-bit ID. The token
contains the payload; it is not an on-chain record and does not claim chain,
contract, CID or transaction provenance. ID encoding is now shared by the
native registry adapter and browser calldata decoder and rejects truncation.
Creating an offline token does not upload/register it or spend funds.

Expiry, revocation and read counts remain registry lifecycle signals. Offline
unseal neither verifies those signals nor records a read; an already-held
ciphertext remains decryptable with the recipient key. Existing metadata fields
are not additional authenticated data under the legacy suite. The browser
registry/revoke panels retain their current read-only behavior. No transactions,
real wallets, accounts, contract deployments or network configuration were used
in validation.

## Validation and local development

The frozen fixture is `crates/bitbid-core/tests/vectors/ipfs-v1.json`, generated
independently with Node/OpenSSL. Core native/WASM tests recompute exact bytes,
open the fixture, reject wrong keys/tampering/unsupported versions/malformed
nonces and oversized ABI offsets, exercise fresh production entropy, and retain
legacy browser and CLI compatibility. Native command tests drive the actual
binary without a wallet or backend.

Use rustup-managed Cargo. The browser retains its Rust `1.98.1` pin and
`wasm32-unknown-unknown` target; the same compiler was used for validation.
Set `CARGO_HOME`, `CARGO_TARGET_DIR`, `TMPDIR` and `XDG_CACHE_HOME` under the
BitSec Desktop `.local` directory when following this workspace's cache policy.
Do not replace HOME or global Rust configuration. The host std and WASM std
were already installed; no global toolchain was installed or changed.

```sh
cd bitsec
cargo test -p bitbid-core
cargo test --locked -p bitbid-cli --test offline_token_tests
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p bitbid-core --target wasm32-unknown-unknown
cd ../webapp
cargo build --locked --target wasm32-unknown-unknown -p bitbid-webapp
```

The wasm-bindgen CLI/test runner must match the version in the relevant lockfile.
Keep downloads/build outputs and local test logs in `.local`, outside commits.
