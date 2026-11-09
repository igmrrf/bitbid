# Canonical secret format contract

The shared owner is `crates/bitbid-core`: `protocol` defines payload types and
wire encoding, `crypto` retains the CLI cipher suite, and `token` provides the
offline native/browser boundary. This freezes the existing implementation;
it does not replace valid historical bytes or introduce a new cipher suite.

## Version and transport

Payload protocol version is integer `1`. Production writers emit compact UTF-8
JSON through `protocol::canonical_bytes`, without a BOM, whitespace between
fields, or a trailing newline. JSON string escapes follow `serde_json`; Unicode
is UTF-8, quotes/backslashes/control characters are escaped. This is a fixed
schema encoding, not a general JSON canonicalization standard.

Native IPFS uploads use those bytes directly. New offline/browser shares are
`bitbid2:` followed by standard RFC 4648 padded base64 of the same bytes. The
transport suffix `2` distinguishes this representation from the historical
browser envelope; it does not mean payload protocol version `2`.

| Position | Field | Canonical representation |
| --- | --- | --- |
| 1 | `protocol_version` | Always integer `1` |
| 2 | `content` | Always a string |
| 3 | `content_key` | Always a string |
| 4 | `ephemeral_pubkey` | String when present; otherwise explicit `null` |
| 5 | `kind` | Optional lowercase `env`, `pem`, `json`, or `cred`; omitted when absent |
| 6 | `filename` | Optional string; omitted when absent |
| 7 | `no_export` | Boolean `true` when set; omitted when false |
| 8 | `members` | Optional array in caller order; omitted when absent; `[]` remains present |
| 9 | `content_encoding` | Optional string; omitted when absent |

Each member has fixed field order `kind`, `filename`, `content`, `encoding`,
then optional `env`. The first four fields always serialize; `env` is omitted
when absent. Missing member `encoding` on read defaults to `"utf8"`, so it is
included on reserialization. Missing optional payload fields default to absent,
and missing `no_export` defaults to false. Empty strings and empty arrays are
not normalized away. The minimum canonical payload is exactly:

```json
{"protocol_version":1,"content":"","content_key":"","ephemeral_pubkey":null}
```

## Compatibility and validation

Readers accept raw CLI JSON and `bitbid2:` shares, trimming surrounding text
whitespace. Missing `protocol_version` means historical CLI v1, including when
that JSON is carried in `bitbid2:`. Readers accept reordered JSON, insignificant
JSON whitespace, unknown fields, absent optional fields, and `null` for optional
fields. Canonical reserialization drops unknown fields. Existing valid legacy
inputs remain readable; canonical output always includes version `1`.

An explicit integer version other than `1` is rejected. Invalid JSON, duplicate
known fields, missing required `content`/`content_key`, invalid field types,
unknown `kind`, trailing non-whitespace, malformed base64 and unknown transport
prefixes are rejected. Version values outside the `u8` domain or of a different
JSON type fail JSON decoding. The wire limit is 32 MiB (33,554,432 bytes), measured
after JSON serialization or base64 decoding. Readers also reject an encoded body
longer than `4 * ceil(limit / 3)` before decoding it. This is a wire size bound,
not a streaming allocator budget.

Protocol decoding validates the schema; cryptographic validation happens at
open. It does not validate ciphertexts, SEC1 points, filenames or content encoding
policy during JSON parsing. `token::unseal` requires private mode, rejects bundle
payloads, and returns plaintext bytes only after authenticated decryption.
Absent/`"utf8"` content encoding returns UTF-8 bytes; `"base64"` decodes arbitrary
bytes. Unsupported encodings, invalid keys, malformed ciphers, wrong recipients
and authentication failures return errors. Bundle materialization and explicit
public-mode policy belong to their existing host interfaces.

The historical `bitbid1:` browser envelope remains readable through the unified
`token::unseal` API and `legacy_seal`. Its binary version remains `1`, with
big-endian lengths: version byte, u16 recipient-id length and UTF-8 id, u8 SEC1
key length and key, 12-byte wrap nonce, u16 wrapped-key length and wrapped bytes,
12-byte payload nonce, then payload ciphertext including tag. It uses the label
`bitbid-webapp-ecdh-aes256gcm-v1` and wraps raw content-key bytes. Production
sealing APIs emit `bitbid2:`; the old deterministic writer exists only in tests.
The compatibility envelope serializer remains available for historical data.

## Cryptography and evolution

CLI v1 retains secp256k1 ECDH, HKDF-SHA256 with no salt and info
`bsec-ecdh-aes256gcm-v1`, and AES-256-GCM with independent random 12-byte nonces.
Cipher strings are `base64(nonce):base64(ciphertext || 16-byte tag)`. The wrapped
plaintext is the base64 string of a random 32-byte content key. Writers emit
uncompressed SEC1 ephemeral keys as lowercase `0x` hex. Bundle member content
is encrypted under the content key. Metadata is not authenticated as additional
data in this inherited suite; the version/transport contract does not add such
authentication. Offline tokens carry neither registry provenance nor enforced
expiry/revocation/read-count policy.

Preserve these bytes and accepted legacy inputs when maintaining v1. Any change
to canonical field order, omission rules, cipher framing, derivation or semantic
interpretation requires an explicit compatibility/version decision. Do not
silently reinterpret v1 or write the historical web envelope again. The actual
browser remains Yew CSR; full adapter extraction and an SSR migration are deferred.
This delivery creates local artifacts only and publishes nothing.

## Executable contract

`crates/bitbid-core/tests/vectors/ipfs-v1.json` is the independent Node/OpenSSL
encrypted fixture. Native and executed WASM tests compare its exact canonical
bytes and transport, decrypt it, and exercise fresh production entropy.
`tests/protocol_contract.rs` freezes literal full optional/member metadata,
omission/default/escaping rules, rejected versions and malformed inputs, size
guards, and unified historical browser reads including every truncation.
Native `tests/offline_token_tests.rs` drives the built CLI with synthetic keys,
stdin, canonical/legacy input, and failure exit/stdout/stderr checks without a
wallet or backend.

```sh
cargo test --locked -p bitbid-core
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --locked -p bitbid-core --target wasm32-unknown-unknown
cargo test --locked -p bitbid-cli --test offline_token_tests
```

Match the WASM runner to the lockfile's wasm-bindgen version. See
[verification strategy](verification-strategy.md) for workspace gates and
[implemented shared protocol](implemented-shared-protocol.md) for integration
boundaries and registry limitations.
