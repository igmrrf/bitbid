# Browser compatibility facade

`webapp/crates/core` retains the `bitbid-webapp-core` package and
`bitbid_webapp_core` Rust namespace. The Yew CSR application continues to use it.
The package has one normal dependency, `bitbid-core`, at
`../bitsec/crates/bitbid-core` relative to the web repository. Check out both
repositories as siblings before building.

The facade delegates directly to the shared library:

| Browser API | Shared owner |
| --- | --- |
| `address::*` | `bitbid_core::address::*` |
| `registry::*` | `bitbid_core::registry::*` |
| `seal::*` | `bitbid_core::token::*` |
| `protocol::*` | `bitbid_core::protocol::*` |
| root `RegistryRecord`, `DecodeError`, `TokenError` | Shared registry/token types |

These exports preserve type identity; they introduce no conversion, duplicate
crypto, ABI decoder, wire schema, or second protocol writer. The compatibility
namespace lets existing app imports remain stable while native and browser
consumers use the same implementation. Transport, wallet access, UI state, and
rendering remain in the application crate. A full adapter/SSR split and changes
to the Yew CSR architecture are deferred.

New `seal::seal_to_share_string` output is `bitbid2:` with the canonical CLI v1
payload. `seal::unseal` reads that output, raw legacy CLI JSON without a version,
and historical browser `bitbid1:` strings. Browser single-body unseal rejects
bundles with `TokenError::Bundle`; file materialization remains a CLI concern.
Binary bodies use the shared content encoding; `unseal_to_string` additionally
requires UTF-8. The canonical format contract is documented in
[canonical-format.md](canonical-format.md).

## Verification ownership

The shared library owns primitive, canonical-byte, and native/WASM protocol
tests. The facade's `tests/public_consumer.rs` uses external public APIs to prove
shared type identity, address and registry behavior, native/browser sealing in
both directions, binary and UTF-8 handling, frozen encrypted payload opening,
legacy CLI/browser reads, wrong-key/tamper rejection, unsupported versions, and
bundle/encoding errors. Its encrypted CLI fixture is copied from the independent
Node/OpenSSL vector in `bitbid-core/tests/vectors/ipfs-v1.json`; its browser
literal is the historical fixed `bitbid1:` vector. Tests never regenerate those
frozen fixtures or use real keys.

From `webapp`, with the pinned Rust toolchain and matching wasm-bindgen CLI:

```sh
cargo test --locked -p bitbid-webapp-core
cargo clippy --locked -p bitbid-webapp-core --all-targets -- -D warnings
cargo build --locked --release --target wasm32-unknown-unknown -p bitbid-webapp
trunk build --release --locked --dist ../.local/dist/webapp
```

The consumer integration tests run natively. The release WASM build verifies
that the actual Yew consumer compiles with the same facade. Executed headless
WASM tests belong to the shared library, as described in
[verification-strategy.md](verification-strategy.md). A browser smoke of the
production bundle must additionally open a frozen/legacy token, seal and reopen
synthetic input, reject malformed input, and inspect console/network behavior.
Compilation alone does not establish that browser journey.

Builds and smoke results are local artifacts. This consolidation does not
publish either crate, deploy the site, send transactions, or change wallet/RPC
behavior. A rollback consists of reverting only the task-owned source/docs
changes and rebuilding the local bundle.
