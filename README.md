# Bitbid browser console

Yew client-side console with local seal/unseal and read-only registry exploration.
The Rust crypto/protocol implementation is shared with the native CLI through
`../bitsec/crates/bitbid-core`. Check out `webapp` and `bitsec` as siblings under
BitSec before building; this repository is not standalone without that core.

The origin is `git@github.com:igmrrf/bitbid.git`. This independent history is
on `webapp/main`; the sibling native checkout uses `main` on the same origin.

Use rustup-managed Cargo; `rust-toolchain.toml` pins Rust 1.98.1 and the WASM
standard library target. The Cargo config has no workstation-specific paths.

```sh
cargo test --locked -p bitbid-webapp-core
cargo build --locked --release --target wasm32-unknown-unknown -p bitbid-webapp
trunk build --release --locked --dist ../.local/dist/webapp
trunk serve --address 127.0.0.1
```

Keep Cargo/tool caches, temporary files and Trunk outputs under the Desktop
workspace's `.local` directory using CARGO_HOME, CARGO_TARGET_DIR, TMPDIR and
XDG_CACHE_HOME. Existing target/dist files are local outputs and ignored.

Seal produces `bitbid2:` tokens compatible with `bitbid seal` / `bitbid unseal`.
Unseal also reads old `bitbid1:` browser strings and CLI IPFS JSON. The browser
only displays single bodies; bundle materialization remains in the CLI. Wallet
connection only requests the injected wallet's public address; registry/revoke
panels do not submit transactions. Offline unseal does not record a chain read.

See [shared protocol and architecture](../bitsec/docs/split-core/implemented-shared-protocol.md)
for the format, compatibility vectors, chain linkage and deferred SSR plan.

`bitbid-webapp-core` remains a thin compatibility facade: `address` and
`registry` reexport the shared modules, `seal` reexports the shared token API,
and `protocol` exposes the shared payload schema and canonical encoding. Existing
`RegistryRecord`, `DecodeError`, and `TokenError` imports keep their shared type
identity. The facade contains no separate crypto or ABI implementation. Its
external-consumer tests cover type identity, native/browser token exchange,
legacy readers, and invalid input. See the
[facade contract](../bitsec/docs/split-core/web-core-consolidation.md) and
[verification ownership](../bitsec/docs/split-core/verification-strategy.md).
