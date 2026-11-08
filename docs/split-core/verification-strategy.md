# Shared-core verification

The native Cargo workspace contains `bsec` and `bitbid-core`. Commands without
`--workspace` at this root can omit the core's own tests, so native lint, tests
and coverage explicitly select the workspace. CI enforces strict Clippy rather
than a formatting gate. Run from the native repository root:

```sh
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo llvm-cov --locked --workspace --all-features --lcov --output-path lcov.info --summary-only
```

Coverage requires `cargo-llvm-cov` and the `llvm-tools-preview` Rust component.
CI uploads the workspace LCOV report; there is no percentage threshold. Use
coverage to find missing error branches and retain assertions on the protocol's
actual bytes and failure behavior.

## Test ownership and boundaries

| Owner | Evidence |
| --- | --- |
| `bitbid-core` unit tests | Address derivation, crypto, canonical protocol, legacy token readers, registry codecs and malformed inputs |
| `bitbid-core/tests/compatibility.rs` | Frozen independent vector, canonical and legacy interoperability, binary/production-entropy round trip, public/private payload semantics and invalid input |
| `bitbid-core/tests/protocol_contract.rs` | Frozen canonical field order, legacy CLI/web readers, discriminator validation, unknown versions and malformed authenticated payloads |
| `bsec/tests/offline_token_tests.rs` | Real CLI invocation through shared protocol, stdin/file handling and failures without a wallet or backend |
| `webapp/crates/core` consumer tests | Public compatibility facade exports and shared type/crypto identity; run in the separate web workspace |
| Existing gated native chain tests | Anvil registry and IPFS adapter flows; CI's existing `e2e` job retains deployment and service readiness checks |

Native adapter integration tests normally skip the live-chain path unless
`BSEC_E2E=1`. A passing offline workspace run does not establish live-chain
behavior. The gated CI job remains responsible for that path.

## Executed WASM tests

Building WASM alone cannot prove browser-compatible crypto and entropy work.
CI builds `bitbid-core` for `wasm32-unknown-unknown` and executes its unit and
compatibility suites through `wasm-bindgen-test-runner` under Node 22. The test
functions use `wasm_bindgen_test` on WASM and native `test` elsewhere.

```sh
rustup target add wasm32-unknown-unknown
python3 scripts/check-core-boundary.py
cargo build --locked -p bitbid-core --target wasm32-unknown-unknown
# Python 3.11+ for tomllib. Install the CLI matching Cargo.lock, not latest.
VERSION=$(python3 -c 'import tomllib; lock = tomllib.load(open("Cargo.lock", "rb")); versions = {p["version"] for p in lock["package"] if p["name"] == "wasm-bindgen"}; assert len(versions) == 1, versions; print(versions.pop())')
cargo install wasm-bindgen-cli --version "$VERSION" --locked
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test --locked -p bitbid-core --target wasm32-unknown-unknown
```

The lockfile currently selects bindgen `0.2.126`. CI derives this version on
every run so a dependency update also updates the runner. A runner mismatch
fails instead of silently substituting an incompatible tool. The separate web
workspace can resolve a different bindgen version and needs its own matching
runner. Node execution covers shared WASM behavior; the real Yew CSR application
still needs a browser smoke test after a web release build.

`scripts/check-core-boundary.py` examines only the core's normal WASM dependency
graph. It rejects CLI-only runtime dependencies from the root manifest and
explicit native adapter packages such as `reqwest`, `tokio`, `dirs`, `rpassword`,
`tempfile`, `libc` and `clap`. These remain forbidden even if added directly to
the core manifest. It also rejects an empty/missing core graph. Dev dependencies and
host build/proc-macro requirements are outside this runtime rule. WASM compilation
is an additional check, since a package-name rule cannot classify every future
dependency's behavior. Keep filesystem, wallet, network and prompting adapters
in native/browser adapter crates when extending the split.

## Release and consumer checks

```sh
cargo build --locked --release -p bsec
target/release/bsec --help
# In the separate ../webapp repository, using its pinned toolchain:
cargo test --locked -p bitbid-webapp-core
cargo build --locked --release --target wasm32-unknown-unknown -p bitbid-webapp
trunk build --release
```

Smoke the built CLI with an isolated temporary `BSEC_HOME` and public synthetic
keys from `crates/bitbid-core/tests/vectors/ipfs-v1.json`: seal stdin, unseal to
identical bytes, open the frozen token, and assert nonzero exits with empty
stdout for a wrong/malformed key and malformed token. No wallet/backend should
be initialized. Serve the production web bundle on loopback and exercise new
seal/unseal, legacy token open and malformed-input errors in a real browser;
inspect console/network and desktop/narrow screenshots. Do not use real secrets.

Validate CI with `actionlint .github/workflows/ci.yml` and run the commands
locally. Hosted CI results require an actual GitHub run; local evidence does not
claim one. The local delivery boundary includes binaries, bundles and checks,
with no publishing, chain transactions or production changes. Full browser
adapter/SSR extraction and rollout remain deferred; the shipped app is Yew CSR.
