# Shared-core verification

The native Cargo workspace contains `bitbid-cli` (binary `bsec`), `bitbid-core` and native `bitbid-adapters`. Commands without
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
| `bitbid-core/tests/ports_consumer.rs` | Public synchronous trait-object consumers; one exact registry RPC, all eleven facts, invalid IDs and malformed ABI/typed RPC failures; in-memory Store/IPFS and fixed clock/random contracts on native and executed WASM |
| `crates/bitbid-cli/tests/offline_token_tests.rs` | Real CLI invocation through shared protocol, stdin/file handling and failures without a wallet or backend |
| `webapp/crates/core` consumer tests | Public compatibility facade exports and shared type/crypto identity; run in the separate web workspace |
| Existing gated native chain tests | Anvil registry and IPFS adapter flows; CI's existing `e2e` job retains deployment and service readiness checks |

Existing native chain integration tests skip the live-chain path unless
`BSEC_E2E=1`. A passing offline workspace run does not establish live-chain
behavior. The gated CI job remains responsible for that path.

Checkpoint P adds a headless public operation without production CLI or browser
wiring. Its interface tests certify the in-memory adapters, not filesystem
permissions, real IPFS, HTTP transport or entropy. Registry numeric/bool values
retain native low-word semantics. CID pointers reject nonzero high bytes and
platform/range overflow; bounded unaligned and in-head offsets retain native
behavior. No clock-based expiry recomputation or other Host port access occurs.

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
graph. It rejects CLI-only runtime dependencies from the CLI and adapter manifests and
explicit native adapter packages such as `reqwest`, `tokio`, `dirs`, `rpassword`,
`tempfile`, `libc` and `clap`. These remain forbidden even if added directly to
the core manifest. It also rejects an empty/missing core graph. Dev dependencies and
host build/proc-macro requirements are outside this runtime rule. WASM compilation
is an additional check, since a package-name rule cannot classify every future
dependency's behavior. Keep filesystem, wallet, network and prompting adapters
in native/browser adapter crates when extending the split.

## Release and consumer checks

```sh
cargo build --locked --release -p bitbid-cli --bin bsec
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

## Native RPC and selected list read

Checkpoint A adds native-only `bitbid-adapters::rpc::BlockingRpc`. Public consumer
HTTP tests in `crates/bitbid-adapters/tests/rpc_read.rs` exercise real loopback
requests, JSON-RPC envelopes, typed failures, status/result compatibility and the
20-second timeout without retries. These tests always execute; no `BSEC_E2E` opt-in
is needed. Native transport dependencies and the public module are cfg-gated away
from WASM. Neither core nor the browser depends on adapters.

`crates/bitbid-cli/tests/registry_read_tests.rs` launches the actual CLI with an isolated wallet and
synthetic HTTP service via `crates/bitbid-cli/tests/support/registry_probe.py`. The probe takes an
explicit binary path, so release and installed binaries can use the same audit:

```sh
cargo test --locked -p bitbid-adapters --test rpc_read
cargo test --locked -p bitbid-cli --test registry_read_tests
cargo build --locked --release -p bitbid-cli --bin bsec
python3 crates/bitbid-cli/tests/support/registry_probe.py --binary target/release/bsec --report /tmp/bsec-registry-report.json
```

The probe imports a public synthetic mnemonic without encryption, closes stdin,
rejects methods other than `eth_call`, checks exact JSON/text, request order,
filters, per-record skips, missing wallet/index and unchanged wallet/config/index
bytes. Its owned ephemeral-port service shuts down and joins on exit. Use
`--baseline-mode` only against the captured pre-A binary: the old decoder panics
on overflowing offsets/lengths; the new typed core rejects them and continues.
`--compare <baseline-report.json>` compares ordinary outputs, exits, requests and
file effects, while requiring the accepted no-panic improvement for those cases.
No live provider, chain, IPFS or hosted CI behavior is established by this probe.

Only list crosses the shared read boundary. The legacy `list_secrets_on_chain`
wrapper remains for hide; get-info/view/materialize and all signing/write paths
remain unchanged. Private unused Host ports fail immediately on access, so this
composition cannot silently acquire filesystem, IPFS, time or entropy behavior.
No new deployment setting, wallet/index schema or CLI invocation is introduced.
Rollback only the selected list wiring and native adapter dependency; retain the
previous additive error/ports work. Full production browser interaction remains
the topology checkpoint's gate because this slice changes no browser code or UI.
