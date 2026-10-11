# Shared-core validation — 2026-10-11

Validated with the existing Rust 1.98.1 host and wasm32-unknown-unknown standard
libraries. Cargo caches, tools, builds, temporary test fixtures and logs remained
under BitSec/Desktop `.local`; global Rust settings were not changed.

- `cargo test --locked --workspace` (native): 131 reported successful cases;
  126 exercised offline behavior and five existing chain tests returned early
  with `BSEC_E2E=0`. No test failures or compiler warnings.
- `cargo test --locked -p bitbid-core --target wasm32-unknown-unknown`:
  24 executed WASM cases, zero failures, via wasm-bindgen-test-runner 0.2.126
  in Node. These include the exact independent Node/OpenSSL ciphertext/token
  vector, legacy browser format, legacy CLI JSON, random entropy, binary bodies,
  tamper/wrong-key rejection, bundle confidentiality and registry encoding.
- `cargo build --target wasm32-unknown-unknown -p bitbid-webapp` succeeded using
  the webapp lockfile (existing wasm-bindgen 0.2.129).
- `trunk --offline=true --skip-version-check build --locked=true --dist ...`
  succeeded; browser assets are in `.local/dist/webapp`. Source `webapp/dist`
  and `webapp/target` from the initial snapshot were preserved.
- WASM normal dependency tree contains no reqwest, dirs, tempfile, rpassword,
  clap or libc. Native adapters do not enter the browser build.
- Git whitespace checks passed. Both newly initialized repository ignore rules
  exclude environment credentials, private-key files, wallets and build outputs.

The optional interactive Chrome smoke test could not run: browser automation
surfaces were unavailable and native Computer Use waited on Accessibility/Screen
Recording permissions. Browser compilation/bundling and actual WASM execution
are verified; interactive form behavior has not been verified.

The CLI token integration tests use synthetic public test keys, no wallet store
and no backend. Live chain/IPFS integration, transactions, funding, deployment,
remote creation and pushes were not performed. This validates the first core
extraction and compatibility boundary, not the deferred full adapter/SSR split.

Local evidence logs: `.local/logs/native-tests.log`, `wasm-tests.log`,
`trunk-build.log`, `core-wasm-dependencies.log`. The canonical frozen vector is
committed at `crates/bitbid-core/tests/vectors/ipfs-v1.json`.
