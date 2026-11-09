# Incremental migration and rollout

Status: accepted decision for [#14](https://github.com/igmrrf/clienv/issues/14), 2026-11-08. This records the next implementation checkpoints; it does not claim their code is shipped.

Keep the shipped shared protocol and Yew CSR consumer working while adding a typed error layer, synchronous ports, one native registry-read adapter, then the production Cargo layout. Serialize these checkpoints because their public types, CLI wiring and package paths depend on one another. A wholesale module move would mix compatibility changes with transport and packaging failures.

## Current truth and precedence

The native repository is `bitsec/` (baseline `c0689b2292495b2598b5a00f0e207bfe8284b5df`); `webapp/` is a separate Git repository (baseline `2eafb1b1e26efa6ef364f36f76490c65b7a4ecc2`). Each retains its own Cargo.lock. The parent folder is coordination only, and its handoff.md remains uncommitted.

[Map #3](https://github.com/igmrrf/clienv/issues/3) and the [partition](module-partition.md), [topology](workspace-topology.md), [error](error-model.md) and skeleton documents describe historical planning. Their plan-only limit does not prevent this explicitly requested implementation queue, but closed decisions do not establish shipped implementations. Where those plans conflict, this rollout governs the next four checkpoints:

- `crates/bitbid-core` already owns shared protocol, crypto, address, registry and token codecs. Extend it; do not replace it with the skeleton.
- The real browser product is Yew CSR through `bitbid-webapp-core`, not Leptos SSR/hydrate. Keep its public exports and type identity. No server functions, SSR features or UI migration are needed.
- Preserve package/binary `bsec` through the adapter checkpoint. The topology checkpoint changes the package to `bitbid-cli`, with explicit binary `bsec`; the later rename decision owns any `bitbid` invocation or alias.
- Keep [canonical CLI v1 bytes and legacy readers](canonical-format.md), `bitbid2:`, `bitbid1:`, browser facade imports and the deployed BsecSecretRegistry contract unchanged.
- This sequence finishes the dependency shape, not all 14 proposed domain moves. Wallet storage, IPFS, signing, transaction writes, process/staging and the remaining CLI orchestration stay in the CLI until individually scoped later tickets.

No runtime configuration, wallet/index schema, contract, token format or persistent data migration is introduced. No publication, deployment, automatic network probe or rename is implied.

## Four buildable checkpoints and ownership

| Checkpoint | Owns | Depends on | Independent completion gate |
| --- | --- | --- | --- |
| E: additive errors (queue 2; basis [#11](https://github.com/igmrrf/clienv/issues/11)) | core `src/error.rs`, export in `src/lib.rs`, public error tests; native `src/errors.rs` compatibility projection/tests; facade public consumer tests | this decision | Existing concrete error APIs compile unchanged; new classifications/messages pass native/WASM public-consumer tests; legacy CLI exits/stdout are characterized and unchanged |
| P: synchronous ports and one headless read (queue 3; basis [#7](https://github.com/igmrrf/clienv/issues/7), [#9](https://github.com/igmrrf/clienv/issues/9)) | core `src/ports.rs`, `src/registry_read.rs`, exports and external port tests; narrowly required core Cargo.toml/lock test dependencies | E | Public Host consumer performs a deterministic registry read on native and executed WASM with in-memory adapters and negative cases; no OS/network dependency |
| A: native RPC adapter and list wiring (queue 4) | new `crates/bitbid-adapters/{Cargo.toml,src/lib.rs,src/rpc.rs,tests/rpc_read.rs}`; native manifest/lock; narrow `src/main.rs`, `src/blockchain.rs`, `src/eth.rs` composition/wrappers; `tests/registry_read_tests.rs` | P and E | Built `bsec list --json --all` crosses the public read seam against loopback synthetic RPC; success and failure behavior match pre-extraction characterization |
| T: production topology (queue 5; basis [#8](https://github.com/igmrrf/clienv/issues/8)) | native manifests/lock, mechanical CLI source/test moves, package lookups/CI/docs; web facade manifest/lock/path documentation if affected | A | Virtual workspace, release CLI invocation, executed WASM, facade consumers, dependency guard and production Yew browser journey all pass from final layout |

Each ticket owns its tests and independent review. Only the orchestrator assigns issue IDs and updates tracker dependencies after reviewed issue bodies exist. Run E → P → A → T serially; do not parallelize shared exports, errors, Cargo manifests or crate moves. Any newly discovered domain extraction becomes another issue, not an extension of these gates.

## Additive error interface frozen for E

Add `bitbid_core::error` and re-export `Error`, `ErrorKind`, `StoreError`, `IpfsError`, `RpcError` from the crate root. No `anyhow`, clap, Yew or Leptos types enter core.

Keep every existing `ProtocolError`, `CryptoError`, `TokenError`, `legacy_seal::SealError`, `registry::DecodeError` path, variant, concrete function return type, Display behavior and facade identity. Add owned `From<T> for Error` conversions; do not change old functions to return the umbrella error. Native `BsecError` remains native; its classification uses `From<&BsecError> for bitbid_core::ErrorKind` in the CLI's errors module, never a core dependency on the CLI.

The umbrella is the historical variants `Store(StoreError), Ipfs(IpfsError), Rpc(RpcError)` with `#[from]`, plus `Wallet(String), Crypto(String), Config(String), Secret(String), NotFound(String), Invalid(String), Decode(String)`. The new per-port variants are fixed as follows:

| Type | Variants, all carrying String |
| --- | --- |
| StoreError | NotFound, PermissionDenied, AlreadyExists, Io |
| IpfsError | InvalidCid, Request, Decode |
| RpcError | Request, Provider, Decode |

`ErrorKind` derives Clone, Copy, Debug, PartialEq, Eq and has exactly `Store, Transport, Chain, Wallet, Crypto, Config, Secret, NotFound, Invalid, Decode`. `Error::kind(&self) -> ErrorKind`, `From<&Error> for ErrorKind`, and `Error::public_message(&self) -> String` are stable. Error and all ports/Host must satisfy Send + Sync + 'static.

| Source | New classification |
| --- | --- |
| Error::Store / Ipfs / Rpc | Store / Transport / Chain respectively (all port variants) |
| Other umbrella variant | Same-named ErrorKind |
| ProtocolError (all variants) | Decode |
| CryptoError (all variants) | Crypto |
| TokenError::Crypto / Protocol | Recursively the wrapped conversion |
| TokenError::Legacy / Bundle / Encoding | Decode / Invalid / Decode |
| SealError::BadRecipientKey / BadRecipientSecret | Invalid |
| SealError::DecryptFailed / Random | Crypto |
| Other SealError variants | Decode |
| registry::DecodeError::Rpc | Chain, via RpcError::Provider |
| Other registry::DecodeError variants | Decode |
| Native InvalidPassword / WalletNotFound | Wallet / NotFound |
| Native SecretNotFound / SecretExpired / PermissionDenied | NotFound / Secret / Secret |
| Native InvalidMnemonic / InvalidRecipient | Invalid |
| Native IoError / ParseError / ConfigError | Store / Decode / Config |
| Native CryptoError / Generic | Crypto / Secret |

The conversion stores diagnostic text in the appropriate umbrella payload (or per-port wrapper); classification never inspects strings. This is an additive taxonomy, not an exit-code migration. In particular WalletNotFound stays exit 1 and native PermissionDenied stays exit 3 despite their new classifications. Preserve `BsecError::exit_code` and `main::handle_cli_error` fallback precedence exactly: password/corrupted → 2; not found/expired/permission → 3; io/parse/config/file → 4; mnemonic/recipient → 5; fallback → 1. Clap usage stays 2. Preserve existing command-specific stdout/stderr and exits, including the list behavior below. Do not derive legacy exits from ErrorKind.

All new public messages are constant and payload-free, including operational errors. By ErrorKind in table order: `storage operation failed`, `IPFS operation failed`, `RPC operation failed`, `wallet operation failed`, `cryptographic operation failed`, `configuration error`, `secret operation failed`, `not found`, `invalid input`, `decode failed`. This supersedes prototype heuristic redaction: short passwords, mnemonic words and provider bodies cannot reliably be identified by pattern matching. New host/client projections use public_message, never raw Display/Debug; legacy CLI rendering is retained for compatibility and is not being certified as sanitized. Add no SSR projection. The Yew facade keeps its current exports; optional new root exports are unnecessary for E.

## Synchronous public ports frozen for P

Put these public types in `ports` and re-export them at the core root. Use `std::sync::Arc`, `std::time::Duration` and `serde_json::Value`. All traits are object-safe, synchronous and Send + Sync. No async_trait, runtime, executor, environment reads, process calls, paths or terminal output.

```rust
pub enum StoreKey { Wallet, NetworkConfig, SecretIndex, ProjectConfig, IpfsCache(String) }
pub struct WriteOpts { pub private: bool, pub create_new: bool }
pub trait Store: Send + Sync {
    fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError>;
    fn write(&self, key: &StoreKey, bytes: &[u8], opts: WriteOpts) -> Result<(), StoreError>;
    fn exists(&self, key: &StoreKey) -> Result<bool, StoreError>;
    fn remove(&self, key: &StoreKey) -> Result<(), StoreError>;
}
pub trait Ipfs: Send + Sync {
    fn add(&self, bytes: &[u8], name: &str) -> Result<String, IpfsError>;
    fn cat(&self, cid: &str) -> Result<Vec<u8>, IpfsError>;
}
pub trait Rpc: Send + Sync {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}
pub trait Clock: Send + Sync {
    fn now_unix(&self) -> i64;
    fn sleep(&self, duration: Duration);
}
pub trait RandomSource: Send + Sync {
    fn fill_bytes(&self, dest: &mut [u8]);
    fn gen_key(&self) -> k256::SecretKey;
}
#[derive(Clone)]
pub struct Host {
    pub store: Arc<dyn Store>, pub ipfs: Arc<dyn Ipfs>, pub rpc: Arc<dyn Rpc>,
    pub clock: Arc<dyn Clock>, pub random: Arc<dyn RandomSource>,
}
```

StoreKey derives Debug, Clone, PartialEq, Eq, Hash; WriteOpts derives Debug, Clone, Copy, Default. Store read returns None for absence, exists agrees with read, remove of absence succeeds, create_new rejects overwriting with AlreadyExists, and private requests private native storage semantics when a native Store is eventually implemented. Ipfs add returns a CID; cat returns bytes; authentication/configuration live in implementations. Rpc returns the JSON-RPC `result` value, not the envelope; transport failures are Request, any present provider `error` member (including null, preserving current native behavior) is Provider, invalid response JSON is Decode, and a missing result is Value::Null. No retries are introduced. Clock/random are infallible like the decision prototype; future production implementations must supply valid entropy/key material or follow their fail-stop policy. This read checkpoint never consumes clock/random. No native Store/IPFS/entropy implementation is promised here.

The representative domain operation is:

```rust
pub fn read_registry_info(host: &Host, registry: &[u8; 20], secret_id: &str)
    -> Result<RegistryInfo, Error>;
```

Expose it and RegistryInfo from `bitbid_core::registry_read`. RegistryInfo derives Debug, Clone, PartialEq, Eq and has public fields `sender: [u8;20], recipient: [u8;20], ipfs_cid: String, created_at: u64, expires_at: u64, max_reads: u32, read_count: u32, revoked: bool, is_public: bool, is_expired: bool, limit_reached: bool`. It deliberately retains all contract tuple fields; current RegistryRecord drops the last two flags and cannot replace this interface.

Validate/encode secret_id using current `registry::encode_bytes32` (map invalid ID to Error::Invalid at this caller-input seam). Send exactly one Rpc::call("eth_call", [{"to": lower-case 0x address, "data": 0x selector+bytes32}, "latest"]). The existing address::bytes_to_hex returns a 0x-prefixed string; do not double-prefix. Decode the result's hex string and the eleven-word native tuple into RegistryInfo; no local expiry recomputation. Preserve the native decoder's valid tuple semantics (nonzero bool words, low u64/u32 numeric words, sender/recipient bytes, dynamic UTF-8 CID) and characterize unusual high-word/offset inputs before moving its behavior. Use checked ranges/addition so malformed inputs return Decode rather than panic. Empty/short data, non-string/null results, malformed hex, invalid UTF-8 or out-of-range offsets are Decode; RpcError remains wrapped as Error::Rpc. Do not convert a transport error or empty return into a fabricated record/NotFound. Existing public registry decoders and errors remain unchanged.

Only Rpc is called by this operation; Store, Ipfs, Clock and RandomSource implementations that panic on access prove the negative guarantee. The in-memory Rpc validates the entire request and returns a fixed ABI fixture. Separate in-memory port contract tests exercise Store/WriteOpts and IPFS data/failure semantics and fixed clock/random output. This creates a real seam with two implementations (in-memory now, native HTTP next), with modest scope.

## Real CLI flow and compatibility observations for A

There is no registry `bsec info` command: `Info` belongs to `wallet info`, which does not read the registry. Choose `bsec list --json --all`. Source trace at the baseline:

1. `src/main.rs::main` List arm (871–912) parses flags, `get_password_or_prompt`, then `wallet::get_wallet_info`; it calls `secrets::list_secrets`.
2. `src/secrets.rs::list_secrets` (279–306) calls `blockchain::list_secrets_on_chain`, then builds SecretRecord values with fixed encrypted-content/key placeholders, ephemeral_pubkey None, hidden false.
3. `src/blockchain.rs::list_secrets_on_chain` (225–274) enumerates a BTreeMap from `secret_index.json`, calls `get_secret_info_on_chain` for each ID, skips failed reads, and applies hidden/user/expired/active filters. Expired includes the returned is_expired, limit_reached or revoked flags.
4. `get_secret_info_on_chain` (158–192) loads network-config.json, parses registry address, encodes the ID, performs `eth::eth_call`, decodes the eleven-word ABI, formats EIP-55 addresses (recipient "public" when public), and overlays local hidden from the index.
5. `src/eth.rs::eth_call` (302–307) calls `rpc` with eth_call and latest. `rpc` (32–46) POSTs JSON-RPC 2.0/id 1 to conf.rpc_url using blocking reqwest and a 20-second timeout. It parses JSON without HTTP status rejection, treats any error member as a provider failure, and substitutes Null for missing result.
6. `load_network_config` falls back to defaults on absent/unreadable/malformed JSON; `load_index` falls back to empty on read/JSON errors. Both paths use `wallet::get_app_dir`: BSEC_HOME or ~/.bsec, creating the directory if absent. Index keys remain the original ID strings.

The transport seam is `Rpc::call`. A adds native `BlockingRpc::new(rpc_url: String) -> Self` implementing Rpc and matching the existing timeout/envelope/result/error behavior. It need not implement other ports. The CLI owns config, wallet, local index, formatting/filtering and Host composition; it may supply private unused-port implementations for this Rpc-only operation which return typed errors/fail-stop if invoked. It does not pretend those are completed native adapters. Keep legacy eth::rpc and every write/signing path in place for unaffected callers.

Only the selected list read branch invokes the new operation; retain an old-signature compatibility wrapper for other callers of get_secret_info_on_chain so view/materialize/write orchestration is not silently migrated. A private list-specific helper may map RegistryInfo into the existing OnChainSecretInfo, formatting addresses and adding local hidden. No direct reqwest access remains on that selected read path.

Before rewiring, A adds characterization and runs it against old code, then repeats it against the seam:
- Valid fixture: same pretty JSON fields, ordering, placeholders, addresses/public recipient and newline; exit 0. Test text mode as well. Retain hidden false in SecretRecord, even for --all.
- Per-record malformed JSON/provider error/non-string/missing/empty/short/invalid ABI/connection refusal: skip that record, continue with good records, and exit 0; all failed gives `[]\n`. Diagnostics are logging-dependent; do not invent a nonzero failure exit. Assert no stdout error text.
- Invalid registry configuration and oversized/invalid-hex ID also skip at list level. Absent/malformed index yields empty list and zero requests. Hidden/user/active/expired filters preserve their current behavior and request order.
- Missing wallet fails before any RPC: BsecError::WalletNotFound exit 1, empty stdout, existing stderr prefix. Typed seam tests separately assert Request/Provider/Decode and malformed data failure, so list's skip policy cannot hide adapter defects.

Use a temporary BSEC_HOME/cwd and a loopback ephemeral-port synthetic HTTP server; record every request and reject all methods except eth_call. Import a public synthetic mnemonic from a file with `bsec init --no-encryption --import-mnemonic <file>`, then run list with stdin closed and no password flag. No interactive wallet prompt is used. Current `wallet::get_wallet_info` does not rewrite wallet.json: assert that its bytes, including last_accessed and stored key data, remain byte-for-byte unchanged after successful list reads and failed list reads (including skipped per-record failures and wallet-load failures when the file exists). Do not reintroduce the removed timestamp/plaintext-key rewrite. Preserve `get_app_dir` directory creation when the application directory is absent; a missing wallet must remain absent. Snapshot and preserve current index/config effects as well. Never call view, materialize, share, revoke or hide for this integration: view_payload records a chain read. Shut down/join the synthetic server and delete only owned temporary files.

## Exact topology checkpoint T

A introduces the adapter crate while the root package is still bsec, so it is independently buildable. T is a mechanical layout change after that path works:

| Before T | After T |
| --- | --- |
| native root Cargo.toml with package bsec + workspace | virtual Cargo.toml, resolver 2, explicit members crates/bitbid-core, crates/bitbid-adapters, crates/bitbid-cli; keep prototype exclusion |
| native src/** | crates/bitbid-cli/src/** (all remaining CLI modules, including offline) |
| native tests/** | crates/bitbid-cli/tests/** |
| native package metadata/dependencies/dev-dependencies | crates/bitbid-cli/Cargo.toml; package bitbid-cli, version 0.1.0, explicit [[bin]] name bsec/path src/main.rs |
| root profile.release | stays workspace root; preserve settings |
| root dependency path crates/bitbid-core | CLI paths ../bitbid-core and ../bitbid-adapters |
| crates/bitbid-core/** and crates/bitbid-adapters/** | same paths |
| root README.md/license references in package metadata | fix relative path (readme ../../README.md); preserve package content/install checks |
| tests/offline_token_tests.rs include_str!("../crates/bitbid-core/tests/vectors/ipfs-v1.json") | from CLI tests: ../../bitbid-core/tests/vectors/ipfs-v1.json; inspect every include/manifest-relative fixture |
| native Cargo.lock and web Cargo.lock | remain separate, regenerate each intentionally; both --locked checks must pass |
| webapp/crates/core/Cargo.toml → ../../../bitsec/crates/bitbid-core | unchanged exact path; core did not move; validate resolution rather than inventing a new path |
| cargo build --release -p bsec / cargo run -p bsec | select -p bitbid-cli --bin bsec; installed/runtime command stays bsec |
| assert_cmd::cargo_bin("bsec"), target/release/bsec | unchanged binary lookup/path |
| scripts/check-core-boundary.py packages["bsec"] | packages["bitbid-cli"] plus native adapter runtime dependencies in forbidden set; exclude the two intended shared edges from derived set, explicitly forbid both bitbid-cli and bitbid-adapters |
| CI e2e implicit root package test selection | cargo test --locked -p bitbid-cli --test materialize_tests --test secrets_tests -- --test-threads=1 |

Core depends on neither CLI nor adapters. Adapters depend on core and put native reqwest dependencies under `target.'cfg(not(target_arch = "wasm32"))'.dependencies` with matching source cfg; their native implementation is absent from WASM. CLI depends on both and remains native; WASM commands select core/web packages instead of building the whole CLI workspace for WASM. No new core std/no_std, SSR/hydrate feature is added.

T also updates native .github/workflows/ci.yml package/path assumptions, scripts/e2e-setup.sh build selection if necessary, README/local/run and docs/cargo.md install/package instructions, this contract's verification status, and web README/facade docs only where paths/commands changed. Existing workspace lint/test/coverage commands remain --workspace. No web workflow currently exists; do not fabricate an SSR pipeline. Validate cargo metadata package/binary identity, cargo package --list -p bitbid-cli --allow-dirty and actual packaged contents/readme/fixture references. Do not publish. Preserve prototype as excluded history.

## Verification and completion limits

From the parent coordination folder use the pinned local wrapper:

```sh
python3 .local/run.py bitsec test --locked --workspace --all-features
python3 .local/run.py bitsec clippy --locked --workspace --all-targets --all-features -- -D warnings
PATH=/Users/igmrrf/.local/share/nvm/v22.22.2/bin:$PATH python3 .local/run.py bitsec test --locked -p bitbid-core --target wasm32-unknown-unknown
python3 .local/run.py webapp test --locked -p bitbid-webapp-core
```

E/P additionally run their public consumer integration targets on native and WASM; retain existing vectors. A additionally runs adapter tests and actual CLI synthetic-service tests, release build -p bsec and offline token smoke. T repeats all gates with -p bitbid-cli --bin bsec, workspace coverage, actionlint, and dependency-guard positive/negative probes. Run `python3 scripts/check-core-boundary.py` from bitsec with the pinned Cargo/tool/cache environment described in verification-strategy.md. The guard probes must reject a direct native core dependency and an adapter edge, then restore only probe edits.

For A/T browser compatibility, run facade tests plus `python3 .local/run.py webapp build --locked --release --target wasm32-unknown-unknown -p bitbid-webapp`. T also runs `python3 .local/run.py webapp trunk build --release --locked --dist ../.local/dist/webapp`, serves that production bundle on loopback, and exercises seal/reopen, frozen/legacy token opening and malformed-input recovery in a real browser; inspect desktop/narrow screenshots, console and network. Clean up only task-owned sessions. Match wasm-bindgen runner versions separately to each lockfile. Node WASM execution does not replace browser smoke.

The durable [verification strategy](verification-strategy.md) defines current checks. This documentation-only decision runs native workspace/facade suites and source/link/scope inspections. It does not claim future code, WASM behavior, runtime or packaging gates already passed. Existing offline tests that return early without BSEC_E2E=1 do not verify chain/IPFS integration; hosted CI/live services remain unverified.

No new or newly required deployable environment setting is introduced by this decision or intended by E/P/A/T. Existing BSEC_HOME/BSEC_E2E inputs are test/runtime compatibility observations, not new requirements. Repository inspection found no encrypted secrets/prod.enc.yaml, secrets catalog/report target or environment completeness tool in these two projects; do not invent a Nervly-specific command. The decision's completeness/unset/demo check verifies that all task changes are documentation and introduced settings are empty. If later implementation necessarily adds a setting, use the project's actual encrypted catalog/tooling, preserve current values and supply unmistakable safe demo values disabling optional features before completion; record the actual completeness and unset/demo report then.

## Rollout, rollback and stop conditions

1. E adds opt-in types/conversions only. Consumers continue using legacy APIs; revert only E-owned additions to roll back.
2. P adds ports/read consumer without wiring the CLI. Roll back P while keeping E; no deployed data is affected.
3. A builds a native adapter beside the root CLI and moves only list's read composition. Keep legacy paths for other callers. On regression, restore the list's previous wiring/remove unused adapter dependency and rerun characterization, native/WASM and facade checks. Do not switch runtime defaults or add a flag.
4. T moves files and package identity together. Coordinate both Git roots as one local checkpoint: build native, then sibling web, then browser. Roll back T's owned path/manifests/locks/docs in both roots together and rebuild; never reset either entire repository or unrelated user edits. No token or wallet rewrite is needed.
5. Stop after the independently reviewed checkpoint's exact gates. Later module moves, bsec→bitbid rename/aliases, Leptos SSR, service deployment and publication need their own issues/authorization. No automatic commit/push is part of this decision.

Retain a source/diff/lock identity and evidence per checkpoint. A failing check rolls back the smallest checkpoint or is fixed within that scope before the next begins. An unavailable prerequisite is recorded as blocked; do not call skipped network tests a pass or ship an unreviewed partially moved tree.


## Local topology implementation status

Checkpoint T now places native source/tests in `crates/bitbid-cli`, with a virtual
workspace and preserved `bsec` binary. The tables above retain the before/after
contract; E/P/A source references describe their historical checkpoints. Local
installation is `cargo install --locked --path crates/bitbid-cli`. Independent
verification is recorded separately; layout alone does not establish delivery.
