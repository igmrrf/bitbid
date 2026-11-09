# Extraction implementation ticket contracts

The user approved all four recommendations in [the execution contract](extraction-execution.md) on 2026-11-09. These sections are normal implementation ticket bodies; letters are local references, not tracker IDs. Tracker links are added only after creation. All depend directly or transitively on [Lock the next core and adapters extraction execution contract](https://github.com/igmrrf/bitbid/issues/26). No implementation is established by this document.

Each ticket uses its own Codinary brief/baseline/implementer/independent review/evidence, max two fix cycles. Execution is serialized where CLI/manifests/persistence ownership overlaps. Only true code prerequisites become native blocking edges; listing order is an execution preference, not an invented dependency. Independent tests/research may proceed read-only. All checks below are required pre_release unless explicitly described as conditional. Local builds and owned installations only; no external release or provider mutation. Rollback means reverse only that ticket's owned patch, retain initial Homebrew/.DS_Store/other work, and rerun affected checks; no user-data migration/rewrite or repository reset.

## Common verification contract

`V1` final-source scope/compatibility: capture both HEADs, staged/unstaged/untracked baseline, current diff including new files, source/lock/build/install hashes; prove preserved unrelated changes, immutable protocol/crypto/schema/alias behavior and accurate failure projections. Review from actual source; no prior evidence substitutes for independent execution.

`V2` native: `python3 .local/run.py bitsec test --locked --workspace --all-features`; strict Clippy `python3 .local/run.py bitsec clippy --locked --workspace --all-targets --all-features -- -D warnings`. New meaningful behavior tests plus focused negative cases from each ticket. Use repository coverage tooling to inspect missed changed behavior where tests leave uncertainty; no invented threshold. Actionlint is required if workflow files change, not an unrelated documentation gate.

`V3` shared consumers: execute core WASM tests with native-lock-matched wasm-bindgen runner (`PATH=/Users/igmrrf/.local/share/nvm/v22.22.2/bin:$PATH python3 .local/run.py bitsec test --locked -p bitbid-core --target wasm32-unknown-unknown`); native public-consumer tests; `python3 .local/run.py webapp test --locked -p bitbid-webapp-core`; actual dependency guard `scripts/check-core-boundary.py` with pinned wrapper Cargo/cache environment and valid positive/controlled negative probes as affected. Native-only additions must still prove core's target boundary. New list/wallet/signing modules are not consumed by a UI route: no browser journey is affected by merely exporting them; if an implementation changes an actual web flow, add production Trunk build and real desktop/narrow interaction/Console/Network before completion.

`V4` native runtime: build final release `python3 .local/run.py bitsec build --locked --release -p bitbid-cli --bin bitbid`; locked/offline path-install in a fresh owned run-directory root through the existing wrapper, then execute the affected journey on release and installed binaries. Closed stdin, synthetic wallets/homes, canonical+legacy root/alias cases, exact stdout/stderr/exits and file hashes/modes before/after. Use explicit binary arguments in existing probes (`crates/bitbid-cli/tests/support/registry_probe.py` and current offline helpers); never accidentally run a stale user binary. Trap all RPC/Pinata/Kubo/gateway destinations locally; no live fallback. No global installation change.

`V5` settings/readiness: actual `SOPS_AGE_KEY_FILE=/Users/igmrrf/.config/sops/age/charmedly-demo.txt make -C bitsec secrets-catalog-check secrets-report`. No planned new setting. Any newly required deployable setting must use encrypted catalog and actual completeness/demo negatives. Never expose secret values or private material. Stop owned services and report cleanup. Post-release/publication/host qualification remains with the separate publication decision.

Run paths/log names and expected observations go in each fresh brief's matrix before edits. Every AC below must map to these common checks plus its specific fixtures/runtime observations. No missing required result counts as pass.

## A — Implement a mapped native filesystem Store and selected-list reads

**Tracker:** [Implement a mapped native filesystem Store and selected-list reads](https://github.com/igmrrf/bitbid/issues/29). **Depends:** extraction decision. **Next:** B. Ownership: new native-only `crates/bitbid-adapters/src/store.rs`, adapter export/dependencies as needed, selected-list-only CLI read composition (`blockchain/list_read.rs`, `blockchain::list_registry_secrets` and narrow native loader helpers), adapter/CLI tests and current docs. Do not globally replace network/index loaders or their write callers; preserve hide's legacy path. No core trait/variant change.

- `A-AC1`: complete read/write/exists/remove for injected NetworkConfig/SecretIndex paths, with no env/home/cwd guesses; all operations on unmapped keys fail fixed safe StoreError::Io. Mapped absence is None/false/remove success; directory/permission errors remain typed.
- `A-AC2`: actual OS read/exists follow valid symlinks; dangling is absence; overwrite rejects final symlink, create_new atomically rejects any existing entry, private writes enforce privacy before truncation/data, unlink removes entry not victim. Preserve bytes/modes on read, invalid target/collision/denial; document partial-I/O and host limits honestly. No false complete adapter from read-only methods.
- `A-AC3`: only selected list accesses use Store. Resolve/revalidate current paths lazily at each original accessor; after selection preserve config default/index-empty fallback including malformed UTF-8/schema/denied files; selection errors remain ConfigError. Initial enumeration/config-per-ID/late index reload ordering unchanged; no extra startup mapping or CLI writes.
- `A-AC4`: existing 54-case synthetic list oracle, canonical/legacy selection and offline help/tokens pass on real release+owned installed binaries; no provider/IPFS/write access, bytes/modes/IDs/RPC order intact. V1–V5 pass independently.

Specific fixtures: missing parent, real non-root denial (prove process cannot read/write), file/directory/FIFO or nonregular target, valid/dangling symlink, existing-file create_new race/collision, private0600, umask ordinary write, remove present/absent/symlink/directory, all key methods unmapped. Test no write/remove reaches selected list and empty index never loads network config. Rollback only adapter/export/selected readers and tests; old readers remain available.

## B — Extract the selected list policy into shared core

**Tracker:** [Extract the selected list policy into shared core](https://github.com/igmrrf/bitbid/issues/30). **Depends:** A. Ownership: new `core/src/registry_list.rs`, core export, selected `blockchain::list_registry_secrets`/`blockchain/list_read.rs` mapping, public native/WASM/facade consumer fixtures and CLI regression tests. Existing persisted Index/NetworkConfig and legacy hide helper stay native.

- `B-AC1`: implement the agreed `ListQuery`/generic `list_indexed` interface with original string IDs, enumeration hidden input and all11 RegistryInfo facts. No new Host port, persisted schema or credentials in core.
- `B-AC2`: callback first for every ordered entry; None skips; generic fatal E returns immediately; native callback logs nonfatal failures immediately and propagates ConfigError. Preserve per-ID config→RPC→late index reads and endpoint/registry pairing, including a later selection failure after earlier warnings.
- `B-AC3`: exact ownership/public/case-insensitive literal `--user public`, hidden/--all, expired/read-limit/revoked, active+expired intersection, ID/order and []/0 behavior; native SecretRecord projection remains byte compatible including hidden:false. Legacy hide's list helper unchanged.
- `B-AC4`: same operation through memory reader/Host and native reader; public native+WASM consumers execute; panic-on-unused ports and call-order assertions prove no premature I/O/filtering. Actual release/install 54-case oracle and dynamic config/index fixtures pass; V1–V5 pass independently.

Rollback only new core policy/export and selected caller, not A or legacy helper. No browser UI route consumes this module.

## C — Extract native IPFS byte transport and compatible text/cache fetch

**Tracker:** [Extract native IPFS byte transport and compatible text/cache fetch](https://github.com/igmrrf/bitbid/issues/31). **Depends:** extraction decision; schedule separately from overlapping CLI work, no B/wallet/signing prerequisite. Ownership: native adapter IPFS/compatibility modules, pure CID core helper if useful, CLI `ipfs.rs` thin lazy composition, HTTP/cache/credential fixtures and tests. Store cache mapping is explicitly injected by compatibility wrapper; no guessed homes or global write cutover.

- `C-AC1`: honest public Ipfs bytes add/cat with arbitrary-byte consumer tests; shared request construction and compatibility wrapper retain current text multipart bytes/name/response schema. Sync ports unchanged. Pinata/Kubo credentials/config are injected after current native selection.
- `C-AC2`: preserve 15s/fallback order, valid-response-invalid-CID immediate error, current CID acceptance, strict cache UTF-8 versus HTTP charset/BOM/lossy text, cache hash/extension, config/path-before-cache order, cache-path fatal versus write-I/O ignored semantics. No strict final UTF-8 conversion replaces current behavior.
- `C-AC3`: config/canonical/legacy JWT selection, empty disable/header errors and exact warning budget remain native and lazy. All-source unset/demo/error paths make no authenticated request; logs/errors contain no JWT/payload. No new deployable setting to redirect tests.
- `C-AC4`: differential baseline/final loopback Pinata/Kubo/configured/public gateway traps, malformed bytes/charset/BOM/status/decode/timeout/CID cases and real cache permission/symlink failures pass. Final release/install offline token journeys and owned local share/fetch fixture reach the new wiring; V1–V5 pass independently.

All fallback endpoints must be redirected/injected before requests; public network is forbidden in fixtures. Rollback CLI delegation/modules only; no cache migration, rewrite-on-read or protocol change. Shared core cache relocation remains an explicit included follow-up requiring a byte/text metadata seam, not silently claimed here.

## D — Extract wallet codecs and reject malformed nonce lengths

**Tracker:** [Extract wallet codecs and reject malformed nonce lengths](https://github.com/igmrrf/bitbid/issues/32). **Depends:** extraction decision; serialize overlapping crypto/CLI edits. Ownership: new core wallet codec/derive helpers and exports, existing wallet pure-helper wrappers, deterministic public vectors, malformed wallet regression and native/WASM consumers. No wallet storage/init cutover in this ticket.

- `D-AC1`: freeze full current KDF/encrypted/manual-JSON/mnemonic/key/address vectors before moving; preserve Argon2id v0x13 m19456/t2/p1/output32, short-salt expansion, salt16/nonce12/GCMtag16/noAAD, padded base64 and BIP44 path/field escaping/order.
- `D-AC2`: explicitly fix decoded nonce length !=12 before Nonce::from_slice. Synthetic current binary SIGABRT baseline is retained; final native/WASM and real release/install wallet-info malformed fixtures return sanitized failure without panic or writes. Wrong password and valid bytes/errors remain unchanged.
- `D-AC3`: pure transforms take explicit inputs and existing RandomSource for randomness; no OS/env/filesystem/time in core. Fixed test entropy proves exact consumption/bytes; production uses OS randomness without deterministic fallback. Existing secret guards preserved, new owning types avoid Debug exposure/unnecessary plaintext copies; no unsupported complete-zeroization claim.
- `D-AC4`: malformed base64/field count/nonce/UTF-8/key/mnemonic cases and frozen decrypt/encrypt vectors pass; native release/install closed-stdin valid encrypted/plain/wrong-password journeys preserve wallet hashes/modes. V1–V5 pass independently.

Rollback codec wrappers/module only (retain nonce correction as separately recorded safety fix if rollback would reintroduce abort; do not silently restore a known unsafe path). No data migration.

## E — Extract read-only wallet unlock through native storage

**Tracker:** [Extract read-only wallet unlock through native storage](https://github.com/igmrrf/bitbid/issues/33). **Depends:** D and A. Ownership: core wallet read/unlock entry, native FileStore Wallet mapping/composition, `wallet::get_wallet_info` wrapper and affected public consumers/fixtures. No initialization or project/config write cutover.

- `E-AC1`: Store Wallet mapped explicitly at current lazy get_app_dir access; parse encrypted/plain WalletFile with unchanged missing-wallet/password/wrong-password/sanitized malformed behavior and public projection. Existing get_wallet_info callers use the new read flow, not duplicate disconnected helpers.
- `E-AC2`: reads never write/remove/chmod/change last_accessed or stored key data; no Clock/Random/IPFS/RPC calls. Enforce via panic-on-access memory ports plus real file hashes/modes and canonical/legacy homes/selection failures.
- `E-AC3`: retain redacted native errors, no secret-bearing Debug/log/stdout or extra plaintext copies; new APIs have deliberate secret ownership. Existing passwords/private data never appear in evidence.
- `E-AC4`: real release/install wallet info plus dependent list/offline paths, malformed recovery and no-prompt negative fixtures pass; public native/WASM consumers and V1–V5 pass independently.

Rollback only wallet reader/composition/mapping; retain D codec/nonce correction. No wallet rewrite is part of rollback or normal read.

## F — Extract explicit wallet initialization with clock and entropy

**Tracker:** [Extract explicit wallet initialization with clock and entropy](https://github.com/igmrrf/bitbid/issues/34). **Depends:** E. Ownership: core initialization preparation/orchestration, additive StoreKey::WalletConfig and its public consumer matches, native clock/random adapters, explicit wallet/config mappings, `wallet::init_wallet` native prompt/output wrapper and tests. No production caller writes outside explicit init.

- `F-AC1`: explicitly add WalletConfig for `config.json`, distinct from NetworkConfig. Compile all exhaustive consumers/fixtures; sync method signatures unchanged. Native clock maps current pre-epoch timestamp behavior, OS entropy fail-stop/no test fallback.
- `F-AC2`: missing password without plaintext opt-in fails before app selection. Preserve config.json-based overwrite gate, import mnemonic validation, one timestamp, rendered bytes/key/address/derivation. Clock/random test doubles provide deterministic characterization; real init uses actual OS entropy/private storage.
- `F-AC3`: preserve sequential wallet.json then config.json writes, existing overwrite/private/no-follow leaf behavior and observable partial failure. Use an explicit native compatibility Store writer for Wallet/WalletConfig that delegates the existing secure-write/best-effort permission helpers, with all mapped Store methods honestly implemented. Keep stronger FileStore private-write enforcement unchanged; characterize and preserve native success/failure projections. Extract the writer into adapters, do not change its behavior. No false two-file transaction/automatic rollback/migration.
- `F-AC4`: owned actual init/read subprocesses cover both absent, config-only, wallet-only, overwrite, plaintext opt-in, first/second-write failure, entropy and clock control, canonical/legacy roots and bytes/modes/last_accessed. V1–V5 pass independently; malformed no-panic remains fixed.

Rollback only initialization/key/adapter changes, preserve user files (never roll data backward). Two-file atomic initialization remains a named proposed hardening follow-up, not part of this ticket.

## G — Extract and freeze legacy and type2 signing bytes

**Tracker:** [Extract and freeze legacy and type2 signing bytes](https://github.com/igmrrf/bitbid/issues/35). **Depends:** extraction decision; serialize overlapping core/eth ownership. Ownership: pure `eth.rs` RLP/integer/address/selector/ABI/signing functions and compatible wrappers, shared core signing export and public native/WASM vectors. No transaction sender caller switches here.

- `G-AC1`: full exact frozen signed legacy/type2 hex from public synthetic key, calldata/selector/chain/nonce/gas/fees/value/access-list/address vectors match baseline and final native/WASM consumers.
- `G-AC2`: malformed hex/address/key/ranges return agreed typed/sanitized errors without new panic; no environment/HTTP/clock/storage or real provider access. Preserve valid byte and existing host error APIs/projections.
- `G-AC3`: current CLI wrappers consume the extracted signing helpers; native transaction behavior stays otherwise unchanged. Actual release/install loopback synthetic revoke signing exercises resulting raw submission bytes; no live sender.
- `G-AC4`: V1–V5 pass independently, with source/lock fingerprints and exact public-consumer proof. UI is unaffected unless actual web wiring changes.

Rollback helpers/wrappers only; no on-chain mutation or storage migration.

## H — Extract revoke transaction orchestration over Rpc and Clock

**Tracker:** [Extract revoke transaction orchestration over Rpc and Clock](https://github.com/igmrrf/bitbid/issues/36). **Depends:** G and E; no IPFS/index-write capability dependency. Ownership: core send/fee/receipt/revoke functions, native `eth.rs` transaction compatibility composition, selected `blockchain::revoke_secret_on_chain` and its `secrets::revoke_secret` caller only, synthetic RPC/Clock and CLI fixtures. Other sender callers remain native.

- `H-AC1`: exact pending nonce→estimateGas(saturating12/10/nonstring300000)→basefee→tip fallback/type2 or gasPrice/legacy→sendRaw→receipt order, envelopes/id/fields/raw bytes and error classification. Characterize old eth::rpc versus BlockingRpc HTTP/status/error/result semantics before selecting/reusing adapter; no implicit behavior change.
- `H-AC2`: receipt exactly60 attempts and2s sleep per null including last, status missing/nonstring defaults success, exact0x0 revert, RPC error abort; no new retry/backoff. Fixed Clock tests avoid120s wall time; actual local success/error/poll CLI verifies wiring.
- `H-AC3`: real main revoke entry unlocks read-only wallet, validates original secret ID, uses deployed ABI/address unchanged, submits only to loopback and preserves stdout/stderr/exits/state. Share/view/record-read/hide use old sender; no accidental index/IPFS writes or all-caller cutover. Review hide's reuse of revoke explicitly: preserve its legacy sender path with a separate internal wrapper if necessary.
- `H-AC4`: full success/revert/malformed/offline/timeout/fee/overflow/wrong-key/no-panic cases through memory and loopback; real release/install canonical+legacy fixtures closed stdin; V1–V5 pass independently.

Rollback selected revoke composition/core orchestration only. No live provider transaction, registry change or file migration. Remaining lifecycle operations are included proposed follow-ups, sized after this exact cutover rather than claimed delivered.

## Retained follow-ups and independent decisions

- Shared cache-policy placement beyond the selected native text wrapper, additional Store keys/cutovers and remaining share/view/record-read/hide/materialize orchestration remain included, explicitly proposed and unimplemented. Do not invent their issue identities or silently drop them.
- Atomic wallet/config initialization is proposed hardening requiring a separate contract; current partial-write behavior remains documented.
- SSR decision and conditional server/client implementation remain at [Rebase the SSR execution decision on the shipped Yew and shared core](https://github.com/igmrrf/bitbid/issues/27), with its closed native research/security prerequisites unchanged.
- Publication channel selection, preparation and separately authorized external execution remain at [Choose publication channels and the release verification contract](https://github.com/igmrrf/bitbid/issues/28). Neither this decision nor a local green build authorizes external release.
