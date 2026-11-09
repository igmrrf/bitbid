# Rename acceptance and check matrix

Part of [execution contract](rename-execution.md). All checks below are required
pre_release for their ticket. Record exact command, target/source/diff/lock/build
identity, exit/result and full evidence paths in handoff/independent review.
Future criteria are not claims of implementation. No post_release is authorized;
release here means local production builds and task-owned installs only.

| Ticket | Owner | Dependencies |
| --- | --- | --- |
| N2 | native secrets/prod.enc.yaml, minimal encryption/catalog/check/report tooling/docs | reviewed N1 + approved public recipient |
| N3 | CLI manifest/entry/errors/usage/completion/staging identity and necessary binary test selectors | reviewed N1; eligible while N2 externally blocked |
| N4 | home/credential/project resolver, narrow callers, tests/catalog | completed N2 + N3 |
| N5 | CI/scripts/e2e/probes/current docs/native+sibling metadata | completed N3 + N4, serialize after them |

## Stable acceptance IDs

| ID | Observable acceptance | Checks |
| --- | --- | --- |
| N2-AC1 | Inventory existing/planned deployable settings/aliases, optional/required/test-only; preserve values securely | N2-V1,V3 |
| N2-AC2 | Approved public recipient, versioned native encrypted catalog and repeatable encrypt/decrypt; no generated private identity/plaintext exposure | N2-V2 |
| N2-AC3 | Actual completeness/report rules pass; missing entry fails; names/status only report | N2-V3 |
| N2-AC4 | Empty/unset config+env disables Pinata; fake nonempty demo catalog rejected before runtime export/auth | N2-V4 |
| N2-AC5 | No runtime name/behavior change; blocked encryption does not block independent N3 | N2-V1,V5 |
| N3-AC1 | bitbid-cli retained, only bitbid target/install; owned fresh/upgrade removes prior owned command, preserves sentinels | N3-V1,V2 |
| N3-AC2 | Exact agreed identity projections/native type compatibility; unchanged flags/data/exits/errors except approved text | N3-V3,V4 |
| N3-AC3 | Actual debug/release/installed canonical+legacy offline and 54-case list flows preserve outputs/bytes | N3-V4,V5 |
| N3-AC4 | Native/WASM/facade/Clippy/boundary gates pass; verified repository/omitted homepage; N4 hint deferred | N3-V1,V3,V6 |
| N3-AC5 | No runtime env/path/schema/wire/contract migration, global uninstall or publication | N3-V2,V7 |
| N4-AC1 | Both env pairs cover absent/blank/invalid/conflict, config-first JWT, exact once-per-surface redacted warnings | N4-V1,V4 |
| N4-AC2 | Both/neither/default/type/error home rules; one selected root, no invalid-new fallback/move/merge/delete | N4-V2,V4 |
| N4-AC3 | Project precedence/malformed/unreadable boundary, valid flag overrides and explicit selected save destination | N4-V3,V4 |
| N4-AC4 | Actual filesystem/subprocess reads/failures and deliberate fixture writes preserve bytes/permissions, no child/network on selection error | N4-V1,V2,V3,V4 |
| N4-AC5 | Encrypted catalog/report covers each new name, disabled Pinata all-source proof and compatibility gates pass | N4-V5,V6 |
| N5-AC1 | Current selectors bitbid-cli/bitbid; BITBID_E2E* tests/CI agree, no test aliases; valid boundary probes | N5-V1,V2 |
| N5-AC2 | Remaining bsec hits classified; cutover/deprecation/rollback docs accurate; no invented distribution resources | N5-V1,V8 |
| N5-AC3 | Native tests/Clippy/coverage/actionlint, executed core WASM/facade/boundary gates pass | N5-V2,V3 |
| N5-AC4 | Final release/fresh+upgrade installed offline/synthetic-RPC journeys, invariants/settings gates pass | N5-V4,V5 |
| N5-AC5 | Optimized real Yew browser canonical/legacy/malformed recovery and CLI interoperability, inspected desktop/narrow/screens/Console/Network | N5-V6,V7 |
| N5-AC6 | Both final source/lock/build identities, independent review and owned session cleanup; honest external verification limits | N5-V8 |

## Required concrete checks

| ID | Kind | Procedure and expected result |
| --- | --- | --- |
| N2-V1 | readiness | Graph-first inventory/config-key/script inspection, no real-secret reads. Include both HOME/JWT pairs, DOTENV_PASS/DOTENV_<ENV>_PASS; separate current/future *_E2E*. No N2 runtime rename. |
| N2-V2 | automated | Validate approved public recipient/config; synthetic encrypt→approved decrypt→compare in owned temporary sink without logging values. Missing/wrong decryption fails clearly; clean plaintext residue. Missing public recipient is blocked, not passed. |
| N2-V3 | automated | Actual native make secrets-catalog-check secrets-report. Isolated catalog copy missing required entry must fail; unset/demo report names/status visible but credential/path sentinels absent. Restore copy only. |
| N2-V4 | runtime | Isolated env+network-config config pinning_jwt absent/null/blank and both env aliases absent/empty/blank: no Pinata credential/auth request. Fake nonempty demo credential (config source too) rejected before export/run. No live Pinata/provider test. |
| N2-V5 | readiness | Only owned encrypted/config/tool/docs changes; tool failure paths exercised. Run native/facade suites if tooling touches their setup; otherwise source/lock hashes unchanged. Record exact prerequisite and actual gate failures. |
| N3-V1 | automated | metadata --locked --no-deps; debug/release -p bitbid-cli --bin bitbid; exactly three production members/one canonical bin, --bin bsec fails. Repository clienv, homepage omitted. |
| N3-V2 | runtime | Actual offline locked fresh source-path install and --force upgrade of proven owned prior bsec install; installed commands and probes run; no owned bsec/alias, Cargo ownership and unrelated executable sentinels intact. |
| N3-V3 | runtime | Actual debug/release/installed --help/--version/no-command/banner/bash+zsh completion, all-shell generation and invalid-subcommand with stdin closed. Exact N1 text/widths/canonical registrations, unchanged option table/clap exit 2; N4 credential hint remains legacy. |
| N3-V4 | runtime | Missing wallet, wrong password, invalid mnemonic/recipient, malformed token, unsafe child env preserve baseline exits/stdout/bytes. Compile alias variants/Result/From/downcast, keep typed-kind/fallback tests. Wallet/index/config/last_accessed/permissions unchanged on reads/failures; mnemonic init banner remains. |
| N3-V5 | runtime | Actual debug/release/installed offline canonical/legacy and committed tests/support/registry_probe.py --binary absolute-path: all 54 synthetic RPC cases match golden outputs/exits/request order/count; all-failed []/0 valid; no writes/IPFS. |
| N3-V6 | automated | Native workspace tests, strict Clippy, executed core WASM/public consumers, facade tests; guard positive and controlled valid core-native/core-adapter negative probes, restore only probes, positive rerun. |
| N3-V7 | readiness | Diff/hashes prove no runtime env/path/schema/wire/contract changes. Verified metadata only, owned sessions stopped, exact source/artifact identity recorded. |
| N4-V1 | automated/runtime | Cartesian N/L absent/valid equal+different/empty/whitespace/invalid/non-Unicode for both pairs; config absent/null/blank/valid/header-invalid with conflicting env. Assert exact selection/error/warning counts/redaction; canonical blank JWT suppresses legacy, nonblank config wins silently. No auth on disabled/error. |
| N4-V2 | runtime | Isolated real homes: both/neither/old-only/new-only, file/FIFO/dangling/valid symlink dirs, denied metadata/search/read/create, failed home discovery, relative/space paths. Invalid new never falls back, explicit env bypasses defaults. Snapshot wallet/config/index/cache+alternate, read bytes/permissions preserved, missing wallet absent. |
| N4-V3 | runtime | Cwd files both/neither/new/old; {}, empty/malformed/wrong schema, dir/dangling/denied read. Invalid canonical + valid old/explicit flags fails before child/network. Valid explicit flags override fields. Direct save writes selected old in place/new selected/new if neither; malformed/unusable target refuses overwrite/namespace switch/alternate creation. |
| N4-V4 | runtime | Multiple resolutions in one process then separate processes: exact one warning/surface/process, ignored old silent, invalid selected old warns then fails. No synthetic path/JWT/content sentinels in stderr; JSON stdout unchanged. Offline/help/completion resolve none/create nothing; selection failures exit 4 without child/network/mutation. |
| N4-V5 | automated/runtime | Actual catalog-check/report for every introduced name, missing-entry negative and fake-demo rejection; disabled Pinata env+config proof. No encrypted values logged. |
| N4-V6 | automated/runtime | N3 native/WASM/facade/Clippy/boundary gates plus release/installed offline and full RPC probes with canonical/legacy roots; core vectors/errors/contract unchanged. |
| N5-V1 | readiness | Current references classified: kept wire/crypto/contract, supported aliases/type alias, historical docs. All current package/bin examples canonical; *_E2E* only BITBID_, no test aliases. External artifact links verified or omitted/labeled future. |
| N5-V2 | automated | Native tests/strict Clippy/llvm-cov repository policy/actionlint; correct binary helpers; guard positive+valid core-native/core-adapter negative probes then clean positive. |
| N5-V3 | automated | Execute core WASM/public consumers with native-lock-matched runner; facade tests separate web lock; optimized web package/Trunk build. Compile-only is insufficient. |
| N5-V4 | runtime | Final release/fresh+upgrade installed help/completions/offline canonical+legacy+malformed/54-case list and canonical/legacy path fixtures, stdin closed; bytes/permissions/exits exact. |
| N5-V5 | automated/runtime | Final-source actual completeness/unset-demo reports, missing-entry negative, all-source disabled/fake-demo Pinata checks. |
| N5-V6 | runtime/visual | Serve final optimized Trunk bundle on owned loopback port; actual browser fresh seal→open/frozen canonical+legacy/malformed→recovery/keyboard. Installed CLI token opens in browser and reverse; plaintext matches. Inspect 1280×900/390×844 or documented equivalents, Console/Network; no app exceptions/required-asset failures/secret crypto requests. |
| N5-V7 | runtime | Reload/open recovery and supported legacy readers/public errors, exact CLI↔browser plaintext; no unexpected persistent/network effects. Attribute baseline tool diagnostics explicitly. |
| N5-V8 | readiness | Final both-root diffs including untracked docs, source/locks/build/install/bundle hashes, independent review, honest rollback/release notes. Stop only owned services/browser sessions; preserve user work/.DS_Store/handoff. No unapproved push/publication/deploy. |

Permission tests must prove process denial, not just chmod bits under a
privileged user. Native fixtures may express non-Unicode/host boundaries beside
reachable real subprocess cases. No real wallet/accounts/live chain/IPFS.

## Commands

From coordination root, existing pinned Rust 1.98.1/cache/target wrapper:

```sh
python3 .local/run.py bitsec test --locked --workspace --all-features
python3 .local/run.py bitsec clippy --locked --workspace --all-targets --all-features -- -D warnings
PATH=/Users/igmrrf/.local/share/nvm/v22.22.2/bin:$PATH python3 .local/run.py bitsec test --locked -p bitbid-core --target wasm32-unknown-unknown
python3 .local/run.py webapp test --locked -p bitbid-webapp-core
python3 .local/run.py bitsec build --locked --release -p bitbid-cli --bin bitbid
python3 .local/run.py bitsec llvm-cov --locked --workspace --all-features --lcov --output-path ../.local/coverage/rename.lcov --summary-only
python3 .local/run.py webapp build --locked --release --target wasm32-unknown-unknown -p bitbid-webapp
python3 .local/run.py webapp trunk build --release --locked --dist ../.local/dist/webapp
```

Binary selectors above apply after N3; before that bsec remains. N5 updates
coordination wrapper's E2E disable name together with tests, never earlier.
Install via same wrapper, --offline/--locked --path crates/bitbid-cli --root owned
(--force upgrade). Guard script uses pinned Cargo/cache env from
[verification strategy](verification-strategy.md); run actionlint on native
workflow. Match WASM runner to each lockfile. E2E-disabled suites/synthetic RPC
are not live-service/hosted CI proof. N1 docs-only needs no UI/production rollout
check; final optimized real-browser/install checks remain mandatory N5 gates.
