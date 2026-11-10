# Rename execution contract

> Current override (2026-11-10): [immediate canonical-only selection](../rename-cutover.md)
> removes `BSEC_HOME`, `BSEC_PINATA_JWT`, `~/.bsec`, and `.bsec.json` fallbacks
> at 0.1.0. Earlier 0.x/1.0 promises and fallback rules below are historical and
> superseded for those four inputs only. Type aliases, stored formats, tokens and
> cryptographic/on-chain identities retain their existing compatibility.

N1 specification, 2026-11-09; no rename implementation or publication is implied.
Current native baseline is `296ad8b7af45c50d5be27ab189263782acfd286c`; web is
`051352370c456294bfe6f1cf6d034e13a834aadb`. This is the authoritative execution
contract refining [#13's accepted resolution](https://github.com/igmrrf/clienv/issues/13#issuecomment-5927312244).
The [old surface inventory](rename-surface.md) and [split rollout](migration-rollout.md)
retain historical context; their old root `src/` paths/668-occurrence count are
not a current inventory. Use [acceptance and checks](rename-acceptance.md) and
issue drafts [N2](rename-issue-n2.md), [N3](rename-issue-n3.md),
[N4](rename-issue-n4.md), [N5](rename-issue-n5.md) with this contract.

## Shipped topology and tracker reconciliation

Native is already a virtual resolver-2 workspace with exactly production
members `crates/bitbid-core`, `crates/bitbid-adapters`, `crates/bitbid-cli`.
Package **bitbid-cli 0.1.0 already exists; its binary is still bsec**. Core
depends on neither adapters nor CLI; adapters depend on core with native HTTP
dependencies/source behind native cfg; CLI depends on both. Do not repeat crate
moves or package renaming. Excluded `prototype/split-core-skeleton` bodies are
historical, not completed production adapters. Only list's read is composed
through shared Host/Rpc and native BlockingRpc; wallet/filesystem/IPFS/signing/
writes/staging/process orchestration remain CLI facilities.

The sibling is Yew CSR, not Leptos SSR. Its `webapp/crates/core` facade package
`bitbid-webapp-core` still points to `../../../bitsec/crates/bitbid-core`.
Keep that path and separate lockfiles. No full fourteen-module extraction,
SSR, registry publication, deployment or data migration shipped.

Tracker states observed 2026-11-09 are distinct from code completion:

| Tracker | State | Reconciled progress; do not reimplement |
| --- | --- | --- |
| [#3](https://github.com/igmrrf/clienv/issues/3) | open | Map's plan-only/Leptos/full-extraction assumptions are historical; replace progress with this shipped topology and retain future work separately. |
| [#10](https://github.com/igmrrf/clienv/issues/10) | open, no comments | Canonical/shared crypto and versioned readers shipped in `ebb6853`, verified in `c0689b2`; [format](canonical-format.md), [protocol](implemented-shared-protocol.md). |
| [#12](https://github.com/igmrrf/clienv/issues/12) | open, no comments | Thin web facade shipped; [facade contract](web-core-consolidation.md) and the same commits. |
| [#13](https://github.com/igmrrf/clienv/issues/13) | closed decision | Accepted rename policy; implementation still N3/N4/N5. |
| [#14](https://github.com/igmrrf/clienv/issues/14) | open, no comments | E/P/A/T rollout specified and shipped by `296ad8b`; broader extraction remains separate. |
| [#15](https://github.com/igmrrf/clienv/issues/15) | open, no comments | CI/native/WASM/consumer verification now specified/executed for split; [verification](verification-strategy.md), `c0689b2`/`296ad8b`; rename has new gates. |
| [#17](https://github.com/igmrrf/clienv/issues/17) | open | Typed errors/safe public classifications/native exit compatibility shipped in `296ad8b`. |
| [#18](https://github.com/igmrrf/clienv/issues/18) | open | Synchronous ports and eleven-field registry_read plus native/WASM consumers shipped in `296ad8b`. |
| [#19](https://github.com/igmrrf/clienv/issues/19) | open | BlockingRpc and list-only read composition shipped in `296ad8b`; old read/write paths retained. |
| [#20](https://github.com/igmrrf/clienv/issues/20) | open | Workspace/CLI/test moves, preserved bsec target and CI/guard selectors shipped in `296ad8b`. |

This is the proposed tracker reconciliation basis, not an issue mutation.
Native commit provenance is local/unpublished history in the `bitsec/` repository:
`296ad8b7af45c50d5be27ab189263782acfd286c`,
`c0689b2292495b2598b5a00f0e207bfe8284b5df`, and
`ebb6853cc7c1484d211c22d92885f0dd3afb4139`. The coordination root's `handoff.md`
records that no commits were pushed; inspect these objects from that root with
`git -C bitsec show <SHA>`. Closed decisions do not establish delivery;
source/tests/contracts do.

## Current source inventory

All unprefixed paths are native-root-relative. Graph search/snippets/traces were
checked against actual manifests/callers; heuristic graph edges do not override
manifest dependency directions.

| Surface/current behavior | Source and consumer | Owner |
| --- | --- | --- |
| bitbid-cli package, bsec target | `crates/bitbid-cli/Cargo.toml`; root Cargo.toml release profile | N3 target only |
| clap/banner/completion/command hints | `crates/bitbid-cli/src/main.rs::{Cli,main,print_banner}`; `env_file.rs::run_with_envs` usage hint | N3 |
| native error enum/exits/downcast | `crates/bitbid-cli/src/errors.rs::BsecError`, `fallback_exit_code`; `main::handle_cli_error` | N3 |
| only BSEC_HOME then ~/.bsec today; creation errors ignored | `crates/bitbid-cli/src/wallet.rs::get_app_dir`; wallet init/read, network config path, blockchain index, IPFS cache | N4 fallible resolver/callers |
| cwd .bsec.json only; read/JSON failure → None; secure save | `crates/bitbid-cli/src/project_config.rs::{get_project_config_path,load_project_config,save_project_config}` → `env_file::run_with_envs` | N4 |
| nonblank config ipfs.pinning_jwt first, then nonblank BSEC_PINATA_JWT | `crates/bitbid-cli/src/ipfs.rs::resolve_pinning_jwt` → upload_to_ipfs (Pinata→Kubo); fetch cache→Kubo→gateways | N4; config priority retained |
| list → shared read → persistence/network | main → secrets::list_secrets → blockchain::list_registry_secrets → list_read::read → core registry_read::read_registry_info → adapters BlockingRpc; network config/index from selected home | Preserve one eth_call/latest, 20s timeout, original IDs/order/filter/failed-record skipping |
| operational selectors | `.github/workflows/ci.yml`, `scripts/e2e-setup.sh`, `scripts/check-core-boundary.py`, CLI tests/support probes | N3 necessary binary test selectors; N5 integration |
| stale repository/homepage | CLI manifest repository `https://github.com/igmrrf/bsec`, homepage `https://bsec.dev`; web Cargo.toml stale repository | N3 native/N5 sibling: repository exactly `https://github.com/igmrrf/clienv`; **omit homepage** |

Canonical repository is grounded in actual native origin
`git@github.com:igmrrf/clienv.git` and repository/issue records; web has no remote.
No verified canonical homepage is established. Do not invent bitbid URLs or
rename external repositories/domains/distribution resources. Proposed historical
npm/Homebrew/container/winget/scoop/registry names are not published artifacts.

## Immutable compatibility and exact N3 text changes

At N3 cutover the built/installed command is **bitbid only**, with no bsec
target/wrapper/symlink/binary alias. Preserve bsec until that explicit checkpoint.
Env/path aliases survive **all 0.x**, removed at **1.0** with breaking notes.
Keep canonical payload v1 bytes, bitbid2:, bitbid1:/legacy JSON readers, concrete
core/facade errors, ErrorKind/public_message(), BsecSecretRegistry and deployed
address/ABI, `bsec-ecdh-aes256gcm-v1`, `bsec_public_secret_wrapper_key_v1`, legacy
`bitbid-webapp-ecdh-aes256gcm-v1`, DOTENV_PASS/DOTENV_<ENV>_PASS. Keep schemas,
wallet/key/last_accessed/index/config bytes, private permissions and cache hashes.
No move/copy/merge/deletion or migrate command is authorized.

N3 permits only these text/identity differences and corresponding fixtures:

| Current | Required |
| --- | --- |
| clap name/Usage/help references `bsec` | `bitbid`; same flags/options/subcommands/defaults/table |
| long_about `bsec is a CLI tool for secure environment variable management, schema validation, format conversion, and ephemeral secret sharing.` | Same sentence starting `bitbid is` |
| version `bsec 0.1.0\n` | `bitbid 0.1.0\n`; no rename-driven version bump |
| banner `║                 BSEC                  ║` | `║                BITBID                 ║`; all other lines unchanged |
| completion generation bsec, bash _bsec, zsh #compdef bsec and other-shell command identifiers | bitbid/_bitbid/#compdef bitbid and equivalent fish/PowerShell/elvish; no old command registration |
| `Wallet not found. Please run 'bsec init' first.` | Same text with `bitbid init` |
| `To view this secret, run: bsec view {id}` | Same text with bitbid view, same ID |
| `This secret is a bundle of files. Run: bsec materialize {id} --dir <DIR>` | Same text with bitbid materialize, same ID |
| `No command provided. Usage: bsec run -- <command>` | Same text with bitbid run |
| ephemeral bsec-…/bsec-stage prefix | bitbid-…/bitbid-stage; cleanup/ownership/permissions unchanged |

Native canonical enum becomes `BitbidError`, retaining local
`pub type BsecError = BitbidError` through 0.x for source inclusion compatibility.
Preserve variants, Result alias, conversions, typed downcast and classification;
this is not a binary alias or a new core API. Error prefixes such as `Error
getting wallet info`, `Seal failed`, `Unseal failed` remain unchanged. Typed
exits remain InvalidPassword=2; SecretExpired/SecretNotFound/PermissionDenied=3;
IoError/ParseError/ConfigError=4; InvalidMnemonic/InvalidRecipient=5; others=1.
Keep untyped fallback precedence password/corrupted→2, not-found/expired/
permission→3, io/parse/config/file→4, mnemonic/recipient→5, else 1. Preserve
actual command behavior: missing wallet info JSON exits 1/empty stdout; clap
usage exits 2; invalid mnemonic init exits 5 and already prints its banner.
Do not normalize outputs/exits or change machine stdout/crypto bytes.

**Deferred to N4:** runtime BSEC_HOME/BSEC_PINATA_JWT/.bsec/.bsec.json and the
IPFS credential hint/comment stay truthful during N3. N4 replaces the hint's
single BSEC_PINATA_JWT token with BITBID_PINATA_JWT; rest of sentence/backend
behavior stays unchanged except selection errors explicitly defined below.

Fresh source-path install to an owned root must create bin/bitbid only. Upgrade
first installs the old bitbid-cli/bsec into another owned root, records binary
and Cargo metadata, then uses `cargo install --locked --force --path
crates/bitbid-cli --root <owned>`. Verify no old owned command and unrelated
sentinels untouched. If Cargo retains stale bsec, remove only the proven
task-owned prior-package binary as an explicit logged upgrade step; preserve
metadata/unrelated files. Never scan/delete user PATH/install roots. Document
manual removal for old global/manual installs; runtime never uninstalls them.
Exercise actual fresh/upgrade installed commands, not just built artifacts.

## N4 selection contract

Resolve lazily and consistently per process/surface. Help/version/completion
and offline seal/unseal must not resolve/create home/project or warn. Only
lexical absence allows fallback: invalid type, denied metadata/read, I/O error
or dangling symlink is present/invalid. Existing symlinks to the required type
may be followed without replacing them. Selection errors below are redacted
stderr/exit **4**, empty machine stdout, no child/network/mutation; existing
command prefix may precede the fixed text. Never append OS error paths/values.

### Env pairs: BITBID_HOME/BSEC_HOME and BITBID_PINATA_JWT/BSEC_PINATA_JWT

| Canonical N | Legacy L | Result |
| --- | --- | --- |
| absent | absent | default home table; JWT disabled unless nonblank config wins |
| present valid | absent/valid equal/valid different/invalid | N; ignore L with no warning |
| present empty/blank | any | N selected: HOME fails, JWT disables; no L fallback/warning |
| present invalid | any | fail; no L fallback/warning |
| absent | present valid | L selected, one legacy-env warning |
| absent | present empty/blank/invalid | L selected, warning once, HOME fails/JWT blank disables or invalid fails; no default fallback |

HOME valid means nonempty/non-all-whitespace Unicode path, no NUL, usable
directory or creatable missing directory. Relative is cwd-relative; do not trim
nonblank paths or expand shell/~ syntax. Non-Unicode OS env is present invalid.
Files/special files/dangling links/unusable directory/failed creation fail.
Fixed error: `Configuration error: invalid BITBID_HOME.` or selected legacy
`Configuration error: invalid BSEC_HOME.`; no default directory creation.

JWT preserves **nonblank config ipfs.pinning_jwt first**, then env N, then L.
Absent/null/blank config permits env resolution; nonblank config suppresses env
lookups/warnings. Selected blank env explicitly disables, never falls through.
Nonblank selected token is opaque and not trimmed. Non-Unicode env or invalid
bearer-header bytes (controls/newlines) fails `Configuration error: invalid
Pinata credential.` without fallback/auth attempt. No online JWT validation or
signature/parser tightening is part of rename; header-safe opaque fake tokens
can currently enter auth, so they are never safe disabled placeholders.

**Disabled Pinata proof:** catalog runtime values are absent/null/empty, with
demo status separate; never nonempty fake JWT. Isolated disabled test clears
both env aliases AND config pinning_jwt. A demo catalog with nonempty fake
credential must fail checker before export/runtime (including config source),
not rely on provider rejection. N2 establishes this without changing resolver;
N4 proves canonical blank suppresses nonempty legacy, but valid nonblank config
still wins. Blank env is not a global off switch; no new enable flag is added.

### Default directories when both HOME env names are absent

Failed user-home discovery fails `Configuration error: cannot determine home
directory.`; do not fall back to cwd. Make get_app_dir/callers fallible as needed.

| ~/.bitbid | ~/.bsec | Result |
| --- | --- | --- |
| usable dir | anything | canonical, no legacy warning |
| invalid type/dangling/unusable/metadata error | anything | `Configuration error: invalid application directory.`; no fallback/create |
| absent | usable dir | legacy **in place**, warning; no canonical creation |
| absent | invalid/dangling/unusable/error | same failure, no canonical creation |
| absent | absent | create/use canonical with existing private directory policy; creation failure same error |

Explicit env selection bypasses both defaults. Wallet/network-config.json/
secret_index.json/ipfs_cache share one selected root. Retain read-side selected
directory creation and missing-wallet absence; wallet reads never rewrite data.
Existing network-config/index decoding defaults remain, rather than tightening
unrelated schemas. Only root selection errors become explicit failures.

### Cwd project config and explicit writes

Only cwd files, no parent search. Explicit flags override valid project fields
as today; selection/validation error blocks run even with explicit flags.

| .bitbid.json | .bsec.json | Load / explicit save |
| --- | --- | --- |
| readable valid ProjectConfig | anything | canonical / canonical; legacy ignored silently |
| malformed/wrong schema/unreadable/invalid type/dangling | anything | `Configuration error: invalid project configuration.`; no legacy/default/child/write |
| absent | readable valid | legacy / **legacy in place**, warning; no canonical creation |
| absent | malformed/unreadable/invalid type/dangling | same failure; no canonical creation/overwrite |
| absent | absent | None / create canonical using secure writer |

Empty file is malformed; `{}` is valid empty config. This intentionally replaces
today's silent error→None behavior. Never overwrite malformed/unreadable selected
file during resolution/save. No new save CLI command; direct native fixtures
exercise save_project_config plus real subprocess reads. Recheck destination
before deliberate writes; if selected path changes/becomes unusable fail safely,
never switch namespaces. Normal secure deliberate writes may change selected
content; alternate file, wallet/index/permissions remain untouched. No silent
copy/merge/move/delete or automatic migration.

### Warning bytes, frequency and redaction

Exact lines with newline, stderr, **once per process per selected legacy
surface**, on first resolution (even selected invalid legacy then failure).
Repeated resolver calls do not repeat warnings; ignored legacy never warns.
Independent surfaces each warn once in first-use order; children have their own
budget. Existing unrelated security warnings remain. Identifier literals only,
never actual path/JWT/cwd/content/key/ID; JSON stdout stays byte-identical.

```text
Warning: BSEC_HOME is deprecated; use BITBID_HOME. Support ends at 1.0.
Warning: BSEC_PINATA_JWT is deprecated; use BITBID_PINATA_JWT. Support ends at 1.0.
Warning: ~/.bsec is deprecated; use ~/.bitbid. Support ends at 1.0.
Warning: .bsec.json is deprecated; use .bitbid.json. Support ends at 1.0.
```

## Ordering, encrypted settings and rollback

N1→N2→N4 and N1→N3→N4→N5. N3 may proceed after reviewed N1 if N2 is
externally blocked; serialize overlapping N3/N4/N5 work. N2 owns versioned
native **bitsec/secrets/prod.enc.yaml**, minimal encryption/catalog/check/report
tooling and docs. Preserve coordination secrets/.env without reading/dumping/
copying it. No approved project public SOPS/age recipient/config was found;
approved public recipient and user-controlled decrypt workflow are N2's external
prerequisite. Never generate/read a private identity for the user.

Inventory existing/planned deployable settings and aliases, unchanged DOTENV_*,
and separate test-only BSEC_E2E*→BITBID_E2E* (N5, no test aliases). Preserve real
values through authorized secure workflow; no plaintext logs/decrypted artifacts.
New runtime names require catalog coverage **before N4**. After N2 actually run
native `make secrets-catalog-check secrets-report`; prove missing entry fails and
unset/demo names/status report redacts values. N1 introduces zero runtime
settings and records actual absent-rule attempts, not successful secret gates.

Rollback only owned changes: N2 encrypted/config/tooling revision with preserved
values/recovery procedure; N3 target/text/selectors and owned install metadata/
binary; N4 resolver/callers/fixtures (no data migration to reverse); N5 coordinated
operations/docs/selectors. Never reset whole repos or others' edits. If N4 rolls
back while N3 stays, bitbid temporarily uses old names/paths as the staged
sequence already does; final release requires all N5 gates. No commits/push/
publication/deployment implied. Live chain/IPFS, hosted CI and external release
need actual authorized runs before being claimed.
