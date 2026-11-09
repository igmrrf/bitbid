# Rename surface and back-compat plan: `bsec` → `bitbid`

> Historical decision/inventory at `6a0ffb8`. Current production paths, completed
> topology/package work, exact rename/error/alias/write policy and N2–N5 criteria
> are in [rename execution](rename-execution.md) and [acceptance](rename-acceptance.md),
> which supersede execution details here. Accepted #13 no-binary-alias and
> 0.x/until-1.0 compatibility rulings remain. The 668-occurrence inventory is
> historical; distribution URLs/names below do not prove publication.

This document records the ruling from wayfinder ticket #13: the complete surface
of identifiers that change in the `bsec` → `bitbid` rename, the identifiers that
must **not** change, the back-compat/deprecation strategy, and a
line-anchored enumeration of every case-insensitive `bsec` occurrence in the
enumerated paths. It is a **decision document**, not execution: no code is
changed here and the rename is not performed.

It is consistent with `docs/split-core/workspace-topology.md` (crate names) and
`docs/split-core/module-partition.md` (module seams).

## 1. Rename table (identifiers that change)

| Current | New | Category |
|---|---|---|
| package `bsec` | packages `bitbid-core` / `bitbid-adapters` / `bitbid-cli` | crate/package name |
| binary `bsec` | `bitbid` | binary |
| `BSEC_HOME` | `BITBID_HOME` | env var (aliased, see §3) |
| `BSEC_PINATA_JWT` | `BITBID_PINATA_JWT` | env var (aliased, see §3) |
| `~/.bsec` | `~/.bitbid` | config dir (fallback, see §3) |
| `.bsec.json` | `.bitbid.json` | project config file (fallback, see §3) |
| `bsec` in user strings (banner, `--help`/about, error prefixes, usage, hints) | `bitbid` | user-facing text |
| `bsec` in README/docs/tutorials | `bitbid` | docs |
| `repository`/`homepage` metadata in `Cargo.toml` | current canonical project URL | metadata |
| `BSEC_E2E*` test-harness env vars | `BITBID_E2E*` | env var (test-only, no alias) |
| temp dir/file prefixes `bsec-*`, `bsec-stage` | `bitbid-*`, `bitbid-stage` | ephemeral path naming |
| internal Rust identifiers `BsecError` | `BitbidError` | code identifier |
| completion identifiers `_bsec`, `#compdef bsec` | `_bitbid`, `#compdef bitbid` | generated shell completion |

Distribution/package names in docs (npm `bsec-cli`/`bin/bsec.js`, `bsec.nuspec`,
`igmrrf.bsec` winget/scoop ids, docker `bsec:latest`,
`ghcr.io/igmrrf/bsec`, artifacts `bsec-<target>.*`) follow the same rename to
their `bitbid` equivalents; the canonical registry URLs/metadata are the
`Cargo.toml` metadata ruling above and are settled at execution time.

## 2. Keep table (identifiers that MUST NOT change)

| Identifier | Why it is kept |
|---|---|
| `BsecSecretRegistry` (Solidity contract, `contracts/BsecSecretRegistry.sol`, deploy/forge commands, docs) | On-chain contract name; renaming it would orphan deployed state. |
| Deployed contract address(es) | Immutable on-chain identity. |
| `b"bsec-ecdh-aes256gcm-v1"`, `b"bsec_public_secret_wrapper_key_v1"` (HKDF/domain-separation labels in `src/secrets.rs`, mirrored in `docs/from-scratch-guide/`) | On-chain/wire secret format identifiers owned by "*Lock the canonical secret format and the web envelope's fate*"; changing them breaks decryption of existing secrets. |
| `DOTENV_PASS`, `DOTENV_<ENV>_PASS` | Generic, not name-derived. |
| IPFS gateway/CID/pinning specifics (Pinata/Kubo/gateway URLs, CID inputs) | Storage-layer identity, not a `bsec` identifier. |

No case-insensitive `bsec` occurrence in the enumerated paths is left without a
ruling in §4. `webapp/` is outside the enumerated paths; it already consumes the
new `bitbid-*` naming and only retains `BsecSecretRegistry` references, which are
kept.

## 3. Back-compat strategy and deprecation window

- **Env vars (`BSEC_HOME`, `BSEC_PINATA_JWT`):** read the new `BITBID_*` name
  first; if unset and the old `BSEC_*` name is set, use the old value and emit a
  one-line deprecation warning to stderr. Keep both aliases through the current
  `0.x` line; remove the old names at `1.0`. `BSEC_E2E*` are test-harness-only and
  are renamed outright with no alias.
- **Config dir:** if `~/.bitbid` does not exist and `~/.bsec` does, use `~/.bsec`
  **in place** with a deprecation warning. No silent data move. A future explicit
  `bitbid migrate` command is out of scope for this ticket.
- **Project config:** accept `.bsec.json` as a fallback when `.bitbid.json` is
  absent, with a warning. Same precedence rule for the in-cwd file.
- **Binary:** no alias. The old `bsec` binary is simply gone at the next release.
- **Deprecation window:** all aliases live until `1.0`; the `0.x` line is the
  window. Removal is a single breaking release, documented in `CHANGELOG.md`.

## 4. Enumeration and classification (case-insensitive `bsec`)

Rulings: **R** = rename, **K** = keep, **A** = alias (new name preferred, old
accepted with deprecation warning). Line numbers are from baseline
`6a0ffb83061f8dab13137624b65cc1ec6f722ae1`.

### `bitsec/src/`

| File:line | Occurrence | Ruling |
|---|---|---|
| `project_config.rs:14` | `.bsec.json` | R → `.bitbid.json` (A: `.bsec.json` fallback) |
| `eth.rs:3` | `BsecSecretRegistry` (comment) | K |
| `env_file.rs:458` | usage `bsec run` | R (user text) |
| `wallet.rs:2,226,345,436` | `BsecError` | R → `BitbidError` |
| `wallet.rs:64` | `BSEC_HOME` | R (A) |
| `wallet.rs:65` | `bsec_home` local | R |
| `wallet.rs:72` | `.bsec` config dir | R (A: `~/.bsec`) |
| `errors.rs:5,43,47–52,59,67–77` | `BsecError` enum/impl/tests | R → `BitbidError` |
| `errors.rs:6` | `'bsec init'` in message | R (user text) |
| `main.rs:20` | clap `name = "bsec"` | R → `bitbid` |
| `main.rs:23` | `long_about` "bsec is a CLI…" | R (user text) |
| `main.rs:73` | `BsecSecretRegistry` (doc comment) | K |
| `main.rs:414` | banner `BSEC` | R → `BITBID` (user text) |
| `main.rs:461–462` | `BsecError` | R → `BitbidError` |
| `main.rs:514` | completion bin name `"bsec"` | R → `bitbid` |
| `main.rs:720,747` | `bsec view` / `bsec materialize` hints | R (user text) |
| `blockchain.rs:1` | `BsecSecretRegistry` | K |
| `blockchain.rs:5` | `~/.bsec/secret_index.json` | R (A: `~/.bsec`) |
| `ipfs.rs:41` | `BSEC_PINATA_JWT` lookup | R (A) |
| `ipfs.rs:140` | error text `BSEC_PINATA_JWT` | R (message follows new name) |
| `network_config.rs:13` | doc `BSEC_PINATA_JWT` | R |
| `secrets.rs:126,249,386` | `b"bsec-ecdh-aes256gcm-v1"`, `b"bsec_public_secret_wrapper_key_v1"` | K (wire format) |
| `secrets.rs:211,365,374,379` | `BsecError` | R → `BitbidError` |
| `materialize.rs:431,438` | temp prefix `bsec-…` | R → `bitbid-…` |
| `materialize.rs:992` | test `"bsec-stage"` | R → `bitbid-stage` |

### `bitsec/Cargo.toml`

| File:line | Occurrence | Ruling |
|---|---|---|
| `2` | `name = "bsec"` | R → `bitbid-core`/`-adapters`/`-cli` + `bitbid` bin |
| `8` | `homepage = "https://bsec.dev"` | R → canonical URL |
| `9` | `repository = "…/igmrrf/bsec"` | R → canonical URL |

`Cargo.lock:270` (`name = "bsec"`) is generated and not in the enumerated paths;
it regenerates on the next `cargo` build after the manifest rename. Noted for
completeness.

### `bitsec/README.md`

All 54 occurrences rename: title `# BSEC` → `# BITBID`; every `bsec` command,
prose reference, and `./target/release/bsec` path → `bitbid`. The
`BsecSecretRegistry` mentions (lines 34) are **kept**. Ruling: R (docs), K for
contract references.

### `bitsec/tests/`

| Cluster | Ruling |
|---|---|
| `Command::cargo_bin("bsec")` (all files) | R → `"bitbid"` |
| `fn bsec` test helper + call sites (`materialize_tests.rs:36,44,77,125,133,167,176,184,203,210,234,241,262,269,274`) | R → `fn bitbid` (internal identifier) |
| `BSEC_HOME` env calls (`wallet_tests.rs:24,47,57,82,92,113,122`; `encryption_tests.rs:67,81,114,126`; `env_file_tests.rs:85,94`; `secrets_tests.rs` many; `config_and_cli_tests.rs:26,42,146,157,171,184,205`; `materialize_tests.rs:39`) | R → `BITBID_HOME` |
| `BSEC_E2E`, `BSEC_E2E_RPC`, `BSEC_E2E_REGISTRY`, `BSEC_E2E_IPFS_GATEWAY`, `BSEC_E2E_FUNDER` (`materialize_tests.rs:12,21,29,65–74`; `secrets_tests.rs:20,22,30,38–47`) | R → `BITBID_E2E*` (test-only, no alias) |
| `.bsec.json` (`env_file_tests.rs:197,199,207,208`) | R → `.bitbid.json` (A fallback) |
| `//!` flow comments naming `bsec <cmd>` (all files) | R (docs/comments) |
| `bsec_parse_env_helper` (`env_file_tests.rs:229,233`) | R → `bitbid_parse_env_helper` |
| `_bsec` completion assert (`config_and_cli_tests.rs:116`), `#compdef bsec` (`:131`) | R → `_bitbid` / `#compdef bitbid` |
| `BsecSecretRegistry` in comment (`materialize_tests.rs:71`) | K |

### `bitsec/scripts/e2e-setup.sh`

| Line(s) | Occurrence | Ruling |
|---|---|---|
| `2,3,6,30,51` | comments/echo naming `bsec` | R (docs/user text) |
| `44,46` | `BsecSecretRegistry` deploy | K |
| `16` | `BSEC_HOME`, `BSEC_E2E` | R → `BITBID_HOME`, `BITBID_E2E` |
| `23` | `BIN="./target/release/bsec"` | R → `bitbid` |
| `24` | `BSEC_HOME` / `~/.bsec` default | R (A) |
| `56,57` | `/tmp/bsec-init.txt` | R → `/tmp/bitbid-init.txt` |

### `bitsec/.github/workflows/ci.yml`

| Line(s) | Occurrence | Ruling |
|---|---|---|
| `75,81` | `BsecSecretRegistry` deploy step + forge create | K |
| `88` | comment `BSEC_HOME` | R → `BITBID_HOME` |
| `92–96` | `BSEC_E2E`, `BSEC_E2E_REGISTRY`, `BSEC_E2E_RPC`, `BSEC_E2E_IPFS_GATEWAY`, `BSEC_E2E_FUNDER` | R → `BITBID_E2E*` |

### `bitsec/docs/`

Ruling: **R** (docs) for every prose/command/reference to `bsec`, `BSEC`, the
project URLs, and distribution names; **K** for `BsecSecretRegistry`, deploy
commands/addresses, and the two crypto domain-separation labels; **A** for
`.bsec.json` / `~/.bsec` path references.

| File | Notable occurrences and ruling |
|---|---|
| `README.md` | title `BSEC`, `bsec` crate/CLI, npm/docker refs → R; `BsecSecretRegistry.sol` → K |
| `binary_releases.md` | `bsec` binary, artifact names `bsec-*.tar.gz`/`.zip`, `target/.../bsec` → R |
| `docker.md` | image/`WORKDIR`/`ENTRYPOINT`/tags `bsec`, `ghcr.io/igmrrf/bsec`, `bin` paths → R |
| `linux_packages.md` | deb/rpm artifact `bsec`, `usr/bin/bsec`, AUR `pkgname=bsec`, URLs → R |
| `npm.md` | package `bsec-cli`, `bin/bsec.js`, `@bsec/*`, URLs → R |
| `smart_contracts.md` | `bsec` CLI commands/wallet → R; `BsecSecretRegistry` deploy/address → K |
| `windows_packages.md` | winget/choco/scoop ids (`igmrrf.bsec`, `bsec.nuspec`, `bucket/bsec.json`) → R |
| `cargo.md` | publish/install `bsec`, `name="bsec"`, `homepage=bsec.dev`, `repository=.../igmrrf/bsec`, stale `tmp/bsec` link → R |
| `homebrew.md` | `Formula/bsec.rb`, `class Bsec`, `brew install bsec`, tap/URLs/`bsec-mac.tar.gz` artifacts → R |
| `security_audit.md` | `BsecSecretRegistry.sol` audit scope/report/forge → K; `bsec config --network` CLI → R |
| `superpowers/plans/2026-08-02-secret-file-materialization.md` | prose `bsec` secret → R |
| `superpowers/specs/2026-08-02-secret-file-materialization-design.md` | `bsec` flow/CLI prose, `BSEC_E2E` → R (test-only, no alias), `<tmp>/bsec-<random>/` → R |
| `superpowers/specs/2026-08-02-real-onchain-ipfs-design.md` | `~/.bsec/secret_index.json` → R (A fallback); `BSEC_PINATA_JWT` → R (A); `BsecError` → R; `BsecSecretRegistry` → K; `QmBsecMock` mock CID prose → R |
| `research/deps-wasm-matrix.md` | `bsec` crate/deps references → R |
| `research/core-adapter-prior-art.md`, `research/leptos-ssr-contract.md` | `bsec` CLI → R |
| `split-core/module-partition.md:32,33` | `~/.bsec/network-config.json`, cwd `.bsec.json` → R (A fallback) |
| `split-core/workspace-topology.md:4` | `bsec` → `bitbid` (already frames rename) → R |
| `from-scratch-guide/README.md` | title/prose `bsec` → R; `BsecSecretRegistry.sol` → K |
| `from-scratch-guide/01_PREREQUISITES_AND_PROJECT_SETUP.md` | `cargo new bsec`, `name="bsec"`, `BsecError` → R; `BsecSecretRegistry.sol` → K |
| `from-scratch-guide/02_CRYPTOGRAPHY_AND_WALLET.md` | `BsecError`, `BSEC_HOME`, `.bsec` → R |
| `from-scratch-guide/03_ENV_PARSING_AND_COMMAND_INJECTION.md` | `bsec run` usage, `.bsec.json`, temp `bsec-*`/`bsec-stage` → R |
| `from-scratch-guide/04_STORAGE_AND_BLOCKCHAIN.md` | `BSEC_PINATA_JWT`, `~/.bsec` → R; `BsecSecretRegistry` → K |
| `from-scratch-guide/05_SMART_CONTRACT.md` | `BsecSecretRegistry` title/contract/forge/address → K |
| `from-scratch-guide/06_SECRET_SHARING_AND_VIEWING.md` | crypto labels `b"bsec-*_v1"` → K; `BsecError` → R |
| `from-scratch-guide/07_CLI_INTERFACE_AND_TESTING.md` | `name="bsec"`, banner `BSEC`, `BsecError`, completions, hints → R; `BsecSecretRegistry` → K |

Stale `file:///Users/igmrrf/Desktop/tmp/bsec/...` and `/Users/igmrrf/Desktop/tmp/bitsec/...`
links inside `linux_packages.md`, `binary_releases.md`, `README.md` and the
`from-scratch-guide/` are updated as part of the path/`tmp` cleanup; they carry
no separate ruling beyond R (docs).

## Out of scope

Performing the rename; editing any code or existing doc; a `bitbid migrate`
command; committing. This ticket produces this document only.
