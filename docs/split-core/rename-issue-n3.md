# Implement canonical bitbid executable and CLI identity

Normal implementation issue; decision [#13](https://github.com/igmrrf/clienv/issues/13),
map [#3](https://github.com/igmrrf/clienv/issues/3). Depends on independently
reviewed N1 [execution contract](rename-execution.md); eligible while N2 is
externally blocked. Blocks N4; serialize overlapping CLI ownership with N4/N5.

Owner: `crates/bitbid-cli/Cargo.toml`, entry/errors/usage/completion/staging
identity and necessary binary-selector tests. Package bitbid-cli and core/adapter
topology already shipped; no new moves. Produce only bitbid, **no bsec binary
alias**. Keep old runtime env/path names and IPFS credential hint until N4.
Repository metadata exactly https://github.com/igmrrf/clienv; omit unverified
homepage, never invent domains or rename external resources.

Acceptance is [N3-AC1–N3-AC5 and N3-V1–N3-V7](rename-acceptance.md): exact N1
help/version/banner/completion/error-hint substitutions; canonical BitbidError
with local BsecError type compatibility; unchanged flags, successful machine
stdout, command-specific failure exits, typed/fallback mappings and crypto/wire
bytes. Preserve invalid-mnemonic init's banner. Fresh and upgraded **owned**
source-path installs must actually run and contain bitbid only; preserve unrelated
sentinels and install ownership, never remove user PATH binaries.

Run actual debug/release/installed help/version/bash+zsh/all-shell completion,
closed-stdin negative cases, canonical/legacy offline flows, full committed
54-case synthetic RPC probe and state/permission invariants. Execute workspace
tests, strict Clippy, core WASM/public consumers, facade tests and positive/valid
negative boundary probes, restoring only probes. Exact commands and negative
cases are in the linked matrix; skipped chain tests are not live verification.

Use Codinary implementation→independent review with all stable IDs/full logs
and source/lock/artifact identities. Rollback only owned target/text/selectors
and task-owned install metadata/binary. No persistent namespace/schema change,
data migration, contract rename, publication, commit/push/deploy implied.
