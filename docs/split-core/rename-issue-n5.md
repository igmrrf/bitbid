# Integrate rename across operations and local release verification

Normal implementation issue; decision [#13](https://github.com/igmrrf/clienv/issues/13),
map [#3](https://github.com/igmrrf/clienv/issues/3). Depends on reviewed N1
[execution contract](rename-execution.md) and completed N3/N4 (including N2).
Serialize after their overlapping CLI/tests/docs edits.

Owner: native current operational docs/metadata, CI/e2e/helper/probe selectors,
packaging examples and relevant sibling facade docs/metadata. Current examples
must select package bitbid-cli/bin bitbid. Rename test-only BSEC_E2E* to
BITBID_E2E* across tests/scripts/CI/coordination wrapper together, **no test-only
aliases**. Keep guard package lookup correct and both valid negative probes.
Classify remaining bsec hits as kept wire/crypto/contract, deliberately supported
legacy aliases/type compatibility or historical docs. Do not mass-replace history
or advertise unpublished distribution artifacts; verified repository is clienv,
homepage omitted unless separately verified.

Acceptance is [N5-AC1–N5-AC6 and N5-V1–N5-V8](rename-acceptance.md). Run native
workspace tests/strict Clippy/coverage/actionlint, executed core WASM/public
consumers and facade tests, positive+negative boundary probes; actual final
release and fresh/upgrade installed bitbid help/completion/offline canonical+
legacy+malformed and full 54-case synthetic RPC journeys with isolated state
invariants. Actual final encrypted settings completeness/unset-demo gates and
all-source disabled Pinata proof must pass.

Build and serve the optimized Trunk Yew bundle; use an actual browser for fresh
seal→open, frozen canonical/legacy, malformed→recovery, keyboard, reload and both
directions of installed CLI↔browser token interoperability. Inspect desktop/narrow
screenshots, Console and Network from exact final bundle. Compile-only/Node tests
do not replace this. Record baseline tool diagnostics honestly, stop task-owned
services/browser sessions, preserve user sessions/work/.DS_Store/handoff.

Use Codinary implementation→independent review with every stable ID/full logs,
both source/lock/build/install/bundle identities and actual limits. Document
binary cutover, aliases through 0.x/removal at 1.0, manual legacy uninstall and
scoped rollback. Rollback only owned coordinated operations/selectors/docs;
never reset repos or migrate data. Local release/install only; no commit/push,
registry publication, deployment, hosted CI or live chain/IPFS claim implied.
