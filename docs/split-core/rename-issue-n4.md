# Implement environment and filesystem name compatibility

Normal implementation issue; decision [#13](https://github.com/igmrrf/clienv/issues/13),
map [#3](https://github.com/igmrrf/clienv/issues/3). Depends on reviewed N1
[execution contract](rename-execution.md), completed N2 encrypted settings gates
and completed N3 executable cutover. Blocks N5; serialize CLI/test ownership.

Owner: `crates/bitbid-cli/src/wallet.rs::get_app_dir`, IPFS credential resolver,
`project_config.rs` load/save/path, narrow callers/shared resolver/fixtures and
required catalog updates. Use graph discovery; production code is under crates,
not root src. Make caller boundaries fallible where needed; no full wallet/Store/
IPFS adapter extraction or unrelated network-config/index schema tightening.

Acceptance is [N4-AC1–N4-AC5 and N4-V1–N4-V6](rename-acceptance.md): canonical
env names first with absence-only fallback; empty/invalid/conflicting cases,
config-first JWT priority, exact redacted once/process/surface warnings; default
both/neither/invalid home rules; cwd canonical/legacy config selection, malformed/
unreadable canonical fails without old fallback or child launch; explicit save
uses selected legacy **in place**, canonical if selected/neither. No migration,
merge, deletion or namespace switch on failure. Aliases survive all 0.x until 1.0.

Run real isolated filesystem/subprocess and narrow native fixtures for all N1
negative cases, denied permissions/non-Unicode/dangling links, repeated warnings,
valid flag precedence and deliberate saves. Snapshot wallet/key/last_accessed/
index/config/alternate paths and permissions across reads/failures; no child,
auth request or data mutation on selection failure. Help/completion/offline must
not resolve/create home/project. Update IPFS credential hint now that canonical
runtime name exists. Preserve DOTENV_*, wire/crypto/contract identities and exits
outside explicitly specified configuration failures.

Actual encrypted catalog completeness/unset-demo reports cover every introduced
name. Test disabled env+config state and fake-demo rejection, canonical blank
suppresses old JWT but nonblank config still wins. Repeat native/WASM/facade/
Clippy/boundary gates plus actual release/installed offline and full synthetic
RPC journeys under canonical/legacy roots. No real credentials/services needed.

Use Codinary implementation→independent review, stable ID mapping/full logs and
source/locks/build identity. Rollback resolver/callers/fixtures only; no data
migration to reverse. No commit/push/publication/deployment implied.
