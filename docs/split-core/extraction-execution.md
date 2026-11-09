# Next core/adapters extraction execution contract

**Status: agreed 2026-11-09. The user chose “go with recommendation for all 4 questions”.**

Decision: [Lock the next core and adapters extraction execution contract](https://github.com/igmrrf/clienv/issues/26), claimed by `igmrrf` on 2026-11-09. This is the only decision being worked this session. [Source inventory](extraction-inventory.md) contains factual traces and a reproduced baseline defect; [candidate tickets](extraction-candidates.md) are drafts without tracker identities. All four recommendations received an explicit live answer; no other decision is resolved by that answer.

## Baseline and delivery boundary

Native `ec659bacef56555bbbbd65a9b22521b6e56dcff1`; web `149e8d48415e85b68d859abd6727181f94ee4e9e`. N1–N5, topology/errors/ports/registry read/BlockingRpc, facade consolidation and Homebrew cleanup are locally delivered even when historical tracker issues remain open. Native Homebrew correction and pre-existing `.DS_Store` must be preserved; web starts clean. Current product is Yew CSR.

No commit, push, publication, deployment, global install mutation or live-provider mutation is authorized. Every future implementation ticket uses a separate Codinary run: captured baseline, fresh implementer, independent current-source review, meaningful tests and actual applicable runtime evidence; at most two fix cycles. No future implementation is claimed here.

Preserve protocol/token/on-chain/cryptographic bytes, KDF, schemas, wallet data, supported aliases through 0.x, selected-path revalidation, redacted warning bytes/frequency, stdout/exits and current per-record request ordering. No silent migration, merge, deletion or automatic wallet rewrite. Existing synchronous ports and Host remain unchanged in the recommended plan. Test endpoints are constructor/test injection, not new deployable environment settings.

## Q1 — Store and list (agreed)

Recommendation: a complete explicitly mapped native blob Store, plus a pure core list policy with typed enumeration and a reader callback. Do not move native persisted network-config/credential schema into core or freeze configuration at command startup. Snapshot behavior would lose current revalidation and can mismatch the registry with a preconstructed RPC endpoint.

### Filesystem Store interface

- New native-only `bitbid-adapters::store::FileStore`, constructed from explicitly supplied `StoreKey`/path bindings. Initially only NetworkConfig and SecretIndex are mapped. No environment/home/cwd selection or guessed parent creation; CLI resolves/revalidates each accessor when reached, then supplies that accessor's path.
- All four methods work for every mapped key. Every method on an unmapped key returns existing `StoreError::Io` with fixed safe `unconfigured store key`; never ordinary absence, success, a no-op or a panic. No new error variant is necessary. Public error projections never include paths, payloads or credentials.
- `read` returns exact bytes; missing target is `Ok(None)`. `exists` agrees with readable blob presence: missing/dangling target false, directories/non-file targets fail Io, metadata/access denial fails PermissionDenied. Existing valid final symlink reads follow the target, matching current readers; errors remain typed.
- `write(create_new=true)` atomically refuses an existing entry, including symlinks, with AlreadyExists. Never precheck then overwrite. Unix final-component symlinks are refused for ordinary writes too; parent symlinks retain current support. No recursive mutation. Private writes enforce descriptor permissions before data/truncation, create mode0600 and fail on inability to enforce privacy; ordinary new writes honor umask and existing modes remain unless private is requested. Open without truncation, validate file type/privacy, then truncate/write. A later partial I/O failure can leave partial data: no atomic-replace/fsync guarantee is invented.
- `remove` unlinks only the configured entry; absent succeeds; a symlink entry is removed without following its target; directory removal fails Io; permission denial is typed. No parent cleanup.
- Host-specific private semantics must be implemented or fail explicitly; Unix evidence does not establish Windows ACL support. Initial local acceptance targets the available macOS host plus shared native/WASM consumers; future supported distribution-host qualification remains with the publication contract.
- CLI selected-list accessors retain path-selection failures as fatal ConfigError. After selection, network-config file read/UTF-8/JSON/schema failure still defaults; index failures still yield an empty BTreeMap. That fallback belongs to the native decoder, not FileStore. Initially no CLI write/remove is switched. Wallet, project-config and cache mappings are not implicitly available.

### Pure list policy interface

Agreed `bitbid_core::registry_list::{ListQuery, list_indexed}`:

```rust
pub struct ListQuery<'a> {
    pub user_address: &'a str,
    pub filter_user: Option<&'a str>,
    pub all: bool,
    pub expired_only: bool,
    pub active_only: bool,
}
pub fn list_indexed<'a, E>(
    entries: impl IntoIterator<Item = (&'a str, bool)>,
    query: ListQuery<'_>,
    read: impl FnMut(&str) -> Result<Option<RegistryInfo>, E>,
) -> Result<Vec<(String, RegistryInfo)>, E>;
```

This extracts policy; the callback composes the existing Host, without adding an I/O port. CLI keeps persisted index schema/decode, path selection, prompts, wallet unlock, native errors/warnings and formatting. Typed inputs retain original ID and enumeration-time hidden flag; rows retain original ID and all eleven RegistryInfo facts. Native wrapper converts back to its existing projection.

Order is contractual: enumerate BTreeMap once; for each ID call the reader before filtering; reader reloads network config, pairs its endpoint+registry, performs the existing single eth_call/latest, and after success reloads index for hidden/path-validation effects. Callback propagates ConfigError, immediately warns/skips other failures via Ok(None). Never defer warnings until the end. Filter on enumeration hidden, preserve case-insensitive strings including `--user public`, existing ownership/public policy and expiry = expired OR limit_reached OR revoked. Apply expired_only then active_only; both may legitimately yield none. Preserve `[]`/exit0, output hidden:false and original IDs. Empty enumeration touches no network configuration/RPC. No Store/IPFS/Clock/Random access is added to registry_read.

Only selected `blockchain::list_registry_secrets` switches. Legacy `list_secrets_with`/`list_secrets_on_chain` used by hide remains unchanged. No hide/write cutover is implied.

## Q2 — IPFS byte and text ownership (agreed)

Recommendation: preserve the byte port; add a native compatibility text/cache wrapper. This explicitly refines the older partition's proposed core cache placement for the next cutover because current HTTP text decoding depends on response charset/BOM and differs from strict cache UTF-8. No public port change is recommended.

- Native raw transport implements current `Ipfs::add(bytes,name)` and `cat(cid)->Vec<u8>` honestly; arbitrary bytes are not secretly text-decoded/reencoded. Native constructors receive selected configuration and optional validated credentials. No env access inside adapters. Tests exercise bytes/name/route/multipart/headers exactly; existing JSON upload text multipart remains byte-identical through its compatibility wrapper.
- Native `IpfsCompatibility` owns current upload/fetch fallback and text/cache policy for this cutover, with injected native transport/client/cache paths and existing selection hooks. CLI `upload_to_ipfs`/`fetch_from_ipfs` delegate only after the same lazy selection point. No second, disconnected production transport is acceptable: raw and compatibility methods share HTTP request construction, but preserve their distinct response decoding.
- Preserve config-first/new/legacy JWT precedence, blank-disable/header validation, warning budget, 15-second client, Pinata then Kubo upload, exact successful-invalid-CID immediate error, and cache resolution failure versus ignored cache-write I/O distinction.
- Fetch order remains CID validation → config selection → cache path → strict UTF-8 cache → Kubo → configured gateway → ipfs.io → dweb.link. HTTP text retains pinned reqwest charset/BOM/replacement behavior; non-success/request/decode errors fall through. CID policy stays 2..64 ASCII alphanumeric, not a new CID standard. Cache key stays lowercase SHA256(CID bytes) plus `.json`; cache hits still perform prior config/path selection.
- Core can share pure CID validation. A future move of cache policy into core must preserve the decided text contract through an explicit metadata/text seam; it is retained follow-up work, not a claimed current extraction or permission to change ports silently.
- Pinata fixed endpoint/public fallbacks must be injectable for local trap tests without new production env names. All test requests stay loopback. Status/body diagnostics must be redacted; preserve existing safe public classifications, never propagate a credential/payload into logs.

Rejected alternative in Q2: explicitly approve an additive public text operation and core-owned cache policy. The native wrapper was selected; no public text-operation addition is authorized.

## Q3 — Wallet and signing scope (agreed)

Recommendation: separate codec, read/unlock and init runs; explicitly repair the reproduced malformed-nonce abort in the codec run; extract signing bytes before a revoke-only transaction run.

- Core wallet codec owns the pure current KDF/encryption/decryption/manual serialization/mnemonic/key/address transforms. Freeze the current lockfile-backed Argon2id settings, short-salt SHA256 expansion, standard-base64 `salt:nonce:ciphertext`, AES256GCM salt16/nonce12, BIP39/BIP44 path, escaping/field ordering and all valid bytes. RandomSource supplies entropy; deterministic adapters exist only in tests. Production OS entropy failure stops; no deterministic fallback.
- Exact current KDF: argon2 0.5.3, Argon2id v0x13, m19456KiB/t2/p1/output32, no secret/ad; salt shorter than8 is SHA256-expanded. Encrypted fields use standard padded base64, GCM tag16 and no AAD. Retain existing zeroizing guards; current passwords, KDF/seed temporaries and initial plaintext allocations are only partially protected, so complete zeroization is not an inherited guarantee. New secret-owning types must avoid Debug disclosure and unnecessary copies.
- Proposed explicit correction: reject a decoded nonce length other than12 with a sanitized existing wallet/native error projection, rather than generic-array SIGABRT. Preserve valid encrypted/plain schema and wrong-password behavior. Add baseline-failing synthetic regression and public native/WASM negative tests. This is an intentional scoped fix, not a claim that extraction alone preserves the panic. If human chooses isolation, create the separate fix dependency before wallet extraction.
- Read/unlock uses explicitly mapped Wallet storage, parses without write/chmod/time/random access, preserves bytes/mode/last_accessed/key data and current errors. Missing password, missing wallet, malformed JSON/base64/UTF-8, invalid key and wrong-password remain safe; passwords/private data stay in zeroizing scopes where currently supported. Current zeroization is partial; do not promise historical complete zeroization or log WalletInfo Debug.
- Initialization is a separate deliberate write cutover with injected Store/Clock/RandomSource. Missing password without plaintext opt-in fails before app lookup; current overwrite gate is config.json presence, not wallet.json. One timestamp populates current fields. Wallet then config remain sequential writes with current partial-failure semantics, not a promised two-file transaction. Preserve current private modes/no-follow leaf rules, schema/bytes and prompts/output. Atomic pair initialization is a separate explicitly proposed hardening follow-up, not bundled silently.
- Pure signing exposes the current legacy/type2 signed-byte operations through core. Freeze full exact signed hex, chain IDs, nonce/value/fee/gas fields, selectors/addresses and empty access list before moving. Native library helpers keep compatibility wrappers; no global call-site rewrite.
- First transaction cutover: `main` revoke → `secrets::revoke_secret` → `blockchain::revoke_secret_on_chain` → shared transaction orchestration over Rpc/Clock. It needs wallet read and selected network config/RPC, not IPFS/index writes. Other callers remain on their old sender until their own tickets.
- Preserve pending nonce→estimateGas×12/10 saturating→latest base fee→priority fallback/type2 or gasPrice/legacy→raw submission→receipt order; exact JSON envelope/id and HTTP/JSON/error behavior must be characterized against old eth::rpc before reusing BlockingRpc. Receipt has60 attempts and a2-second sleep for every null including final null; no new retry policy. Missing/nonstring status defaults success; exact0x0 reverts; RPC error aborts. Tests use memory Rpc/Clock and loopback CLI, never a provider.

Share/view/record-read/hide/materialize lifecycle orchestration remains included in the roadmap, with exact later slices created only when their own cutovers can be specified. A successful revoke cutover does not mean all signing/lifecycle callers moved.

## Q4 — Initialization's separate wallet config key (agreed)

`wallet.json` maps to Wallet; initialization also writes `config.json`, distinct from `network-config.json`. Current StoreKey has no WalletConfig variant. Recommendation: explicitly add `StoreKey::WalletConfig` only in the initialization ticket, wire its resolved path there, and preserve sequential wallet/config writes. This keeps synchronous method signatures but expands a public enum; review exhaustive downstream matches and compile public native/WASM/facade consumers. Never overload NetworkConfig or ProjectConfig. The alternative of leaving the key unspecified was not selected. To preserve historical best-effort chmod failure behavior, initialization uses an explicitly documented native compatibility Store writer with all mapped methods, delegating the existing secure-write semantics; it does not silently weaken FileStore's stronger private-write guarantee. Extract that writer rather than change failure behavior or claim two-file atomicity.

## Separate roadmap decisions and resolution procedure

[Rebase the SSR execution decision on the shipped Yew and shared core](https://github.com/igmrrf/clienv/issues/27) remains open/unclaimed, natively blocked only by its closed SSR research/secret-handling prerequisites. Its conditional implementation waits for a different HITL session; CSR compatibility is required. [Choose publication channels and the release verification contract](https://github.com/igmrrf/clienv/issues/28) stays open/unclaimed and unblocked. Channel selection precedes preparation; external publication additionally needs action-specific authorization. Native channels need not depend on SSR unless selected.

The explicit answer confirms shared understanding of Q1–Q4. Record one resolution comment, close this decision, append its gist/link to the map, and create precise normal implementation issues from the candidates. Create before wiring native blocking relationships; never treat local N-labels or candidate letters as GitHub identities. Preserve all other claims and historical open/completed states. Only actual unblocked implementation tickets are ready; historical open/completed issues are not repeated.

No new deployable setting is needed by this plan. Future newly required settings must be recorded in encrypted `secrets/prod.enc.yaml` with preserved values and safe unset/demo policy. Actual session gate: `SOPS_AGE_KEY_FILE=/Users/igmrrf/.config/sops/age/charmedly-demo.txt make -C bitsec secrets-catalog-check secrets-report`; status/name output only. No secret/private material goes in docs, issues or evidence.
