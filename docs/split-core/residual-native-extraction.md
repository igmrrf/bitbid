# Accepted remaining native extraction execution contract

Decision: [Specify remaining native lifecycle, configuration and shared-cache extraction cutovers](https://github.com/igmrrf/bitbid/issues/48). **Q11 and final shared understanding accepted on 2026-11-11.** R1–R14 are local cross-reference anchors for the fourteen actual normal continuation issues and exact scopes below. This adopts the execution contract and records those issues; implementation and release actions remain separate.

Current checkpoint: native `a43a805`, webapp `170f293`, static web `803fce9`; all use `git@github.com:igmrrf/bitbid.git` with independent `main`, `webapp/main` and `web/main` remote branches, histories and locks. Only primary worktrees remain after verified cleanup. Alias removal47 is completed at `b0a6b62`; there is no active isolated47 integration to finish. Protocol50 remains independently owned frozen unfinished committed WIP at native `92c75ea` / webapp `12ff9d7`; preserve its original18-native/5-web source/ownership checkpoint and do not resume or overwrite it. Refresh source/claims before each implementation. Historical graph-first native inventory `/tmp/bitbid-decisions-native-inventory.md` is evidence of the original plan, not a substitute for a current implementation baseline. Completed Store29/list30/codecs32/read33 are retained, not repeated. Existing [IPFS31](https://github.com/igmrrf/bitbid/issues/31), [init34](https://github.com/igmrrf/bitbid/issues/34), [signing35](https://github.com/igmrrf/bitbid/issues/35), and [revoke36](https://github.com/igmrrf/bitbid/issues/36) remain actual open first-slice tickets with their identities/scopes; references below to completed31/35/36 mean their required future delivered interfaces, not a claim that their present open scopes are already implemented.

## Accepted ruling

Keep synchronous Store/Ipfs/Rpc/Clock/RandomSource and Host fields unchanged. Share pure transforms/policy and selected lifecycle ordering through narrow, operation-specific lazy callbacks; do not snapshot native config at startup or add a blanket lifecycle I/O port. Native configuration selection, credentials/persisted deployment schema, path identity, warning/error projection, output paths, terminal/process/staging/signal handling stay native. Byte IPFS remains honest bytes; CLI text keeps pinned charset/BOM/replacement semantics. Native compatibility writes retain historical secure-write/best-effort permission behavior; stronger FileStore is not weakened. Two explicitly named safety corrections require failing baseline evidence: env nonce length and legacy ABI pointer decoding. Atomic wallet/config pair initialization is a separate **unselected hardening proposal**, not part of init34 or these normal candidates.

All future runtime acceptance is **canonical-only on completed47**: BITBID_HOME, BITBID_PINATA_JWT, ~/.bitbid and .bitbid.json. Removed legacy inputs get negative/inert fixtures, never supported fallback journeys. This supersedes older0.x alias assumptions in historical extraction documents; immutable protocol/contract/crypto labels remain unchanged. New work begins from the actual owner-reconciled baseline, preserving frozen unfinished50 and the delivered47 canonical-only behavior. Quiescence/source ownership is the gate; completion of the50 feature or closing its issue is not required for unrelated nonoverlapping work.

## Common implementation, interface and evidence contract

Each normal ticket gets a separate Codinary run, captured source/lock/Git/artifact baseline, focused implementer, independent current-source review, required tests/runtime proof and its own local scoped commit(s). Use max two fix cycles and record remaining findings explicitly. Stage only owned files/hunks; preserve .DS_Store, private files, other tickets and extra web checkout. Root current handover and tracker completion must identify commit(s) and exact proof. No missing/skipped required result counts as PASS.

Common gates **V1–V5**:

- **V1:** both Git states/claims/source and separate locks, explicit owned diff including new files, unrelated bytes/modes preserved, final source/artifact/install fingerprints, independent review against ACs. No protocol/KDF/token/schema/on-chain change except the two named malformed-input corrections.
- **V2:** native locked workspace tests/all features and strict Clippy/all targets/all features; focused meaningful expected-value/differential cases below. Coverage tooling only where changed branches remain unproven; no invented percentage threshold.
- **V3:** public native and actually executed WASM consumers for new shared APIs, lock-matched bindgen runner per repository; web facade tests and actual core dependency guard/affected controlled negatives. An unchanged UI route needs no invented browser claim; an actual web-flow change requires optimized Trunk build plus desktop/narrow interaction and Console/Network proof.
- **V4:** current release and fresh owned locked/offline path-installed executable, closed stdin, synthetic owned homes/files, loopback-only services, exact stdout/stderr/exits/RPC order and file hashes/modes. Explicit binary paths avoid a stale user install. No new deployed test endpoint variables: constructor/fixture injection redirects every fallback. Gated BITBID_E2E skips do not prove service journeys; use always-executed local oracles.
- **V5:** actual encrypted environment completeness and redacted unset/demo report with the existing decrypt workflow; no new setting planned. Any newly required deployable setting must be recorded in encrypted prod.enc.yaml without exposing values. Clean up only owned fixture services/files. Existing external publication/provider limits remain.

Core interfaces take explicit values and bounded typed errors, not anyhow/native env/path schemas. Native callback errors retain native identity E and error/exit projection. New secret-owning types/captures have no Debug/Clone disclosures and retain existing zeroizing guards; no complete process-memory-erasure claim. Native code resolves/revalidates at each old accessor. Per-transaction context pairs one selected chain_id/registry with the matching Rpc; separate transaction/read phases may reselect independently. Reuse actual completed35/36 APIs; do not invent a second sender.

Recommended operation signatures, names illustrative within fixed semantics:

- `parse_duration(&str)->Result<u64,DurationError>`, `resolve_recipient(to,own_address,own_public_key)->Result<Option<PublicKey>,RecipientError>`, `derive_secret_id(sender,recipient,now,nonce:u64)->String`.
- `check_view_policy(facts,viewer,now: impl FnOnce()->u64)->Result<(),ViewPolicyError>` calls now only after identity and revoked checks. Facts preserve original rendered sender/recipient strings, public/revoked, expiry and counters; viewer borrows address/public key/user_address.
- `view_payload_with(request, callbacks)->Result<IpfsPayload,LifecycleError<E>>` lazily invokes read_info(id), unlock(), policy-time(), fetch_text(cid), record_read(key,id), note_index(id,role), in that order; callbacks supply existing native selection/error boundaries. `share_secret_with` similarly receives explicit ShareRequest plus callbacks for time, unlock, upload_text, random_id_nonce, register and note, preserving its different source order below.
- Callback aggregates are narrow operation inputs, not extra Host fields. Error display/source chains must not retain arbitrary secret-bearing diagnostics. Native wrappers preserve existing safe/concrete projections.

## Fourteen bounded normal continuations

| Local anchor | Actual normal continuation |
| --- | --- |
| R1 | [Extract pure environment parsing, rendering and child-variable policy](https://github.com/igmrrf/bitbid/issues/65) |
| R2 | [Extract pure materialization and file-metadata transforms](https://github.com/igmrrf/bitbid/issues/66) |
| R3 | [Extract env-file codecs and explicitly reject malformed nonce lengths](https://github.com/igmrrf/bitbid/issues/67) |
| R4 | [Cut over native network configuration through compatibility storage](https://github.com/igmrrf/bitbid/issues/68) |
| R5 | [Cut over native secret-index storage and share typed mutations](https://github.com/igmrrf/bitbid/issues/69) |
| R6 | [Extract identity-guarded project configuration access into native adapters](https://github.com/igmrrf/bitbid/issues/70) |
| R7 | [Extract shared text-cache policy while isolating raw IPFS bytes](https://github.com/igmrrf/bitbid/issues/71) |
| R8 | [Share legacy registry-info decoding and explicitly reject malformed ABI pointers](https://github.com/igmrrf/bitbid/issues/72) |
| R9 | [Cut over recordRead transaction callsite to the shared sender](https://github.com/igmrrf/bitbid/issues/73) |
| R10 | [Cut over share registration transaction callsite and post-receipt index note](https://github.com/igmrrf/bitbid/issues/74) |
| R11 | [Extract authorized view/read-recording lifecycle and env projection](https://github.com/igmrrf/bitbid/issues/75) |
| R12 | [Extract share preparation, ID derivation and registration lifecycle](https://github.com/igmrrf/bitbid/issues/76) |
| R13 | [Extract local-hide orchestration and retire only its legacy list composition](https://github.com/igmrrf/bitbid/issues/77) |
| R14 | [Extract native materialization composition while preserving staging/process boundaries](https://github.com/igmrrf/bitbid/issues/78) |

### R1 — Extract pure environment parsing, rendering and child-variable policy

**Ownership:** new core env-transform module/export and public native/WASM consumers; native env_file pure wrappers/callers, focused facade export/consumer only if needed. No process/fs/password selection or protocol-core implementation edits. **Depends:** shipped core topology only; serialize export overlap with50.

**ACs:** (1) parse_env_content/parse_json_content preserve BTreeMap order, duplicate last-wins, export prefix, quote escape replacement order, comments/whitespace/empty keys, nonobject JSON empty map and nested JSON rendering. (2) pure convert/template/schema-completion transformations accept explicit format/affix/embed/text inputs and preserve exact bytes/newlines; native read/write/printing order remains. (3) safe_env_name and current blocked-name set preserve exact ASCII/case-insensitive policy; no new dotenv parser or escaping/security policy change. (4) real convert/template/validate/run callers delegate to these exports.

**Proof:** V1–V5; frozen expected fixtures for env/JSON/nested/scalar/duplicates/quotes/comments, JSON/YAML/env/embed/prefix/suffix/template/missing-key output, blocked-name negatives and allowed names. Actual canonical-only CLI convert/validate/template and child-env synthetic journeys prove output bytes/file modes/exit and no unexpected child spawn. **Rollback:** shared module/export + delegating wrappers only; retain all user files and approved safety fixes.

### R2 — Extract pure materialization and file-metadata transforms

**Ownership:** core materialization transforms/export/consumers; native materialize/env wrappers. **Depends:** R1 for schema env parsing; no IPFS/sender/init prerequisite.

**ACs:** (1) move parse_kind/format, decode_body, sniff/resolve-format, schema extraction, default names, per-member bytes and file-kind/stem-key transforms; SecretKind/OutputFormat already shared and remain one type identity. (2) core lexical basename checks preserve exact rejection reasons; native Path component/extension/file_stem/nonUTF8 interpretation stays native and supplies explicit basename/extension/stem inputs. Do not claim WASM path behavior proves Windows filesystem qualification. (3) retain explicit-format→kind→sniff priority, schema sorted/deduplicated keys/no values, no_export and binary/schema guards. (4) expose per-item preparation only; do not eagerly prepare all bundle members or change filesystem/write order.

**Proof:** V1–V5; exact binary/base64 and malformed-encoding vectors, format/kind/sniff priority, schema errors/no values, traversal/separators/NUL/home/dot/default-name/stem cases through public native/WASM and real wrappers. **Rollback:** pure module/export/delegations only; no data rewrite.

### R3 — Extract env-file codecs and explicitly reject malformed nonce lengths

**Ownership:** pure env codec module or scoped wallet-codec reuse, env_file encrypt/decrypt/load wrappers, independent fixtures/consumers and CLI regression. **Depends:** shipped wallet codecs32; no chain/IPFS/init dependency. Reuse approved existing entropy/codec adapters where applicable; do not add a new share-crypto entropy seam.

**ACs:** (1) freeze env-specific payload trimming, salt/KDF/base64/AES-GCM/UTF8/error/output bytes independently of wallet CLI projections, preserving password-source order and default target naming natively. (2) intentional correction rejects decoded nonce length !=12 before Nonce::from_slice in **both** decrypt_env_file and load_and_parse_env; sanitized failure/no abort/no target write. (3) retain salt16/nonce12/KDF/tag/noAAD and production OS entropy/no deterministic fallback; use existing approved wallet codec interfaces where equivalent, with private deterministic test material only. crypto::seal_payload remains untouched. (4) actual encrypt/decrypt/run-load paths use shared transforms; guards avoid new plaintext copies/Debug exposure.

**Proof:** V1–V5; isolated current-binary baseline reproductions for both malformed-env paths before edits, final public native/WASM and actual release/install no-panic regressions, valid frozen decrypt vectors, wrong password/field/base64/UTF8/trim cases, exact target bytes/modes/no writes on failure. **Rollback:** codec/wrappers only while retaining the nonce-length correction; never restore known abort behavior or roll back user data.

### R4 — Cut over native network configuration through compatibility storage

**Ownership:** native adapter configuration schema/load/save/update module, complete NetworkConfig mapping in the compatibility writer, CLI network_config wrappers and all affected callers/tests/docs. **Depends:** no unfinished wallet-init feature. R4 owns the small mechanical extraction of the already-existing write_secure_file/write_secure_file_new native byte helpers into one reusable adapter support module, with unchanged CLI helper wrappers; it also owns only its complete NetworkConfig mapping/codec cutover. If another ticket already delivered that exact support API, reuse it. Do not implement34 initialization, WalletConfig, clock/entropy or its wallet Store cutover here. Serialize shared helper/export files;34 subsequently reuses the single support API rather than duplicating it.

**ACs:** (1) keep credential-bearing NetworkConfig/IpfsConfig/default URLs/serde native; load/save use explicit injected paths/Store, no env/home/cwd selection inside adapter. (2) lazy native path resolution stays at original access; post-selection read/UTF8/JSON/schema failure→full default; selection ConfigError remains fatal; save resolves path before pretty serialization and propagates errors. (3) network presets plus absent/explicit RPC override and registry/gateway/pinning patches preserve exact output/persisted bytes and key order. (4) compatibility writer preserves old secure-write/no-follow/best-effort chmod behavior; all mapped methods honest; stronger FileStore unchanged. No unintended global startup snapshot or auth request.

**Proof:** V1–V5; real config update/show, default/preset/override/malformed/denied/symlink/nonregular and missing-parent cases; native dynamic per-access selection, exact bytes/errors/exits and real permission failures. Prove no credential values in logs and no authenticated request for disabled settings. **Rollback:** selected config delegation/mapping/module only; preserve config contents, the shared compatibility support API used by other tickets and other Store readers.

### R5 — Cut over native secret-index storage and share typed mutations

**Ownership:** native index codec/load/save/composition adapter, SecretIndex compatibility mapping, tiny core typed mutation policy if needed, blockchain wrappers and probes. **Depends:** R4's reusable compatibility byte-writer support API (not network configuration data or wallet initialization). R5 adds only the complete SecretIndex mapping/native codec policy. Persisted serde schema remains native initially; no duplicate schemas. If the same support API already exists at the ticket baseline, this support prerequisite is already satisfied; do not wait for unrelated feature completion.

**ACs:** (1) retain BTreeMap string IDs and entry hidden=false/role=empty defaults/pretty serialization. Shared mutation input/output retains those exact facts. note fills role only when empty, preserves hidden/nonempty role; set_hidden inserts default if absent. (2) load/save each resolve/revalidate lazily at their old accessor; all post-path read/UTF8/schema errors→empty. (3) note/set_hidden ignore ordinary save I/O errors and propagate only native ConfigError; do not make stronger FileStore failures newly fatal. (4) selected list remains read-only, keeps enumeration snapshot and late-index reads; wallet/config/cache writers do not switch accidentally.

**Proof:** V1–V5; malformed/fallback/ordered/missing entries, role/hidden preservation, denied or failed ordinary writes versus late selection ConfigError; exact before/after bytes/modes and call order. Existing54-case list and lazy/dynamic store-list probes on actual release/install remain unchanged in ordinary behavior. **Rollback:** index-specific delegation/mapping/mutation exports only, preserving data and the shared compatibility support API.

### R6 — Extract identity-guarded project configuration access into native adapters

**Ownership:** dedicated native project-file guarded adapter plus ProjectConfig native schema/wrappers/selector interface and direct API fixtures. **Depends:** final canonical-only47 baseline for source integration; no blockchain/IPFS/init dependency. Reuse moved low-level helpers if already available; do not duplicate a generic wallet writer.

**ACs:** (1) preserve .bitbid.json-only selection, cached identity plus per-use cwd/namespace/target revalidation, fatal invalid schema/read/identity behavior and explicit-flags precedence. (2) existing valid symlink writes continue following the validated canonical target; compare prior bytes, reselected path, canonical target and Unix opened/selected dev+ino before truncation; regular-file checks and O_NOFOLLOW/O_NONBLOCK remain. (3) absent save uses create_new; successful deliberate creation updates selector identity; collision/replacement/retarget/change fails without overwriting alternate target. (4) no generic FileStore ProjectConfig mapping or invented remove capability; schema validation native, guarded byte writer receives explicit path/prior bytes/next bytes plus revalidation callback and preserves typed errors.

**Proof:** V1–V5; direct public API child-process fixtures because save currently has no production CLI, real run-config reads, absent/valid/malformed/denied/FIFO/directory/valid+broken symlink/cwd-change/namespace-change/byte-change/retarget/dev+ino/collision cases. Assert exact selected/alternate/victim bytes and modes. **Rollback:** guarded adapter/wrapper only; do not move/merge/delete project files or revive removed aliases.

### R7 — Extract shared text-cache policy while isolating raw IPFS bytes

**Ownership:** core text-cache policy/export/consumers, completed31 native text-wrapper delegation/cache binding and trap tests. **Depends:** completed31's actual byte transport and compatible text seam; reuse its established cache Store mapping. No new raw-cache production candidate is created.

**ACs:** (1) `read_through_text(store,key,fetch_decoded)` strict-UTF8 reads cached bytes; absence/read error/invalid UTF8 invokes decoded-text callback; callback failure propagates; successful text is written as UTF8 with private=true/create_new=false, write I/O ignored. (2) native CID validation→config selection→cache-path mapping stays before policy even for hits. Upload caches only after success+valid CID; path-selection failure fatal, subsequent write I/O ignored. Existing hash(CID).json namespace preserved. (3) HTTP text/fallback/charset/BOM/replacement remains native31; Ipfs.cat remains raw bytes and never consumes legacy decoded-text cache as original network bytes. No Host/Ipfs text method or production env override added. (4) shared policy is reached by real CLI text fetch/upload caching, not a disconnected helper.

**Proof:** V1–V5; loopback all fallback traps, cache hit/miss/read-denial/invalidUTF8/write-denial/path-failure, HTTP charset/BOM/malformed bytes then cached read, CID invalid-before-I/O and successful-invalidCID immediate error. Raw transport arbitrary-byte fixtures explicitly bypass text cache. **Rollback:** shared text policy/delegation only, retain31 transport/compatibility and all existing caches. **Retained conditional scope:** raw-byte cache needs a selected real consumer and separate typed/namespace mapping contract before a normal production ticket; no false delivery claim or text/raw collision.

### R8 — Share legacy registry-info decoding and explicitly reject malformed ABI pointers

**Ownership:** existing core checked registry decoder public reuse/export as needed, native legacy eth::decode_secret_info wrapper, get-info/view/hide codec fixtures/probes. **Depends:** shipped registry/list core; no sender/IPFS dependency. Do not rewrite transaction/RPC transport or selected-list behavior here.

**ACs:** (1) ordinary legacy eleven-word facts, low-word numeric/bool semantics, bounded unaligned/in-head offsets, UTF8, address/public projection and error/exits remain frozen. (2) explicitly correct unchecked offset+32/body-length arithmetic and platform overflow using the already shipped checked decoder policy; reject unsupported nonzero pointer high words rather than aliasing/wrapping. Name this malformed-input behavior change in notes. (3) actual legacy get-info path used view/hide delegates to safe shared decoding; network config/RPC/hidden-index selection and requests remain at old points, ordinary native diagnostics preserve projections. (4) no malformed-provider input can panic/abort or write data; no broad protocol tightening or key/ID normalization.

**Proof:** V1–V5; synthetic current baseline malformed-RPC/decoder failure cases before edits; final native/WASM and actual loopback release/install get-info-through-view/hide cases reject safely. Ordinary exact ABI/projection/error/request cases compare to baseline; no live provider. **Rollback:** wrapper/shared-export delta only while retaining checked-arithmetic safety correction; do not reintroduce the reproduced abort/wrap path.

### R9 — Cut over recordRead transaction callsite to the shared sender

**Ownership:** core recordRead ABI/orchestration entry as needed, native blockchain::record_read_on_chain composition only, focused RPC/Clock/CLI fixtures. **Depends:** completed36 shared sender (and its transitive35/33 prerequisites). No index/IPFS/init dependency.

**ACs:** (1) resolve config once at this operation's old call point and pair selected registry+chain/Rpc; original ID validation and exact recordRead(bytes32) calldata. (2) reuse36 sender/fees/raw submission/poll behavior verbatim; no new sender/retry or concurrent phase snapshot. (3) view caller's plaintext/crypto/index order stays native and unchanged until R11. Other register/share/hide callsites remain on their prior paths. (4) selected path makes no index/cache/wallet writes beyond existing caller behavior.

**Proof:** V1–V5; memory exact sender method/params/raw bytes/Clock traces; actual loopback view-driven recordRead success/revert/RPC/decode/receipt failure and dynamic selected config; canonical closed-stdin fixtures. Prove failures expose no plaintext and no premature recipient note. **Rollback:** recordRead composition only, retaining36 sender and data.

### R10 — Cut over share registration transaction callsite and post-receipt index note

**Ownership:** core shareSecret ABI/registration entry as needed, native blockchain::register_secret_on_chain only, index callback composition and focused fixtures. **Depends:** completed36 sender and R5 index interface; no R9/view/shared-cache/init prerequisite.

**ACs:** (1) same lazy selected config context, original ID and recipient bytes, CID/expiry/read-limit/public fields and exact calldata/raw bytes. (2) index_note(id,sender) occurs only after confirmed receipt; ordinary index write failure retains ignored behavior, ConfigError after chain success still fails command. (3) reuse35/36 sender rather than duplicate signing/poll code; existing share preparation/upload/randomness unchanged until R12. (4) return same tx hash/native failure projections and no implicit rollback of successful IPFS/chain effects.

**Proof:** V1–V5; exact memory calldata/sender/order and real loopback CLI share upload→register→receipt→index; revert/early RPC/malformed/late ConfigError cases, source/target file hashes/modes and output/exits. **Rollback:** registration/index-callback wiring only; retain sender/index abstractions and actual chain/index data.

### R11 — Extract authorized view/read-recording lifecycle and env projection

**Ownership:** core view policy/orchestration/export/consumers, native secrets::view_payload/view_secret/load_secret_as_env and selected main/run composition, focused loopback fixtures. **Depends:** R1, R5, R8, R9 and completed31; shipped wallet-read33 reused. R7 text-cache relocation is not required because31 already supplies compatible text. No wallet-init/share dependency.

**ACs:** (1) inner read-info→wallet unlock→identity→revoked→time→read-limit→text fetch→shared decode/open→recordRead→recipient note→return order exactly. Identity retains case-insensitive address/user strings and exact stored public-key alternatives. Time callback occurs only after identity/revoked; expiry is now>expires_at, equality allowed; public ignores read limit; do not substitute list chain flags. (2) keep existing CLI outer wallet unlock plus inner unlock; no hidden normalization/rederivation. Config may change between info/fetch/record phases; preserve selections. (3) no plaintext result on decrypt/recordRead/late ConfigError failure; one whole bundle read transaction; load_secret_as_env reuses R1 exact conversion. (4) output/no_export/materialize validation remains after view as currently; no new paid-read policy or transactional guarantee.

**Proof:** V1–V5; public callback trace tests with unused ports fail-stop; actual release/install loopback unauthorized/revoked/equality/+1/private/public limits/wrong-key/malformed/fetch-failure/recordRead-failure/post-receipt-ConfigError; exact request/file/output/order and two native unlock effects. **Rollback:** selected view/exports only, retaining R8 safety and R9 sender; never reverse recorded reads or user files.

### R12 — Extract share preparation, ID derivation and registration lifecycle

**Ownership:** core TTL/recipient/ID/share policy/orchestration/export/consumers, native secrets::share_secret/main wrappers and fixture support. **Depends:** R10 and completed31; shipped wallet/read/crypto reused. No view/init/shared-cache prerequisite.

**ACs:** (1) encoded content+member string-size limit10MiB→TTL→time/checked expiry→inner unlock→recipient resolution→existing seal/canonical payload→upload→u64 ID nonce→ID derivation→private-key decode→registration/receipt→sender note→result. Keep CLI outer unlock and source-order failure effects. (2) freeze TTL units/default/cap/overflow, exact lowercase public/self/SEC1 acceptance and SHA256 sender:recipient:now:nonce full0x64hex ID; derived on-chain recipient address exact. (3) retain crypto::seal_payload direct production fallible getrandom/ephemeral behavior; **no injectable crypto entropy API or deterministic production nonce/key path**. Only deterministic ID helper has explicit nonce input; native random nonce remains sampled once after upload. (4) preserve payload metadata/native SecretRecord projection/errors and possible upload/chain partial success, no automatic cleanup/rollback.

**Proof:** V1–V5; frozen pure TTL/recipient/ID vectors public native/WASM; callback order/failures; actual loopback public/self/recipient/file/bundle share, decrypt captured random payload to independently expected content/metadata and verify ABI/ID relationships. Do not fake exact random ciphertext baseline equality. Upload-success/register-fail and receipt-success/index-ConfigError effects verified. **Rollback:** share wrappers/policy exports only; retain safety/sender/data and no remote payload deletion.

### R13 — Extract local-hide orchestration and retire only its legacy list composition

**Ownership:** core narrow hide matching/count policy plus reused shipped list policy, native secrets::hide_secret and blockchain hide/list callback composition, focused fixtures. **Depends:** R5, R8 and completed36. No IPFS/init/share/view dependency.

**ACs:** (1) initial unlock/private-key decode then legacy-equivalent list(all=true) in BTreeMap order; preserve enumeration hidden snapshot, per-ID config/RPC/late-index reads and immediate list warnings/fatal initial ConfigError. Reuse shipped list policy only after exact projection proof. (2) each matching row sets local hidden first, then attempts shared revoke; no new creator prefilter. Non-ConfigError revoke failure warns and returns per-item success; ConfigError fails item. (3) outer hide counts only successful item callbacks, swallows **all per-item errors**, continues later items; ordinary ignored index write failure may still count. Do not silently correct this awkward inherited behavior. (4) no IPFS/read-recording/no automatic local-hide rollback on revoke failure; other callers unchanged.

**Proof:** V1–V5; actual multi-ID loopback success/noncreator/revoke-error/index-I/O/late-ConfigError sequences prove write-before-revoke/count/continuation and warning order, upstream initial-list ConfigError fatal, exact files/modes/output; panic on IPFS. **Rollback:** hide-specific policy/list/revoke composition only; retain local hidden data, shared list/sender and R8 correction.

### R14 — Extract native materialization composition while preserving staging/process boundaries

**Ownership:** native adapter materialization/private directory/guarded write/staging facilities, narrow CLI materialize/run wrappers and fixture tests; shared per-item helpers from R2 reused. **Depends:** R2, R11 and the actual R4 reusable compatibility byte-writer support API. No prerequisite on the wallet-init34 feature; reuse already-existing equivalent support if delivered at baseline. No new arbitrary-output StoreKey/Host port or process/signal code in core.

**ACs:** (1) CLI performs one authorized view/record for single or whole bundle **before** --as/output-kind/no_export/write checks. Invalid --as, bundle --file, no_export or later write failure retain read/index effects. (2) single no_export/bundle guards→decode/schema→target basename→write order; explicit output file path retains bypass of sender filename; bundle creates dir before per-member sanitize→decode→write, leaving earlier files on later failure. No eager all-or-nothing plan, bundle rollback or dedup. (3) parents born0700, compatibility0600/no-follow force write, atomic create_new/no-force collision and exact errors preserved; stronger FileStore not substituted. (4) temp dirs/file env injection, security name filtering, lifetime/drop/child exit and current signal-registry cleanup remain native with same bytes/permissions/limits; unlink cleanup is not a secure-overwrite claim. No new run product behavior.

**Proof:** V1–V5; real loopback view→recordRead→single/binary/bundle/schema/no_export/invalid-format/output-conflict, duplicate member/member2 traversal/decode/collision partial-file assertions, force/symlink/denied/umask/mode cases. Actual owned run child records staged path/env, validates cleanup normal/error/child-failure and real signal subprocess when moving signal code; helper-only cleanup test cannot substitute. **Rollback:** adapter location/wrappers only, preserving files/results and all completed read/safety APIs.

## Dependency DAG and scheduling

Existing substantive prerequisites are kept, not recreated:35→36,33→36;33→34;31 owns transport/text compatibility. The source already has reusable secure-write functions. R4 owns their mechanical adapter support extraction only if still needed; unchanged native wrappers preserve all callers. R5/R14 consume that actual API/mapping support, not completion of wallet-init34. Shared-file serialization is an ownership rule, not a feature dependency; no second compatibility writer is introduced.

```
R1 -> R2 -> R14
R1 --------------------------> R11 -> R14
32 -> R3
R4 -> R5 -> R10 -> R12
R4 --------------------------> R14
       |      ^       ^
       |      36      31
       |      |
       +----> R11 <- R9 <- 36
       |       ^
       |       R8
       +----> R13 <- R8
                 ^
                 36
31 -> R7
31 -> R11
```

For avoidance of diagram ambiguity, exact prerequisite sets: R1={} (shipped topology); R2={R1}; R3={32}; R4={} (existing byte helpers); R5={R4 support API if not already present}; R6={} (canonical47 baseline/source gate); R7={31}; R8={shipped registry core}; R9={36}; R10={36,R5}; R11={R1,R5,R8,R9,31}; R12={R10,31}; R13={R5,R8,36}; R14={R2,R11,R4 support API if not already present}. Read33 and sign35 are transitive/previously shipped; no extra duplicate edges. R4/R6/R7 are not prerequisites for all lifecycle work merely because they appear earlier. Frozen unfinished50/completed47/path moves create source-ownership/quiescence gates, not a requirement to complete50 or fake feature dependencies.

Preferred sequencing: reconcile/preserve frozen unfinished50 and checkpoint all active owners before overlapping work; run existing31/34/35/36 when genuinely ready; pure R1/R2/R3 and guarded project R6 are independent when their files are free; R4 extracts/reuses the existing byte helpers and R5 consumes that actual support; then small callsites R8/R9/R10 before view/share/hide, and R14 after its real inputs. Shared cache R7 can follow31 independently. No additional normal ticket for raw-byte cache without a real consumer. Field/function naming inside these contracts is implementation judgment, not a new user decision.

## Explicitly retained separate proposals and limits

- **Wallet/config pair atomicity:** unselected hardening. Current init34 remains wallet.json then config.json with config-presence overwrite gate and partial failure. Two atomic renames are not an atomic pair. Journal/recovery versus generation-pointer design requires separate choices about crashes/power loss/concurrency/reader coordination/layout migration and kill-at-every-stage proof; current Store has no transaction/durability port. Do not create or implement a hardening issue as accepted work from Q11 alone.
- **Raw-byte cache production:** conditional on a real consumer and explicit isolated namespace/typed mapping; not dropped and not falsely implemented by text-policy relocation.
- **Share crypto entropy injection:** not selected; production seal API/failure semantics stay as shipped. A future need requires an explicit fallible entropy seam decision rather than silently substituting the infallible RandomSource contract.
- Hosting/team account/client-encrypted vault work, protocol50, publication and physical checkout/Compose work retain their own decisions/tickets. No new deployment variable, schema migration, global install change, Git push/tag/publication/deployment or live-provider mutation is authorized here.

**Human decision recorded:** Q11 and the final shared-understanding answer explicitly accept this ruling, the fourteen bounded scopes and the two named safety corrections. There is no further factual or implementation-naming question required for their normal issues. Atomic pair guarantees and raw-cache consumer work remain explicitly unselected/conditional, not blockers for these fourteen continuations.
