# Team-vault qualification harness and evidence

This checkpoint belongs to [protocol qualification](https://github.com/igmrrf/bitbid/issues/49).
It qualifies an isolated executable candidate, not a shipped team-vault feature
or a cryptographic audit. The separate protocol contract remains frozen at
SHA256 `6a9b26878f1192727e8ca6e52a9da449d21d7b8b7c45b827e601de2cd9b66d6a`.
No production wallet/token/KDF/on-chain behavior is connected to this harness.
The harness and independent lockfiles live under
[`qualification/team-vault`](../../qualification/team-vault/README.md).

## Reproduction and exact primitive profile

The harness README gives actual native/reference/build/Node/server commands.
It uses its own Cargo workspace/lock; the production workspace, dependency lock
and web facade are unaffected by qualification source. Concurrent wallet-codec
work in this session owns separate production changes and is checked by the
final legacy gates, not included as team-vault source ownership.

| Primitive | Exact direct pin; enabled application features |
|---|---|
| Argon2 |0.6.0; alloc, zeroize; explicit Argon2id19/m65536KiB/t3/p4/salt16/out32; no secret/AD in production |
| HPKE |0.15.1; alloc, x25519, chacha; Base mode, suite32/1/3 only |
| Ed25519 |ed25519-dalek3.0.0 fast/zeroize; curve25519-dalek5.0.0 alloc/precomputed-tables/zeroize |
| XChaCha |chacha20poly1305 0.11.0 alloc/zeroize; key32, nonce24, full tag16 |
| Entropy |getrandom0.4.3; native OS and explicit wasm_js browser backend; no fallback |
| HKDF/SHA |hkdf0.13.0, sha2 0.11.1; exact distinct T purpose transcripts |
| Binding |wasm-bindgen0.2.129, matching CLI; optimized release/LTO WASM |

The manifest and resolved feature tree establish the actual transitive union.
The source-owned [primitive research](../research/team-vault-primitive-qualification-facts.md)
records maintainer/registry/source/advisory evidence and pinned upstream KAT
provenance. Enrollment explicitly decompresses/re-encodes the public point and
rejects small-order keys; strict individual verification checks canonical
signature R/scalar and signature/context. No additional torsion-free policy or
legacy compatibility/batch mode is enabled. HPKE consumes a fresh fallibly
prefilled32-byte IKM buffer through a finite RNG adapter; it does not use the
library's entropy-unwrapping convenience entry points. All-zero DH rejects.
Argon memory is fallibly reserved and held in Zeroizing caller-owned scratch;
allocation failure returns no derived key and never changes the profile.

Reference versions are argon2-cffi25.1.0/bindings26.1.0, PyNaCl1.6.2,
cryptography50.0.2, cffi2.1.1 and pycparser3.12 with complete wheel/sdist hashes
in `reference/requirements.lock`. Actual OpenSSL backend is4.0.3 (29Sep2026).
The PyNaCl wheel does not expose a runtime sodium-version query through its
CFFI or exported symbol; the exact wheel/package and bundled libsodium source
provenance are retained instead. Do not claim a separately observed runtime
libsodium version. A historical46.0.5 reference candidate had advisories; it was
replaced with50.0.2 before final fixture generation/testing. Retain that failed
candidate evidence rather than reporting it clean.

The final standalone Rust lock SHA256 is
`394593d0fa941d9d323402fc2b1b141b11d9e9524c20d25d5de2e69cb5758cf9`;
its64 registry packages have no OSV matches at the captured check. Cargo-audit
0.22.2 against RustSec snapshot `d9cb059f3217db87aeccd190b81eaffe8cc29cb9`
reports zero vulnerabilities/warnings with no filters or ignores. All six Python
packages in lock SHA256
`7df5b3987928aa0f0f12ca96793fb39e64b2425abfb03017a4c0aecb299cf15d`
also have no captured OSV matches. These are dated dependency checks, not a claim
that unknown vulnerabilities cannot exist; exact requests and source/artifact
checksums are retained in `evidence/primitive-final`.

## Executed assertions

The independent public corpus SHA256 is
`04205ee43e91990522f726c56f17617664e1cfa0e031cea4e83ac87769427064`.
Native Rust and optimized WASM execute the identical canonical signed/encrypted
records:54 lifecycle cases and21 encrypted export cases (139 records). The Rust tests consume
fixed independently generated expected bytes; they do not regenerate expected
and actual results with one implementation.

Coverage includes all twelve action classes, Member add/edit/delete/restore,
read-only/stale/removed writer denial, unique item-kind and omission rules,
Owner-only role powers, verification-bound acceptance cardinalities, offline
all-vault grants, replacement/frozen-read retention, exact epoch/snapshot
succession and complete rotation with actual before/after plaintext equality.
Structurally valid correctly signed forbidden transitions are separate from
signature-tamper tests. Atomic failed operations leave accepted state/heads
unchanged. Pending local cancellation has no disclosure; abandoning a sent
validated activation requires rotation of possibly disclosed epochs; observing
the old head does not resolve that uncertainty. Restore writes a fresh signed
current revision and rejects concurrent removal, replacement, rotation or
content-head changes by comparing both current hashes.

The first review found that activation snapshots did not bind every introduced
content signature to the authority actor. The bounded correction applies to
vault creation and full epoch replacement, including selected-export replay at
each selected body's introduction. It preserves ordinary Member CRUD and
privileged label edits under the same current `new-vault` or `rotate` plan.
Appended signed semantic negatives retain identical encrypted payloads, exact
sets/revisions/epochs and Owner-signed snapshots/grants while changing the body
signer. Secret, tombstone and privileged-label cases and retained selected-body
provenance assert the specific actor rejection. All original82 record bytes,
37 lifecycle cases,10 exports and primitive values remain unchanged; the old
corpus hash is `0441fc2c92e1ad0a9a543c310e6a3eef6844d0616cda02ecbffb596e2b3c52a6`.

Encrypted recovery-only backup has exactly four bound account roots, including
a sequence3 trust wrapper with historical hashes as context markers. Selected
backup verifies actual genesis/authority/acceptance/snapshot/identity proofs,
first-introduction and continuous-retention provenance, exact body closure and
current exporter grant/content decryption. Missing selected bodies/proofs and
unreferenced extra ciphertext reject. Recovery code framing, checksum and
account/generation binding are decoded separately; no recovery code is nested
inside an export. Historical/unselected ciphertext bodies are not materialized
or claimed decrypted by the projection, and it cannot install live authority.

Primitive checks include RFC9106§5.3 (with its separate secret/AD settings),
RFC8032 test1, RFC9180A.2.1 Base suite32/1/3 single-shot sequence0 and upstream
libsodium XChaCha KAT; independent production Argon2/HKDF/Ed25519/HPKE/XChaCha
bytes; wrong key/context/tamper, malformed/short/unknown/trailing/bounded-list,
noncanonical/weak enrollment and signature scalar, all-zero/low-order DH,
fallible entropy, usage exhaustion, duplicate nonce and immutable retry cases.
This is focused qualification coverage, not exhaustive parser fuzzing or a
proof of unknown primitive safety.

## Resource and platform policy fixed before measurements

Candidate targets are macOS27.2 ARM64 installed Chrome156 and Safari27.2, and
the user-selected physical Pixel7/Android17/Chrome156 under existing app memory
pressure. Record exact hardware/browser/available RAM; do not infer every Android
class is supported. All use the fixed production KDF, passphrase<=1024 UTF8
bytes, one KDF per owned worker/tab and two actual concurrent tabs. Cold/warm
KDF each<=30s;50ms main-thread heartbeat gap<=500ms; foreground lock/cancel
invalidation<=250ms. Scratch is64MiB and normal WASM maximum256MiB. A separate
32MiB-max optimized WASM instance must reject the full-profile allocation.
This is failure injection, not a weak production profile or a physical-RAM claim.

Idle15m/hidden5m checks use explicit injected clock boundaries. Actual tab/app
visibility/resume and reload/lock actions are observed separately; no claim
that wall-clock5m/15m elapsed is made. Worker generation invalidation rejects a
real delayed completed result; default lock terminates the owned worker. Keys
are zeroized/worker ownership is bounded where controlled; memory erasure of
all browser/compiler/OS copies is not claimed. User phone apps/tabs/data and
browser security settings remain intact.

## Completed qualification and final review

The Codinary run is
`/var/folders/wt/srss_rcj5cq7f60_2h9gvt040000gn/T/codinary/bitbid-team-qualification-20261109T223428Z`.
Full commands/results are in its `evidence/`; final implementer/reviewer handoffs
are authoritative for the exact final source and phase verdict. Temporary run
paths may expire; committed source/fixtures retain reproduction inputs.

The current optimized normal module hash is
`4e377edc6cb81ff36220083e017a085439606c21a08ff53875b591d7f1399bc6`;
bounded module `bc54208ff97187f939ab07d0fe807ef7df34592a70a468e439b866eed1407464`.
After the activation-content actor correction and appended regressions, served
`web/build.json` SHA256 is
`97b9026672fe85b9fd166f93deacdb8dae774bd0f58b0df85e96328f2cdc35cc`.
Its file hashes bind the unchanged page/worker and both rebuilt optimized modules.
The earlier manifest `a101c841173f018e7556a829c5f37ece8852bffa66e9634b68d554ff9a1de32d`
and its phone observations remain historical interim evidence.
Foreground samples are taken for every acknowledged KDF, including separately
triggered concurrent-tab work. Hidden timer gaps are recorded separately and
excluded from the foreground UI budget, with the sampling baseline reset on
visibility changes. Worker start/end timestamps establish actual overlap; a
background-only tab reports unmeasured foreground coverage rather than a pass.
The server startup metadata's earlier manifest hash is historical; it is not
the final browser build identity. No source change to frozen protocol bytes
was made after schema review2.

Native and optimized Node22 execution pass. Installed Chrome156.0.8078.80 and Safari27.2
worker/KDF/failure/lifecycle suites pass, with actual visibility/resume locking,
reload initially locked, two real tabs and inspected screenshots/console/network.
Safari blocked an early asynchronous peer opener; the manual owned `?peer=1`
fallback and the final worker-ready peer opener exercise actual tabs without
changing that security setting. A failed early Chrome probe is retained as historical evidence;
final corrected runs have no unexpected page errors. Exact per-run timings,
linear-memory high water and heartbeat gaps remain in the captured JSON; do not
substitute Node timing for browser timing.

The user completed the physical Pixel7/Android17/Chrome156.0.8078.79 protocol
under unchanged existing app memory pressure. Independent reviewer2 validated
six raw records against the complete final build dictionary and attributed
human observations in `evidence/reviewer2-phone-final-validation.json` within
the run above. The full suite passed with 139 records, 54 lifecycle cases and
21 exports; cold/warm/final KDF times were 356.8/332.9/410.4 ms, maximum foreground
heartbeat gap 51 ms, cancellation 3.1 ms and linear-memory high water 70909952
bytes. Two actual tabs overlapped 409 ms; the visible peer recorded eight
heartbeat ticks with a 50.1 ms maximum gap. The background tab's foreground responsiveness remained
unmeasured. The user confirmed actual app resume and final reload showed Locked,
and reported no lag or issues. Actual visibility/resume is distinct from the
injected five-minute deadline clock; no elapsed five-minute claim is made.
Historical a101 or mixed-build records are excluded from these final results.

Read-only phone RAM samples recorded total 7647536 KiB. Reviewer2 conservatively
attributes two complete sample-read intervals to measured suite KDFs (cold and
final, MemAvailable 1732768/1764088 KiB) and one to the actual concurrent overlap
(MemAvailable 1590524 KiB). These intervals remain contained for every assumed
phone lead from 0–200 ms; collector transit is unknown and this is not exact clock
synchronization. These observations describe the selected phone under existing
app pressure, not peak process RSS or qualification of another hardware class.
The 32 MiB WASM allocation failure remains a separate injected test.

Final `review-2.json` and `review-2.md` record independent pre-release PASS for
all five acceptance criteria and nine required checks, with zero findings,
blockers or waivers. The final production checkpoint is native
`e38a4cc92ed32d14ed5c829448277a1d0c0ac930` and web
`9a52f1bb61b348943e3d9504156ad06f91f389d1`. Refreshed legacy gates passed 209 native
runtime tests, 61 executed core WASM tests and eight facade tests, plus both
privacy compile-fail examples on native and WASM. One pre-existing ignored child
fixture is explicitly invoked by parent tests. Strict Clippy, harness formatting,
the actual dependency boundary and encrypted catalog/report passed; all seven
existing environment names were unset and no deployable setting was introduced.
Exact results and source preservation are in `evidence/reviewer2-final-*`.

All owned collectors, samplers, test windows and USB forwarding were cleaned up;
user sessions were preserved. Local commit provenance is recorded in the run's summary and
`evidence/root-commit-checkpoint.json`.
No cryptographic audit, shipped product integration, production deployment,
publication, push or team-vault product readiness is claimed.
