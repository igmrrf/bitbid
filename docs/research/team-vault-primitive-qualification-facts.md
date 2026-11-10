# Team-vault primitive qualification facts

Research snapshot: 2026-11-09/10 UTC, for [protocol qualification](https://github.com/igmrrf/bitbid/issues/49).
The reviewed contract is `docs/split-core/team-vault-keys.md`, SHA-256
`6a9b26878f1192727e8ca6e52a9da449d21d7b8b7c45b827e601de2cd9b66d6a`.
This note supports the isolated qualification harness; it does not approve a
production implementation, claim a cryptographic audit, or establish browser
performance. Actual native/WASM/reference tests and device measurements remain
separate evidence.

## Exact candidates and features

The captured crates.io API identifies all eight versions below as the latest
stable, un-yanked releases at retrieval. Release activity, versioned source,
and current advisory records support selecting these maintained candidates;
they do not establish future maintenance or absence of unknown vulnerabilities.
Sources are the package-owned registry records linked in each row.

| Crate pin | Explicit feature recommendation (`default-features = false`) | Published UTC; MSRV |
| --- | --- | --- |
| [`argon2 = "=0.6.0"`](https://crates.io/api/v1/crates/argon2) | `alloc`, `zeroize`; omit `parallel`, PHC/password-hash and automatic randomness | 2026-08-27; Rust 1.85 |
| [`hpke = "=0.15.1"`](https://crates.io/api/v1/crates/hpke) | `alloc`, `x25519`, `chacha`; omit `getrandom`, `mlkem`, `nistp`, `aes`, `kat` | 2026-10-28; Rust 1.87 |
| [`ed25519-dalek = "=3.0.0"`](https://crates.io/api/v1/crates/ed25519-dalek) | `fast`, `zeroize`; precomputed tables do not change wire semantics; raw signing/verification needs no `alloc`; exclude `legacy_compatibility`, `batch`, `hazmat`, `digest` | 2026-07-06; Rust 1.85 |
| [`curve25519-dalek = "=5.0.0"`](https://crates.io/api/v1/crates/curve25519-dalek) | If directly needed for fixture/point checks: `alloc`, `zeroize`, optionally `precomputed-tables`; exclude `legacy_compatibility` | 2026-07-06; Rust 1.85 |
| [`chacha20poly1305 = "=0.11.0"`](https://crates.io/api/v1/crates/chacha20poly1305) | `alloc`, `zeroize`; exclude `getrandom`, `reduced-round` | 2026-06-28; Rust 1.85 |
| [`getrandom = "=0.4.3"`](https://crates.io/api/v1/crates/getrandom) | Native needs no optional backend; browser executable enables `wasm_js`; direct `fill` needs no `sys_rng` | 2026-06-17; Rust 1.85 |
| [`hkdf = "=0.13.0"`](https://crates.io/api/v1/crates/hkdf) | No features | 2026-03-30; Rust 1.85 |
| [`sha2 = "=0.11.1"`](https://crates.io/api/v1/crates/sha2) | No features needed for SHA-256; optional `zeroize` is independent of wire semantics | 2026-10-12; Rust 1.88 |

These are exact source recommendations. The final executable's manifest,
lockfile, and resolved `cargo tree -e features` must establish the actual
feature union. For example, HPKE's `chacha` dependency itself enables ChaCha's
`zeroize`; a direct declaration should also state that requirement. A direct
curve dependency is unnecessary solely to call
`VerifyingKey::to_edwards().compress()`. The harness may retain one for fixture
construction. No production workspace dependency change is authorized by this
note.

The final standalone manifest and offline locked feature resolution were
checked at 2026-11-09T23:53:57Z. Manifest SHA-256 is
`9b2f4e48005c542116ca2eb514596f84b7fad443114e1008ee3a91cef8e7a1ae`;
its Rust lock SHA-256 is
`394593d0fa941d9d323402fc2b1b141b11d9e9524c20d25d5de2e69cb5758cf9`.
This is the actual resolved union, including transitive features, rather than
only the minimal recommendations above:

| Final crate | Resolved enabled features |
| --- | --- |
| argon2 0.6.0 | `alloc`, `zeroize` |
| hpke 0.15.1 | `alloc`, `chacha`, `hkdfsha2`, `x25519` |
| ed25519-dalek 3.0.0 | `fast`, `zeroize` |
| curve25519-dalek 5.0.0 | `alloc`, `digest`, `precomputed-tables`, `zeroize` |
| chacha20poly1305 0.11.0 | `alloc`, `zeroize` |
| getrandom 0.4.3 | `wasm_js` |
| hkdf 0.13.0 | none |
| sha2 0.11.1 | `alloc`, `default`, `oid` |
| rand_core 0.10.1 | none |
| zeroize 1.9.1 | `alloc`, `default`, `zeroize_derive` |
| serde_json 1.0.154 | `default`, `std` |

The final graph has 64 registry packages plus the local harness. All 64 local
crate archives match the lock's package checksums; all 2,220 archived source
files match the unpacked sources used by the wrapper. Only Cargo's unpack
metadata is extra. The nine previously inspected primitive archives and
normalized manifests, including X25519, remain byte-identical to the earlier
source evidence. `evidence/primitive-final/{cargo-metadata.json,cargo-features.log,rust-source-integrity.json}`
records this verification. These source checks do not prove compiler output
or platform timing properties.

The normalized manifests, crate archives, registry snapshots and embedded VCS
commits were retained in the qualification run's `evidence/primitive-source/`
and `evidence/primitive-registry/`. Each downloaded archive matched the
registry checksum. `source-manifest.json` includes source and manifest hashes.

| Archive | SHA-256 |
| --- | --- |
| argon2-0.6.0 | `134c52ddac6d63c576bef8168db10c83c49c26444ecbc68060fef078925a901c` |
| hpke-0.15.1 | `8f512e325a1a71bf3273fb9b7fc9e5d96dac136fb4a95d0e6637001b12ea3e09` |
| ed25519-dalek-3.0.0 | `6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de` |
| curve25519-dalek-5.0.0 | `b5eed333089e2e1c1ac8c6c0398e5e2497b4c9926ca6d0365ed1e099afa5bc23` |
| chacha20poly1305-0.11.0 | `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb` |
| getrandom-0.4.3 | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` |
| hkdf-0.13.0 | `4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018` |
| sha2-0.11.1 | `47d7069beb7d6ac7b9acd1039986e73443f24234f41074da099d6f994ac9ad19` |

## Primitive/API requirements

**Argon2id.** Select `Algorithm::Argon2id`, `Version::V0x13`, and explicit
`Params::new(65536, 3, 4, Some(32))`; validate salt16, passphrase byte bound
and the whole tuple before invoking it. Do not use library defaults: they are
not this contract. Four lanes do not require four browser threads. The
versioned implementation processes segments sequentially without `parallel`;
that feature uses Rayon. Its allocating method returns `OutOfMemory` when its
checked allocation fails. However, the internal allocation's `Drop` only
deallocates; enabling `zeroize` does not erase the whole backing scratch.
Use fallibly reserved, explicitly wiped caller-owned scratch when qualification
requires control of its lifetime. These observations come from the exact
[`argon2` library](https://github.com/RustCrypto/password-hashes/blob/b1e0ad6fe229b1ba74e4696c7359ab45d7e931f0/argon2/src/lib.rs),
[`block.rs`](https://github.com/RustCrypto/password-hashes/blob/b1e0ad6fe229b1ba74e4696c7359ab45d7e931f0/argon2/src/block.rs)
and [`memory.rs`](https://github.com/RustCrypto/password-hashes/blob/b1e0ad6fe229b1ba74e4696c7359ab45d7e931f0/argon2/src/memory.rs).

**HPKE.** Bind `OpModeS::Base`/`OpModeR::Base`,
`X25519HkdfSha256`, `HkdfSha256`, and HPKE's `ChaCha20Poly1305`;
this is `(0x0020, 0x0001, 0x0003)`, with enc32 and a 16-byte tag.
The checked X25519 exchange rejects an all-zero result in constant time and
maps failures to encapsulation/decapsulation errors. Both paths must be tested.
Private input is clamped when deserialized. The 0.15 change also clamps private
serialization: older raw secret encodings may serialize differently while
remaining operation-equivalent. Do not compare old raw secret bytes as a
cross-version compatibility test.
Sources: [`X25519 implementation`](https://github.com/rozbb/rust-hpke/blob/7992688f3fa03fc2d26cd6a7e2363b51481d229a/src/dhkex/x25519.rs),
[`DHKEM paths`](https://github.com/rozbb/rust-hpke/blob/7992688f3fa03fc2d26cd6a7e2363b51481d229a/src/kem/dhkem.rs),
[`0.15 changelog`](https://github.com/rozbb/rust-hpke/blob/7992688f3fa03fc2d26cd6a7e2363b51481d229a/CHANGELOG.md).

X25519 coordinate decoding masks the high bit and accepts noncanonical field
representatives; do not import Ed25519's canonical-point admission rule into
X25519. HPKE still binds the encoded `enc`/recipient key in its KEM context, so
equivalent DH coordinates do not imply identical HPKE ciphertext behavior
after a wire-byte mutation. Test decoding compatibility separately from
authenticated transcript mutations. Sources:
[RFC 7748 §5](https://www.rfc-editor.org/rfc/rfc7748.html#section-5),
[RFC 9180 §§4.1, 7.1.4](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.4),
[`curve25519-dalek` field decoding](https://github.com/dalek-cryptography/curve25519-dalek/blob/07bef73ff85998a206cd2cea7f2605c801d0d1c9/curve25519-dalek/src/backend/serial/u32/field.rs).

**Ed25519.** Sign the message bytes with pure `Signer::sign`, and verify each
signature using `verify_strict`. `from_bytes` uses permissive ZIP-215 point
decoding; `to_bytes()` retains the original compressed input. Enrollment must
therefore additionally require
`vk.to_edwards().compress().to_bytes() == supplied_public_bytes` and
`!vk.is_weak()`. This rejects noncanonical representations and small-order
keys before accepting identity possession. Strict verification rejects
small-order A/R, noncanonical R and unreduced S with legacy compatibility
disabled. A torsion-free enrollment restriction is stronger than rejecting
small-order keys and must be identified as an additional application check,
not attributed to `verify_strict`. Source:
[`verifying.rs`](https://github.com/dalek-cryptography/curve25519-dalek/blob/07bef73ff85998a206cd2cea7f2605c801d0d1c9/ed25519-dalek/src/verifying.rs),
[`signature.rs`](https://github.com/dalek-cryptography/curve25519-dalek/blob/07bef73ff85998a206cd2cea7f2605c801d0d1c9/ed25519-dalek/src/signature.rs),
[RFC 8032 §§5.1, 7.1](https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1).

**XChaCha20-Poly1305.** `XChaCha20Poly1305` has key32/nonce24/tag16;
the selected 20-round variant is distinct from HPKE's nonce12 AEAD and from
NaCl/XSalsa20 secretbox. Use ciphertext with the full appended tag and exact
AAD; reject truncation and wrong-key/nonce/AAD/context modifications. This
construction has a draft and established implementation vectors, not a final
XChaCha RFC. The upstream historical NCC audit statement does not establish
an audit of 0.11.0, this application composition, or this compiler/target.
Sources: [`versioned Rust implementation`](https://github.com/RustCrypto/AEADs/blob/e37a978ccf0992d9053fbc039470d6527108e393/chacha20poly1305/src/lib.rs),
[libsodium construction/combined mode](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).

**Entropy.** `getrandom::fill` returns `Result`; on macOS its selected backend
uses `getentropy`. `wasm_js` uses `globalThis.crypto.getRandomValues`, chunks
at 65536 bytes, catches JavaScript exceptions and returns an error. Application
failure handling must discard the destination buffer: an error is not usable
partial entropy. No time/counter/fallback seed is allowed.
Sources: [`getrandom 0.4.3 documentation`](https://docs.rs/getrandom/0.4.3/getrandom/),
[`exact browser backend`](https://github.com/rust-random/getrandom/blob/5e7cd5733536844a9856dc7259bd4696bbe5e3ae/src/backends/wasm_js.rs).

HPKE 0.15.1's built-in OS-randomness functions call `UnwrapErr(SysRng)`;
entropy failure panics. Its `_with_rng` APIs take infallible
`rand_core` 0.10 `CryptoRng`. To retain a fallible application boundary,
first obtain fresh 32-byte IKM fallibly, then pass only those bytes through a
finite checked RNG to `single_shot_seal_with_rng`. Reject entropy failure before
constructing a context. This is IKM for `DeriveKeyPair`, not an already-derived
ephemeral scalar. Erase the prefetched IKM; never refill with zeros or reuse it
for a retry. The exact fixed consumption must be tested at the pinned version.
Sources: [`single-shot API`](https://github.com/rozbb/rust-hpke/blob/7992688f3fa03fc2d26cd6a7e2363b51481d229a/src/single_shot.rs),
[`KEM key generation`](https://github.com/rozbb/rust-hpke/blob/7992688f3fa03fc2d26cd6a7e2363b51481d229a/src/kem.rs),
[`upstream finite test RNG`](https://github.com/rozbb/rust-hpke/blob/7992688f3fa03fc2d26cd6a7e2363b51481d229a/src/test_util.rs).

## Known answers and independent implementation

The run's `evidence/primitive-vectors/` contains original published RFC text,
full source hashes, and field-extracted JSON. Expected bytes came from those
public sources, not from the Rust implementation being checked:

| Fixture | Provenance and scope | Extracted JSON SHA-256 |
| --- | --- | --- |
| `rfc9106-argon2id-5.3.json` | [RFC 9106 §5.3](https://www.rfc-editor.org/rfc/rfc9106.html#section-5.3): Argon2id19, memory32KiB/t3/p4, secret8/ad12. A primitive KAT; full production-profile interop must be separate. | `7455267b5487fa9d57b5d13f98a1ea54667087dcff708e2d25019ce63b9282af` |
| `rfc8032-ed25519-test1.json` | [RFC 8032 §7.1 TEST1](https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1): seed/public/signature, empty message, pure Ed25519. | `2b689f727997bd192ba593946b7bd48c334c8e4a074606121200560b21a89651` |
| `rfc9180-base-32-1-3.json` | [RFC 9180 A.2.1](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.1): exact selected Base suite, IKM/keys/enc/secret/context and six published encryption sequences/three exports. | `57a118c8749975bded0bde90eb2e99103417007fb3ff5b93ce9ebbe52b343f0c` |
| `libsodium-xchacha20poly1305-ietf-tv1.json` | First `tv()` key/nonce/AAD/plaintext from libsodium test source and first 130 ciphertext/tag bytes from its checked-in `.exp`, inside the hash-verified PyNaCl 1.6.2 source archive. | `6ba3cdb70c0374a4aabf8ac725b79ef314bd6be9471ccb61b5902c978b880a73` |

Additional useful source-owned tests are
[libsodium's XChaCha test](https://github.com/jedisct1/libsodium/blob/master/test/default/aead_xchacha20poly1305.c),
[Argon2 reference KATs](https://github.com/P-H-C/phc-winner-argon2/tree/master/kats),
and [RFC 5869 Appendix A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
for HKDF-SHA256. Freeze exact bytes/commit/hash when importing mutable test
repositories. The complete [CFRG HPKE vector bundle](https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json)
was retrieved at commit `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb`, SHA-256
`61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`.
It contains one exact Base/32/1/3 record, extracted as
`hpke-base-32-1-3.json`; all setup fields and six published encryption records
were compared byte-for-byte with RFC A.2.1. This is source agreement, not
execution of a cryptographic implementation.

The recommended independent stack is `argon2-cffi==25.1.0`,
`argon2-cffi-bindings==26.1.0`, `PyNaCl==1.6.2`, and
`cryptography==50.0.2`. Use Argon2's explicit raw API
for the exact full profile; do not rely on changing platform defaults. Its
low-level context API is needed for the RFC secret/ad KAT.
[Maintainer Argon2 API](https://argon2-cffi.readthedocs.io/en/25.1.0/api.html#low-level).
PyNaCl/libsodium supplies independent Ed25519 and XChaCha implementations;
the reference must still enforce the frozen enrollment policy explicitly.
[PyNaCl release](https://github.com/pyca/pynacl/releases/tag/1.6.2),
[PyNaCl bindings source](https://github.com/pyca/pynacl/tree/1.6.2/src/nacl/bindings).
Constructing HPKE's RFC-labeled HKDF with cryptography's X25519 and
ChaCha20Poly1305 supplies an independent composition, but is not a separately
maintained complete HPKE library; prove it against the official HPKE KAT first.
[Versioned AEAD API](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/),
[versioned X25519 API](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/x25519/).
Pin the complete reference environment, artifact hashes and actual backend
versions in its own lock/evidence. Native reference outputs can be frozen for
both native and WASM consumers; that does not itself execute a browser.

The first proposed `cryptography==46.0.5` reference was rejected after the
exact-version OSV query returned 11 records, including aliases. For example,
the maintainer's [bundled OpenSSL advisory](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf)
is fixed at 48.0.1. The [current maintainer release record](https://pypi.org/project/cryptography/50.0.2/)
and [changelog](https://cryptography.io/en/50.0.2/changelog/) identify 50.0.2
and OpenSSL 4.0.3 project wheels. Fresh exact-version OSV queries returned
empty results for 50.0.2 and bindings 26.1.0, as for the selected Argon2/PyNaCl
versions. Historical downloaded 46.0.5/25.1.0-bindings archives in
`primitive-reference/` are research history, not the selected executable
reference. The final complete lock and observed backend still control the
qualification claim; package advisories do not establish which vulnerable
operations an application executes.

## Advisory snapshot and limits

The primary RustSec database was captured at immutable commit
[`d9cb059f3217db87aeccd190b81eaffe8cc29cb9`](https://github.com/RustSec/advisory-db/tree/d9cb059f3217db87aeccd190b81eaffe8cc29cb9),
archive SHA-256 `0ade63b10cd00dcafbaed5aa17c2c05dcb0579dbdda7ed93c5a64b6fc72a21e9`.
Relevant records and the retrieval manifest are in `evidence/primitive-advisories/`.

| Record | Published patched range and relevance |
| --- | --- |
| [RUSTSEC-2022-0093](https://rustsec.org/advisories/RUSTSEC-2022-0093.html) | Ed25519-dalek double-public-key signing oracle; patched `>=2`. Selected 3.0.0 is outside the affected range. Keep hazmat signing disabled. |
| [RUSTSEC-2024-0344](https://rustsec.org/advisories/RUSTSEC-2024-0344.html) | Curve25519 scalar subtraction timing; patched `>=4.1.3`. Selected 5.0.0 is outside the affected range. |
| [RUSTSEC-2021-0100](https://rustsec.org/advisories/RUSTSEC-2021-0100.html) | SHA2 0.9.7 AVX2 wrong results; patched `>=0.9.8`, unaffected `<0.9.7`. Selected 0.11.1 is outside the affected range. |
| [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) | Ctutils timing; patched `>=0.4.4`. Inspected harness lock has 0.4.8. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) | Crypto-bigint timing; patched `>=0.7.6`. Absent from the inspected enabled harness lock. HPKE's 0.15 changelog explicitly responds to this and the ctutils advisory. |

OSV's primary `/v1/querybatch` API returned empty results for the exact eight
candidate versions and, separately, all 67 registry packages in harness lock
SHA-256 `83b6f6105dd4163d2cad6265eec172c6670ebfc3678dec71b39a80ba83d7d0a5`
at 2026-11-09T23:02:55Z. Requests/responses and the lock fingerprint are retained
as `osv-querybatch-*` and `osv-lock-*`. This is a time-bound known-advisory
lookup, not an audit, exploitability analysis or future guarantee. Refresh the
whole resolved graph if the final lock changes. Historical upstream audit
statements must retain their original scope.

### Final lock refresh: supersedes the earlier dependency snapshots

The current final lockfiles were copied without modification into
`evidence/primitive-final/` at 2026-11-09T23:53:57Z. The earlier 67-package
Rust snapshot and the rejected Python 46.0.5 advisory results remain preserved
as history; neither describes the final graph below.

| Final input | SHA-256 | Authoritative lookup result |
| --- | --- | --- |
| Standalone Rust `Cargo.lock` | `394593d0fa941d9d323402fc2b1b141b11d9e9524c20d25d5de2e69cb5758cf9` | All 64 registry packages queried through OSV at 23:54:46Z: 64 empty results. |
| Python `reference/requirements.lock` | `7df5b3987928aa0f0f12ca96793fb39e64b2425abfb03017a4c0aecb299cf15d` | All six packages queried through OSV at 23:54:49Z: six empty results. |

The exact Python versions are argon2-cffi 25.1.0, argon2-cffi-bindings 26.1.0,
cffi 2.1.1, cryptography 50.0.2, pycparser 3.12, and PyNaCl 1.6.2. Every one
of the lock's 229 allowed distribution SHA-256 hashes was matched to that
exact version's [primary PyPI metadata](https://docs.pypi.org/api/json/).
`python-artifact-integrity.json` retains artifact filenames, URLs, hashes,
yanked flags and metadata hashes. This checks the complete artifact allowlist;
the installed platform selects a subset.

The [primary OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/)
requests, responses and summaries bind the package manifests to the snapshot
manifest hash. Rust request/response SHA-256 values are
`6e8dc66ddff2d4fd9ef59f901a405bf0b69e23a3341ffe4a28d40eb48f950c35` /
`de4eed3305872924d5b397a299fcc60e261d068739477fe0055547eb1e759095`;
Python request/response values are
`2704edc70047f407d245e7b35bc1e5ea8f79d2868828be69c77f3fb3b3cb8ce5` /
`e7e00f5759742ba9322ec6db4bd44d79d245d9831a06655a80cdb93e39c27928`.
Evidence filenames are `rust-osv-*` and `python-osv-*`.

RustSec's primary GitHub head was freshly retrieved at 23:54:47Z and remained
`d9cb059f3217db87aeccd190b81eaffe8cc29cb9`. Its earlier immutable archive was
reused only after rechecking SHA-256
`0ade63b10cd00dcafbaed5aa17c2c05dcb0579dbdda7ed93c5a64b6fc72a21e9`.
The installed `cargo-audit 0.22.2` compared the entire final lock against those
1,430 advisory records: zero vulnerabilities and zero warnings. The command
used no target filters or ignored IDs, with `--no-fetch --no-yanked` against
the explicitly identified local database. It did not perform a registry-wide
yank check. The tool reports 65 total lock dependencies, comprising the local
harness and the 64 registry packages. Its extracted archive has no Git
metadata, so the report's null database commit fields must be interpreted
using the independently recorded `rustsec-retrieval.json` commit/archive
fingerprint, not as an unidentified database. Exact output is
`rustsec-comparison.json`, with empty stderr.

The copied four public KAT files and RFC retrieval metadata match the original
research evidence byte-for-byte (`kat-integrity.json`). The frozen schema hash
remains `6a9b26878f1192727e8ca6e52a9da449d21d7b8b7c45b827e601de2cd9b66d6a`.
The implementer's actual backend report records `OpenSSL 4.0.3 29 Sep 2026`
and Argon2 version constant 19; its libsodium runtime version API was not
exported. No libsodium runtime version is inferred from the retained wheel or
the bundled source version. The report was copied unchanged as
`reference-backends.json.snapshot`, SHA-256
`1e2d3289f1d15aed726af3158f45651a3355d5e93fd4d73b3f39087b5f1f9178`.

These results establish time-bound known-advisory and artifact-integrity
checks for the named inputs. They are not a cryptographic audit, a proof of
exploitability, or the empirical execution gates. A changed lock, manifest,
source or vector requires appropriate refresh before reusing this evidence.

## Remaining empirical gates

The harness must execute the same immutable vectors in optimized native and
WASM builds, plus context/tamper/wrong-length/weak-key/noncanonical/scalar/
all-zero-DH/entropy-failure/usage-limit negatives. Validate explicit entropy
and allocation-failure seams without presenting them as observed system
failures. Browser memory high-water, physical mobile pressure, full-profile
latency, worker responsiveness, duplicate work, lock/cancel/late reply and
visibility/resume behavior require actual execution under the qualification
brief. Source documentation cannot establish those results. There are no new
deployable environment settings in this research; the project completeness
and unset/demo report remain required session gates.

## Research verification evidence

Run: `bitbid-team-qualification-20261109T223428Z`; evidence is under its
`evidence/primitive-*` paths. `primitive-verify-evidence.py` rechecks registry
checksum matches, the frozen contract hash, RFC extraction provenance and
fixture shapes. Its log distinguishes artifact checks from runtime evidence
and flags a changed Cargo lock for advisory-query refresh. `git diff --check`
passed. The actual encrypted catalog/report commands passed with seven unset
entries, recorded in `primitive-environment-check.log`; no encrypted settings
were changed. `primitive-research-commands.md` records retrieval/check commands
and the bounded download recovery. The final build owner must refresh any
changed lock and perform all remaining qualification gates.
