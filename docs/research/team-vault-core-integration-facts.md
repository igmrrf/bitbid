# Team-vault core integration facts

Research snapshot: 2026-11-10 UTC, for [portable protocol core](https://github.com/igmrrf/bitbid/issues/50).
This is a narrow infrastructure compatibility check against native baseline
`272987add635904e970bea0ff04ede4048359afe`, its retained locks, and the separate
[qualified candidate](team-vault-primitive-qualification-facts.md). It does not
qualify the final production graph or replace public-interface/native/WASM/browser
execution. The algorithm pins and frozen protocol are unchanged inputs.

## Source provenance

The published archives below were checked against each exact version's primary
crates.io checksum. Every archived file in each available unpacked cache copy
matched the archive used for this research. The embedded VCS records identify
the immutable upstream sources cited below. Full manifests, archives, VCS IDs,
file comparisons, requests and dated results are under this run's
`evidence/integration-facts-*` paths:
`/var/folders/wt/srss_rcj5cq7f60_2h9gvt040000gn/T/codinary/bitbid-team-core-20261110T022610Z`.

| Exact published crate | Archive SHA-256 |
| --- | --- |
| [zeroize 1.9.0](https://crates.io/api/v1/crates/zeroize/1.9.0) | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` |
| [zeroize 1.9.1](https://crates.io/api/v1/crates/zeroize/1.9.1) | `e13084392c5e4bc371903e2935a5eaeed24905a7511356b883835e18a78f6879` |
| [serde_json 1.0.151](https://crates.io/api/v1/crates/serde_json/1.0.151) | `c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14` |
| [serde_json 1.0.154](https://crates.io/api/v1/crates/serde_json/1.0.154) | `e7e9cc8b1b85264074fbcc02a88680c4096b1e47df8f739dceb03bf482f04bd6` |
| [getrandom 0.4.3](https://crates.io/api/v1/crates/getrandom/0.4.3) | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` |
| [wasm-bindgen 0.2.126](https://crates.io/api/v1/crates/wasm-bindgen/0.2.126) | `4b067c0c11094aef6b7a801c1e34a26affafdf3d051dba08456b868789aaf9a4` |
| [wasm-bindgen 0.2.129](https://crates.io/api/v1/crates/wasm-bindgen/0.2.129) | `9bb54f33acc68fd454578d9820b0bde1a1a3d17aa17bb7b6595806d02886d409` |

The source manifest additionally records exact js-sys 0.3.103/0.3.106,
wasm-bindgen-test 0.3.76/0.3.79, and both versions of the shared/CLI/CLI-support
packages. The copied baseline native lock hash is
`03ccf6d296c396132640389549f3df1469bc8fc7df9eef8a592fe31059064585`;
web is `1b58d546d497cbbecae252a453864acb5929ca938511b70f911a4a4d2c9f9f7a`.
The isolated qualification lock remains
`394593d0fa941d9d323402fc2b1b141b11d9e9524c20d25d5de2e69cb5758cf9`.
These are distinct graphs, even when the selected algorithm packages match.

## Zeroize: targeted patch justified

The actual 1.9.0 source has a known safe-API defect: its non-asm
`optimization_barrier` fallback reads byte zero as `u8`, including when that byte
is uninitialized. The public call
`optimization_barrier(&MaybeUninit::<u8>::uninit())` is a concrete trigger.
`wasm32-unknown-unknown` selects that fallback; normal aarch64 native selects
the asm branch, while Miri selects the fallback. In 1.9.0 the ordinary primitive,
Option, MaybeUninit, slice and flat-type zeroizers also call the barrier.
The fixed fallback reads `MaybeUninit<u8>`, and 1.9.1 removes internal barrier
calls. Sources: [1.9.0 barrier](https://github.com/RustCrypto/utils/blob/0b715735a660a8566ccd240bf42489fe2ed98efb/zeroize/src/barrier.rs),
[1.9.0 zeroizers](https://github.com/RustCrypto/utils/blob/0b715735a660a8566ccd240bf42489fe2ed98efb/zeroize/src/lib.rs),
[fixed barrier](https://github.com/RustCrypto/utils/blob/34a6ebcb9b920ec7ae5809e470fce94fe7c0cb55/zeroize/src/barrier.rs),
[maintainer fix](https://github.com/RustCrypto/utils/pull/1551).
This does not establish that initialized byte buffers or fully initialized KDF
scratch trigger the defect, nor that a previous wallet operation was exploitable.

There is also an observable privacy change: 1.9.0 derives `Debug` for
`Zeroizing<T>` and prints its inner value; 1.9.1 supplies an opaque implementation.
Both versions still allow conditional `Clone`, dereferencing and, if the optional
`serde` dependency is enabled, serialization/deserialization of the inner value.
The guard alone therefore cannot enforce the product's private, non-cloneable,
non-serializable secret interface. Explicit redacted secret owners remain needed.
Sources: [1.9.0 guard](https://github.com/RustCrypto/utils/blob/0b715735a660a8566ccd240bf42489fe2ed98efb/zeroize/src/lib.rs),
[1.9.1 guard](https://github.com/RustCrypto/utils/blob/34a6ebcb9b920ec7ae5809e470fce94fe7c0cb55/zeroize/src/lib.rs),
[maintainer Debug change](https://github.com/RustCrypto/utils/pull/1497).

`Zeroizing::drop` still calls the inner `zeroize` in both versions. Both cover
Vec spare capacity, but 1.9.0 zeroizes initialized elements, clears/drops them,
then zeroes the entire now-spare allocation; 1.9.1 zeroes the genuinely spare
capacity first, then zeroizes and drops initialized elements. This removes a
second pass over the initialized region; it does not add protection for old
allocations left by reallocation. Feature maps are unchanged: default enables
`alloc`, `std` enables `alloc`, `derive` enables `zeroize_derive`, and optional
`serde` remains separate. Sources: [fixed implementation and limits](https://github.com/RustCrypto/utils/blob/34a6ebcb9b920ec7ae5809e470fce94fe7c0cb55/zeroize/src/lib.rs),
[Vec change](https://github.com/RustCrypto/utils/pull/1525),
[exact manifest](https://github.com/RustCrypto/utils/blob/34a6ebcb9b920ec7ae5809e470fce94fe7c0cb55/zeroize/Cargo.toml).

**Integration decision:** after receiving this concrete source evidence, the
root coordinator approved the minimal exact `zeroize = 1.9.1` patch and necessary
native/web lock changes. The source owner implements it; this researcher changes
no manifests or locks. This matches the qualified guard version and removes the
known fallback defect. It does not authorize a broad legacy upgrade. The old
Argon2 algorithm/profile and legacy bytes still require the prescribed regression
gates. The pre-patch offline dependency probe resolved zeroize features
`alloc`, `default`, `zeroize_derive`; the final production union must be recorded
after resolution, including confirmation of any optional `serde` enablement.

## Serde JSON: retain 1.0.151, verify the bounded schema

Published changes from 1.0.151 through 1.0.154 are specific:

| Release | Relevant change and condition |
| --- | --- |
| [1.0.152](https://github.com/serde-rs/json/releases/tag/v1.0.152) | Preserve negative zero with `arbitrary_precision`; fix comparison of large non-integer numbers with `f32::INFINITY`. |
| [1.0.153](https://github.com/serde-rs/json/releases/tag/v1.0.153) | Invalid UTF-8 errors point at the first bad byte, including optional raw-value paths. Acceptance still rejects invalid UTF-8; error locations can differ. |
| [1.0.154](https://github.com/serde-rs/json/releases/tag/v1.0.154) | Enable `preserve_order` without `std`; this adds optional foldhash for that mode. |

The exact archive comparison finds `src/ser.rs`, `src/error.rs`,
`src/value/ser.rs` and `src/value/de.rs` byte-identical. The numeric changes are
in `de.rs`/`number.rs`; UTF-8 positions change in `read.rs`; map backing/feature
changes are in `map.rs`/Cargo. Sources: immutable
[1.0.151 tree](https://github.com/serde-rs/json/tree/de8500740cdcabffb9734f503e4889def823cf10/src),
[1.0.154 tree](https://github.com/serde-rs/json/tree/20572a6d066958542d79cdd6cf1a7cd9f0c8e1f8/src).
The observed pre-patch probe and qualified graph both enable only `default,std`
for JSON. This supports retaining 1.0.151 for bounded integer/string/list
trust/export data; it is not a claim of equivalence for arbitrary inputs or
feature unions. No source finding here requires changing the legacy JSON parser,
and an upgrade could change existing invalid-UTF-8 diagnostics. Final features,
frozen bytes and malformed-input behavior still need actual verification.

Neither version makes arbitrary `Value` parsing a strict canonical-schema
validator: its object visitor inserts entries into a map, replacing an earlier
duplicate key. Both start with recursion depth128; that is not the contract's
input-byte, element-count or allocation budget. Strict duplicate/shape/order/
integer/size checks and payload-free application errors must be enforced by the
bounded trust/export layer before expensive work. Sources:
[Value visitor](https://github.com/serde-rs/json/blob/de8500740cdcabffb9734f503e4889def823cf10/src/value/de.rs),
[parser limits/end check](https://github.com/serde-rs/json/blob/de8500740cdcabffb9734f503e4889def823cf10/src/de.rs).

## Getrandom and artifact/tool coupling

The exact getrandom0.4.3 manifest has no default feature. `fill` needs neither
`std` nor `sys_rng`. `wasm_js` enables optional wasm-bindgen and js-sys: the
OS-less WASM target requires wasm-bindgen `0.2.98`, while js-sys `0.3.77` is
targeted only to the atomics branch. Under Cargo's default version-range rules,
these admit retained bindgen0.2.126/js-sys0.3.103 and web0.2.129/js-sys0.3.106;
this is a requirement calculation, not runtime evidence. Enabling the feature
selects the JS backend on OS-less WASM unless an explicit backend overrides it.
Keep it at the browser adapter/executable boundary: upstream warns that enabling
it in a general library breaks non-Web WASM uses, with an exception for libraries
already requiring the JS bindings. Sources: [exact manifest](https://github.com/rust-random/getrandom/blob/5e7cd5733536844a9856dc7259bd4696bbe5e3ae/Cargo.toml),
[backend dispatch](https://github.com/rust-random/getrandom/blob/5e7cd5733536844a9856dc7259bd4696bbe5e3ae/src/backends.rs),
[Cargo range rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#version-requirement-syntax).

The non-atomics backend passes mutable `MaybeUninit<u8>` slices to caught
`globalThis.crypto.getRandomValues` calls in chunks of at most65536 bytes.
The atomics backend uses a JS Uint8Array and copies back after each call. The
relevant wasm-bindgen slice conversion source is identical in 0.2.126/0.2.129;
both js-sys versions supply `copy_to_uninit`. `fill` returns an error on any
failure and provides no guarantee about destination contents on error, so the
application must discard/wipe the complete owned destination after partial
failure. Sources: [getrandom API](https://github.com/rust-random/getrandom/blob/5e7cd5733536844a9856dc7259bd4696bbe5e3ae/src/lib.rs),
[browser backend](https://github.com/rust-random/getrandom/blob/5e7cd5733536844a9856dc7259bd4696bbe5e3ae/src/backends/wasm_js.rs),
[bindgen0.2.126 slice support](https://github.com/wasm-bindgen/wasm-bindgen/blob/21ac804a96c0c5c5d6459084686a9a17a8a3c865/src/convert/slices.rs),
[js-sys0.3.103 support](https://github.com/wasm-bindgen/wasm-bindgen/blob/21ac804a96c0c5c5d6459084686a9a17a8a3c865/crates/js-sys/src/lib.rs).

The binding family itself has exact edges: js-sys0.3.103 and test0.3.76 require
bindgen0.2.126; js-sys0.3.106 and test0.3.79 require bindgen0.2.129. More
precisely, the CLI checks descriptor **schema equality**, not broad semver:
shared0.2.126 has schema0.2.122 and shared0.2.129 has schema0.2.128. These two
artifacts therefore cannot share one of those mismatched CLIs. The test runner
uses the same CLI-support Bindgen machinery. Use the exact matching CLI/runner
for each final producing lock, record hashes, and rebuild JS with its WASM.
Sources: [native binding manifests](https://github.com/wasm-bindgen/wasm-bindgen/tree/21ac804a96c0c5c5d6459084686a9a17a8a3c865/crates),
[web binding manifests](https://github.com/wasm-bindgen/wasm-bindgen/tree/165586f854c852bcbc4d14d8a75a0a0e0d0abc12/crates),
[native schema](https://github.com/wasm-bindgen/wasm-bindgen/blob/21ac804a96c0c5c5d6459084686a9a17a8a3c865/crates/shared/src/lib.rs),
[web schema](https://github.com/wasm-bindgen/wasm-bindgen/blob/165586f854c852bcbc4d14d8a75a0a0e0d0abc12/crates/shared/src/lib.rs),
[schema check](https://github.com/wasm-bindgen/wasm-bindgen/blob/21ac804a96c0c5c5d6459084686a9a17a8a3c865/crates/cli-support/src/wit/mod.rs),
[test runner](https://github.com/wasm-bindgen/wasm-bindgen/blob/21ac804a96c0c5c5d6459084686a9a17a8a3c865/crates/cli/src/wasm_bindgen_test_runner.rs).

## Limits and required final evidence

The dated [OSV exact-version batch](https://google.github.io/osv.dev/post-v1-querybatch/)
returned17 empty results for the inspected infrastructure versions. The known
zeroize defect above still exists in the source despite that empty response;
absence of an advisory record is not proof of safety. This lookup covers only
these packages, not the final production graph. A changed final graph requires
its own current advisory/source/feature record. There is no cryptographic audit
or claim that production equals qualification's64-package graph.

Actual final native/WASM/facade tests, frozen139/54/21 interoperability and four
primitive KATs, explicit Debug/ownership/error/entropy-failure checks, optimized
production consumer and existing Yew/browser smoke gates remain with the source
owner and independent reviewer. Source compatibility cannot establish WebCrypto
availability, JS glue correctness, performance or allocation behavior in the
installed browser. No browser/device action or production setting was introduced
by this research. Its encrypted catalog/report check passed with all seven
existing entries unset (`integration-facts-environment-check.log`); final session
verification remains required. No secret value belongs in this note or evidence.
