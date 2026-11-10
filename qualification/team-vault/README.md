# Isolated team-vault qualification

This standalone Rust workspace qualifies the agreed candidate protocol. It does
not integrate a production vault, backend, identity provider, dashboard, wallet,
or legacy decoder. All roots, passphrases, signing seeds, recovery codes and
values in `reference/` and `vectors/` are **public synthetic test material**.
Never reuse deterministic fixture entropy for real accounts.

The schema input is `../../docs/split-core/team-vault-keys.md`, frozen SHA256
`6a9b26878f1192727e8ca6e52a9da449d21d7b8b7c45b827e601de2cd9b66d6a`.
The committed independent Python corpus is consumed unchanged by native Rust and
optimized WASM. A manifest records its hash plus all served browser artifacts.
Keep expected bytes under review; do not regenerate them during a Rust test to
make its result pass.

From the BitSec project root (the parent of `bitsec/`):

```sh
uv venv bitsec/qualification/team-vault/reference/.venv
uv pip sync --require-hashes --python bitsec/qualification/team-vault/reference/.venv/bin/python bitsec/qualification/team-vault/reference/requirements.lock
bitsec/qualification/team-vault/reference/.venv/bin/python bitsec/qualification/team-vault/reference/generate.py
python3 .local/run.py bitsec/qualification/team-vault test --locked --release -- --nocapture
python3 .local/run.py bitsec/qualification/team-vault run --locked --release
python3 .local/run.py bitsec/qualification/team-vault fmt --check
python3 .local/run.py bitsec/qualification/team-vault clippy --locked --all-targets -- -D warnings
python3 bitsec/qualification/team-vault/scripts/build.py
/Users/igmrrf/.local/share/nvm/v22.22.2/bin/node --experimental-default-type=module bitsec/qualification/team-vault/scripts/node.mjs
python3 bitsec/qualification/team-vault/scripts/serve.py --evidence /absolute/evidence/browser --port 0
```

`.local/run.py` is this checkout's pre-existing pinned Rust toolchain wrapper.
On another host use equivalent Cargo commands from this directory, its own
Cargo.lock, a compatible Rust toolchain, the wasm32-unknown-unknown target, and
wasm-bindgen CLI0.2.129 matching the exact library schema. `build.py` currently
uses that wrapper and checkout-local CLI. No parent workspace exclude is needed:
this manifest declares its own `[workspace]` and independent lockfile. Generated
`web/pkg/` is ignored; build before serving. `web/build.json` records generated
WASM/JS and source worker/page hashes. `--manifest-only` refreshes those hashes
without compiling; it is not a substitute for rebuilding changed Rust/corpus.

The reference generator uses separately pinned PyNaCl/libsodium for Ed25519 and
XChaCha, cryptography/OpenSSL for X25519/ChaCha/HKDF, and argon2-cffi/libargon2 for
the production KDF. Its RFC9180 labeled HKDF composition does not import Rust
code. Standard RFC9106 secret/associated-data KAT is separate from the fixed
production profile. RFC8032, RFC9180 Base suite32/1/3 sequence0 and an upstream
libsodium XChaCha vector retain primary-source extraction provenance.

`src/codec.rs` bounds/parses canonical frames, lists, transport and identities.
`crypto.rs` binds strict canonical enrollment/signatures, distinct KDF domains,
fallible entropy/allocation and nonce/usage retry accounting. `protocol.rs`
checks actual signed authorities and snapshots against accepted prior state;
`backup.rs` checks the exact selected-data proof projection and decrypts selected
current data plus account wrappers. `client_state.rs` exercises local pending/
sent/uncertain activation and current-authority/content-head import CAS.
`src/suite.rs` executes actual fixture inputs and asserts results; expected
accept/reject values are test assertions, never verifier authorization inputs.

Activation content is bound to the authority actor at the snapshot that creates
a vault or replaces its epoch. Every replacement body, including labels and
tombstones, must carry that actor's signature. Selected exports apply the same
rule at each selected body's introduction, including an initial body retained
by later snapshots. Ordinary eligible Member content edits/deletes/restores and
privileged label edits remain valid under the same current `rotate` or
`new-vault` plan. The appended regression corpus preserves all original records,
cases and exports, and pairs correctly signed forbidden bodies with valid
Owner-signed snapshots, exact grant/content sets and matching plaintext.

Open the printed loopback URL in an actual target browser. **Run qualification**
executes the same suite, real cold/warm full-profile KDF, worker acknowledgement
before cancellation, duplicate submission denial, actual delayed old-generation
reply, injected15m/5m deadline boundaries, and a distinct32MiB-max WASM allocation
failure. No weak KDF is substituted. Final metrics auto-save; the upper message
says “Saved synthetic metrics…” and JSON contains `pass`/`status`.

**Arm visibility/resume check**, switch to a different tab/app and return. This
uses real visibility events plus an explicitly injected5m clock offset; it is
not a claim that five wall-clock minutes elapsed. **Run two-tab KDF** coordinates
actual separate tabs with timestamped overlapping KDF intervals. If Safari
blocks its asynchronous popup, manually open the same URL with `?peer=1` in a
new owned tab after pressing the button; keep popup security settings unchanged.
Close only the owned peer after its auto-save. Reload must begin Locked; an
ordinary KDF may complete, and **Lock / cancel** invalidates its generation.

The page has no durable storage, service worker, external scripts or analytics.
The worker emits case statuses, timing, memory and reference-match metadata;
it emits no derived root/key/plaintext. The local collector accepts bounded
metrics JSON under `/evidence`, not arbitrary uploaded content. Restrictive CSP
limits connections to the same origin. A controlled worker UI state exercises
lifecycle logic; it does not prove a future product clears every JS/WASM/OS copy.

Required resource budgets, observed targets, evidence and remaining gates are in
`../../docs/split-core/team-vault-qualification.md`. A32MiB forced WASM cap is
allocator failure injection, not evidence that a physical device has32MiB RAM.
The selected Pixel7 is tested under its existing app memory pressure, preserving
user apps/data. No other hardware class is implicitly qualified.
