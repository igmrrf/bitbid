# Legacy wallet codecs

[Extract wallet codecs and reject malformed nonce lengths](https://github.com/igmrrf/bitbid/issues/32)
adds `bitbid_core::wallet_codec`. Native `wallet.rs` delegates its KDF, encryption,
decryption, manual JSON rendering, mnemonic generation and BIP44 derivation to
this module. Initialization, filesystem paths, permissions,
sequential wallet/config writes, timestamps and `StoreKey` are unchanged.

The format is frozen: Argon2 **0.5.3**, Argon2id v19, m19456 KiB/t2/p1/output32;
salts shorter than eight bytes first expand through SHA256. Encryption consumes
16 salt bytes followed by 12 nonce bytes through the existing `RandomSource`.
AES-256-GCM uses its 16-byte tag and no AAD; all three colon-separated fields use
standard padded Base64. Decryption retains legacy salt acceptance, error order,
wrong-password behavior and UTF-8 validation. A decoded nonce of any length other
than 12 now returns `Invalid wallet nonce length` before `Nonce::from_slice`.
The old optimized CLI aborted on that input.

Mnemonic generation consumes exactly 16 injected bytes. Derivation uses
`m/44'/60'/0'/0/0`, an empty BIP39 passphrase, uncompressed SEC1 public keys and
EIP-55 addresses. Derivation failure has no alternate-key fallback. `bip32` uses
its Rust `k256` implementation, without its optional C secp256k1 backend; `bip39`
uses its current locked 2.2.2 version. These pure dependencies are qualified by
executed native and WASM consumers and removed from the guard's explicit native
adapter deny list. OS/filesystem/CLI/HTTP adapters remain forbidden.

This legacy profile is separate from team-vault qualification. Its Argon2
0.6 candidate and m65536/t3/p4 parameters never replace existing wallet bytes.

Core functions accept explicit inputs and never read OS randomness, environment,
files or time. The native adapter uses `OsRng` and its fail-stop behavior; it has no
deterministic fallback. `WalletFields` borrows native fields. New secret-owning
key results have no `Debug`/`Clone`, and guard private output with `Zeroizing`.
The renderer reserves worst-case escaping space and writes into one guarded
allocation. Decryption moves its checked UTF-8 allocation without cloning.
Seed, entropy, KDF working output and private-key buffers are guarded; existing
native `WalletInfo` and decrypted-JSON guards remain. Existing native APIs return
some unguarded strings/arrays, imported mnemonic ownership and library/compiler
copies have limits, and complete process-memory erasure is **not** promised.

`crates/bitbid-core/tests/vectors/wallet-codec-v1.json` contains only public,
synthetic test keys/passwords. Never use them for funds or secrets. It was frozen
from the actual pre-extraction implementations before production edits, with
only evidence-copy OS entropy replaced by sequential test bytes. Original wallet
source SHA256: `204535fac4831ee72eb6b9585a31b47aed81d69a0204aeb914a09ca3be3ec6a2`.
Vector SHA256: `da7b9da879cda88da93dbbde192696a7342b60eb5a1ce4a2aa7fd2a69059a00c`.
Full baseline-source/harness hashes and runtime evidence live in the ticket's
Codinary run. Public native/WASM consumers compare full ciphertext, JSON variants,
KDF/key/address/mnemonic bytes and reject malformed fields, Base64, nonce sizes,
authenticated invalid UTF-8, mnemonic and private-key values.

No new deployable setting or existing wallet data migration is required. No web
UI route consumes this module. Rollback may remove the extraction wrappers, but
must retain the explicit nonce-length guard to avoid restoring the known abort.
[Read-only Store integration](wallet-read.md) is a separate extraction over these
codecs. Initialization lifecycle extraction remains a separate ticket.
