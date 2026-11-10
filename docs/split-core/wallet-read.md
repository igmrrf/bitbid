# Read-only legacy wallet unlock

[Extract read-only wallet unlock through native storage](https://github.com/igmrrf/bitbid/issues/33)
adds `bitbid_core::wallet_read::read_wallet(&dyn Store, Option<&str>)`. It reads
`StoreKey::Wallet` exactly once. It never calls `exists`, writes/removes data, or
uses Clock, RandomSource, IPFS or RPC. Native `wallet::get_wallet_info` resolves
and revalidates its existing application directory at the same lazy point, then
constructs one explicit Wallet mapping in the real native FileStore. Existing
wallet info/export, list and all other get_wallet_info callers use this flow.

Order remains native path selection → original native Path::exists metadata
check → wallet read/UTF-8 → outer WalletFile JSON →
encrypted-only password requirement → existing guarded codec decrypt → inner
WalletInfo JSON. Plaintext ignores a supplied password. Stored address, public
key, private key, mnemonic, user ID and timestamps are returned unchanged; keys
are not rederived or newly validated. The outer timestamp is not copied over the
inner timestamp. No read updates last_accessed, file bytes, modes or mtime.

The native path selector still may create a missing application directory0700;
this historical effect occurs before the read and is not performed by core or
FileStore. Canonical/legacy selection, warnings and revalidation are unchanged.
Valid final/root symlinks are followed, dangling wallet symlinks are absence,
directories fail, and real file-read permission denial stays typed. The original
native presence check still masks metadata failures (including a denied symlink
target-parent or a final symlink loop) as native WalletNotFound/exit1. Core does
not duplicate this host compatibility check or call Store.exists. FileStore now accepts
explicit Wallet bindings with its existing complete read/write/exists/remove
semantics; this does not switch any native wallet writer or initialization.

Missing wallet and wrong password retain their concrete native error types.
Missing password, UTF-8, safe JSON portions and codec errors retain legacy text.
Malformed serde Data diagnostics previously quoted input strings/numbers and
could leak private data. The new error keeps only static allowlisted schema
fields/expected types, redacted unexpected-value kinds and line/column. Unknown
Data diagnostics use fixed text. Parser Syntax/EOF messages remain static. The
historical exit is classified before redaction into a bounded code, then projected
explicitly by the CLI; removing an input word such as password does not change
its old exit. Raw serde/Store payloads are not retained in the returned error,
Debug or source chain. FileStore discards OS errno wording, so native permission
read errors now display `Permission denied` with the original exit3; other Store
read errors display `Wallet storage read failed` with exit1. No extra OS read or
port API was added to reconstruct errno text.

The core result and outer record have wiping Drop and no Debug/Clone. Read bytes,
outer data and decrypted JSON are guarded; native fields move into its existing
Zeroize-on-Drop WalletInfo without cloning. Explicitly requested private
info/export output is preserved. Serde/library temporaries, native legacy APIs
and compiler copies have limits: complete process-memory erasure is not promised.

Public native/executed-WASM consumers cover exact stored fields, one-read traces,
panicking other ports, malformed/password order, safe errors with historical
input-influenced exits and recovery. CLI regressions cover real mapping,
no-prompt failures, redaction, explicit private output and unchanged file state.
Runtime qualification uses public synthetic data only, never a user's wallet.
No web UI route consumes this module; no new deployable setting is required.

Rollback only this reader/export, Wallet mapping and native composition/exit
projection. Preserve [wallet codecs](wallet-codecs.md), their nonce-length safety
check, and all wallet data. Initialization and WalletConfig remain separate work;
there is no migration, rewrite-on-read, write cutover or data rollback.
