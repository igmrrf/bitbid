# Native mapped Store and selected list reads

`bitbid_adapters::store::FileStore` implements the public synchronous `Store`
interface for explicitly supplied `NetworkConfig` and `SecretIndex` paths. It
performs no environment/home selection, parent creation, JSON decoding or fallback.
Other keys remain unconfigured, even if passed to the constructor; every method
returns `StoreError::Io("unconfigured store key")` for them.

```rust
use bitbid_adapters::store::FileStore;
use bitbid_core::{Store, StoreKey};
let store = FileStore::new([(StoreKey::SecretIndex, resolved_index_path)]);
let bytes = store.read(&StoreKey::SecretIndex)?;
```

For mapped keys, reads return exact bytes and absence is `None`; `exists` opens
and validates a readable regular file, returning false for missing/dangling
entries. Valid final symlinks are followed for reads. Directories/nonregular
objects fail with `Io`; actual access denial is `PermissionDenied`. Reading or
checking does not rewrite data or chmod files. Missing parents are not created.
Errors carry fixed safe text, without paths or content.

On Unix, writes use `O_NOFOLLOW` on the final component; parent symlinks remain
supported. `create_new` uses the operating system's atomic exclusive create and
returns `AlreadyExists` for any existing entry, including dangling symlinks.
Files are opened without truncation, checked as regular files, then (for private
writes) chmodded to `0600` on the descriptor before truncation or payload data.
New private files are created with mode `0600` and the descriptor permissions are
enforced even under a restrictive umask. Ordinary new files honor umask; ordinary
replacement retains existing permissions. Failure before truncation preserves
existing bytes. Later truncation/write errors may leave partial data: this is not
an atomic replacement, transaction, durability or fsync guarantee.

`remove` unlinks the mapped entry only, including a symlink without touching its
target. Absent entries succeed; directories fail with `Io`; permission failures
remain typed. It never removes parent directories.

Local OS qualification is macOS/Unix. Private writes on non-Unix hosts fail
explicitly because Windows ACL privacy is not implemented. The Unix descriptor
and symlink guarantees do not establish Windows distribution-host qualification.

Only the selected CLI `list` reads use this adapter. Each accessor first invokes
the existing lazy native path selector, then constructs its single-key Store:
initial index enumeration; network config for each enumerated ID; index reload
after each successful RPC, before filtering. The selected root remains cached by
the existing selector and is revalidated each time. Its existing directory
creation policy is retained. Path-selection failures remain fatal `ConfigError`;
subsequent file I/O/UTF-8/JSON/schema errors preserve the original default-network
or empty-index fallback. Empty enumeration never loads config or calls RPC.
Registry core still receives only Rpc and panic-on-unused other ports.

Global native loaders, hide's legacy list/read/write path, wallet data, index/config
writers, IPFS/cache and signing retain their existing implementations. There is
no data migration or write/remove cutover. Reverting only this adapter/export,
manifest/lock additions, selected composition and tests restores the previous
read path without rewriting stored data; preserve unrelated working-tree work.

Real-OS tests live in `bitbid-adapters/tests/file_store.rs` plus the private
before-truncation descriptor test in `src/store.rs`. Actual selected-list lazy,
denied-access and dynamic config/index checks are in
`bitbid-cli/tests/support/store_list_probe.py` (accepts an explicit `--binary` and
`--home-env BITBID_HOME|BSEC_HOME`). The existing 54-case `registry_probe.py` remains
the output/RPC oracle; both probes use disposable synthetic homes and loopback
services and leave no service running.
