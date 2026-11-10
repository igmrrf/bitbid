# Native mapped Store and selected list reads

`bitbid_adapters::store::FileStore` implements the public synchronous `Store`
interface for explicitly supplied `Wallet`, `NetworkConfig` and `SecretIndex` paths. It
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

Selected CLI `list` reads and [read-only wallet unlock](wallet-read.md) use this adapter. Each list accessor first invokes
the existing lazy native path selector, then constructs its single-key Store:
initial index enumeration; network config for each enumerated ID; index reload
after each successful RPC, before filtering. The selected root remains cached by
the existing selector and is revalidated each time. Its existing directory
creation policy is retained. Path-selection failures remain fatal `ConfigError`;
subsequent file I/O/UTF-8/JSON/schema errors preserve the original default-network
or empty-index fallback. Empty enumeration never loads config or calls RPC.
Registry reads still receive only Rpc and panic-on-unused other ports. The
selected caller now delegates filtering to the [pure list policy](registry-list-policy.md);
its native callback retains these lazy reads and immediate error/warning behavior.

Global native loaders, hide's legacy list/read/write path, wallet writers, index/config
writers, IPFS/cache and signing retain their existing implementations. There is
no data migration or write/remove cutover. Reverting only this adapter/export,
manifest/lock additions, selected composition and tests restores the previous
read path without rewriting stored data; preserve unrelated working-tree work.

Real-OS tests live in `bitbid-adapters/tests/file_store.rs` plus the private
before-truncation descriptor test in `src/store.rs`. Actual selected-list lazy,
denied-access and dynamic config/index checks are in
`crates/bitbid-cli/tests/support/store_list_probe.py`. From the native workspace
root, pass the absolute path of the built CLI and the canonical home selector:

```sh
python3 crates/bitbid-cli/tests/support/store_list_probe.py \
  --binary /absolute/path/to/bitbid --home-env BITBID_HOME
```

The probe accepts only `BITBID_HOME`. Retired environment/path inputs are ignored
by the CLI; [alias_removal_probe.py](../../crates/bitbid-cli/tests/support/alias_removal_probe.py)
verifies that denial/nonselection behavior. The existing 54-case
`registry_probe.py` remains the output/RPC oracle. These probes use disposable
synthetic homes and loopback services and leave no service running.
