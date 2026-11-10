# Selected registry list policy

`bitbid_core::registry_list::{ListQuery, list_indexed}` selects ordered typed
registry facts through a caller-supplied reader. Its public interface takes
original string IDs and enumeration-time hidden flags; it returns original IDs
and all eleven `RegistryInfo` fields without normalization. It owns no Host,
configuration, credentials, persisted index schema, or I/O.

For each entry the reader runs before every filter. `Ok(None)` skips the entry;
`Err(E)` immediately returns the same generic error. Hidden entries require
`all`; otherwise the default owner/recipient/public policy applies. An explicit
user filter replaces ownership selection and compares the visible sender and
recipient case-insensitively, including the literal `public`. Public recipient
selection uses that literal, while the binary recipient fact remains unchanged.
Expiry is the chain's `is_expired || limit_reached || revoked`; timestamps and
counters never recompute it. Applying both active and expired filters yields no
rows. Input order is retained and empty enumeration never invokes the reader.

Only CLI `blockchain::list_registry_secrets` uses this policy. Its callback
retains native error classification: typed `BitbidError::ConfigError` is fatal;
other failures warn immediately and skip. Each read resolves/revalidates native
network config, pairs that config's endpoint and registry, and performs one
`eth_call` at `latest`. After a successful read it reloads the index, retaining
fallback and fatal path-selection effects even though policy uses the original
hidden flag. Empty enumeration does not select config or RPC. Native projection
preserves checksum addresses, public recipient text, every chain fact and the
existing `SecretRecord` bytes with `hidden: false`.

Legacy hide continues through unchanged `list_secrets_on_chain`,
`list_secrets_with`, `list_index_with` and `get_secret_info_on_chain`. There is no
wallet, write, signing, IPFS or lifecycle cutover, schema migration, dependency,
lockfile or deployable setting change. Rollback removes only this policy/export
and restores the selected caller/raw-reader projection; retain Store mapping,
wallet codec/nonce safety and legacy behavior.

Public native/executed-WASM consumers cover policy, callback order, exact facts,
original IDs, typed fatal errors and Host/RPC composition with every unused port
fail-stop. Native tests cover immediate warning/error order and projection.
`tests/support/registry_probe.py` retains the 54-case output/RPC oracle and now
records stderr and checks file modes. `tests/support/store_list_probe.py` covers
actual lazy config/index selection, enumeration-hidden snapshots, public filters,
late failures and read-only file effects. Both accept explicit binary paths and
baseline reports, use only synthetic homes/loopback services and stop owned
services. Release and fresh offline path-installed binaries are exercised; no
live provider or global installation is needed. No web UI route consumes this
module, so browser/mobile visual checks are not applicable to this extraction.
