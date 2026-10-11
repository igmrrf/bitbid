# Module partition — core vs adapters

This document records the ruling from the wayfinder partition spec: how each of
the 14 modules in `bitsec/src/*.rs` is assigned to a pure `core` crate, a native
`adapters` crate, or split between the two. It is a planning prototype; the real
split is not performed here.

## Port seams (sync)

All five port traits are **synchronous** (`Send + Sync`). Async is confined to
the SSR server-function shell, which bridges blocking work with
`tokio::task::spawn_blocking`. Polymorphism is by trait object (`Arc<dyn Trait>`),
not generics. A `Host` bundle carries `store: Arc<dyn Store>`, `ipfs: Arc<dyn
Ipfs>`, `rpc: Arc<dyn Rpc>`, `clock: Arc<dyn Clock>`, `random: Arc<dyn
RandomSource>`; core entry points take `&Host`. Errors are per-port typed enums
(`StoreError`, `IpfsError`, `RpcError`) unified by an umbrella `core::Error`
via `#[from]`; `anyhow` is rejected in core. Adapter-only concerns (never in the
core interface) are process spawn, terminal I/O, env-var reads, all
`println!`/`eprintln!`, user-addressed file I/O, and `libc` staging/signal
cleanup.

## Per-module ruling

| Module | Ruling | Core content | Adapter / CLI content |
|---|---|---|---|
| `bip39_words` | core | the static word list | — |
| `wallet` | split | pure `hash_digest`, `bytes_to_hex`, `hex_to_bytes`, `derive_key`, `encrypt_wallet`, `decrypt_wallet`, `json_escape_into`, `render_wallet_json`, `generate_mnemonic`; orchestration `init_wallet`, `get_wallet_info` over `Store`/`Clock`/`RandomSource` | concrete `Store` impl: fs, perms, `O_NOFOLLOW` |
| `secrets` | split | pure `parse_duration`, `derive_ecdh_key`, `encrypt_text`, `decrypt_text`, `seal_member_bodies`, `open_member_bodies`, `resolve_recipient_pubkey`; orchestration `share_secret`, `view_secret`, `view_payload`, `list_secrets`, `revoke_secret`, `hide_secret`, `load_secret_as_env` over `Host` | concrete `Ipfs`/`Rpc`/`Store` impls |
| `eth` | split | all RLP/ABI/address/signing pure fns (`hex_to_u128`, `be_trim`, `rlp_str`, `rlp_list`, `parse_address`, `addr_hex`, `selector`, `decode_secret_info`, `sign_legacy_tx`, `sign_eip1559_tx`, …) plus `eth_call`, `send_contract_tx`, `latest_base_fee`, `suggested_priority_fee`, `wait_for_receipt` over `Rpc`+`Clock` | concrete `Rpc` impl (`reqwest::blocking`, timeout) |
| `blockchain` | split | pure `keccak256`, `bytes_to_checksum_address`, `encode_bytes32_hex`, `registry_address`; state fns `load_index`, `save_index`, `index_note`, `index_set_hidden`, `index_is_hidden`, `register_secret_on_chain`, `get_secret_info_on_chain`, `record_read_on_chain`, `revoke_secret_on_chain`, `hide_secret_on_chain`, `list_secrets_on_chain` over `Store`+`Rpc` | concrete impls |
| `ipfs` | split | `valid_cid` (pure) + cache policy via `Store::IpfsCache` | concrete `Ipfs` impl: Pinata/Kubo/gateway + JWT |
| `network_config` | split | config types, `default_ipfs_api_url`, `Default`; `load_network_config`, `save_network_config`, `update_network_config` over `Store` | concrete `Store` (`~/.bsec/network-config.json`) |
| `project_config` | split | `ProjectConfig` type; load/save over `Store::ProjectConfig` | concrete `Store` (cwd `.bsec.json`) |
| `env_file` | split | pure `parse_env_content`, `parse_json_content`, `safe_env_name`, `BLOCKED_ENV_NAMES`; byte-level encrypt/decrypt transforms | fs read/write, `DOTENV_*` env lookup, `Command` process spawn, printing |
| `materialize` | split | pure `sanitize_basename`, `decode_body`, `SecretKind::as_format`, `parse_format`, `sniff_format`, `resolve_format`, `extract_schema_from`, `extract_schema`, `default_filename`, `member_bytes`, `infer_kind`, `parse_kind`, `stem_env_key`, `is_file_kind` | staging fs, `libc` signals, temp dirs |
| `errors` | split | core error types + per-port errors | CLI exit-code mapping (`exit_code`) |
| `helpers` | adapter | (`find_matches` may live in core as a pure util) | `log`, `search_file` (stdout + `process::exit`) |
| `main` | adapter | — | clap parsing, terminal, composition root wiring |
| `helpers_test` | adapter | — | test-only |

## Crate / layout sketch

```
crates/
  core/       # pure domain + orchestration + the five port traits
  adapters/   # native impls of the ports + CLI-only facilities
  cli/        # thin binary; the composition root
```

A virtual manifest at the workspace root lists the three members. `core` depends
on neither `adapters` nor `cli`; `adapters` depends on `core`; `cli` depends on
both and is the only place that constructs a `Host` and wires concrete adapters.

Net shape: a pure `core` crate holding domain + orchestration + the five port
traits; a native `adapters` crate implementing the ports (fs store, blocking
reqwest, `SystemTime`, `OsRng`) plus CLI-only facilities (terminal, process,
printing, env); and a thin `cli` binary that is the composition root.
