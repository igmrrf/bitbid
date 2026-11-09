# Encrypted deployable settings catalog

N2 adds local catalog gates without changing CLI runtime settings. The native
catalog destination is `secrets/prod.enc.yaml`; only that encrypted file is
allowed by `.gitignore`. The versioned catalog is an **unset-only local demo**
encrypted to the existing user-controlled demo identity at
`~/.config/sops/age/charmedly-demo.txt`. The user approved locating and using
that persistent identity; no identity was generated for this catalog. This
establishes a repeatable local decrypt workflow, not production credential
readiness. Coordination `../secrets/.env` is preserved and must not be read,
copied, or logged by these tools.

## Inventory

Every listed environment entry must exist in the catalog, even when unset.
Required catalog coverage does not mean a runtime value is required.

| Catalog name | Runtime purpose and requirement |
| --- | --- |
| `BSEC_HOME` | Legacy optional home override, used only when `BITBID_HOME` is absent. |
| `BITBID_HOME` | Canonical optional home override; otherwise select `~/.bitbid`, or legacy `~/.bsec` in place when canonical is absent. |
| `BSEC_PINATA_JWT` | Legacy optional Pinata credential, after nonblank config and only when `BITBID_PINATA_JWT` is absent. |
| `BITBID_PINATA_JWT` | Canonical optional Pinata credential after nonblank config. A present blank value disables the env source and suppresses the legacy alias. |
| `DOTENV_PASS` | Unchanged optional encryption password source; another supported password source is required when actually encrypting/decrypting an env file. |
| `DOTENV_<ENV>_PASS` | Unchanged dynamic password family. This is a coverage marker with no runtime value; add concrete deployed names such as `DOTENV_STAGING_PASS` separately. File-name-derived `DOTENV_ENV_*_PASS` and trimmed forms are the same family. |
| `ipfs.pinning_jwt` in `network_config` | Optional JSON config credential, takes priority over env. Config absent/null/blank plus blank/unset env sources disables Pinata. |

`BITBID_E2E`, `BITBID_E2E_RPC`, `BITBID_E2E_REGISTRY`,
`BITBID_E2E_IPFS_GATEWAY`, and `BITBID_E2E_FUNDER` belong only to the local/test
harness. These canonical names have no legacy test aliases. They are not deployable application settings and are not in this
catalog. `HOME`, proxy variables, Cargo/CI inputs, and SOPS identity discovery
are host/tooling inputs, not new application deployment settings. Existing
network RPC, registry, gateway and Kubo settings remain JSON configuration,
with no new environment aliases.

## Approved local demo workflow

Install Python 3, SOPS and age. Select the existing persistent local identity
explicitly, then run the actual gates from the native root:

```sh
export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/charmedly-demo.txt"
make secrets-catalog-check secrets-report
```

For secure local editing, retain that environment and run
`sops edit secrets/prod.enc.yaml`. SOPS reads the private identity internally;
do not print it or paste it into chat. The file must remain private (mode 0600).
The encrypted catalog records the approved public recipient
`age1g8dek56ugp0n5f8vx7hwpztwqxprccny7a283ful8gk2kagrpq8qh5dg73`.
No machine-specific private identity is versioned, and `.sops.yaml` is not
required because initialization supplies the public recipient explicitly.

Initialization is only for a new, absent catalog. For an authorized local demo
recreation or isolated copy, use:

```sh
make secrets-catalog-init SECRETS_RECIPIENT=age1g8dek56ugp0n5f8vx7hwpztwqxprccny7a283ful8gk2kagrpq8qh5dg73
```

Before storing real production credentials, obtain the production-approved
recipient and authorized secret import/rotation workflow, preserve existing
values, and rerun the gates. The local demo identity does not satisfy that
production prerequisite. Never generate a production identity or place private
key material in this repository.

`SECRETS_RECIPIENT` and `SECRETS_CATALOG` are Make inputs for these tools, not
deployable runtime environment settings. Initialization exclusively creates the
file with mode 0600 and refuses an existing file. All initial values are null
with `status: unset`, so optional Pinata auth stays disabled. Encryption needs
only the approved public recipient; subsequent check/report/edit requires the
approved user's SOPS decrypt access. Missing/wrong access fails without printing
SOPS diagnostics, paths, recipients, or values.

Use `sops edit secrets/prod.enc.yaml` through that approved secure workflow to
preserve existing values while making changes. SOPS editing may use temporary
plaintext internally: use a trusted private editor and temp directory, never
print/redirect a decrypted catalog into the repository or logs. Do not import
coordination secrets into a new catalog. The helper reads decrypted JSON into
memory and never writes a plaintext intermediate or exports runtime variables.
For an authorized one-time import from a private in-memory JSON producer, pipe
its schema-conforming output into `python3 scripts/secrets-catalog.py encrypt
--recipient '<approved public recipient>'`; the destination must not exist.
Do not put secret values in command arguments.

The decrypted schema has exactly `schema_version: 1`, `settings`, and
`network_config`. Each setting maps to `{status: unset|demo|configured, value:
null|string}`. All six environment names/patterns above are required;
`network_config` requires `ipfs.pinning_jwt`. `unset` and `demo` allow only
null/empty/whitespace values. Nonempty demo values are rejected, including both
env credential aliases and the config credential. `configured` requires a
nonblank value; nonblank JWTs must be safe HTTP header text. Demo status is
metadata and is never a fake JWT. The pattern marker cannot hold a password.

Checks verify required names and safe statuses after real SOPS decryption.
`make secrets-report` prints only sorted names and statuses. It does not expose
values, recipient metadata, file paths, or other config. Run both gates after
every deployment setting change. Neither gate mutates a catalog, a runtime
configuration, a wallet, or another secret store. An unsupported/malformed
catalog fails closed. A separate local `validate` command accepts schema JSON
on stdin and performs the same gate without encryption; it never exports it.

## Tests and rollback

```sh
make secrets-catalog-test
make secrets-catalog-check secrets-report
```

The test command uses real installed SOPS/age with disposable synthetic keys and
an isolated home. It covers encrypt/decrypt comparison, missing entries,
redacted reports/errors, unsafe demo values from both env and config sources,
blank disabled values, malformed input, missing tooling/decrypt access, and
non-overwrite behavior. It deletes its temporary directory and identities on
exit. These fixture passes do not prove project-recipient approval or access.
N2's isolated real-source Pinata probe/evidence is recorded in the Codinary run;
no live provider call is made. The actual local demo catalog and gates now
resolve N2's former recipient/decrypt blocker. N4 may consume the covered
canonical names after independent N2 review; no production deployment or
credential readiness is implied.

Rollback only these catalog tools and the approved encrypted catalog revision.
Preserve the preceding encrypted revision and its approved decryption access;
restore that revision through the authorized local change process and rerun the
gates. Do not delete or replace other encrypted values, global identities,
coordination settings, runtime homes, or unrelated work. This workflow does not
authorize a deployment or any external secret mutation.
