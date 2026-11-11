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

Every listed setting/binding entry must exist in the catalog, even when unset.
Required catalog coverage does not mean a runtime value is required. The two
`BSEC_*` entries are retained historical inventory, not active fallbacks; their
status reports describe stored inventory only. No new setting or secret value is
introduced by the immediate canonical-only cutover. See [migration and rollback](rename-cutover.md).

| Catalog name | Runtime purpose and requirement |
| --- | --- |
| `BSEC_HOME` | Retired inventory only; ignored by runtime, with encrypted values preserved. |
| `BITBID_HOME` | Canonical optional home override; otherwise select `~/.bitbid` only. |
| `BSEC_PINATA_JWT` | Retired inventory only; ignored by runtime, with encrypted values preserved. |
| `BITBID_PINATA_JWT` | Canonical optional Pinata credential after nonblank config. A present blank value disables the env source. |
| `DOTENV_PASS` | Unchanged optional encryption password source; another supported password source is required when actually encrypting/decrypting an env file. |
| `DOTENV_<ENV>_PASS` | Unchanged dynamic password family. This is a coverage marker with no runtime value; add concrete deployed names such as `DOTENV_STAGING_PASS` separately. File-name-derived `DOTENV_ENV_*_PASS` and trimmed forms are the same family. |
| `ipfs.pinning_jwt` in `network_config` | Optional JSON config credential, takes priority over env. Config absent/null/blank plus blank/unset env sources disables Pinata. |

The accepted [production authentication and D1 hosting decision](split-core/production-web-auth-hosting.md) adds the following 12 exact names. All are initially `status: unset`, `value: null`; that adoption brought the catalog to 18 settings plus one network-config credential; the chain amendment below brings the current total to 26 settings plus one credential. These are configuration inventory entries, not a claim that an auth runtime or live binding exists. The future implementation must require explicit auth enablement plus valid origin/store/generation/keys and applicable provider/mail prerequisites; unset/demo enablement and generation fail optional web authentication closed. Standalone CLI/chain access remains independent.

| Catalog name | Kind and future requirement/safe inactive condition |
| --- | --- |
| `BITBID_WEB_ORIGIN` | Runtime non-secret configuration; selected trusted HTTPS origin is `https://bitbid.theldo.com`. Catalog remains unset until authorized deployment preparation. |
| `BITBID_WEB_AUTH_ENABLED` | Runtime non-secret enablement; unset/demo is disabled, never implicit enablement. |
| `BITBID_DB` | Scoped D1 Worker binding, not an exported environment string or connection secret. Unset means no bound store/auth. |
| `BITBID_D1_DATABASE_ID` | Deployment selector/metadata used to wire D1, not a runtime database URL/password. Unset means no live database selection. |
| `BITBID_AUTH_GENERATION` | Independently managed deployment configuration outside the database; unset/demo disables auth, never defaults. Rotate before private restore re-enrollment. |
| `BITBID_TOTP_ENCRYPTION_KEY` | Runtime secret for server TOTP seeds, distinct from client vault keys; unset disables required MFA/auth. |
| `BITBID_GOOGLE_CLIENT_ID` | Optional relying-party client configuration; unset pair disables Google sign-in/linking. |
| `BITBID_GOOGLE_CLIENT_SECRET` | Runtime secret paired with the Google client ID. |
| `BITBID_GITHUB_CLIENT_ID` | Optional relying-party client configuration; unset pair disables GitHub sign-in/linking. |
| `BITBID_GITHUB_CLIENT_SECRET` | Runtime secret paired with the GitHub client ID. |
| `BITBID_MAIL_FROM` | Verified sender configuration; unset disables email signup/reset delivery. |
| `BITBID_MAIL` | Scoped Worker mail transport binding, not an invented API token or exported string; unset disables delivery and cannot fake success. |

Binding entries record safe inactive inventory metadata; they are not serialized Worker binding objects and the report does not export them. A future deployment manifest must supply and qualify real bindings separately. No `DATABASE_URL`, Hyperdrive binding, Cloudflare API credential or OIDC issuer setting is added. The accepted chain amendment below reserves eight chain/RPC/registry/IPFS/retention metadata names; none is an active CLI override or runtime fallback. Resource access, production-approved encryption recipient, OAuth registrations, sender/DNS/quota, actual target qualification and deployment authorization remain prerequisites.

The accepted [blockchain authority/synchronization contract](split-core/blockchain-authority-sync.md) reserves exactly eight additional optional **deployment-profile metadata** names. All eight are `status: unset`, `value: null`; there are now 26 settings plus `ipfs.pinning_jwt`, currently 27 unset entries. These names do not introduce runtime CLI fallback behavior or implement a team-chain feature. Future implementation must require explicit enablement and the complete qualified chain/registry/provider/retention profile; unset/demo enablement keeps that optional feature disabled. No live address/endpoint/token or provider purchase is guessed here.

| Catalog name | Reserved purpose and safe inactive condition |
| --- | --- |
| `BITBID_TEAM_CHAIN_ENABLED` | Explicit future optional profile enablement; unset/demo means disabled, never implicit enablement. |
| `BITBID_TEAM_CHAIN_ID` | Exact qualified selected network identity; unset means no selected team chain. |
| `BITBID_TEAM_RPC_URL` | Approved qualified node/provider endpoint reference; unset means no endpoint. Real authenticated endpoint values stay encrypted and never enter reports. |
| `BITBID_TEAM_REGISTRY_ADDRESS` | Isolated new versioned team registry deployment; unset means no selected registry, never legacy-registry reuse. |
| `BITBID_TEAM_REGISTRY_VERSION` | Qualified immutable registry/profile version; unset or unknown means disabled. |
| `BITBID_TEAM_REGISTRY_CODE_HASH` | Expected actual deployed runtime code identity; unset means no accepted deployment identity. |
| `BITBID_TEAM_IPFS_GATEWAY` | Qualified bounded retrieval profile endpoint metadata, not proof of retention/current authority. Unset means no configured team retrieval profile. |
| `BITBID_TEAM_RETENTION_PROFILE` | Reference to approved independent encrypted storage/credential handles, including owner-controlled retention. Never a plaintext vault/private/recovery key or raw credential bundle; unset means no qualified retention configuration and publication remains disabled. |

No additional credential setting/alias is introduced. Actual providers, CID/import/retrieval limits, full public verification/gas/capacity, finality and two-copy independent retention remain qualification/implementation gates. Configuration inventory alone cannot validate those facts. The native JSON network configuration and existing CLI credential/path behavior remain unchanged.

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
null|string}`. All 26 exact setting names/patterns above are required;
`network_config` requires `ipfs.pinning_jwt`. `unset` and `demo` allow only
null/empty/whitespace values. Nonempty demo values are rejected, including both
current/retired env credential inventory and the config credential. `configured` requires a
nonblank value; nonblank JWTs must be safe HTTP header text. Demo status is
metadata and is never a fake JWT. The pattern marker cannot hold a password. The exact allowlist permits only those names plus concrete `DOTENV_[A-Z0-9_]+_PASS` family entries; arbitrary `BITBID_*` names, database URLs and binding aliases fail closed. Catalog schema validity alone does not validate runtime auth readiness or binding configuration.

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
exit. Production/chain-decision regressions assert the exact 26-setting inventory and 27 disabled entries, reject each missing required name and nonempty unset/demo value, preserve configured existing/retired and concrete DOTENV entries through real encrypted roundtrip, and reject unknown production-like names before any report output. Chain regressions independently reject every missing new field and nonempty unset/demo value through real encrypted check/report, preserve all pre-chain configured entries and network credential, and reject unknown chain-like credential/alias names before report output. Reports/errors redact configured new secrets as well as existing values. These fixture passes do not prove project-recipient approval or access.
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
