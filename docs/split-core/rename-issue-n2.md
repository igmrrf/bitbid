# Establish encrypted settings catalog and completeness/report tooling

Normal implementation issue; decision [#13](https://github.com/igmrrf/clienv/issues/13),
map [#3](https://github.com/igmrrf/clienv/issues/3). Depends on independently
reviewed N1 [execution contract](rename-execution.md). Blocks N4; N3 may proceed
independently when this ticket is externally blocked. No runtime rename here.

Owner: native `secrets/prod.enc.yaml`, minimal SOPS/age/catalog/check/report
tooling and corresponding docs. Preserve existing secret values through an
authorized secure workflow; never read/dump coordination `secrets/.env`, private
identities or real JWTs into logs. Discover approved public recipient/config;
if absent, obtain the specific public recipient/decrypt prerequisite. Do not
generate a private identity for the user. This is not deployment authorization.

Acceptance is [N2-AC1–N2-AC5 and N2-V1–N2-V5](rename-acceptance.md): inventory
existing/planned deployable env names and legacy aliases, unchanged DOTENV_*,
separate test-only E2E names; repeatable approved encrypt/decrypt; actual native
`make secrets-catalog-check secrets-report`; missing required entry fails on an
isolated catalog copy; names/status-only redacted reports. Native versioned
catalog covers future BITBID_HOME/BITBID_PINATA_JWT before N4 consumes them.

Optional Pinata disabled values must be null/empty/unset, with demo status
separate. Test env aliases **and config-first ipfs.pinning_jwt** empty state
produces no credential/auth attempt; reject any nonempty fake demo catalog
credential before export/runtime. Provider rejection does not prove disabled.
No fake JWT is installed in runtime config and no new enable flag is introduced.
Exercise tooling failure paths; run native/facade suites if their setup changes,
otherwise prove source/lock hashes unchanged. Record encryption blockers while
finishing independent tooling work.

Use Codinary implementation→independent review, full logs, source/diff/lock
identity and all acceptance/check IDs. Rollback only owned encrypted/config/tool
revision with preserved values and documented recovery; no plaintext residue,
global secret mutation, commit/push/publication/deployment implied.
