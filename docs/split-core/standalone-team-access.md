# Accepted standalone team CLI and scoped runner contract

Status: **accepted by final shared-understanding confirmation on 2026-11-11; implementation and deployment remain future work**.
Supports [Define standalone team CLI and service-account access](https://github.com/igmrrf/bitbid/issues/41),
rebased on the user's full standalone chain/IPFS direction of 2026-11-10.
Exact registry integration belongs to
[Design canonical on-chain teams and registry synchronization](https://github.com/igmrrf/bitbid/issues/57).
This contract does not turn earlier OAuth-CLI research into a requirement. Its three bounded normal continuations are recorded below; no feature is delivered by this adoption.

Current checkpoint: native `a43a805`, webapp `170f293`, static web `803fce9`; only primary worktrees remain. Alias removal47 is complete. Protocol50 remains independently owned frozen committed WIP at native `92c75ea` / webapp `12ff9d7`, with final qualification and independent review unfinished. The [accepted production contract](production-web-auth-hosting.md) uses optional private D1 web state; PostgreSQL/Neon/Hyperdrive and a managed IdP are not current requirements.

## Destination, scope and prerequisites

The native CLI and browser offer the same team/vault capabilities allowed by
canonical chain authority and verified client-held grants. The CLI talks directly
to the chosen chain RPC and public IPFS; no Bitbid web host, D1 or any other host database, email,
Google/GitHub, browser OAuth issuer, web cookie or server MFA session is required
for core functionality. Its operator selects the network, verifies canonical
registry configuration and signs necessary transactions locally. Development is
Polygon Amoy; production is the Polygon PoS plan with user-funded transactions.
No existing contract is claimed to contain the required teams/schema, and no
mainnet transaction, new contract deployment or funding is authorized here.

Public wallet/account/team/vault/item IDs, role/relationship/epoch/permission
metadata and selected chain references are deliberate. Secret names, vault
labels and values remain encrypted on IPFS. Content addressing and encryption
do not make a public IPFS object access-controlled or guarantee its availability.
No plaintext/private keys are stored in registry events, public IPFS, logs,
telemetry, crash reports or automatic local caches. Explicit requested plaintext
reveal/output to an authorized human/process is a client action with leakage
consequences, not a server feature.

Dependencies are real gates: #57 freezes canonical identity-to-wallet/protocol
binding, machine-principal representation, registry schema, signed publication,
version/epoch compare-and-publish, log/index/finality and reorg/failure semantics.
Portable core [#50](https://github.com/igmrrf/bitbid/issues/50) remains independently
owned pure cryptographic work, not blocked or modified by this decision. Product
work uses its qualified public interfaces and approved downstream lifecycle
slices; it must not relabel protocol account IDs or implement a competing core.
Existing historical CLI chain/wallet/token formats remain compatible; alias/path
cutover is a separate authorized ticket.

## Human parity and local custody

The required parity matrix includes team create/switch, membership/invitation,
role/promotion/ownership transfer/deletion, vault access assignment, recipient
verification, vault unlock/lock/recovery, encrypted list/search/create/edit/
reveal/copy/delete, grant activation, rotation after loss/removal and encrypted
export/restore. Each operation remains unavailable until its real #57/core/key
lifecycle prerequisites exist; a command stub or fake backend cannot count as
parity. Explicit read/write permission and pending key delivery are enforced in
both clients. Exact command syntax and wire/RPC DTOs are implementation-ticket
outputs after #57, not invented APIs in this contract.

Chain signing wallet keys, protocol account encryption/signing identity and web
login credentials are distinct. Keep each private key on its authorized client;
verify the approved binding rather than assuming their algorithms/bytes are
interchangeable. One account-level vault passphrase/recovery identity unlocks
current authorized grants across teams, each vault with independent epoch keys.
Do not put a shared all-team root or an Owner's root on a runner.

Preserve the original first-sharing/replacement trusted-channel comparison of
the complete protocol fingerprint, account/generation and peer identity. A wallet
signature, email, OAuth claim, host assertion or self-signature does not by itself
replace that ceremony. Preserve encrypted trust pins, signed authority/snapshot/
content verification and observed rollback/fork rejection. A fresh client cannot
establish global latest state solely from valid historical proofs; #57 may add
chain finality context but must explicitly reconcile that trust model, not assert
an unimplemented witness or silently weaken protocol validation.

Before first secret storage require the existing recovery-kit save and successful
restore test. Distinguish recovery of the same key identity from fresh identity
replacement/reverified teammate regrant; no password reset creates keys. Exports
retain the approved typed proof closure and current-data selection rules; imports
re-encrypt locally for the verified current epoch and cannot restore old roles.
No automatic offline history grants or background synchronization are added.

Start CLI secret state locked; use 15-minute inactivity lock, explicit lock/logout
and process-exit cleanup. A browser still uses the unchanged five-minute-hidden
rule and immediate logout/reload lock. Headless CLI has no fabricated browser
visibility signal: use bounded one-shot jobs that release controlled key/plaintext
state at completion, plus the inactivity rule for a long-lived interactive process.
Recheck deadlines before actions and reject late async replies after lock using
generation/lifetime control. No indefinite background unlock or automatic plaintext
cache. Zeroization is best-effort for controlled buffers; no promise covers all
OS/compiler/clipboard/subprocess copies.

Web MFA protects the self-owned Bitbid web session. The same authorized wallet
can sign a valid direct chain transaction without contacting that web service.
Thus this contract makes no global on-chain TOTP guarantee and no web-MFA bypass
claim: the authorization surfaces are explicitly different. A global second-factor
wallet/contract restriction would require a separate reviewed #57 design.

## Separate machine principals and trusted runners

Use separate machine identity per team/workload/environment, public accountable
wallet/protocol identity and explicit minimum vault grants. Default **read-only**;
no Owner/Admin, membership administration, recovery takeover, ownership transfer,
write or automatic bulk-export power. A service principal is not a hidden human
account, borrowed human password, copied Owner root or project-wide API secret.
Exact principal/permission schema is a #57 gate. Read-only still permits copying
all granted plaintext, so dedicated narrow CI vaults bound exposure.

### Executable bootstrap and later-job state machine

The designated team Owner is accountable for initial enrollment, input recovery,
manual credential/identity rotation and revocation; an authorized unlocked grantor
still supplies grants under #57 and the original protocol. Initial generation and
secure input installation may run on an explicitly owner-controlled trusted local
bootstrap device. This device is a trusted client, not Bitbid-host/indexer escrow.
Normal execution remains protected ephemeral GitHub Actions, not a persistent
runner or a routine job with administrative credentials.

Before enabling real enrollment, the machine implementation freezes and exercises
this complete state machine using owned fixture principals:

1. **Prepare/generate:** select the exact #57-approved machine representation,
   minimum private material, account/generation/wallet binding and vault read
   allowlist. Generate the dedicated identity using trusted client entropy; never
   copy a human root or add Owner/Admin powers. No profile/wire/authority extension
   here is normative before #57 freezes it.
2. **Encrypt/persist:** on the trusted bootstrap client, create the explicitly
   versioned authenticated-encrypted runtime credential package and independent
   high-entropy unlock input under the reviewed profile. The Owner installs the
   ciphertext file and the unlock input through separate protected GitHub secret
   inputs using a secure owner-authenticated channel, without argv/log/artifact/
   cache export. Owner administrative access is used only for this trusted setup;
   broad repository/environment administration tokens never enter routine jobs.
   The host/indexer receives no private key, unlock input or unwrapping capability.
3. **Prove persistence and verify recipient:** before any real grant disclosure,
   run a protected no-grant fixture/preflight that retrieves the stored ciphertext
   and separate input and validates the same public identity locally without
   exporting private material. Present the full public protocol fingerprint,
   account and generation to the authorized human; compare the trusted bootstrap
   device and unlocked grantor client through the original trusted-channel
   ceremony. A host-supplied value or self-signature alone is insufficient. Lock
   the selected profile/key identity and protected workflow/ref inputs against
   substitution before activation.
4. **Activate:** obtain the required machine-signed pre-key acceptance using the
   trusted enrollment execution, and have the unlocked grantor submit only the
   approved signed identity/acceptance/grant activation under the existing atomic
   protocol and #57 publication rule. No current-epoch key is disclosed before
   verification or for an unsigned proposal. Failed/canceled/uncertain activation
   follows the original disclosure/reconciliation/rotation rules; pending state
   cannot revoke a key already sent. Real transactions remain separately covered
   actions; routine read jobs need no administrative chain key.
5. **Run later jobs:** the next protected ephemeral job receives the same
   versioned package plus separate unlock input, verifies identity/scope/current
   proofs, unwraps only in that authorized runner and reads explicitly granted
   values. Use restrictive job-owned ciphertext paths and secret-safe process
   input rather than a private-key environment variable or command-line secret.
   The accepted one-shot job ceiling is 15 minutes, with always-run controlled-state/
   file cleanup on success, cancellation or failure. This job limit is not a vault
   key TTL and cannot erase already copied keys/plaintext.
6. **Recover/rotate:** missing/lost package or input fails closed. Prefer a newly
   generated/reverified machine identity and current authorized regrant rather
   than recovering a human root or adding host escrow. Manual package rewrapping
   or unlock-input replacement protects only that new wrapper; it does not revoke
   a copied old package+input or unwrapped private identity. Suspected private-key
   or full-pair exposure requires canonical principal replacement/removal,
   reverified regrant and complete affected-vault rotation before new epoch writes.
   Historical copied-key decryption remains possible under the stated limits.

The implementation owns this wiring and qualification; previously verified wiring
is not a circular prerequisite to starting its ticket. Real enrollment is gated on
passing its own bootstrap/second-job tests. Freeze protected environment/ref/
workflow allowlists, minimum routine-job permissions, input format and cleanup in
the ticket. Fork/untrusted pull-request code receives no secret inputs; do not run
attacker-controlled code under a privileged event. Pin actions to reviewed immutable
revisions. A compromised authorized job receiving both inputs can copy them; separate
delivery does not claim protection from that compromise. No workflow is configured
or credential installed by accepting this contract alone.

**Cost evidence supplied by the parent, 2026-11-10:** the canonical
`igmrrf/bitbid` repository was verified PUBLIC through the connected GitHub API.
GitHub documents free standard hosted-runner compute for public repositories;
larger runners are charged and artifact/storage allowances are separate. The
initial machine workflow uses only standard Ubuntu runners, uploads **no Actions
artifacts**, keeps caches at GitHub's included/default cap, and uses no larger
runners or paid third-party actions. This keeps the accepted initial CI compute/
storage within included scope; it is not a configured workflow/budget or an
unlimited-storage promise. Gas and IPFS costs remain distinct. Source:
[GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Workload OIDC may later authorize a narrowly constrained CI transport/key store
or optional service endpoint, but it does not create a decryption key or replace
the on-chain machine/grant binding. No new Bitbid OAuth issuer is justified solely
for CLI support. Issuer/audience/repository/workflow/ref/environment validation,
replay controls and actual issuer support are necessary if federation is selected.
A static bootstrap, if necessary, requires explicit scope/owner/rotation/leak
handling and an approved secure delivery path; it is not the default assumption.

CI execution retrieves only explicitly selected vault/item IDs, verifies current
signed authority/epoch/proofs, decrypts locally and passes requested values to the
intended process with deliberate secret-safe output. Avoid command-line secrets,
job logs, traces, caches and artifacts; test redaction including failures. Pin
third-party actions and isolate untrusted pull-request code. A compromised or
previously authorized runner can copy plaintext/keys; no software output flag
can promise otherwise.

## Revocation, rotation and expiry without false promises

Public IPFS downloads remain possible after membership/credential removal.
Disabling a web/API credential or removing a chain principal prevents only the
current authorized operations under the selected policy; it cannot delete the
runner's downloaded ciphertext or epoch key. Demonstrate historical ciphertext
still decrypts with the historical copied key as an expected threat-limit test.

Apply the existing access-loss rule: commit canonical removal/replacement or
read-access loss, deny current server-authorized access where applicable, mark
affected vaults rotation-required and freeze new writes/grants until an authorized
remaining client generates fresh vault keys, excludes removed recipients and
re-encrypts the complete current snapshot/labels/items. Activation is one checked
current-authority/current-head transaction under #57 with the existing protocol
proofs. Partial staging, stale epochs, retry/uncertain commits, concurrent removal
and reorgs cannot silently reactivate writes. Remaining clients may read the last
active snapshot. Absence of any remaining decrypt-capable client/recovery material
can make rotation impossible and data irrecoverable. The host cannot mark that work
complete itself.

**No invented automatic vault-key TTL:** initial v1 has explicit grant/revoke/
rotate lifecycle and no automatic 30-day expiry. Authentication/bootstrap
credentials may have finite lifetimes without pretending the vault key expires.
If an `expires_at` authorization is later selected, #57 must define its trusted
clock/head, effective boundary, deny/freeze transition and complete key rotation
before new epoch writes. Expiry alone never makes copied keys stop decrypting
public objects; continuing to encrypt future writes under that old key continues
exposure. No retroactive secrecy, secure deletion or history recall is claimed.

## Acceptance and evidence

| Acceptance | Required evidence |
|---|---|
| CLI-AC1 | Complete allowed parity matrix runs with the Bitbid web host/D1 or other host database/web-login providers/email unavailable; direct RPC/IPFS and locally signed transactions are real, not mocks or a hidden server fallback. No change to historical CLI formats/behavior. |
| CLI-AC2 | #57 schema/binding/current-head/finality/publication contracts and qualified core interfaces are consumed; wallet/protocol identity substitution, wrong team/epoch/key/version/signature, stale/forked proof and pending grant negatives fail. |
| CLI-AC3 | Actual native CLI plus browser interoperate on approved vectors and complete encrypted create/read/update/delete/grant/recovery/rotation/export/restore journeys. Trusted-channel first sharing/replacement and recovery save/test gates remain. |
| CLI-AC4 | Dedicated read-only machine identity completes trusted Owner bootstrap→protected ciphertext/separate-input persistence→full fingerprint verification→approved activation→second ephemeral-job read. Missing/wrong/tampered/substituted inputs, wrong workflow/ref, failed/canceled/uncertain activation and lost-input fresh-identity/regrant cases fail safely. Routine jobs hold no broad admin token; no private material enters host/indexer, logs/argv/caches/artifacts. Rewrapping alone never claims identity revocation. |
| CLI-AC5 | Removal/expiry semantics distinguish current authority from public-IPFS retrieval and copied-key decryption. Full current-data rotation, frozen writes, cached old key, partial staging, concurrency/retry/uncertain commit and reorg cases are exercised; historical decryption remains an explicitly expected limit. |
| CLI-AC6 | Inactivity/lock/exit/stale async completion and bounded parsing/KDF/network/resource failure tests pass. Browser retains 15-minute idle/five-minute hidden/logout/reload rules. No silent offline cache or false memory-erasure claim. |
| CLI-AC7 | Explicit encrypted backup closure/restore, proof limits, revoked-role import denial and irrecoverable-key behavior pass. Independent review and scoped per-ticket local commit follow real final-source verification. |

Use task-owned disposable chain/IPFS fixtures and registered local test principals
first. Any devnet/mainnet write must be authorized for its actual action/funding.
Freeze exact executable commands and negative fixtures in each ready implementation
ticket, and inspect actual release/installed CLI behavior, not only unit helpers.
All implementation work must preserve the closed #50 session's frozen unfinished
committed source/ownership checkpoint and unrelated edits; do not resume or overwrite it.

## Bounded normal implementation continuations

| Local anchor | Actual normal continuation |
| --- | --- |
| CLI1 | [Standalone transport/identity adapter qualification](https://github.com/igmrrf/bitbid/issues/62) |
| CLI2 | [Human team-vault parity journeys](https://github.com/igmrrf/bitbid/issues/63) |
| CLI3 | [Scoped machine enrollment and runner execution](https://github.com/igmrrf/bitbid/issues/64) |

These are the three actual normal continuation issues; list positions remain local cross-reference anchors. Reconcile existing native extractions/key-lifecycle/browser tickets instead of equating open issues with unimplemented code or creating duplicate first slices.

1. **Standalone transport/identity adapter qualification** — own narrow native
   adapters/CLI composition and public-consumer integration fixtures only. Depends
   on #57's frozen RPC/registry/IPFS/binding surface and qualified portable core;
   no core crypto redesign or legacy wallet policy change. Its bounded acceptance
   is correct selected-network/registry/identity mapping, actual owned-fixture
   RPC/IPFS request/response and byte round trips, local signing where this adapter
   owns it, forbidden web-host contact, and finite input/deadline/concurrency/
   cancellation/retry behavior. Exercise adapter-level CLI-AC2 negatives that its
   public interfaces actually own. This slice does not claim full CLI-AC1 parity
   or the downstream team-vault lifecycle matrix delivered by continuation 2.
2. **Human team-vault parity journeys** — own native command orchestration/tests
   and only coordinated browser parity fixtures. Depends on #57 plus the actual
   downstream grant/unlock/rotation/CRUD/export lifecycle implementations, not
   just core compilation. Prove full CLI-AC1 host/DB/provider-off parity and
   CLI-AC3/5/6/7 with complete real workflows; only this integrated human journey
   qualifies the complete parity matrix, not continuation 1's adapter proof.
3. **Scoped machine enrollment and runner execution** — own service-principal
   enrollment/profile/secure runner integration/tests and minimal documentation.
   Depends on #57 machine schema and working grants/removal/rotation. It owns the
   trusted bootstrap state machine and protected GitHub Actions encrypted-file/
   separate-secret wiring plus its qualification; passing that proof gates real
   enrollment, not starting the ticket. The first-runner custody choice is accepted.
   Prove CLI-AC4/5; no OAuth issuer, privileged
   human-root reuse, automatic vault TTL or blanket CI-secret product expansion.

## Minimal candidate settings and release limits

The standalone auth profile introduces no required web-origin/issuer/client-secret
setting. Reconcile existing canonical configuration before adding anything.
Candidates needing final #57 names/catalog coverage are network/RPC URL, canonical
registry address/version, IPFS read gateway and optional pin endpoint/credential.
A machine profile needs the scoped team/vault allowlist, dedicated runner identity,
a protected encrypted-credential-file input and a separately delivered unlock
secret. Exact protected GitHub Actions input names must be confirmed against the
existing catalog, without inventing a plaintext private-key variable. Private-key
values and plaintext secrets must never enter this contract,
ordinary environment reports or committed fixtures. Actual deployable CI settings
belong in encrypted `secrets/prod.enc.yaml` with unmistakable disabled safe states,
and must pass completeness/unset reporting before ticket completion.

No push, publication, deployment, live provider configuration, data migration or
transaction occurs by accepting this contract alone. Local commits are scoped per
completed reviewed implementation ticket under the project's existing instruction.
