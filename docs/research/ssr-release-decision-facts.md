# SSR and release decision facts

Researched 2026-11-09 against primary documentation. This note supports
[Rebase the SSR execution decision on the shipped Yew and shared core](https://github.com/igmrrf/bitbid/issues/27)
and [Choose publication channels and the release verification contract](https://github.com/igmrrf/bitbid/issues/28).
It records facts and explicitly marked implications, not a resolved product
decision, implementation, release authorization or verification of a published
artifact. Framework and action versions must be checked again when an
implementation ticket pins its dependencies.

## Repository inputs and limits

The accompanying source inventory at native commit
`ec659bacef56555bbbbd65a9b22521b6e56dcff1` and web commit
`149e8d48415e85b68d859abd6727181f94ee4e9e` established that the shipped web app is Yew
CSR, uses shared browser crypto and direct RPC, and has no application server or
server authentication. Its manifest selects Yew 0.23 with `csr`. Native
production adapters at that checkpoint export RPC; wallet/unlock and list policy remain
CLI-owned. These are repository inputs to this research, not claims that the
prospective server-wallet design is implemented. The prior
[SSR key-handling contract](../split-core/ssr-key-handling.md) and
[Leptos research](leptos-ssr-contract.md) remain historical decision evidence;
this note does not rewrite them. Concurrent extraction work in the working tree
must be reconciled before implementing a dependent server ticket.

## Yew SSR is technically available

**Facts.** Yew 0.23.0 exposes `ServerRenderer` behind `ssr`, including buffered and
streamed rendering. Its renderer can emit information used during hydration;
the `hydratable` option defaults to true. The browser renderer exposes
`Renderer::hydrate` behind `hydration`. These are separate capabilities from
ordinary CSR, and the framework's feature list explicitly distinguishes all
three. Sources: [Yew 0.23 ServerRenderer](https://docs.rs/yew/0.23.0/yew/struct.ServerRenderer.html),
[Renderer::hydrate](https://docs.rs/yew/0.23.0/yew/struct.Renderer.html#method.hydrate),
[Yew features](https://docs.rs/yew/0.23.0/yew/#supported-features).

**Implications, not demonstrated compatibility.** Retaining Yew while adding
SSR is a feasible branch of the architecture decision; SSR alone does not force
a Leptos migration. Conversely, enabling a Cargo feature does not prove this
app's browser-specific initialization, injected-wallet integration, state,
asset delivery or hydration works on a server. A chosen Yew branch needs a
native renderer build and actual browser hydration/error/recovery evidence.
A server API added to a CSR app is also distinct from rendering HTML on the
server: the ticket should say which behavior is required.

## Leptos serialization is an exposure surface

**Facts.** A Leptos server function creates an HTTP endpoint. Browser builds call
that endpoint through a generated client stub; arguments and results must be
serializable. Hiding the function body from the browser does not authenticate
requests or make returned data private. The Leptos book explicitly requires
security procedures such as authentication, encryption and rate limiting for
sensitive results. Source:
[Leptos server functions and security](https://book.leptos.dev/server/25_server_functions.html).

Leptos `Resource` can serialize server-fetched data for client hydration, while
`LocalResource` supports client-local, non-serializable futures. Consequently,
the statement that every kind of resource necessarily serializes is too broad;
the relevant question is the concrete type and data path. Source:
[Loading data with Resources](https://book.leptos.dev/async/10_resources.html).

**Implication.** For the proposed server-owned-wallet mode, choose explicit
request and response projections and verify that passwords, keys, decrypted
values and bearer credentials never enter serialized results, hydration data,
logs or error strings. This does not retroactively establish that the existing
browser-local seal/unseal mode follows a server-only key policy. Whether those
remain distinct product modes is a human decision. Framework selection leaves
authentication and per-wallet authorization unresolved.

## Blocking execution, admission and secret lifetime

**Facts.** Tokio's `spawn_blocking` requires `Send + 'static` closure and result
values. Tokio creates blocking threads up to its configured upper limit and
then queues work; its default limit is large. Its documentation recommends
explicit concurrency control for CPU-heavy workloads. Once a blocking task
starts, `abort` cannot stop it. Runtime shutdown normally waits for these tasks;
`shutdown_timeout` limits the wait but does not terminate the tasks. Source:
[Tokio spawn_blocking](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html).

**Implications.** An HTTP timeout or client disconnect cannot by itself prove
that wallet unlock, Argon2 or synchronous transport has stopped or erased its
secrets. Admission limits should apply before secret-bearing work is spawned;
bounded concurrency alone does not define a bounded waiting queue. A selected
contract needs queue/rejection behavior, operation deadlines, disconnect
behavior, shutdown/drain semantics and ownership through task completion.
Zeroization remains an implementation property requiring code and verification;
this research does not promise removal of every compiler/runtime copy.
Interruptible execution or stronger isolation would be additional design work.

## Cargo registry preparation is separate from binary distribution

**Facts.** crates.io does not accept ordinary dependencies specified only by
local path. A dependency may specify both `path` and `version`: local builds use
the path and check its version, while registry publication uses the registry
version. The Cargo Book's example requires publishing the dependency crate
before its dependent can use that registry release. Source:
[Cargo paths and multiple locations](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#local-paths-in-published-crates).

`cargo publish` packages, uploads and waits for registry indexing; an indexing
timeout does not undo an upload. `--dry-run` checks without uploading, while
`--no-verify` skips the package build verification. Source:
[cargo publish](https://doc.rust-lang.org/cargo/commands/cargo-publish.html).

**Implications.** For the current dependency direction, registry preparation
must make `bitbid-core` available before `bitbid-adapters`, and both before
`bitbid-cli`. This is dependency ordering, not a requirement to implement a
custom publisher. Exact names, ownership, versions and toolchain support remain
to be verified. A successful workspace build or source-path install does not
establish packaged-registry installation. GitHub CLI archives are a separate
channel and need not wait for publishing those crates. No name availability or
registry ownership was asserted or changed by this research.

## Binary integrity and provenance

**Facts.** GitHub's release API exposes asset metadata including a SHA-256
`digest`. Build provenance attestations are a distinct feature: workflows
generate an attestation for an artifact, and consumers can verify it with
`gh attestation verify ARTIFACT -R OWNER/REPO`. The documented workflow requires
appropriate OIDC and attestation permissions. Sources:
[Release asset metadata](https://docs.github.com/en/rest/releases/releases),
[Generating and verifying attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

**Implications.** The release contract should distinguish matching bytes from
establishing their build origin. It can require a recorded digest manifest,
attestations bound to the selected repository/workflow/revision, and fresh
download/install/runtime checks for each supported target. Attestation verifies
provenance under its trust policy; it does not prove application correctness.
Local build evidence is not evidence that a hosted release contains the same
artifact. Supported OS targets, archive formats, signing policy and recovery
steps remain user decisions or preparation-ticket outputs.

## macOS signing and notarization prerequisites

**Facts.** Apple distinguishes Developer ID signing from notarization.
Notarization scans submitted software, checks code-signing issues and produces
a ticket used by Gatekeeper; it is not App Review. Apple's current submission
requirements include appropriate Developer ID certificates, valid executable
signatures, hardened runtime for app and command-line targets, and secure
timestamps. `notarytool` is the supported command-line submission route;
`altool` is no longer accepted. Sources:
[Apple notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution),
[Custom notarization workflows](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

**Implications.** A tar archive, checksum or ad-hoc signature does not establish
Developer ID signing or notarization. If the release promises either, the
preparation ticket needs the actual identity/access prerequisites and evidence
for the final deliverable and installation path. No signing identity, Apple
membership, credential access, notarization success or macOS end-user launch
behavior was verified here. Choosing a staged unsigned preview versus a signed,
notarized distribution is a release-policy decision, not an assumption to hide
in a packaging template.

## Team web-app clarification — researched 2026-11-09

**Live decision status.** The user has selected a public landing page with an
authenticated per-team app, owner/admin management of team secrets, a dashboard
as the first authenticated flow, and preparation of GitHub CLI archives,
crates.io and Homebrew. These directions do not yet settle key custody,
authentication, administrative data access or recovery. This section informs
those open choices; it does not amend the prospective server-wallet contract.

### A similar interface does not imply equivalent key custody

**Facts.** Bitwarden's security whitepaper describes vault items encrypted on
the client before transmission, using item keys wrapped by user or organization
keys; authorized clients decrypt them locally. Its cloud stores encrypted vault
data. This is materially different from a server receiving a wallet password
and decrypting keys during a request. Source:
[Bitwarden security whitepaper, Data protection](https://bitwarden.com/help/bitwarden-security-white-paper/#data-protection).

Bitwarden explicitly separates SSO authentication from vault decryption. Its
documented choices include a master password, device-held key material through
trusted devices, or a separately self-hosted Key Connector. An identity-provider
login is therefore not itself the vault-decryption mechanism. Source:
[SSO decryption options](https://bitwarden.com/help/sso-decryption-options/).

**Implication.** “Like Bitwarden” needs a precise scope: the team/dashboard
experience, a client-encrypted vault model, or both. SSR can render a public page
or authenticated shell without decrypting vault contents. Choosing client-side
vault encryption would require an explicit revision of any applicable
server-only-key rule. Name vault-decryption keys and blockchain-signing keys
separately rather than assuming one custody decision covers both.

### Login, unlock, authorization and recovery are different operations

**Facts.** Bitwarden distinguishes logging in, which authenticates the account,
from unlocking an already logged-in vault, which regains access to encrypted
data. Sources:
[Understand login versus unlock](https://bitwarden.com/help/understand-log-in-vs-unlock/),
[Automatic logout or lock](https://bitwarden.com/help/vault-timeout/).

Organization roles, organization-wide collection settings and per-collection
permissions interact. Automatic owner/admin management of all collections is
configurable. Importantly, disabling that automatic access does not prevent
owners/admins exporting organization-owned data. These interface permissions
must not be interpreted as cryptographic exclusion of administrators. Source:
[Collection settings](https://bitwarden.com/help/collection-management/).

Recovery enrollment wraps a user's encryption key for the organization;
authorized administrators can recover the account without learning the old
master password. Bitwarden warns enrollment can allow administrators access to
personal items. Sources:
[About account recovery](https://bitwarden.com/help/account-recovery/),
[Recovery enrollment warning](https://bitwarden.com/help/account-recovery-enrollment/).

**Implication.** Team membership administration, permission to read/export team
secrets, and ability to recover lost key access need separate decisions. An
account-password reset does not inherently recover encrypted data. The first
dashboard should define which metadata is available before vault unlock and
what team isolation must hold even while a member is authenticated.

### OIDC and passkeys establish authentication facts, not vault policy

**Facts.** OpenID Connect defines authentication on top of OAuth 2.0 and conveys
identity claims in ID tokens. Validation includes issuer, audience, expiry and
the applicable signature/nonce checks. Its subject identifier is unique within
an issuer, so application account linking needs issuer and subject rather than
assuming email alone is a permanent identity. Source:
[OIDC Core 1.0, ID-token validation and subject identifiers](https://openid.net/specs/openid-connect-core-1_0.html).

WebAuthn registers a public-key credential scoped to a relying party and uses
signed authentication assertions. User verification occurs at the authenticator
and can use a PIN or biometrics; it does not itself identify an application's
team or grant collection access. Source:
[W3C WebAuthn Level 2 Recommendation](https://www.w3.org/TR/webauthn-2/).

Bitwarden can combine passkey login with vault unlocking using the optional PRF
extension and additional encrypted key material. It explicitly notes that PRF
support varies by environment. Thus basic passkey authentication must not be
silently treated as a portable vault-decryption scheme. Source:
[Bitwarden login with passkeys](https://bitwarden.com/help/login-with-passkeys/).

**Implication.** OIDC federation and application-managed passkeys are sign-in
branches, not provider recommendations. Each still needs explicit enrollment,
session/logout, credential-loss recovery and team-membership rules. Neither
automatically defines the vault-key recovery or server-versus-client custody
contract.

## Consistency check after agreed contracts — 2026-11-09

The user has now agreed the architecture/product choices recorded in
[Team web execution](../split-core/team-web-execution.md) and
[Publication](../split-core/publication-contract.md). The exploratory status
paragraphs above are chronological research context, not an assertion that
those product choices remain unanswered. The new team-vault direction uses
client custody and supersedes the historical server-unlock approach; its exact
versioned cryptographic protocol still requires its stated decision gate.
Repository rename to `igmrrf/bitbid` preserves issue identity; live links above
use the new canonical name. These contracts remain preparation requirements,
not evidence of implemented or released behavior.

### Database cancellation is not proof of rollback

**Fact.** PostgreSQL states that successfully dispatching a query-cancellation
request does not guarantee that it has an effect; the command may have already
finished. Source:
[PostgreSQL cancellation semantics](https://www.postgresql.org/docs/current/libpq-cancel.html).

**Material wording correction.** A server contract must not treat every HTTP
timeout/disconnect as proof that a transaction rolled back. Cancel and roll back
uncommitted work where possible, preserve connection/transaction cleanup, and
reconcile a potentially completed commit before retrying a mutation. Commit
outcome and cancellation-race behavior need explicit tests. This is consistent
with the contract's requested finite deadlines and concurrency testing; it
narrows an otherwise overbroad cancellation sentence rather than changing
accepted team policy.

### MFA and macOS evidence details remain preparation outputs

**Facts.** OIDC `acr` and `amr` are optional claims. The meanings of authentication
context values and nonstandard method values need agreement between parties.
A valid OIDC login cannot therefore be assumed to prove the application's
required MFA assurance. Source:
[OIDC ID-token claims](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
The team contract correctly requires server-validated assurance and a tested
provider configuration; the implementation must pin and reject missing or
insufficient assurance under that mapping.

Apple accepts ZIP, UDIF disk images and signed flat installer packages for
notarization. Tickets can be created for standalone binaries, but cannot be
stapled directly to those binaries; ZIP archives cannot be stapled either.
Source:
[Apple custom notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
Thus a CLI tar-archive release needs a supported submission container and
evidence tying the notarized executable bytes to the final distributed archive,
with the chosen online/offline Gatekeeper path tested. Do not demand an
impossible staple onto a standalone CLI binary or call an unsubmitted tar file
itself a notarization submission. The publication contract's required final
artifact/installation evidence is compatible with this preparation detail.

No other material contradiction with the researched framework, identity,
client-custody/recovery, metadata/revocation, or registry-publication facts was
identified in the reviewed contracts. This statement assesses their factual
wording; it does not certify future implementation security or release
readiness.
