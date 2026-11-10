# Hosted human CLI and service-account access facts

Researched 2026-11-10 against primary standards and current provider documents
for [Define hosted-team CLI and service-account access](https://github.com/igmrrf/bitbid/issues/41).
Live steering confirms both human CLI access and separate least-privilege CI
identities, with machines read-only by default. The detailed flow, token/key
storage and provider configuration below remain proposals for its execution
contract. This is not a claim that hosted CLI support is implemented or that
the independent native release already includes it.

## Authentication never substitutes for the vault protocol

The accepted [team-web](../split-core/team-web-execution.md) and
[team-vault](../split-core/team-vault-keys.md) contracts separate sign-in,
membership authorization and client-held decryption/signing keys. An OAuth
token proves permitted API access under its verification/authorization policy;
it is not a vault decryption key. Human CLI unlock/recovery must use the same
versioned shared protocol and verified identity/grants as browser clients.
The backend must enforce current team/vault rights on every operation, even
when the CLI has a valid token. Client signatures do not replace tenancy/MFA.

**Architecture revision in progress:** live steering on 2026-11-10 requires
chain business state to be authoritative and PostgreSQL accounts/memberships
to be a rebuildable synchronized replica. Exact chain schema, OIDC-to-wallet
binding, effective permission-change/finality and replica-lag behavior remain
open. Every reference to current membership below means the eventual selected
verified authority/freshness rule, not an independently authoritative SQL row.
No provider login or CLI token alone proves a chain membership. See the
[hosting research](production-identity-hosting-facts.md) for source-backed
indexing primitives and the immediate-removal tension.

The existing protocol names human account identities/roles; introducing a
nonhuman principal requires an explicit identity/authority/grant profile and
reviewed tests, not treating a CI bearer token as an account root or silently
sharing an Owner's key. Default machine read-only access still permits copying
any granted plaintext; cryptographic revocation cannot retract that copy.

## Human authorization options

| Flow | Primary-source facts | Proposed Bitbid use |
|---|---|---|
| System-browser authorization code + PKCE | Native-app BCP uses an external browser, requires PKCE for public clients, permits an HTTP loopback IP redirect and requires support for an ephemeral loopback port. A client secret embedded in a distributed CLI is not confidential. | Interactive desktop default candidate. Bind listener only to loopback; use S256, unpredictable state, exact callback path, one pending login, bounded listener lifetime and verified issuer/audience/signature/nonce. Close listener on completion/cancellation. Qualify provider registration/port rules before locking this choice. |
| Device authorization | RFC 8628 permits browser authorization on a separate device. Device code is a bearer credential; poll at the server's interval, increase interval on `slow_down`, and stop on expiry/denial. Remote phishing and user-code confirmation require explicit treatment. | Candidate for SSH/headless terminal where same-device browser/loopback cannot work. Display trusted verification origin and code; require deliberate user approval. It is still a human login, not unattended CI authentication. |

Sources: [RFC 8252 §§7.3, 8.1, 8.3–8.5](https://www.rfc-editor.org/rfc/rfc8252.html),
[RFC 8628 §§3.5, 5](https://www.rfc-editor.org/rfc/rfc8628.html).
The current OAuth security BCP rejects the resource-owner password grant and
requires public-client refresh-token replay protection by rotation or sender
constraint. Thus the CLI should not collect provider passwords or use an
embedded browser/password grant as a shortcut. Source:
[RFC 9700 §§2.4, 4.14](https://www.rfc-editor.org/rfc/rfc9700.html).

## Provider capability caveats

- **Auth0:** documents authorization code + PKCE, device authorization and
  client credentials, plus rotation for native refresh tokens. MFA assurance
  on a CLI/native API path still needs an exact tested mapping; a web-only
  step-up example does not qualify device-flow claims. Sources:
  [PKCE](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce),
  [device flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow),
  [client credentials](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow),
  [refresh rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation).
- **Keycloak:** documents public/confidential clients, PKCE configuration,
  device grant, service accounts and signed-JWT client authentication. Enable
  only selected grants and restrict redirect URIs/scopes. Its availability
  does not remove self-hosted identity operations. Source:
  [Keycloak server administration](https://www.keycloak.org/docs/latest/server_admin/index.html).
- **Supabase:** current OAuth/OIDC server docs list only `authorization_code`
  with PKCE and `refresh_token`; other grants, including `client_credentials`,
  are unsupported. Device flow is not in its documented supported list. Do
  not infer support from unrelated upstream Google/GitHub capabilities or
  confuse Supabase's ordinary social-login PKCE with its separate OAuth-server
  client registration/consent flow. A required device/M2M path therefore needs
  separately verified support or a different selected issuer/profile. Source:
  [Supabase OAuth-server flows](https://supabase.com/docs/guides/auth/oauth-server/oauth-flows).

These providers can authenticate a CLI independently of a Cloudflare-hosted
frontend. API token validation/session policy must be implemented on the
chosen server runtime. The [hosting research](production-identity-hosting-facts.md)
records why Axum-on-Workers is feasible but still needs actual Rust/WASM OIDC,
database and SSR qualification.

## Refresh, logout and revocation are separate outcomes

RFC 7009 defines token revocation; self-contained access tokens can require
additional resource-server coordination for immediate invalidation. Auth0
documents refresh-token/grant revocation behavior controlled by tenant
configuration and supports public-client refresh-token revocation. Provider
logout ends an SSO session through its own endpoint; it is a separate operation
from revoking local/API credentials. Sources:
[RFC 7009 §§2.1, 3](https://www.rfc-editor.org/rfc/rfc7009.html),
[Auth0 revocation](https://auth0.com/docs/secure/tokens/refresh-tokens/revoke-refresh-tokens),
[Auth0 OIDC logout](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0).

**Proposed contract:** use short-lived access tokens, opt-in offline refresh
with finite idle/absolute limits, atomic refresh-token replacement and explicit
concurrent-refresh recovery. Store human refresh credentials in the operating
system credential store; any fallback needs a deliberate encrypted-storage
policy. Keep unlocked vault keys/plaintext in process memory and separate from
persisted sign-in credentials. `logout` clears controlled plaintext/key state
and local tokens, attempts selected grant/session revocation and reports
network failure accurately; browser-wide IdP logout is an explicit separate
scope. No claim of complete OS/compiler memory erasure.

Immediate team removal/service-account disablement requires current verified
authorization/session state at each request; neither JWT expiry nor an
eventually synchronized SQL row alone supplies that guarantee. Resolve the
chain-head/lag/finality policy before promising it. Access-token expiry/revocation, refresh-grant disablement,
client lock and vault-key rotation each need distinct tests and audit events.

## Machine authentication and CI decryption bootstrap

OAuth client credentials authenticates an application acting on its own behalf.
Auth0 supports `private_key_jwt` as client authentication using a one-time signed
assertion; this is not proof of arbitrary external-issuer workload federation.
Sources: [Auth0 client credentials](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow),
[Auth0 private-key JWT](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authenticate-with-private-key-jwt).

Keycloak documents federated client assertions from external OIDC providers,
SPIFFE and Kubernetes; its first-party explanation binds issuer, audience and
external subject and discusses replay considerations. Pin the deployed
version/feature support before depending on it; an older preview configuration
does not establish current supported behavior. Source:
[Keycloak federated client authentication](https://www.keycloak.org/2026/01/federated-client-authentication).

GitHub Actions can issue workload OIDC tokens containing repository/workflow,
ref/environment, audience and subject claims. `id-token: write` authorizes token
request, not Bitbid resource access. A verifier/exchange needs an allowlist of
trusted issuer, audience and precise workload claims; a repository-only or
unrestricted subject match can admit unintended branches/jobs. Source:
[GitHub OIDC reference](https://docs.github.com/en/actions/reference/security/oidc).

**Proposed least-privilege profile:** one service principal and cryptographic
key identity per team/workload/environment, explicit vault grants, default
read-only, no Owner/Admin role or membership/recovery/export powers. Dedicated
vaults should limit CI exposure. Team administrators create/disable credentials
and scope; an authorized unlocked client verifies the machine key identity and
delivers approved grants. Removal immediately denies the API and triggers the
protocol's affected-vault rotation; never equate disabling authentication with
erasing a runner's copied keys.

| Bootstrap candidate | What it solves | What still must be decided |
|---|---|---|
| Workload OIDC federation to a short-lived Bitbid/API token | Avoids storing a reusable API authentication secret in CI when the chosen issuer/exchange verifies the exact workload. | It does **not** create/deliver a vault private key. Choose a separately controlled external key store/KMS/encrypted machine-key delivery path accessible only to that authorized runner; the Bitbid host retains no unwrapping key. Test the complete federation-to-key-to-grant chain. |
| Scoped static bootstrap credential | Can initialize an explicitly limited workload when federation is unavailable. | Store only in a protected runner/secret store; define expiry, rotation, revocation, owner and leak response. Keep API authentication and vault-key wrapping credentials distinct; do not copy a human root/passphrase or store host-readable vault keys. |

These are proposals, not an accepted external key custodian or invented
federation support. CI decryption necessarily trusts the authorized runner and
the selected key-delivery boundary. Protect jobs from untrusted code, pin
third-party actions, avoid secret command-line arguments/logs/artifacts, and
use protected environments where required. GitHub explains that masking is
not guaranteed, and that a compromised action can access the job's available
secrets. Sources:
[GitHub secrets handling](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets),
[GitHub secure workflow use](https://docs.github.com/en/actions/reference/security/secure-use).

Supabase project secret/service-role credentials are not a least-privilege
Bitbid team credential: API keys identify the calling application, while Auth
identifies a signed-in actor; elevated keys have project-wide authority. Do not
ship them to end-user CLI/CI consumers as the hosted-team API credential.
Source: [Supabase API-key model](https://supabase.com/docs/guides/getting-started/api-keys).

## Remaining decisions and qualification outputs

1. Choose provider-compatible interactive default and headless fallback; lock
   client registration, scopes/audience, MFA assurance/freshness, exact redirect
   behavior, token lifetimes and credential-store fallback policy.
2. Choose actual CI platform/workload constraints and federation versus scoped
   bootstrap. Select the independent machine-key custodian/delivery method and
   verified bootstrap ceremony. High-level human + CI and machine read-only
   defaults are already accepted; provider support remains unproved.
3. Specify a reviewed machine-principal protocol/server profile, command/API
   scope and tests: denial/expiry/polling, state/PKCE/issuer mismatch, removed
   membership, refresh reuse/concurrency, interrupted logout, absent/stale MFA,
   wrong-workflow token, forbidden write/admin/export, key substitution and
   rotation after cached machine access. Require native/browser protocol
   interoperability without changing historical CLI chain commands.

No provider registration, new runtime setting, credential, tracker write,
publication or deployment is performed here. Future deployable settings must
enter encrypted `secrets/prod.enc.yaml` with disabled safe states and the actual
completeness/unset reports. Never place tokens, recovery codes or private keys
in this note, tests, handovers or environment reports.
