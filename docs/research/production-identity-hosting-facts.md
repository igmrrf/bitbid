# Production identity, domain and hosting facts

Researched 2026-11-10 against current primary documentation for
[Choose production Bitbid identity provider, domain and hosting](https://github.com/igmrrf/bitbid/issues/39).
The latest user direction below supersedes the managed-provider proposals.
Library/runtime plans are qualification candidates, not implemented behavior.
No purchase, provider registration, DNS change, deployment or new setting is
performed by this research. Prices/quotas were checked on 2026-11-10; recheck
before committing money. The parent agent supplied the account inventory.

## Current accepted direction

Live decisions on 2026-11-10 revise the earlier
[team-web contract](../split-core/team-web-execution.md):

- Chain state is authoritative; PostgreSQL is an optional rebuildable index
  for that state, and the CLI remains fully usable standalone.
- Wallet identifiers and roles are public; secret payloads are encrypted on
  IPFS. Polygon Amoy is for development, Polygon PoS for production; users pay
  transaction gas. Complete schema, finality and synchronization behavior still
  need reconciliation against source, rather than assuming they already exist.
- Build and own Bitbid's optional email/password and Google/GitHub login,
  authenticated signed-wallet linking and privileged MFA using established
  libraries. **No paid hosted identity provider is selected or required.**
- The chosen web origin is **`https://bitbid.theldo.com`**. The chosen local
  layout is **`Bitbid/bitbid`**; physical cutover belongs to its own ticket.
- The user states they **already have Cloudflare Workers Paid** and accepts
  the recommended self-owned-auth direction on that existing runtime. This is
  a user-attributed subscription fact, not a verified billing/API entitlement
  or a request to purchase/upgrade. Workers Free's 10 ms budget is not the
  selected deployment target.

Canonical accounts/wallets/roles derive from the selected chain authority.
Private optional web-login credentials and session extras in PostgreSQL are
**not** canonical chain identity and are **not reconstructible solely from the
chain**. Password hashes, TOTP seeds, OAuth secrets/tokens, email addresses,
reset codes and sessions never belong on-chain or public IPFS. If optional web
login is enabled, its private persistence, backup or deliberate re-enrollment
policy is necessary even when the business-state index can be rebuilt.

The [vault contract](../split-core/team-vault-keys.md) retains client-held
vault unlock/decryption/recovery. A web-login password is a separate credential
from the vault passphrase; the server must never receive the latter, vault
recovery material, vault private keys or decrypted labels/values. Web-password
or MFA recovery does not recover a lost wallet or vault root.

## Small self-owned web-auth module

**Proposed minimum:** keep the existing Yew/Axum direction, one private
PostgreSQL auth store, explicit login/link/MFA/session handlers and established
cryptographic/protocol libraries. Act as a Google/GitHub **relying party**;
there is no requirement to build an OAuth/OIDC issuer, token-exchange service
or new identity framework. Standalone CLI chain commands do not depend on this
web authentication, its cookies, email service or database.

### Password hashing on the selected Workers Paid runtime

RustCrypto's current `argon2` docs expose a pure-Rust Argon2id implementation
and PHC password-hash encoding/verification. This is a concrete library
candidate; pin a reviewed compatible release during implementation instead of
silently changing existing vault-KDF code or lockfiles. Source:
[RustCrypto Argon2](https://docs.rs/argon2/latest/argon2/).

OWASP recommends Argon2id at a minimum 19 MiB memory, two iterations and one
lane, with target benchmarking and parameter tuning. Cloudflare Workers Paid
retains **128 MB memory per isolate** and documents a default **30-second HTTP
CPU limit**, configurable up to five minutes. An implementation must set a
deliberate finite limit appropriate to login; the published maximum is not its
selected budget. Network waiting does not consume CPU time, but asynchronous
Rust does not exempt local Argon2 computation from it.
Sources: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[Workers CPU/memory limits](https://developers.cloudflare.com/workers/platform/limits/).

**Gate, not a benchmark result:** measure suitably strong password hashing plus
Rust startup/routing/session work on the actual selected Paid runtime. Test
hash and verify, concurrent requests, peak
isolate memory, malformed/oversized inputs, sustained guessing and resource
termination. Bound admission, input length and per-account/IP/global attempts
before expensive work; cap accepted stored PHC parameters as well. Do not
weaken hashing to make a demonstration pass or move the reusable password
verifier into a client-only check. The existing Paid plan resolves the earlier
Free-tier target concern; actual CPU/memory/concurrency qualification still
determines safe admission and deployment settings.

### Server-verified TOTP and recovery

`totp-rs` is a small existing Rust implementation with configurable algorithm,
time step and skew; its secret is shared with the verifier. The library
calculates/verifies codes but does not supply Bitbid's distributed replay,
rate-limit, enrollment or recovery state machine. Source:
[totp-rs maintainer API](https://docs.rs/totp-rs/latest/totp_rs/).

RFC 6238 requires rejecting an OTP after its first successful use and bounds
clock-drift acceptance. NIST guidance likewise requires one-use acceptance and
rate limiting for short OTP outputs; OTP is not phishing-resistant. These are
useful requirements, not a claim of NIST certification. Sources:
[RFC 6238 §§5.2, 6](https://www.rfc-editor.org/rfc/rfc6238.html),
[NIST SP 800-63B, OTP verifiers](https://pages.nist.gov/800-63-4/sp800-63b.html#sfotpver).

**Proposed contract:** generate a unique random seed, protect it encrypted at
rest with an independently managed server key, confirm enrollment with a valid
code, and atomically consume the accepted step/code across concurrent requests
in the private store. Keep last-used and failed-attempt state out of isolate
memory alone. Primary login creates only a restricted pending session until
required MFA succeeds. Record server-controlled factor/assurance time and
check fresh assurance on every privileged action under the chosen policy;
client flags and a GitHub account's MFA-enabled flag are insufficient.

Issue separate high-entropy, hashed, one-use **web MFA recovery codes** and
atomically consume them. Require recent authentication for factor changes,
notify the account and revoke affected sessions on compromise. Recovery must
not silently bypass signed wallet ownership or grant roles. These codes and
the server-readable TOTP seed are unrelated to the client-held vault recovery
kit. A phishing-resistant WebAuthn option would be a separate bounded addition
using a maintained verifier, not a homemade signature protocol or a claim that
TOTP already provides phishing resistance.

### Google/GitHub code flow and signed wallet linking

Use code flow with unpredictable session-bound `state`, PKCE S256, exact
allowlisted HTTPS callbacks, short-lived one-use pending authorization state
and constant-time secret comparisons. Google's live discovery advertises S256;
its OIDC guide requires state verification, validates ID-token signature,
issuer/audience/expiry and identifies users by `sub`, not mutable email. Bind
and verify nonce for the selected OIDC flow. Sources:
[Google discovery](https://accounts.google.com/.well-known/openid-configuration),
[Google OIDC validation and identifiers](https://developers.google.com/identity/openid-connect/openid-connect).

GitHub's OAuth code flow explicitly supports PKCE S256 and state; exchange the
code server-side and call its authenticated-user API to obtain the provider
user ID. Treat GitHub OAuth login as its documented OAuth/API flow, not an
invented Google-style ID token. Request only required login/profile/email
scopes; private email retrieval needs `user:email`. Sources:
[GitHub code/PKCE/state](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps),
[authenticated user](https://docs.github.com/en/rest/users/users#get-the-authenticated-user),
[verified email fields and scope](https://docs.github.com/en/rest/users/emails#list-email-addresses-for-the-authenticated-user).

The Rust `oauth2` and `openidconnect` client libraries support code/PKCE and
asynchronous/custom HTTP clients; they warn against following arbitrary HTTP
redirects because of SSRF. Pin provider endpoints/discovery policy and qualify
the WASM HTTP/signature path. Use the OIDC library for Google and its OAuth
layer for GitHub; no separate issuer stack is needed. Sources:
[Rust OAuth client](https://docs.rs/oauth2/latest/oauth2/),
[Rust OIDC relying party](https://docs.rs/openidconnect/latest/openidconnect/).

**Proposed binding:** provider identity plus authenticated existing Bitbid
session and a fresh domain/nonce/chain-bound wallet signature, with explicit
consent and replacement/recovery rules. Matching emails never proves the
wallet link. ERC-4361 is primary prior art, not a frozen Bitbid binding format.
No upstream API use is currently required after login/profile verification;
discard tokens when no longer needed rather than automatically storing
long-lived provider refresh credentials. Provider app registrations, consent
branding and callback configuration remain real prerequisites. Source:
[Sign-In with Ethereum](https://eips.ethereum.org/EIPS/eip-4361).

### Opaque sessions, CSRF and account mail

Use opaque unpredictable session cookies and server-side session records,
rotate session IDs after login/MFA/privilege changes, enforce idle/absolute
expiry and invalidate on logout/reset. Prefer one-way stored verifiers for
random session tokens where the store-disclosure threat requires them; never
put roles or MFA authority in a browser-owned flag. OWASP documents CSPRNG
session IDs, server-side storage and rotation. Source:
[OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

A host-only `__Host-` cookie with `Secure`, `HttpOnly`, `Path=/` and deliberate
`SameSite` policy avoids sharing credentials with sibling subdomains. Protect
cookie-authenticated mutations with CSRF tokens and strict origin checks;
`SameSite` alone is insufficient, particularly on a shared registrable domain.
The OAuth callback must still receive its intended pending-state cookie.
Source: [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

`tower-sessions` is an Axum-compatible middleware candidate with a pluggable
store; its documentation explicitly warns about lost updates under concurrent
session mutation. Qualify it with the chosen Worker/database path before use.
MFA-step consumption, recovery/reset tokens, revocation and wallet-link writes
need database compare-and-update/transactions; a session-map update is not
atomic security enforcement. Do not add another auth framework by default.
Source: [tower-sessions stores and concurrency](https://docs.rs/tower-sessions/latest/tower_sessions/).

Verification/reset tokens must be random, purpose-bound, short-lived, one-use,
protected in storage and consumed atomically; generic responses and rate
limits prevent account enumeration and mail flooding. Build reset URLs from
the configured trusted origin, not arbitrary Host input; don't auto-login after
reset. Test delivery failure, expiry, replay and concurrent consumption. Source:
[OWASP password-reset guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

**Cloudflare delivery prerequisites, checked 2026-11-10:** current Email Service
supports arbitrary-recipient transactional sending on **Workers Paid**, which
the user states they already have. It includes 3,000 outbound emails/month,
then $0.35 per 1,000; sends to
preverified destination addresses in the Cloudflare account remain free on any
plan. No upgrade is requested. Sending is a public-beta service and still
requires sender/domain DNS onboarding. Verify actual sending/usage entitlement,
account access, DNS conflicts, deliverability and rate limits before claiming
verification/reset delivery works.
Sources: [Email Service plan/cost](https://developers.cloudflare.com/email-service/platform/pricing/),
[onboarding requirements](https://developers.cloudflare.com/email-service/get-started/send-emails/),
[sending beta status](https://developers.cloudflare.com/changelog/post/2026-04-16-email-sending-public-beta/).
A separately operated/selected mail transport is possible but has hosting,
reputation, abuse and delivery responsibilities; building the auth handlers
alone does not make mail delivery free. No mail service is purchased here.

## Workers, persistence and chain freshness

Cloudflare's `worker` crate documents calling an Axum router from a Worker
fetch event; its supported-crates guide lists WASM `reqwest` using fetch and
`tokio-postgres` with a workers-rs socket. These are concrete Rust integration
paths, not proof that Bitbid's actual Yew SSR, middleware, Argon2/MFA,
transactions and limits work unchanged. The usual path is WASM/event-loop
execution; workers-rs also documents experimental Emscripten/Tokio support.
Pin and qualify a single path. Sources:
[worker HTTP/Axum integration](https://docs.rs/worker/0.8.7/worker/#http),
[Cloudflare supported Rust crates](https://developers.cloudflare.com/workers/languages/rust/crates/),
[workers-rs runtime caveats](https://github.com/cloudflare/workers-rs#notes-and-faq).

Hyperdrive connects/pools an existing PostgreSQL database; it does not supply
the database. Its default eligible-read caching is not invalidated by writes.
Use a cache-disabled path for auth/session/permission/authority-head reads;
this still cannot make an eventually updated chain replica current. Sources:
[Hyperdrive](https://developers.cloudflare.com/hyperdrive/),
[query caching and fresh-read guidance](https://developers.cloudflare.com/hyperdrive/concepts/query-caching/).

Workers can periodically fetch RPC data using Cron. Ethereum JSON-RPC provides
filtered historical logs, removed-log/reorganization information and block
tags such as `safe`/`finalized`. These are indexing primitives, not a delivered
synchronizer or the specific Polygon finality policy. Freeze effective-change
head/finality, lag/outage behavior, fail-closed/revalidation rules, bounded
backfill/reorg recovery and RPC quotas before promising immediate removal.
Sources: [Workers Cron](https://developers.cloudflare.com/workers/configuration/cron-triggers/),
[Ethereum log API](https://ethereum.org/developers/docs/apis/json-rpc/#eth_getlogs).

**Optional PostgreSQL candidate, checked 2026-11-10:** Neon Free offers
100 CU-hours/project/month, 1 GB/project (20 GB total account storage), and
5 GB monthly transfer/project at $0 without a card. Compute/transfer exhaustion
suspends compute until the next period or upgrade; storage-growing operations
fail at the storage cap. Frequent indexing/session activity can keep compute
active. Free restore history is up to six hours/1 GB of changes, and compute
scales to zero after five idle minutes. This is not a durable backup policy
for non-reconstructible private login state. Sources:
[Neon pricing/quota behavior](https://neon.com/pricing),
[Neon plan/restore limits](https://neon.com/docs/introduction/plans).

A conventional self-operated Rust service is an alternative if the Worker
qualification fails; Render supports Rust/Docker and Fly offers managed
Postgres. These earlier technical alternatives are not selected purchases.
Sources: [Render runtimes](https://render.com/docs/docker),
[Fly Postgres](https://docs.fly.io/postgres).

## Superseded managed-identity evaluation

Auth0, Supabase Auth and Keycloak were evaluated before the user chose
self-owned Bitbid auth. They are not the current proposal. For provenance,
Auth0's ordinary Free plan explicitly excludes Pro MFA; current guidance maps
TOTP to Essentials and WebAuthn MFA to Professional. Displayed 500-MAU monthly
prices were $35/$240, and trial enablement is not production entitlement.
Sources: [Auth0 pricing](https://auth0.com/pricing),
[factor-to-plan mapping](https://auth0.com/blog/seven-architectural-readiness-checks-before-production-launch/),
[entitlement caveat](https://support.auth0.com/center/s/article/Entitlements-for-Enterprise-MFA-Feature).
Supabase's documented automatic email linking also needed reconciliation;
self-owned linking must enforce the signed-wallet proof explicitly. Source:
[Supabase linking behavior](https://supabase.com/docs/guides/auth/auth-identity-linking).

## Domain inventory, gates and authorization limits

**Parent-supplied authenticated inventory, 2026-11-10:** existing Cloudflare
account access works and exposes an active `theldo.com` zone. Pages listed no
projects; five Workers were listed, none named for `bsec`/`bitbid`. An exact DNS
read returned 403, so the chosen `bitbid.theldo.com` DNS collision/configuration
is still unknown. The user's chosen hostname is recorded; it is not claimed
to be configured, unused or reachable. No account identifiers or secrets are
recorded here.

Before production, pin and independently review the small module and its
schema/handlers, then qualify actual native/WASM dependencies and deployed
CPU/memory/concurrency. Prove password/MFA/reset replay/rate-limit negatives,
CSRF/session fixation/revocation races, provider mix-up/state/PKCE/nonce
failures, signed-wallet linking/recovery, cross-team/chain-lag denial and no
vault-secret server/SSR/log/storage paths. Demonstrate private-auth restore or
explicit re-enrollment separately from chain-index rebuilding. Mail delivery,
OAuth registrations, DNS/TLS and sufficient compute remain prerequisites;
local mocks do not establish them.

Self-owned auth avoids a hosted-IdP license fee, but runtime, database/private
backups, transactional mail, RPC/IPFS capacity and operations still need a
usage/spend plan. Users paying Polygon gas does not cover those operator
resources. No purchase, live configuration, push or deployment is authorized
by the research. The implementation owner must catalog actual newly required
settings in encrypted `secrets/prod.enc.yaml`, preserve existing values/use
disabled safe demo values where necessary, and execute completeness/unset
reports. This note introduces no actual setting and contains no credentials.
