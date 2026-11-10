> Versioned draft checkpoint for [Choose production Bitbid authentication, domain and hosting](https://github.com/igmrrf/bitbid/issues/39).
> Committed at the user's request to save all changes by ticket or feature; this does not resolve the open decision or turn pending choices into approvals.
> The reviewed proposal below is preserved byte-for-byte. Its work-in-progress references describe the planning snapshot; alias removal has since completed at `b0a6b62`, and portable-core work remains unfinished.

# Proposed production web identity and hosting contract

Status: **ready-to-review proposal; not accepted, committed, implemented or deployed**.
Supports [Choose production Bitbid identity provider, domain and hosting](https://github.com/igmrrf/bitbid/issues/39).
Prepared 2026-11-10 from live choices and `bitsec/docs/research/production-identity-hosting-facts.md`.
The tracker owner must reconcile this with the final human confirmation before resolution.

## Scope and inherited choices

Use self-owned Bitbid web authentication, established Rust libraries, the existing
Yew/Axum direction and the user's existing Cloudflare Workers Paid subscription.
Origin: `https://bitbid.theldo.com`. No paid hosted identity provider, new OAuth
issuer or CLI dependency on web login is required. Optional email/password and
Google/GitHub sign-in link to a canonical wallet using authenticated signed proof.
Privileged Bitbid web sessions require server-verified TOTP MFA.

Canonical wallet/account, team, role, relationship and current-authority state
belongs on-chain under the forthcoming registry contract. Public IDs, roles and
relationships are intentional metadata; names/values remain encrypted on IPFS.
PostgreSQL may index chain state. Neon Free is the recommended PostgreSQL
candidate, **pending provider-specific approval**, not a provisioned resource.
Its private optional web credential/session extras are not a chain replica and
need backup and the fail-closed fresh re-enrollment procedure below; do not call
those extras reconstructible or automatically reactivate restored credentials.

[Design canonical on-chain teams and registry synchronization](https://github.com/igmrrf/bitbid/issues/57)
owns the exact new chain schema, wallet/protocol identity binding, registry/API,
publication ordering, synchronization and finality rules. This proposal does not
assert that the existing deployed registry already has teams or finalize that API.
Polygon Amoy is the development plan and Polygon PoS the production plan; users
fund transactions. Neither plan authorizes a live deployment or transaction here.

Preserve the accepted vault protocol: one account-level unlock/recovery identity,
independent vault keys, trusted-channel fingerprint verification before first
sharing/replacement, encrypted trust pins, recovery-kit save plus successful
restore test before first secret storage, complete epoch rotation and frozen
writes after access loss, verified signed authority/content, 15-minute inactivity
and 5-minute hidden browser locks plus logout/reload lock, no automatic offline
plaintext cache, and the stated historical-copy/freshness limits. No source or
wire change to independently owned portable-core work [#50](https://github.com/igmrrf/bitbid/issues/50)
is implied. Its separate execution session is closed with unfinished source frozen;
retain that owner/checkpoint and do not resume, overwrite or stage its changes.
Existing legacy token/wallet/cryptographic behavior remains protected;
environment/path alias removal belongs to its separate authorized ticket.

## Exact proposed auth boundary

Build a bounded module in the web server, rather than a general identity product.
Private records cover credential IDs bound to canonical wallet references,
password PHC hashes, confirmed email, provider-subject links, protected TOTP
seeds/enrollment state, hashed one-use web recovery/reset/verification tokens,
server sessions, pending OAuth/wallet challenges and redacted security events.
Never publish these records, emails, passwords/hashes, TOTP seeds or provider
credentials on-chain/public IPFS. Never persist vault roots/passphrases/recovery
codes, plaintext labels/values or unlocked vault state in the host.

A web-login password differs from the vault passphrase and has no vault-decryption
role. Password/MFA recovery cannot recreate a lost wallet/vault root, change an
on-chain role or silently replace a linked wallet. The signed-wallet link requires
fresh proof of the selected wallet plus authenticated proof of the intended
existing web/provider identity; matching email, a self-signature or an unverified
profile field cannot merge identities. Exact wallet challenge/contract-wallet
verification and replacement mappings depend on #57. Email/social remains
optional: a wallet-only web session can be linked to private MFA extras without
requiring an email account.

**MFA scope is explicit:** this controls Bitbid server-mediated privileged web
sessions/actions, including wallet-only web sessions. It is not a global on-chain
second factor and cannot prevent the same authorized wallet from directly using
a standalone client. Global on-chain MFA would be a different #57/account-design
decision. A valid web session likewise cannot confer a missing chain capability
or decrypt public-IPFS ciphertext without the client-held epoch key.

### Password and TOTP profile

Propose a separately versioned server-login profile: RustCrypto Argon2id v19,
19456 KiB memory, t=2, p=1, fresh 16-byte salt, 32-byte output, PHC encoding.
Accept only this bounded profile in v1 before hashing; future rehash/profile
migration requires review. Minimum password length is 15 Unicode scalar values,
maximum 1024 UTF-8 bytes; permit paste/password managers, reject known-compromised
choices, and never silently truncate or normalize. Keep password policy and
hashing separate from the approved client vault KDF; no weakening or relabeling
of its domains/parameters. This is an OWASP-baseline candidate that still needs
actual Workers Paid hash/verify, memory, concurrency and sustained-abuse proof.
If it fails resource qualification, revise the deployment boundary or explicitly
review a stronger/adequate profile; do not silently reduce protection.

Propose RFC 6238 TOTP through a maintained library such as `totp-rs`: unique
20-byte random seed, six digits, 30-second step, HMAC-SHA-1 for authenticator
compatibility, maximum one step of clock skew each direction. Confirm enrollment
with a valid code. Encrypt seeds at rest with a separate server-managed key and
a reviewed AEAD, binding credential/enrollment/auth generation/key version as
associated data.
Atomically consume a successful timestep once across concurrent requests and
maintain failure/rate-limit state in consistent private persistence, not an
isolate-local map. Expired, replayed, out-of-window, pending or unconfirmed
factors fail. TOTP is not phishing-resistant; no NIST certification is claimed.

A primary login or wallet proof creates only a restricted pending session until
required MFA succeeds. Store factor completion/freshness on the server; privilege
checks reject absent/expired assurance. Propose a 15-minute freshness window for
privileged web actions, independent of the vault inactivity lock, and an absolute
12-hour/idle-30-minute web session ceiling. These exact proposed values require
human review; session expiry cannot revoke copied vault keys. Rotate session IDs
after login/MFA/privilege change and revoke them on logout/password reset or
compromise. Do not trust a browser flag or upstream MFA-enabled profile field.

Web MFA recovery codes are independent random one-use credentials stored as
one-way verifiers, shown once and atomically consumed. Factor change requires
recent primary authentication plus the current factor/recovery proof; notify
the account and invalidate affected sessions. Email password reset alone cannot
remove MFA or replace the wallet link. No account-by-account operator bypass or
email-only recovery of all lost factors is included. The deployment-wide disaster
restore/re-enrollment procedure below is a separate fail-closed path; standalone
chain access remains independent.

### OAuth clients, sessions, CSRF and mail

Use `openidconnect`/its OAuth client layer for Google and GitHub relying-party
flows, not an issuer stack. Pin reviewed compatible versions/features and
endpoints, use code+PKCE S256, unpredictable session-bound state, exact configured
callbacks, finite deadlines and one-use short-lived pending state. Google ID
tokens require signature/issuer/audience/expiry/nonce validation and issuer+sub
identity. GitHub uses its documented code flow and authenticated-user API ID;
do not invent an OIDC ID token. Request only necessary scopes, validate verified
email separately when needed, and discard upstream tokens after login/profile
verification when no API use remains. Real provider app registration/consent and
callback configuration are production prerequisites, not credentials inferred
from examples.

Use opaque CSPRNG session credentials in host-only `__Host-` Secure/HttpOnly
cookies with Path=/ and deliberate SameSite policy. Persist revocable sessions
server-side, preferably with one-way token verifiers; no roles/secrets in a
client-owned flag. Qualify an established Axum-compatible session component,
such as `tower-sessions`, with the chosen store/runtime. Cookie flags do not
replace CSRF tokens plus strict origin checks on mutations. Ordinary GET/HEAD
routes perform no application, wallet-link, role or permission mutation. The
configured OAuth GET callback has only a narrow protocol exception: it may
transition authentication/create the intended session only after the successful
provider exchange with bound PKCE and applicable OIDC nonce/issuer/audience proofs,
with matching session-bound pending state claimed/finalized exactly once through
atomic private-store transitions. This does not pretend the remote provider
exchange is a database transaction. Replay/concurrent attempts fail closed.
It cannot link or replace existing
wallet/provider identities or change privileges. Those changes require an
explicit authenticated CSRF/origin-protected confirmation mutation; a cross-site
GET link alone cannot perform them. Mail GET links render confirmation forms;
verification/reset token consumption and credential changes use explicit protected
mutations. Test the callback exception, intended pending cookie, replay/missing/
wrong state/provider, and GET-based link/privilege-change denial. Session cache/
update races cannot implement atomic MFA/reset/revocation enforcement.

Apply bounded distributed account/challenge/IP/global throttling to signup,
login, MFA, recovery, reset, verification and linking, before expensive work.
A proposed initial ceiling is five failed password/MFA attempts per credential
per 15-minute window and five recovery/reset sends per credential/hour, plus
separately bounded IP/global admission. Exact IP/global rates and hash concurrency
must be frozen from the runtime qualification before the auth ticket is ready;
no unbounded queue or persistent attacker-controlled account lockout. Uniform
responses avoid enumeration; do not log credential, code, seed or token values.

Verification/reset tokens are high-entropy, purpose-bound, finite-lived,
one-use, protected in storage and atomically consumed. Propose 30-minute
verification and 15-minute reset lifetimes. Build links from the configured
origin, rate-limit delivery, handle suppression/bounce/timeout accurately, and
never automatically create a privileged session after reset. Existing Workers
Paid addresses the plan prerequisite for Cloudflare Email Service; sender/domain
DNS onboarding, sending entitlement/quota and actual delivery remain unverified.
Current included sending is 3,000/month then $0.35/1,000, subject to live terms.
No new mail purchase or quota promise follows from this proposal.

## Private-auth disaster restore: invalidate, then re-enroll

This is an explicit proposed recovery contract, not an implemented backup feature.
Restore private auth data only while maintenance/auth-disabled; do not immediately
serve its saved credentials. Before reopening auth, set a fresh independently
managed deployment `BITBID_AUTH_GENERATION` and rotate the TOTP seed-encryption key.
The generation is controlled outside the restored database and must not be copied
back from that backup, inferred from its highest counter, or defaulted when unset.
Missing/disabled generation fails optional web authentication closed. Drain/disable
old-generation instances before accepting new-generation auth traffic.

Bind every password/provider/factor link, session, pending OAuth/wallet/MFA
challenge, reset/verification/MFA recovery token and replay/rate state to its auth
generation. Restored old-generation rows are never accepted as active authority.
In particular, do not re-enable an old password hash, provider-to-wallet link,
TOTP seed, consumed reset/recovery token or rolled-back last-used timestep merely
because the restored database labels it valid. The saved database cannot establish
monotonic revocation or one-use history that happened after the backup.

Require fresh canonical-wallet-proven web re-enrollment under #57's approved
binding/recovery rule before installing any new optional password/provider link,
verified email, fresh TOTP seed and new one-use recovery set. Neither email access,
an old provider link, an old factor nor an old session alone can reactivate the
restored profile. New credentials/challenges belong to the new generation; issue
ordinary privileged sessions only after its fresh enrollment and required MFA.
Preferences may restore separately as non-authoritative data. No chain role,
wallet key, vault root, encrypted trust pin or vault-grant recovery rule changes;
standalone chain/vault access remains available under its existing client keys.

Positive proof must show new-generation wallet enrollment, optional email/provider
linking, MFA and ordinary login working after recovery. Negative proof must restore
a stale backup and reject old password/provider links, old TOTP codes/replay state,
old sessions/challenges and consumed/reset/recovery tokens, including concurrent
requests and old-generation deployment traffic. Do not claim these guarantees
from successful SQL restore or the restored database's counters alone.

## Hosting, freshness and verification acceptance

The Worker runs only web auth, an SSR-safe non-secret frame, API projections and
bounded index/persistence work. Vault unlock/KDF/decrypt remain client-side.
Workers Paid still has 128 MB/isolate; choose a deliberate finite CPU limit and
prove CPU/memory/concurrency on the real selected runtime. A native Axum example
or local WASM build alone does not prove the full Yew SSR/OAuth/database journey.
Hyperdrive is connectivity to external Postgres, not the database itself; disable
query caching for credentials/sessions/current authority/permissions. Fresh SQL
cannot make a lagging chain replica current: #57 must define accepted head,
finality, effective permission changes, outages and fail-closed/revalidation.
Private auth restore must use the separate generation/key rotation and fresh
wallet-proven re-enrollment procedure above, not revive any saved credential or
historical chain role.

| Acceptance | Required evidence |
|---|---|
| WEB-AC1 | Current choices, optional web login, direct standalone CLI, private non-chain auth state, web-only MFA scope, #57 ownership and original vault boundaries remain explicit; no claim existing registry has teams. |
| WEB-AC2 | Qualified pinned Rust/WASM dependencies and actual Workers Paid production-build SSR/auth/SQL path; bounded hash CPU/memory/concurrency, overload, timeout/shutdown and secret-free logs/errors. No weakening the vault or login KDF. |
| WEB-AC3 | Real credential/MFA/session persistence with wrong password/code, replay/concurrent timestep, reset/recovery races, fixation, CSRF, stale assurance, disabled sessions and account-enumeration negatives. Exact limits fixed/tested. |
| WEB-AC4 | Real Google/GitHub callback succeeds only through the narrow protected protocol exception; wrong/replayed/missing state/PKCE/issuer/audience/nonce/provider fails. GET cannot link/replace identities or change privileges; explicit authenticated CSRF/origin-protected confirmation is required. Duplicate linking, wallet substitution/replay and replacement recovery negatives pass. Scope/identity proofs do not grant chain roles. |
| WEB-AC5 | Real mail sender/DNS/TLS/delivery and failures; auth-disabled private restore, independent deployment generation/TOTP-key rotation and fresh wallet-proven re-enrollment. Positive new-generation login plus stale password/provider/factor/session/challenge/reset/recovery/replay-state negatives pass without trusting restored counters. Chain-index rebuild and #57 freshness/isolation remain separate; restore cannot revive chain authority. |
| WEB-AC6 | Actual desktop/narrow/keyboard browser signed-out, wallet-only, social/password, MFA-pending/denied, lock/reload, recovery and cross-team cases. Inspect network, console, SSR/hydration and storage for forbidden vault material. |
| WEB-AC7 | Actual selected environment/binding names enter encrypted catalog with disabled safe states; completeness/unset reports and independent review pass precede local scoped commit. Deployment remains a separate authorized action. |

## Bounded implementation continuation proposals

These labels are proposed scopes, not tracker issues or completed implementation.
Reconcile/resize existing [hosted foundation #42](https://github.com/igmrrf/bitbid/issues/42)
instead of creating duplicate claimed work. Each ready implementation ticket must
freeze exact files, DTO/schema, commands, fixtures and rollback boundary.

1. **Qualify Workers Paid Rust auth primitives/runtime** — own only new
   `webapp` server qualification fixtures/tests and task-owned build/deploy
   artifacts; benchmark the proposed Argon2/TOTP/session/SQL/SSR path and freeze
   CPU, admission and input bounds. Can proceed after this decision is confirmed;
   no #50/core or registry edits. Production account writes/deployment need
   separately concrete authorization; local proof is insufficient for WEB-AC2.
2. **Implement private web credentials, MFA and revocable sessions** — own
   `webapp` server auth modules/private migrations/tests and the minimal Yew
   sign-in/MFA/recovery surfaces. Depends on qualified runtime, explicit private
   store/mail prerequisites and #57's canonical wallet/link boundary. No chain
   schema redesign, vault unlock or fake authorization map. Verify WEB-AC3/4/7.
3. **Integrate real wallet/team foundation and production preparation** — own
   resized #42 frame/session/authorized projections, deployed configuration
   artifacts, fail-closed auth restore/re-enrollment and browser fixtures. Depends
   on #57 authority/sync gates; encrypted
   vault feature claims additionally require qualified #50 and downstream key
   lifecycle implementation. Verify WEB-AC1/5/6 and prepare rollback/restore.

## Minimal candidate deployable settings

Names are **proposals to reconcile with existing canonical settings**, not new
live requirements or catalog edits. Fixed security limits belong in reviewed
versioned configuration, not dozens of new environment knobs.

| Candidate | Purpose/safe inactive condition |
|---|---|
| `BITBID_WEB_ORIGIN` | Chosen trusted HTTPS origin; callbacks/reset links/cookie policy. |
| `BITBID_WEB_AUTH_ENABLED` | Disable optional auth until store, keys, providers/mail and gates are ready. |
| `BITBID_DATABASE_URL` | Private auth/optional index connection; no real value in this draft. |
| `BITBID_AUTH_GENERATION` | Independently controlled current auth generation; unset/demo disables auth, never a default generation. Rotate outside DB restore before re-enrollment. |
| `BITBID_TOTP_ENCRYPTION_KEY` | Independent server seed-encryption key; absent means MFA enrollment/auth fails closed, never a demo key in production. |
| `BITBID_GOOGLE_CLIENT_ID`, `BITBID_GOOGLE_CLIENT_SECRET` | Optional registered Google relying-party client; missing pair disables that connection. |
| `BITBID_GITHUB_CLIENT_ID`, `BITBID_GITHUB_CLIENT_SECRET` | Optional registered GitHub client; missing pair disables that connection. |
| `BITBID_MAIL_FROM` plus a scoped Email Service binding | Verified sender/transport; no API token necessary when a scoped Worker binding suffices. Missing transport disables email signup/reset delivery, never fakes success. |

#57 owns chain/RPC/registry/IPFS setting names; reuse its approved catalog rather
than duplicating them here. Opaque server sessions do not require an invented
OIDC issuer/client secret. No secret value is supplied. Provider-specific Neon
approval, actual DNS write permission/collision resolution, email sender choice
and the exact measured global/IP/hash bounds remain concrete prerequisites.
