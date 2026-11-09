# Bitbid hosted team application execution contract

Status: architecture and product/security choices agreed in live exchange on 2026-11-09. Canonical decision: [Rebase the SSR execution decision on the shipped Yew and shared core](https://github.com/igmrrf/bitbid/issues/27). This records accepted Q1–Q12 and the implementation gates that follow; it does not claim a hosted product exists.

## Accepted destination

Bitbid has a public landing page and an authenticated application for teams. Sign-in lands a user on a team dashboard. Owners and Admins manage team secrets; Members receive explicit vault-scoped access. One account can belong to multiple teams. The roadmap includes usable secret management, not merely a dashboard illustration.

Keep Yew, add an Axum backend and PostgreSQL. Render the landing page and non-secret dashboard frame on the server; unlock/decrypt vault contents in the client. Reuse the shared core where its contracts fit. A framework change to Leptos is not required. Native CLI distribution proceeds independently under the publication contract.

## Identity, membership and key access are distinct

- Use an established identity provider for verified email/password plus optional Google/GitHub sign-in. Owners/Admins require MFA. The application verifies identity-provider assurance on the server; a client flag is not evidence of MFA. Exact production provider/domain configuration must be selected and tested before public deployment.
- Account identity is bound to verified issuer and subject, not an unverified email string. Linking identities requires authenticated proof; matching email alone cannot merge accounts. Invitations bind the intended verified identity/email under an explicit acceptance flow.
- Owner manages ownership transfer, team deletion and privileged roles. Admin manages ordinary membership and team secrets. Members see only assigned vaults; grants distinguish reading from modifying secrets, with read-only as the initial grant default.
- Owners/Admins receive access to all team vaults. Role assignment alone cannot invent decryption keys: an authorized unlocked client must supply cryptographic grants. Promotion/invitation remains pending until the required key delivery is complete. The key-protocol decision must define authenticated recipient-key binding and all-vault grant changes.
- Every server query/mutation resolves the actor from its session and checks membership, role and requested vault access. A request's team ID, role or user ID is not trusted authority. Cross-team ID substitution and direct endpoint calls must fail. Preserve at least one owner unless a separately confirmed team deletion is being executed.

## Client custody and recovery

The host stores ciphertext and never receives the vault passphrase, recovery key, vault decryption keys or decrypted secret names/values. Vault unlock is separate from sign-in. Account recovery restores identity access only. A user-held recovery key can restore vault unlock; an authorized Owner/Admin can regrant team access from an unlocked client. The operator has no recovery master key. Losing every authorized key and recovery key can make data irrecoverable.

Secret names, values and vault labels are encrypted. The server may retain account/team membership, opaque vault/item IDs, permissions, timestamps and ciphertext lengths. Search over encrypted names/values runs in the unlocked client. Audit events contain actor/action/opaque target/time, not plaintext labels, values, tokens or key material.

Keys and decrypted content stay in client memory while unlocked; plaintext/key storage in localStorage, IndexedDB, service-worker caches, URLs, analytics or error reports is excluded. Lock on logout/reload; an inactivity lock must clear controlled secret state. A concrete inactivity/session timeout, key ownership types and best-effort memory clearing are implementation-contract outputs, not a claim that every JavaScript/WASM/compiler copy can be erased. Client locks and server session revocation are separate mechanisms.

Membership removal immediately denies server access. Key rotation and re-encryption rules for future access are required outputs of the key-protocol decision. Revocation cannot erase plaintext or keys a previously authorized recipient already copied. A browser client also trusts delivered client code: stored-ciphertext confidentiality is not a promise to withstand malicious replacement of the client bundle, XSS or a compromised endpoint. Harden and verify the delivery path; document this threat limit accurately.

## Scope relative to earlier decisions

This explicitly supersedes the prospective **server-unlock** architecture in [SSR key handling](ssr-key-handling.md) for the new hosted team-vault product. It does not move native blockchain-signing keys to the host or change the existing CLI wallet policy. Retain the historical decision and its reasoning as provenance.

Existing browser-local seal/unseal and canonical/legacy token readers remain compatible. Preserve existing wire bytes, HKDF labels, deployed contract/address/ABI and stored wallets. The team-vault envelope, key hierarchy, sharing, recovery and rotation require a new explicit versioned protocol contract; do not relabel an existing cryptographic domain or silently reinterpret legacy tokens. Hosted CLI/service-account access remains included follow-up work and is not claimed by the independent v0.1.0 native release.

Native FileStore and CLI wallet paths are not a multi-user tenancy store. The first hosted account/team dashboard need not wait for unrelated native wallet/IPFS/signing extractions; it uses its own PostgreSQL identity/membership/ciphertext metadata persistence. Secret-management implementation waits for the key-protocol gate.

## First implementation seams and proposed locations

Current native root is still `bitsec/`; current web root is `webapp/`. Local directory relocation is a separate coordinated cutover. Keep independent lockfiles.

- `webapp/crates/server` (new, package `bitbid-server`, unpublished): Axum composition, OIDC/session verification, authorization, PostgreSQL persistence, request limits and SSR/static asset delivery. No native wallet-password or secret-decryption endpoint.
- `webapp/crates/app`: retain Yew; separate SSR-safe landing/dashboard frame from browser-only wallet integrations and vault state. Existing standalone crypto remains a distinct compatible flow.
- `webapp/crates/core`: keep the facade thin; shared native/WASM team-vault primitives belong in `bitbid-core` only after the separate protocol contract is reviewed. No database/HTTP/identity-provider code enters the shared pure core.
- PostgreSQL migrations define accounts, identities, teams, memberships, invitations, vault grants, ciphertext envelopes and redacted audit events. Database transactions enforce ownership/membership invariants. Authorization tests use a real disposable database, not a map substituted for tenancy enforcement.

Initial interface responsibilities (exact DTOs/schema frozen in each ready ticket):

- Session identity: verified subject/issuer, internal account ID and validated authentication assurance; never taken from browser-supplied role claims.
- `/api/me`: account and allowed team memberships, excluding provider tokens and vault keys.
- `/api/teams/{team}/dashboard`: authorized team/vault summaries and ciphertext/opaque IDs only. An authenticated but locked user sees the frame and permitted non-secret summaries, with client unlock required for encrypted labels/content.
- Team/member/vault/item mutations: server-side action/tenant checks, replay/CSRF controls as appropriate, transaction/optimistic-version handling and safe error projections. An API success cannot claim key delivery if the cryptographic grant is still pending.

Protected routes use secure HttpOnly session cookies in production, configured origin/redirect allowlists, HTTPS, CSRF protection for cookie-authenticated mutations and explicit rate/body/page/concurrency bounds. Provider verification, SQL queries and requests have finite deadlines. Cancel/roll back uncommitted work where possible, reconcile uncertain commit outcomes before retry, and test cancellation/commit races; shutdown drains bounded work. The server never starts secret-bearing blocking KDF/decrypt work; do not inherit a claim that timing out a blocking task erases keys. Exact operational limits must be stated/tested in the server ticket before its QA pass.

## Delivery stages and gates

1. Specify and independently review the client-encrypted vault protocol: envelope/versioning, key hierarchy/KDF, recipient binding, invite/promotion, read/write grants, recovery, rotation, metadata and legacy compatibility. This is a decision gate, not implemented crypto.
2. Deliver the real public landing page, trusted-provider sign-in/session verification and PostgreSQL-backed team dashboard frame, with signed-out, MFA-required, denied/removed-member and cross-team cases. No encrypted-vault feature is marked delivered using mock plaintext or a fake authorization backend.
3. Deliver team creation/switching, invitations, ownership/role management, grants and redacted audit persistence. Join and privilege changes must accommodate the approved key-delivery protocol.
4. Deliver client unlock/recovery and the usable secret-management journey: authorized list/search, create/edit/reveal/copy/delete and role/permission denials; ciphertext round trips through the actual backend/database. Existing standalone browser crypto remains exercised.
5. Resolve production identity/domain/hosting/backup and future hosted CLI/service-account access as explicit follow-ups. Prepare deployment artifacts before requesting deployment authorization.

These stages require separately sized normal implementation tickets and native dependencies. Only stages with a locked interface/acceptance matrix are ready. Do not turn an unresolved cryptographic/provisioning choice into an implementation assumption.

## Stable acceptance and verification

### Actual tracker continuation

- [Specify client-encrypted team-vault keys, sharing and recovery](https://github.com/igmrrf/bitbid/issues/38): next cryptographic decision; blocks concrete encrypted-vault/grant/CRUD implementation sizing.
- [Choose production Bitbid identity provider, domain and hosting](https://github.com/igmrrf/bitbid/issues/39): production trust/resources decision, not a prerequisite to local disposable-provider/database foundation proof.
- [Define hosted-team CLI and service-account access](https://github.com/igmrrf/bitbid/issues/41): follows the key protocol; independent v0.1.0 native publication does not claim this feature.
- [Implement Bitbid landing, sign-in and isolated team dashboard foundation](https://github.com/igmrrf/bitbid/issues/42): first normal implementation ticket, scoped to the actual authenticated SSR/team foundation. Encrypted secret-management slices remain included and are created precisely after the key-protocol contract.
- [Specify remaining Bitbid checkout and Compose identity cutovers](https://github.com/igmrrf/bitbid/issues/40): coordinate local path/resource naming and data preservation after current branding delivery.

- `TW-AC1`: actual landing → sign-in → team dashboard, real session/provider verification and persistent team membership; direct anonymous, forged, wrong-issuer/audience and insufficient-MFA calls fail safely.
- `TW-AC2`: two accounts across two teams prove isolation on every read/write route, guessed IDs, stale membership, invitation, privilege changes, last-owner and concurrency/rollback paths. Client navigation is not the authorization test.
- `TW-AC3`: no vault plaintext/passphrase/key/recovery material in server traffic/state/logs/errors/SSR/hydration/storage; allowed metadata matches the agreed list. Positive crypto/recovery vectors, tamper/wrong-key/version negatives and revocation behavior follow the approved protocol contract.
- `TW-AC4`: final native/WASM public consumers preserve legacy token/crypto/wallet behavior; compile both SSR and browser targets. Run the actual server with disposable PostgreSQL/OIDC fixtures and real browser desktop/narrow/keyboard, lock/unlock, failure/recovery and reload flows against the production build. Inspect Console/Network and screenshots.
- `TW-AC5`: finite limits/deadlines/rate/concurrency/shutdown behavior and migration rollback/backup restore are demonstrated on task-owned data. New deployable settings enter encrypted `secrets/prod.enc.yaml` with disabled safe states and actual completeness/unset reports; no secret values in evidence.

Before implementation, each ticket assigns exact files/DTOs/schema, executable commands, negative cases, rollback boundary, prerequisite issues and which `TW-AC` conditions it owns. Local success does not establish hosted deployment or a reviewed team-vault protocol.

## Execution limits

Use Codinary per ready implementation ticket and commit the verified ticket separately under AGENTS.md. Preserve existing Store/Homebrew/.DS_Store work. GitHub repository rename and native origin relink to `igmrrf/bitbid` are already authorized and complete. Push, release tags, registry publication, hosted deployment and live-provider mutations require authorization covering the concrete action. Production provider/domain/signing credentials are prerequisites to discover securely when the concrete preparation needs them, not secrets to paste into issues.
