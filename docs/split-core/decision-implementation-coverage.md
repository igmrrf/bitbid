# Decision-to-implementation coverage

Reconciled 2026-11-11 against the live
[map](https://github.com/igmrrf/bitbid/issues/3), its native children/dependencies,
current local contracts and recorded delivery evidence. This is an index, not
a second copy of decision resolutions. Historical open issues can describe
delivered local work. No historical issue was automatically closed or reclaimed.
Native/web changes remain local/unpushed.

## Every decision has an explicit disposition

| Decision | Delivered work or remaining ticket coverage |
| --- | --- |
| [WASM dependency research](https://github.com/igmrrf/bitbid/issues/4) | Consumed by production native/WASM boundaries, entropy configuration and verification; no separate feature missing. |
| [Leptos/shared-core research](https://github.com/igmrrf/bitbid/issues/5) | Sync-core guidance consumed; hosted framework/server-secret assumptions superseded by the current team architecture. |
| [Core/adapters prior-art research](https://github.com/igmrrf/bitbid/issues/6) | Consumed by shipped workspace and thin facade. |
| [Synchronous I/O ports](https://github.com/igmrrf/bitbid/issues/7) | [Ports/headless read](https://github.com/igmrrf/bitbid/issues/18), [RPC](https://github.com/igmrrf/bitbid/issues/19), [Store](https://github.com/igmrrf/bitbid/issues/29) delivered; next first slices already tracked under extraction. |
| [Workspace topology](https://github.com/igmrrf/bitbid/issues/8) | [Production topology](https://github.com/igmrrf/bitbid/issues/20) delivered. |
| [Fourteen-module partition](https://github.com/igmrrf/bitbid/issues/9) | Bounded shipped work plus existing first-slice issues; [remaining lifecycle/config/cache contract](https://github.com/igmrrf/bitbid/issues/48) now tracks the residual scope before more normal tickets. |
| [Canonical secret format](https://github.com/igmrrf/bitbid/issues/10) | Delivered canonical v1/bitbid2 and legacy readers; historical issue remains open with provenance. No duplicate implementation. |
| [Error model](https://github.com/igmrrf/bitbid/issues/11) | [Additive errors](https://github.com/igmrrf/bitbid/issues/17) delivered; actual hosted projection belongs to [foundation](https://github.com/igmrrf/bitbid/issues/42). |
| [Thin web facade](https://github.com/igmrrf/bitbid/issues/12) | Delivered with public-consumer/real browser evidence; historical issue remains open. |
| [Rename/compatibility](https://github.com/igmrrf/bitbid/issues/13) | [Catalog](https://github.com/igmrrf/bitbid/issues/21), [binary](https://github.com/igmrrf/bitbid/issues/22), [aliases](https://github.com/igmrrf/bitbid/issues/23), [operations](https://github.com/igmrrf/bitbid/issues/24), [branding](https://github.com/igmrrf/bitbid/issues/37) delivered. [Physical/resource cutover decision](https://github.com/igmrrf/bitbid/issues/40) pending; [1.0 alias removal](https://github.com/igmrrf/bitbid/issues/47) explicitly deferred. |
| [Migration/rollout](https://github.com/igmrrf/bitbid/issues/14) | E/P/A/T and N1–N5 delivered at recorded local commits; historical open state is not new work. |
| [Verification strategy](https://github.com/igmrrf/bitbid/issues/15) | Delivered native/WASM/facade/boundary/CLI/browser gates; every future slice owns its required final-source evidence. |
| [Historical SSR key custody](https://github.com/igmrrf/bitbid/issues/16) | Superseded for hosted vaults by client-only architecture. No server-unlock/Leptos implementation should be created from this old proposal. |
| [Next extraction contract](https://github.com/igmrrf/bitbid/issues/26) | All eight normal issues exist: Store delivered; [list](https://github.com/igmrrf/bitbid/issues/30), [IPFS](https://github.com/igmrrf/bitbid/issues/31), [codecs](https://github.com/igmrrf/bitbid/issues/32), [wallet read](https://github.com/igmrrf/bitbid/issues/33), [init](https://github.com/igmrrf/bitbid/issues/34), [signing](https://github.com/igmrrf/bitbid/issues/35), [revoke](https://github.com/igmrrf/bitbid/issues/36) tracked. Residual contract is a separate decision. |
| [Hosted team architecture](https://github.com/igmrrf/bitbid/issues/27) | [Foundation](https://github.com/igmrrf/bitbid/issues/42) is resized, not duplicated; private auth and the blockchain-authority decision are prerequisites. The production decision supersedes former PostgreSQL, managed-IdP and database-authoritative role clauses. Protocol/product continuations remain gated; hosted CLI retains its separate decision. |
| [Publication contract](https://github.com/igmrrf/bitbid/issues/28) | [crates.io preparation](https://github.com/igmrrf/bitbid/issues/43), [signed archives](https://github.com/igmrrf/bitbid/issues/44), [Homebrew](https://github.com/igmrrf/bitbid/issues/45), [authorized execution](https://github.com/igmrrf/bitbid/issues/46) already cover all three selected channels. |
| [Team-vault key protocol](https://github.com/igmrrf/bitbid/issues/38) | Q1–Q6 and final reviewed contract confirmed; eight implementation continuations below. Qualification is the first gate; no shipped protocol or completed runtime qualification inferred. |
| [Production authentication/domain/hosting](https://github.com/igmrrf/bitbid/issues/39) | Accepted 2026-11-11: self-owned optional wallet-linked password/Google/GitHub web auth with privileged TOTP MFA, `https://bitbid.theldo.com`, existing Workers Paid and D1. [Workers/D1 qualification](https://github.com/igmrrf/bitbid/issues/58), [private web authentication](https://github.com/igmrrf/bitbid/issues/59) and amended [foundation](https://github.com/igmrrf/bitbid/issues/42) cover bounded execution. Encrypted catalog adoption is local; actual resource/feature readiness, provisioning and deployment are unclaimed. |
| [Checkout/Compose cutover](https://github.com/igmrrf/bitbid/issues/40) | Unresolved decision. Its resolution must create exact coordinated move/tool-rebind/real-volume-preservation implementation and rollback tickets; no speculative path/resource change. |
| [Hosted CLI/service accounts](https://github.com/igmrrf/bitbid/issues/41) | Unresolved decision blocked on key protocol; its resolution must create exact human/machine access implementation tickets. Independent native preview is already covered and does not claim this feature. |
| [Remaining lifecycle/config/cache](https://github.com/igmrrf/bitbid/issues/48) | Newly created open/unclaimed decision covering retained residual scope; it must inventory and size exact normal issues without duplicating the existing first slices. |

## New real implementation tickets

These are actual tracker issues, not local candidate aliases. The team-vault
native dependency chain starts at the key decision, then qualification. Once
the confirmed decision is recorded closed, qualification is ready; dependent
core/product work still waits for its required gates. Contract confirmation
and qualification are distinct from product implementation or certification.

| Ticket | Native prerequisites / execution boundary |
| --- | --- |
| [Qualify Workers Paid Rust web authentication and D1 persistence](https://github.com/igmrrf/bitbid/issues/58) | Production decision; pinned actual Workers/Rust/Axum/Yew SSR/auth/D1, guarded zero-row/atomic/race/primary-read/restore and bounded resource qualification. Target access and separately authorized disposable deployment remain prerequisites; local SQLite is insufficient. |
| [Implement private web credentials, MFA and revocable sessions over D1](https://github.com/igmrrf/bitbid/issues/59) | Production decision, Workers/D1 qualification and [Define blockchain-authoritative teams and standalone client synchronization](https://github.com/igmrrf/bitbid/issues/57); canonical wallet binding, private auth/mail prerequisites, generation-bound recovery and fail-closed states. |
| [Implement Bitbid landing, sign-in and isolated team dashboard foundation](https://github.com/igmrrf/bitbid/issues/42) | Private web authentication and blockchain-authority decision; reuse existing foundation issue, qualify chain projections/freshness and production preparation. Encrypted vault claims retain separate core/protocol gates. |
| [Remove deprecated aliases at1.0](https://github.com/igmrrf/bitbid/issues/47) | Rename decision; `status:deferred`, explicit1.0 selection required, preserve all four aliases during0.x. Delivered historical compatibility/operations are context, not false open blockers. |
| [Qualify/freeze protocol and vectors](https://github.com/igmrrf/bitbid/issues/49) | Key-protocol decision. Review/freeze schemas first, then maintained primitive/native/WASM/browser qualification; failed/missing checks block downstream. |
| [Portable team-vault core](https://github.com/igmrrf/bitbid/issues/50) | Qualification; pure versioned primitives/framing/authority verification and explicit facade, preserving all legacy bytes. |
| [Opaque persistence APIs](https://github.com/igmrrf/bitbid/issues/51) | Foundation, portable core and blockchain-authority gates remain. The accepted production decision replaces PostgreSQL with qualified D1: immutable opaque records and checked heads/projections do not make SQL authoritative for chain roles/rights. No server decryption. |
| [Client setup/unlock/recovery/lock](https://github.com/igmrrf/bitbid/issues/52) | Opaque persistence; actual browser worker/lifecycle/recovery readiness, no secret durable cache. |
| [Verified invitations/grants/roles](https://github.com/igmrrf/bitbid/issues/53) | Client unlock; actual verified grants, signed authority/acceptance, membership transactions and browser ceremonies. |
| [Rotation/removal recovery](https://github.com/igmrrf/bitbid/issues/54) | Membership/grants; immediate denial/write freeze, fresh epoch/current ciphertext and atomic resumable activation. |
| [Encrypted dashboard CRUD](https://github.com/igmrrf/bitbid/issues/55) | Rotation; full authorized create/list/search/edit/reveal/copy/delete and signed content-head/tombstone behavior. |
| [Encrypted export/restore](https://github.com/igmrrf/bitbid/issues/56) | CRUD; bounded signed export closure, historical preview and permission/epoch/CAS-checked current import. |

The sequential product chain reflects actual reused interfaces and complete
acceptance journeys, not a claim that research or foundation work must wait for
all native extractions. No new dependency on native wallet/codecs was invented
for hosted vaults. Physical naming/production resources remain separate gates.

## Coverage and evidence limits

All previously resolved decisions now map to delivered work, existing normal
issues, the explicit deferred1.0 obligation, or a retained successor decision.
Open blockchain-authority/path/hosted-CLI/lifecycle choices are tracked as decisions
until exact implementation contracts can be stated. Creating a broad pretend
implementation before those choices would not establish coverage.

The live audit initially mapped20 decisions and23 normal issues. This upkeep
adds one decision and nine normal issues (eight hosted continuations plus one
deferred obligation). Existing claims/states were preserved. Native blocker
and sub-issue readback, full source provenance and independently researched
coverage are retained in the current Wayfinder run referenced by root
nextsession.md. This index is not a rerun of historical product QA.

The production decision registers 12 new unset/null settings/bindings and extends catalog checks; it does not implement auth or a runtime backend. Codinary,
independent final-source verification, owned per-ticket local commits, actual
encrypted settings checks and concrete external-action authorization remain
required when each implementation is selected.

## Production decision amendment — 2026-11-11

The [accepted contract](production-web-auth-hosting.md) and [current D1/hosting facts](../research/production-d1-hosting-facts.md) control production storage/auth choices. The existing [provider-facts note](../research/production-identity-hosting-facts.md) is historical recommendation evidence; its Neon/Hyperdrive and pending-approval wording is superseded, not a second selected plan. Only two new normal issues were created; foundation and opaque persistence were amended instead of duplicated. Native prerequisites, not issue creation alone, determine readiness. The blockchain-authority decision remains unresolved, and portable-core work is frozen unfinished; neither is resumed or completed by this amendment. Other decision drafts remain unresolved.

Catalog/tooling proof is local SOPS/age CLI verification with 19 unset entries, including the original six settings and network credential. Actual production-build SSR/auth/D1, provider/mail, browser and restore journeys are required by the continuations; no deployment, runtime QA waiver, provider/account write or production readiness is implied. Push/publication/provisioning/deployment/live transactions retain concrete authorization gates.
