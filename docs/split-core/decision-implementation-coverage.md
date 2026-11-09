# Decision-to-implementation coverage

Reconciled 2026-11-09 against the live
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
| [Hosted team architecture](https://github.com/igmrrf/bitbid/issues/27) | [Foundation](https://github.com/igmrrf/bitbid/issues/42) independently ready; the eight protocol/product continuations below are real blocked issues. Production and hosted CLI retain their own decisions. |
| [Publication contract](https://github.com/igmrrf/bitbid/issues/28) | [crates.io preparation](https://github.com/igmrrf/bitbid/issues/43), [signed archives](https://github.com/igmrrf/bitbid/issues/44), [Homebrew](https://github.com/igmrrf/bitbid/issues/45), [authorized execution](https://github.com/igmrrf/bitbid/issues/46) already cover all three selected channels. |
| [Team-vault key protocol](https://github.com/igmrrf/bitbid/issues/38) | Q1–Q6 and final reviewed contract confirmed; eight implementation continuations below. Qualification is the first gate; no shipped protocol or completed runtime qualification inferred. |
| [Production identity/domain/hosting](https://github.com/igmrrf/bitbid/issues/39) | Unresolved decision, not an accepted deployment plan. Its resolution must create exact provider/domain/hosting/backup/deployment preparation and authorized-execution tickets after resources/trust choices are known. |
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
| [Remove deprecated aliases at1.0](https://github.com/igmrrf/bitbid/issues/47) | Rename decision; `status:deferred`, explicit1.0 selection required, preserve all four aliases during0.x. Delivered historical compatibility/operations are context, not false open blockers. |
| [Qualify/freeze protocol and vectors](https://github.com/igmrrf/bitbid/issues/49) | Key-protocol decision. Review/freeze schemas first, then maintained primitive/native/WASM/browser qualification; failed/missing checks block downstream. |
| [Portable team-vault core](https://github.com/igmrrf/bitbid/issues/50) | Qualification; pure versioned primitives/framing/authority verification and explicit facade, preserving all legacy bytes. |
| [Opaque persistence APIs](https://github.com/igmrrf/bitbid/issues/51) | Foundation and portable core; real PostgreSQL, immutable records, separate checked authority/content heads and no server decryption. |
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
Open unresolved production/path/hosted-CLI choices are tracked as decisions
until exact implementation contracts can be stated. Creating a broad pretend
implementation before those choices would not establish coverage.

The live audit initially mapped20 decisions and23 normal issues. This upkeep
adds one decision and nine normal issues (eight hosted continuations plus one
deferred obligation). Existing claims/states were preserved. Native blocker
and sub-issue readback, full source provenance and independently researched
coverage are retained in the current Wayfinder run referenced by root
nextsession.md. This index is not a rerun of historical product QA.

No source implementation or deployable setting changes here. Codinary,
independent final-source verification, owned per-ticket local commits, actual
encrypted settings checks and concrete external-action authorization remain
required when each implementation is selected.
