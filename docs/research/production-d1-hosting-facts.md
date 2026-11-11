# Production D1 and hosting facts

Checked 2026-11-11 for [Choose production Bitbid authentication, domain and hosting](https://github.com/igmrrf/bitbid/issues/39). The user selected D1 after approving the authentication/hosting recommendations. This note records primary-source facts and project implications; it is not an account inspection, resource creation, benchmark or deployment. It incorporates the same-day independent database comparison and hosting fact check, with direct readback of the controlling D1/Workers/Email/Yew/Rust documentation.

The [accepted production contract](../split-core/production-web-auth-hosting.md) selects self-owned optional web authentication, `https://bitbid.theldo.com`, the user-attributed existing Workers Paid subscription and D1 managed SQLite. The earlier [identity/hosting facts](production-identity-hosting-facts.md) are historical proposal research: Neon/PostgreSQL/Hyperdrive are unselected alternatives and their pending-choice language no longer governs. No PostgreSQL backend/data migration exists to move. The prior hosted architecture's managed-IdP and PostgreSQL requirements are expressly superseded in the accepted contract.

## D1 state transitions and reads

D1's Worker binding exposes prepared statements and ordered transactional batches. SQL errors roll back a batch; the API does not expose an interactive callback for arbitrary Rust/network work between statements. The current Rust `worker` 0.8.7 D1 binding supplies prepare/batch/session methods under the `d1` feature; that available API is a qualification candidate, not proof that Bitbid's selected dependency graph or middleware works. [D1 binding API](https://developers.cloudflare.com/d1/worker-api/d1-database/), [Rust D1 API](https://docs.rs/worker/0.8.7/worker/d1/struct.D1Database.html)

SQLite conditional `UPDATE` can succeed while changing zero rows. `RETURNING` reports affected rows but cannot be used as a DML subquery/CTE to imitate PostgreSQL. [SQLite UPDATE](https://sqlite.org/lang_update.html), [SQLite RETURNING limitations](https://sqlite.org/lang_returning.html)

**Project implication:** qualify generation/purpose/actor/expiry/version/one-use guards inside mutations. A zero-row claim denies the action and every dependent session/factor/link/token mutation; later batch statements must be guarded too. Checking the result after an unintended write cannot undo it. Password/OAuth work stays outside short SQL transitions. Require exactly one winner under replay/concurrency and SQL-error rollback proof; no isolate map or generic read→Rust→unconditional-write substitute.

Without the D1 Sessions API, direct binding queries use the primary. Replica sessions provide sequential consistency, and `first-primary` constrains only the first query. A bookmark establishes a minimum observed database version, not globally latest revocation. [D1 read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/)

**Project implication:** keep security reads on the direct primary and close read/mutation races with guarded SQL. A D1 session is not a Bitbid login session. Neither a primary SQL read nor a bookmark establishes current chain authority: [Define blockchain-authoritative teams and standalone client synchronization](https://github.com/igmrrf/bitbid/issues/57) owns accepted-head/finality/reorg/outage/revalidation rules and canonical numeric encoding. Database projections must never confer chain roles or rights.

## Capacity, cost and recovery

Workers Paid includes 25 billion D1 rows read/month, 50 million rows written/month and 5 GB aggregate storage; overages are billable and index maintenance adds written rows. These are published plan allowances, not this account's verified usage or a zero-cost promise. [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)

A D1 database has a non-increaseable 10 GB cap and executes queries serially. Its bounded query/row/parameter/result limits and overload behavior constrain usable throughput. [D1 limits](https://developers.cloudflare.com/d1/platform/limits/)

**Project implication:** qualify bounded indexed statements, concurrency/admission, retention, index growth, usage budgets and failure/retry/idempotency alongside chain projection work. One bounded optional-web database is the initial plan; sharding requires measured need and a separate design. Revisit storage explicitly if the selected target cannot satisfy the security/resource gates.

Paid Time Travel retains up to 30 days, is always on and restores in place; in-flight requests are cancelled. Export is supported but can block other requests and has format/feature restrictions; local SQLite or a legacy `dump()` example is not remote D1 recovery proof. [Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/), [import/export guidance](https://developers.cloudflare.com/d1/best-practices/import-export-data/)

**Project implication:** restoration cannot preserve one-use/revocation history after the backup. Disable auth for restore, rotate an independently managed deployment auth generation and TOTP encryption key outside the restored database, drain old-generation traffic and require fresh canonical-wallet-proven re-enrollment. Reject saved old passwords/provider links/factors/sessions/challenges/reset/recovery/replay state; never trust restored counters. Protect exports as private credential data. Rebuilding a chain projection is separate from private credential recovery.

## Workers, SSR and mail are still qualification gates

Workers Paid retains a 128 MB shared isolate memory limit and finite configurable CPU budgets. Rust uses the Worker event loop; published Axum integration and the experimental Emscripten path do not prove the complete application. Current Yew documentation describes experimental SSR, a single-thread renderer and serverless features, which must be reconciled with Bitbid's actual pinned version. [Workers limits](https://developers.cloudflare.com/workers/platform/limits/), [Rust support](https://developers.cloudflare.com/workers/languages/rust/), [worker HTTP/Axum API](https://docs.rs/worker/0.8.7/worker/#http), [workers-rs Emscripten](https://github.com/cloudflare/workers-rs#emscripten), [Yew SSR](https://yew.rs/docs/advanced-topics/server-side-rendering)

**Project implication:** pin and production-build the actual Rust/Axum/Yew SSR/OAuth/session/D1 path. Measure Argon2 hash/verify CPU, aggregate memory, concurrency and sustained abuse; freeze global/IP/hash/SQL limits without reducing the accepted password or vault KDF protections. SSR/hydration may contain only a non-secret frame. A native example or local Wasm build is insufficient.

Cloudflare Email Service sending requires Workers Paid and sender/domain onboarding. Published monthly included volume is 3,000 messages, then $0.35/1,000; separate account-specific daily quotas depend on reputation and are not a universal published number. DNS setup and ordinary-recipient eligibility must be verified; the sending guide remains Beta. [Email pricing](https://developers.cloudflare.com/email-service/platform/pricing/), [Email limits](https://developers.cloudflare.com/email-service/platform/limits/), [Email onboarding](https://developers.cloudflare.com/email-service/get-started/send-emails/)

**Project implication:** verify actual account access/quota, sender choice, DNS collision/write permission and delivery/suppression/bounce/timeout behavior. The user-attributed subscription satisfies only the stated plan prerequisite. No mail entitlement, configured sender or successful delivery is claimed.

## Exact follow-through

[Qualify Workers Paid Rust web authentication and D1 persistence](https://github.com/igmrrf/bitbid/issues/58) owns pinned selected-target atomicity, primary reads, restore and resource proof. [Implement private web credentials, MFA and revocable sessions over D1](https://github.com/igmrrf/bitbid/issues/59) depends on qualification and the blockchain-authority decision. Existing [foundation](https://github.com/igmrrf/bitbid/issues/42) is resized, not duplicated; [opaque persistence](https://github.com/igmrrf/bitbid/issues/51) retains foundation/core/chain gates without database-authoritative rights.

The 12 selected configuration names are registered unset/null under the [approved encrypted catalog workflow](../secrets-catalog.md); `BITBID_DB`/`BITBID_MAIL` are Worker bindings and `BITBID_D1_DATABASE_ID` is a deployment selector. Registration is not a live binding or runtime implementation. Real production recipients/credentials, target access, resource provisioning and separately authorized deployment remain prerequisites. No provider/account mutation, purchase, transaction, deployment or runtime benchmark was performed for this decision adoption.
