# Client-encrypted team-vault protocol contract

Status: **agreed contract for qualification; not implemented**. Human Q1–Q6
and final shared understanding were accepted on 2026-11-09. Independent design
review resolved all five material schema/authority findings. The exact profile
below is the approved input to qualification, not a passed runtime result or
cryptographic audit. Canonical decision:
[Specify client-encrypted team-vault keys, sharing and recovery](https://github.com/igmrrf/bitbid/issues/38).
Read with [team architecture](team-web-execution.md) and
[primary-source findings](../research/team-vault-key-facts.md).

## Accepted product policy

1. One account-level vault passphrase and recovery kit unlock access across
   teams. Each vault has an independent random key; no Member receives a shared
   all-team root. Sign-in/MFA and vault unlock remain separate.
2. Before first key sharing and after replacement, verify the intended person's
   encryption/signing identity fingerprint through a trusted communication
   channel. An email, OIDC claim, self-signature or host-supplied fingerprint
   alone is insufficient. Pending verification cannot activate a grant.
3. Removal immediately denies server access and freezes affected-vault writes.
   Remaining authorized users may read the last active snapshot. An authorized
   unlocked client must replace keys and re-encrypt all current encrypted
   labels/items before writes resume. Historical copies cannot be recalled.
4. Before first secret storage, require recovery-code/backup saving and a
   successful restore test. Original-key recovery differs from teammate regrant
   to a newly verified replacement identity. Lost private keys are not recreated
   by an account-password reset or team role.
5. Clients verify signed grants, ciphertext revisions and authorization history.
   Shared decryption-key possession is not write authority. Disclose that a
   newly unlocked client cannot establish latest-state/fork agreement solely
   from this service's valid historical records. No external witness in v1.
6. Lock after 15 minutes without activity, after 5 minutes hidden, immediately
   on logout/reload. No automatic offline cache. Explicit encrypted recovery/
   data exports are allowed; importing never restores revoked server access.

These choices do not change existing `bitbid2:`, `bitbid1:`, raw IPFS JSON,
wallet/KDF/HKDF domains, contracts/ABI, aliases through 0.x, or native blockchain
signing. New team envelopes are a distinct format and dispatch path.

## Candidate v1 primitives and exact common encoding

The primitive profile is a **qualification candidate**, not an audit
claim. The first qualification ticket must validate the complete composition,
selected version/features, native/WASM vectors, randomness and browser resource
behavior before a dependent product implementation starts. A failing profile
returns here for an explicit revised contract; no silent weakening/fallback.

- SHA-256 for identifiers/commitments; HKDF-SHA256 for high-entropy root-purpose
  derivation only. Passphrase KDF is Argon2id type 2, version 19, total memory
  65536 KiB, t=3, p=4, salt=16 bytes, output=32 bytes; no secret/associated-data
  Argon inputs. Four lanes are algorithm parameters, not four browser threads.
- Symmetric root wrapping and vault contents: XChaCha20-Poly1305-IETF, key32,
  fresh CSPRNG nonce24, full tag16 appended to ciphertext. Never reuse a nonce
  with a key; retries reuse an immutable already-encrypted record or generate a
  fresh nonce. Rotate before 2^32 published encryptions per vault epoch. This is
  an application usage limit, not proof of the number of unpublished operations
  or a guarantee that a malicious key holder obeys a counter.
- Recipient grants: RFC 9180 HPKE Base mode 0x00, KEM 0x0020
  DHKEM(X25519, HKDF-SHA256), KDF 0x0001, AEAD 0x0003 ChaCha20Poly1305.
  Use a new single-shot HPKE context per grant. HPKE manages its own nonce;
  its AEAD is not XChaCha. enc32 and ciphertext48 encrypt a vault key32.
- Signatures: pure Ed25519, seed32/public32/signature64, strict individual
  verification, no Ed25519ph or batch-equivalence assumption. Disable legacy
  compatibility. Enrollment requires canonical public-point encoding and
  rejection of small-order keys; exact chosen-library checks are qualification
  outputs. HPKE uses checked DH with all-zero shared-result rejection on both
  encapsulation and decapsulation; follow RFC 7748 coordinate decoding.
- Every new random root, recovery value, vault key, salt, nonce and opaque ID
  uses native OS/browser cryptographic entropy. No timestamps/counters/fallback
  PRNG. Exhaustion or missing entropy is a safe failure.

`u16/u32/u64` are unsigned big-endian; no signed/float/varint encodings. An ID
is exactly 16 opaque random bytes; a key/digest ID is 32 bytes. Text is exact
UTF-8 with no trim, case-fold, Unicode normalization or terminal newline added.
That includes passphrase bytes. Base64 transport is RFC 4648 URL-safe without
padding; accept exactly its canonical encoding. A new text token uses prefix
`bitbid-team1:`; existing token decoders do not acquire implicit new behavior.

Define one unambiguous transcript function:

```
T(label, fields) = ASCII("bitbid-team-v1/")
  || u16(len(label)) || ASCII(label)
  || u16(number_of_fields)
  || concat(u32(len(field)) || field for each field in order)
```

Labels are the exact lowercase ASCII constants shown here. An ordered list is
`u32(count) || concat(u32(len(entry)) || entry)`. Reject duplicate map identities,
unsorted maps, trailing bytes, wrong field counts/lengths, unknown version/
suite/kind/critical fields and integer overflow before allocation/crypto. Maps
sort lexicographically by raw binary IDs. Empty optional bytes are distinct
from an omitted field; no alternate JSON representation is signed.

An outer wire record is `T("wire", [u16(1), u16(1), kind, payload])`, where kind
is an exact ASCII label below and suite1 means this whole primitive profile.
Sign as `Ed25519(T("signed-record", [kind, signer_key_id, payload]))`; signed
payload encoding is `T("signed-envelope", [signer_key_id, payload, sig64])`.
The outer kind determines whether the payload is signed or an AEAD wrapper;
signature verification always reconstructs the identical outer kind. Hashes
reference the complete canonical wire bytes. No unsigned metadata can override
an authenticated field.

The explicit exception is `authority_plan_hash = SHA256(plan)` over the exact
nested `authority-plan` T bytes. Identity key IDs, fingerprints, key commitments,
recovery checksums and grant-set hashes use their separately specified formulas.
Every field named `*_wire_hash`, snapshot hash or grant hash hashes the complete
canonical wire record. No caller chooses an alternate digest representation.

The finite outer kind registry is: signed `identity`, `grant`, `content`,
`authority`, `snapshot`, `acceptance`, `team-anchor`, `export`; unsigned-but-AEAD
`pass-wrapper`, `recovery-wrapper`, `trust-wrapper`. Other T labels are nested
records only, never new wire kinds. For identity the signer is its key_id;
for grant it equals G.grantor_key_id; for authority it equals plan.actor_key_id;
for acceptance it equals its recipient_key_id. A snapshot/content/export/anchor
signer's eligibility is checked by the corresponding scope rules. No field
becomes an authority claim solely because it matches a signature's key ID.

Core parsers cap ordinary wire records at16 MiB; the outer `export` container is
the sole exception, capped at256 MiB including its signature/framing, with each
contained record still capped at16 MiB. Nested exports are forbidden. Text names/labels cap at4096 UTF-8 bytes,
individual secret values at 1 MiB, public proof chains at 4096 records, and
lists at 10000 entries; also check total byte budgets before loops/allocation.
Server rate/rotation quotas can be stricter. Reaching a proof-chain bound needs
an explicitly reviewed authenticated checkpoint, not an unverified truncation.

## Account root, key identity and wrapping

Generate independent random account root U32 and recovery value R32 locally.
Derive independent X25519 secret input and Ed25519 seed using HKDF-SHA256,
salt=empty, IKM=U, info respectively `T("recipient-seed", [account_id, generation])`
and `T("signing-seed", [account_id, generation])`, output32. Generation is u64,
starting at1, and never reused for a replacement identity. Let the vetted
libraries perform the primitive's normal scalar/key expansion.

Identity bytes are `T("identity", [account_id, generation, x25519_public32,
ed25519_public32])`. key_id = SHA256(identity); self-sign using kind `identity`.
Fingerprint is full lowercase hexadecimal SHA256(`T("fingerprint", [identity])`),
with account ID and generation displayed separately. A self-signature proves
possession only. Compare the whole fingerprint through a trusted channel;
QR transfer is acceptable only if the channel/person is authenticated.

Pass wrapper header P is `T("pass-header", [account_id, generation, key_id,
u32(19), u32(65536), u32(3), u32(4), salt16, nonce24])`. Kp is the explicit
Argon2id profile above. Payload is `T("pass-wrapper", [P, AEAD(Kp, nonce, U, P)])`.
Reject other parameter tuples before the KDF; maximum passphrase input is
1024 UTF-8 bytes. No automatic truncation or alternate legacy derivation.

Recovery wrapping key Kr = HKDF-SHA256(IKM=R, salt=empty,
info=`T("recovery-wrap", [account_id, generation, key_id])`, output32).
Header Q is `T("recovery-header", [account_id, generation, key_id, nonce24])`;
payload is `T("recovery-wrapper", [Q, AEAD(Kr, nonce, U, Q)])`.
After either unlock, derive public keys and require exact identity/key_id match.

The recovery kit has two saved parts: a secret recovery code containing R and
an encrypted account backup containing Q/ciphertext and public identity. The
server may also retain that encrypted wrapper; it never receives R or U.
Code bytes are `T("recovery-code", [account_id, generation, R])`, followed by
the first16 SHA256 bytes of `T("recovery-checksum", [code_bytes])`, transported
with prefix `bitbid-recovery1:` and canonical base64url. The checksum catches
transcription errors and is not authentication. Keep the code secret; possession
of the code and encrypted wrapper restores the root. The save/test ceremony
proves a successful local roundtrip, not durable storage or perfect erasure.

Changing an uncompromised passphrase rewraps U with a fresh salt/nonce; rotate
the recovery wrapper independently. Old copied wrappers still work with their
old secrets. Suspected root/recovery compromise requires a new identity and
rotation of every vault it could access; rewrapping the same root is insufficient.
Teammate regrant only restores explicitly authorized current vault epochs to a
fresh, reverified identity. No automatic historical grants or lost-root recovery.

Encrypted trust-state key Kt = HKDF-SHA256(IKM=U, salt=empty,
info=`T("trust-wrap", [account_id, generation])`, output32). Header H is
`T("trust-header", [account_id, generation, sequence, previous_trust_wire_hash,
nonce24])`. First sequence is u64(1), previous hash zero32. Plaintext is
`T("trust-state", [team_pin_list, peer_pin_list])`; `team-pin` fields are
team_id/genesis_wire_hash, and `peer-pin` fields are account_id/key_id/full
fingerprint_digest32. Sort respectively by team ID and (account ID,key ID).
Payload is `T("trust-wrapper", [H, AEAD(Kt, nonce, plaintext, H)])`. Only the
unlocked client changes pins after verification; live-state sequence checks do
not turn encrypted server persistence into an independent freshness witness.

## Vault content and recipient grants

Each vault epoch has fresh random V32. Directly encrypt each current object
under V; v1 introduces no per-item DEK rewrap shortcut. Key commitment is
SHA256(`T("vault-key-commitment", [team_id, vault_id, epoch, V])`). It binds
decrypted grants to the selected epoch; V has full random entropy.

Content header C is `T("content-header", [team_id, vault_id, item_id, epoch,
revision, object_kind, authority_plan_hash, nonce24])`. epoch/revision are u64;
object_kind is u8: 1=vault label, 2=secret, 3=deletion tombstone. The label
uses zero16 item_id reserved for that purpose; ordinary item IDs are nonzero.
Plaintexts are respectively `T("vault-label", [label_utf8])`,
`T("secret", [name_utf8, value_utf8])`, or `T("deleted", [])`.
Payload is `T("content", [C, AEAD(V, nonce, plaintext, C)])`, signed with kind
`content`. Bind every field as AAD; labels and names never become host indexes.
Writers sign tombstones too. The verified current snapshot selects which
revision exists; possession of an old valid object cannot undelete it.

Grant header G is `T("grant-header", [team_id, vault_id, epoch,
recipient_account_id, recipient_key_id, grantor_key_id, authority_plan_hash,
key_commitment])`. HPKE info=`T("hpke-info", [G])`, aad=G, plaintext=V.
Payload is `T("grant", [G, enc32, ciphertext48])`, signed with kind `grant`.
Verify the identity, signature, plan/authority and scope before decapsulation;
verify the decrypted key commitment before use. Reject a correct signature by
an unauthorized actor. Sharing is Owner/Admin-only in v1; Member read/write
permission permits content mutation, not delegation or membership changes.

## Authenticated authority and current-state selection

The pure verifier owns canonical signed authority records and transition
validation, not a browser/server-supplied `is_admin` boolean. The server also
independently enforces its session/MFA, tenant and read/write ACL rules. Signed
authority does not replace authentication, CSRF protection or database checks.

Team genesis is signed by its creator and binds team ID plus creator identity.
The creator trusts that identity locally; a joiner verifies a trusted existing
Owner/Admin and the team's genesis/authority chain through the accepted
verification ceremony. Trusted peer/genesis pins may persist only in the
account's encrypted state; no plaintext local trusted-state cache is added.

Bootstrap uses signed kind `team-anchor`, payload `T("team-anchor", [team_id,
genesis_authority_wire_hash, accepted_authority_wire_hash, recipient_key_id])`.
The independently fingerprint-verified peer must be an active Owner/Admin in
the named accepted_authority_wire_hash state, not merely an old ancestor of
the proof chain. The ceremony confirms the intended team ID/genesis hash with that
person. A host-only/self-signed team assertion is insufficient. Pin the verified
genesis after this step; do not silently substitute it during key replacement.

Authority plans contain team ID, u64 sequence, previous state hash, action,
actor key ID, complete sorted roster (account ID, current key ID, role, status)
and sorted vault policies (vault ID, epoch, phase, key commitment, sorted
account/permission entries). Roles are owner=1/admin=2/member=3; status is
pending=1/active=2/removed=3; vault phase active=1/rotation-required=2/staging=3;
permission is read=1/read-write=2. Required fields use T-labelled, ordered
records with these exact field orders. List entries use the common list rule.

`plan = T("authority-plan", [team_id, sequence, previous_state_hash, action,
actor_key_id, roster_list, vault_policy_list])`. Roster entry label is `member`;
vault policy entry label `vault-policy`; permission entry label `permission`.
Actions are ASCII `genesis`, `invite`, `activate`, `promote`, `demote`,
`replace-key`, `remove`, `new-vault`, `vault-permission`, `rotate`, `transfer`,
`delete-team`. Full state is signed kind `authority` with payload
`T("authority", [plan, sorted_grant_refs, sorted_snapshot_refs])`.
Grant refs contain recipient account/key IDs, vault ID, epoch and grant hash;
snapshot refs contain vault ID, epoch and snapshot hash. Each ref is a T record
named `grant-ref` or `snapshot-ref`. Missing/extra/duplicate refs fail closed.
Hash the plan before making grants/content and the final authority afterward;
this avoids a circular hash dependency. A state proposal is not active authority.

All account/team/vault/item IDs above are16 bytes, all key/commitment/plan/
wire hashes32 bytes, all sequence/epoch/revision/generation values u64, and
role/status/phase/permission values u8. `member` fields are account_id,key_id,
role,status; `vault-policy` fields vault_id,epoch,phase,key_commitment,
permission_list; `permission` fields account_id,permission. Roster/permission
entries sort by account ID, vault policies/snapshot refs by vault ID, grant
refs by (vault ID,epoch,recipient account ID,recipient key ID), and content refs
by (item ID,object kind). Canonical encodings of every tuple element are used
for comparison. Genesis sequence/epoch/revision start at1; initial previous
hashes are zero32. Team genesis has one active creator Owner and empty vault,
grant, snapshot and acceptance lists. Reject zero IDs except the label sentinel.

Recipient acceptance is a separately signed kind `acceptance` with payload
`T("acceptance", [team_id, recipient_account_id, recipient_key_id,
proposal_plan_hash, recipient_grant_set_hash])`, where the last field is
SHA256(`T("recipient-grants", [sorted_grant_ref_list_for_this_recipient])`).
Before activation, only the intended plan/anchor and grant-ref hashes need be
delivered for acceptance; real grant ciphertext stays with the grantor until
the activation payload. Acceptance acknowledges the verified role plan/grant set and
proves signing-key possession; it does not prove that keys were decrypted or
that a recovery file was durably saved. Final `authority` payload has a fourth
field, sorted_acceptance_refs, whose `acceptance-ref` entry fields are recipient
account ID,key ID,acceptance wire hash, sorted by (account ID,key ID).
`proposal_plan_hash` is the same final plan hash; proofs and grant hashes are
outside the plan, so no circular commitment arises.

Only current Owner may change ownership/privileged roles or delete a team.
Owner/Admin may invite/remove ordinary Members, assign ordinary vault access,
create vaults and rotate; Admin cannot change another privileged membership.
At least one active Owner survives every non-deletion transition. Any removed
or replaced identity is excluded from new epochs. A reader cannot sign a valid
mutation merely by making a self-declared writer roster.

Enrollment/promotion/replacement stays pending while verification, required
grants, explicit recipient acceptance or privileged MFA is missing. Active
Owners/Admins require grants for all active vaults; Members require only their
assigned vaults. A new vault deposits signed grants to every verified active
Owner/Admin even when they are offline. A pending invite is not one of those
active principals. Concurrent vault creation/promotion retries against a fresh
complete state; partial all-vault delivery cannot activate the role.

Determine the actor's authority from the previous finalized accepted state,
never from a proposed roster that promotes the actor. Genesis is precisely
the signed `authority` record with action `genesis` and the initial conditions
above, not a separate unsigned record. A new vault's first snapshot sequence
is1 with zero32 previous hash; subsequent snapshots increment exactly1.

A current vault snapshot is signed kind `snapshot`, payload
`T("snapshot", [team_id, vault_id, epoch, u64(sequence), previous_snapshot_hash,
authority_plan_hash, sorted_content_refs])`. Each `content-ref` contains
item_id, object_kind, revision and content wire hash, in that order. Include
the current label and tombstones. Verify content authors against the authority
under which they signed and ensure the chosen current snapshot is authorized
by its referenced plan; do not trust an API's unproved author/permission list.

Authority snapshot refs are **activation anchors**, not pointers that an
ordinary content edit must mutate. While the current authority is fixed, an
authorized Member writer can append a signed snapshot without changing team
authority: the new snapshot names that current plan, extends the accepted
current snapshot hash/sequence, keeps the same epoch, and changes only content
the writer may mutate. Label/vault-policy changes remain Owner/Admin actions.
The server atomically compares both the current authority hash and content-head
hash when advancing this separate content pointer. Every authority transition
also captures/CAS-checks the latest affected content heads; this seals the
permitted endpoint of the prior authority's snapshot chain.

Retained content/grants keep their original authenticated plan and signature.
They are allowed only as identical references already selected by a verified
ancestor state/head, with the same vault epoch/key commitment and a recipient
still eligible under the current state. Newly introduced refs must bind the
new/current plan and satisfy its writer/grant rules. A removed/old writer cannot
append after the sealed prior head by citing an old plan. A current snapshot
may retain unchanged historical content refs, but each added/replaced ref must
be signed by a writer authorized under its current plan and must extend the
previous item's revision (new item revision1). The current snapshot author is
also authorized; they cannot introduce a different historical ref as a silent
rollback. Explicit restore is a new authorized revision.

When marking rotation-required, retain the sealed old-epoch snapshot/grants as
read-only anchors for remaining users; these refs intentionally name the prior
active plan. Current authorization denies removed recipients even though their
historical grant bytes remain verifiable. Activation of a new epoch requires
new-plan grants and a complete freshly encrypted snapshot; no old-epoch ref is
eligible as new-epoch current content. An unrelated roster change can retain
unchanged-vault anchors; missing/extra checks apply to these explicitly defined
required sets, not a rule that rewrites old AAD to the newest plan.

Honest-server transactions compare previous authority/snapshot hashes and
sequences before publishing immutable records plus a current pointer. A stale
client must reload/verify and explicitly rebase its intended change; no blind
last-write-wins or silent encryption under a stale epoch. Bind idempotency to
the same immutable payload hash; reconcile an uncertain commit before retry.

## Removal, rotation and lifecycle failure cases

Removal first commits an authorized signed state that immediately denies the
principal and marks every affected vault rotation-required. New secret/vault
mutations and grants from stale epochs are denied; remaining reads use the last
active snapshot. Key replacement/demotion also triggers rotation wherever
decryption access is actually lost. Removing a writer's write permission while
retaining read access changes verified authority without promising key erasure.

An authorized client stages fresh V and grants excluding removed recipients,
re-encrypts all current labels/secrets/tombstones with fresh nonces, and signs
the complete replacement snapshot. Activation is one checked transaction over
the same authority and old-snapshot heads, complete key commitments/grants and
all content refs. Partial staging is invisible as current data and never
unfreezes writes. Crash/conflict resumes or discards owned staging; immutable
objects are garbage-collected only after references/backup policy permit it.
No partial key/record activation or stale membership can race into a new epoch.

For invitations/promotions, obtain the signed pre-key acceptance above and
generate the finalized authority/grants locally. Send current-epoch grant
bytes only together with the signed activation payload; do not pre-upload real
keys for an unsigned/cancellable proposal. Once that payload leaves the client,
a malicious service may disclose its grants even if a database response fails.
Treat that as possible cryptographic disclosure: reconcile uncertain commits,
and rotate affected current epochs if activation is abandoned/revoked. A server
pending flag cannot revoke an already disclosed key. Grantor client checks
generated keys against commitments; a server cannot prove recipient decryption
or compel an authorized grantor to provide a working key.

Zero remaining decrypt-capable clients/recovery material means rotation cannot
finish and secrets may be irrecoverable. Server operators cannot bypass this
by marking a job successful. Old snapshots/exports remain readable to holders
of their old keys; no retroactive secrecy or secure deletion promise.

## Client lock, exports and threat limits

Use a dedicated client worker for secret ownership/KDF where available; isolate
UI projections and keep keys/plaintext out of SSR, API requests, logs, analytics,
URLs, service workers and durable browser stores. Track independent idle and
hidden deadlines. Check deadlines before every secret action and immediately
on resume/visibility change; background suspension prevents a promise that
memory is erased at a wall-clock instant. Logout/reload invalidates secret
state; use generation tokens so old async replies cannot repopulate it. Clear
controlled DOM/state and terminate owned work on lock. Memory wiping remains
best-effort, not erasure of every JS/WASM/compiler/OS/clipboard copy.

An explicit encrypted export includes canonical identity/wrappers, encrypted
account trust state, signed authority/proof records, selected epoch grants and
encrypted snapshots/content; no plaintext value/root/passphrase/recovery code.
The separately saved recovery code is secret material, never an API payload.
Before restoring, verify the full format/proofs/keys and show the selected
historical snapshot. Account recovery restores keys; server import separately
checks current identity, membership, epoch and permissions, writes fresh current
records and cannot restore old roles. v1 has current-state management, no
automatic history grants or background offline synchronization.

Import re-encrypts locally under the freshly verified current epoch and uses
the same current-authority/content-head compare-and-publish transaction as
an ordinary mutation. Concurrent removal, key replacement or rotation rejects
the stale import and requires explicit reload/rebase; no privileged restore
endpoint bypasses this check. Recovery-only backup restores the account root/
trust state, not an assertion that all team grants or secret data were saved.

Export wire kind is `export`, signed by the exporting account key, with payload
`T("export", [account_id, generation, export_id16, selected_vault_list,
record_list])`. `selected-vault` fields are team_id,vault_id,epoch,snapshot_hash,
sorted by (team ID,vault ID); each `export-record` has wire_hash32,wire_bytes,
sorted by hash. Require a closed, duplicate-free set of all identity/wrapper/
trust/proof/grant/snapshot/content references needed for that selected export;
reject absent or unreferenced extra records. The exporter signature is verified
after the identity/root binding; import never treats it as team authority.
All contained secret-bearing records remain encrypted under the root/epoch
wrappers above; the export manifest contains only allowed public metadata.
Recovery-only export has an empty selected-vault list and includes its exact
identity, pass/recovery wrappers and current encrypted trust wrapper. Require
the pass/recovery wrappers and trust wrapper to bind the same account/generation/
identity; missing required typed records fail. Cap total export at256 MiB and
10000 records, streaming/bounding before allocation; offer explicit smaller
selections rather than silently truncating. The recovery code/R is never an
export record. Offline reading of an old saved export is distinct from server
import and remains possible for its old key holders.

AEAD/signatures establish integrity relative to verified keys/authority, not
global freshness. Live clients retain accepted head hashes/sequences in memory
and reject rollback/conflicting successors they observe. Encrypted server-side
trust pins protect substitution but can themselves be replayed. A fresh client
may receive a valid old/forked state; no latest-state or global-fork guarantee
exists without an independent trusted checkpoint/witness. A compromised API
can withhold/delete data. Malicious client delivery/XSS or an unlocked endpoint
can steal plaintext/keys; authorized users can copy them. The host cannot
decrypt stored ciphertext solely from its database under this construction's
assumptions, but no broader endpoint/delivery/availability claim is made.

## Delivery gates and acceptance

Actual normal tickets and native dependencies are indexed in
[decision-implementation-coverage.md](decision-implementation-coverage.md):
[qualification](https://github.com/igmrrf/bitbid/issues/49) →
[portable core](https://github.com/igmrrf/bitbid/issues/50) →
[persistence](https://github.com/igmrrf/bitbid/issues/51) →
[unlock/recovery/lock](https://github.com/igmrrf/bitbid/issues/52) →
[membership/grants](https://github.com/igmrrf/bitbid/issues/53) →
[rotation](https://github.com/igmrrf/bitbid/issues/54) →
[CRUD](https://github.com/igmrrf/bitbid/issues/55) →
[export/restore](https://github.com/igmrrf/bitbid/issues/56).
Persistence also requires the independently ready hosted foundation. These
are future implementation/verification gates; the decision establishes their
contract and tracking rather than claiming their execution.

- `KEY-AC1`: accepted Q1–Q6 and threat/legacy boundaries remain explicit.
- `KEY-AC2`: independent composition review resolves medium+ design findings;
  exact primitive/library validation and canonical framing are frozen with
  positive/negative native/WASM public vectors before dependent implementation.
- `KEY-AC3`: signed authority/bootstrap/grants and pending/role/rotation/recovery
  transitions have executable tamper, wrong-key/context, stale/concurrent,
  partial-delivery, cached-key and restore negatives. AEAD alone is never writer
  authority; server tenancy/MFA checks remain independently exercised.
- `KEY-AC4`: actual browser KDF memory/failure/responsiveness, lock/reload/stale
  response behavior and no-secret server/SSR/storage/network paths are qualified.
  Unsupported devices/measurements remain blockers, not pass or silent downgrade.
- `KEY-AC5`: normal implementation tickets cover portable primitives/vectors,
  authority/membership/grants, client unlock/verification/recovery/lock, backend
  encrypted snapshots/rotation, usable CRUD/search and encrypted export/restore;
  real native dependencies keep unqualified work blocked. Existing dashboard
  foundation and native extractions remain independent.
- `KEY-AC6`: final human shared-understanding confirmation precedes resolution/
  close/map index. Commit verified decision artifacts separately; runtime gates
  above are future implementation evidence, not tests claimed by this document.

No new deployable setting is introduced by this decision document. Implementers
record each newly required setting in encrypted `secrets/prod.enc.yaml`, execute
the actual completeness/unset gates and preserve existing values. No push,
publication, deployment, live-provider write or current data migration is implied.
