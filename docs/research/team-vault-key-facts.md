# Team-vault key, sharing and recovery decision facts

Researched 2026-11-09 against primary specifications, maintainer documentation
and source. Supports [Specify client-encrypted team-vault keys, sharing and
recovery](https://github.com/igmrrf/bitbid/issues/38). This is research for a
human decision, not an approved protocol, independent cryptographic audit,
implementation, browser benchmark or deployment authorization.

The [team-web execution contract](../split-core/team-web-execution.md) supplies
the accepted product boundary: client custody, separate account login/unlock,
Owner/Admin access to all team vaults, scoped Members, encrypted names/values/
vault labels, user-held recovery and no operator recovery master key. Its
client-code-delivery/XSS limitation still applies. Existing token/wallet bytes
and HKDF domains remain unchanged. The inspected native/web checkpoints were
`9546614692e37d501a3e90ee5f75ed8ecd852471` /
`3c87d2c10c2097a1e4a0471457ada9733f8f6b93`.

**Decision status at research handoff:** account-wide versus per-team unlock/
recovery, mandatory trusted-channel fingerprint verification versus trust on
first use, and whether removal freezes writes until rotation are pending human
questions. No choice below resolves them implicitly. Other recommendations
are proposals requiring an explicit contract and review before implementation.

## Hierarchy: separate unlock protection from vault access

**Prior-art fact.** Bitwarden generates user encryption material separately
from password derivation, encrypts private asymmetric keys under a user key,
and distributes an organization key encrypted for each member. Its current
whitepaper also describes random per-item Cipher Keys wrapped by a user or
organization key. This demonstrates envelope-encryption and client grant
patterns, not equivalence to Bitbid's required vault-scoped isolation. Source:
[Bitwarden whitepaper, Sharing and Data protection](https://bitwarden.com/help/bitwarden-security-white-paper/).

**Proposed comparison.** An account-wide random user keyring, protected by
independent passphrase and recovery envelopes, gives one unlock across teams.
Independent random vault keys can then be granted only to eligible users.
Per-team user keyrings instead increase unlock/recovery work and reduce the
cross-team effect of a compromised account unlock secret. Either can satisfy
client custody; the account/recovery experience is the pending product choice.
A shared team root given to every Member would defeat vault-scoped
cryptographic isolation. Owners/Admins can receive individual grants for every
vault without distributing such a root to Members.

**Recommendation, conditional on hierarchy choice.** Use independently random
vault keys/epochs; keep passphrase-derived wrapping keys, recovery wrapping
keys, recipient private keys and writer signing keys as separate purposes.
Changing an uncompromised passphrase can rewrap a stable random user root
without re-encrypting all secrets. Root compromise requires a wider key and
grant transition, not merely a new password. HKDF supports purpose/context
separation through `info`; it is not a password-hardening function. Source:
[RFC 5869 §§3.2, 4](https://www.rfc-editor.org/rfc/rfc5869.html#section-3.2).

## Argon2id: candidate profile and actual browser limits

**Facts.** RFC 9106's first recommended Argon2id profile uses 2 GiB, one pass
and four lanes; its memory-constrained second profile uses 64 MiB, three
passes and four lanes. Both use a 128-bit salt and 256-bit output. It also
instructs applications to choose affordable memory/time and offers test
vectors. These are CFRG recommendations, not measurements of this app.
Source: [RFC 9106 §§4, 5, 7.4](https://datatracker.ietf.org/doc/html/rfc9106#section-4).

RustCrypto `argon2` 0.5.3 is pure Rust, supports Argon2id and `no_std`, and
provides raw key-derivation APIs. Library defaults must not be mistaken for an
approved Bitbid wire profile. Source:
[argon2 0.5.3 maintainer documentation](https://docs.rs/argon2/0.5.3/argon2/).
The older [dependency matrix](deps-wasm-matrix.md) supplies earlier compile
evidence only; it is not a new mobile-browser memory/latency result.

**Browser facts and limits.** WebAssembly memory growth can fail because of
embedder resources; an address-space limit is not a guaranteed allocation.
Bitwarden separately documents memory warnings above 64 MiB in iOS autofill/
Share-sheet contexts. That is product/context-specific evidence, not a
universal Safari-tab ceiling. Sources:
[WebAssembly memory growth semantics](https://webassembly.github.io/spec/core/exec/instructions.html#exec-memory-grow),
[Bitwarden KDF guidance](https://bitwarden.com/help/kdf-algorithms/).

**Proposal.** Evaluate the RFC's 64 MiB / three-pass / four-lane profile for
new account envelopes, with explicit algorithm/version/parameters/salt/output
length and password-byte encoding. Do not silently reduce work factors on
unlock failure. Bound parsed parameters before allocating or running a KDF;
untrusted envelope parameters are also a resource-exhaustion input. Preserve
legacy derivation parameters under their original formats.

**Required evidence before pinning.** Measure the production WASM build on
the supported desktop and low-memory mobile browsers, including concurrent
tabs, allocation failure, lock/cancel/reload and UI responsiveness. Define
finite accepted memory/time/parameter bounds and an explicit supported-device
policy. A dedicated worker is a proposed responsiveness/cancellation boundary,
not proof that every browser/runtime memory copy is erased. No profile is
claimed to have passed those checks here.

## Recipient grants: HPKE and sealed boxes solve different parts

**Specification facts.** HPKE defines Base and authenticated modes, including
DHKEM(X25519, HKDF-SHA256). Base does not authenticate a sender. DHKEM Auth
assurance fails under recipient-key-compromise impersonation. Application
identity-to-key binding is outside the primitive. `info`/AAD provide context
binding, not trust in directory entries. HPKE supplies no general replay
protection beyond ordering within one context. Static recipient-key compromise
also exposes recorded grants encrypted to that key; ephemeral encapsulation
does not give those stored grants forward secrecy. Source:
[RFC 9180 §§5.1, 8.1, 9.1, 9.7](https://www.rfc-editor.org/rfc/rfc9180.html).

**Sealed-box facts.** Libsodium sealed boxes intentionally hide the sender.
Recipients verify ciphertext integrity but cannot identify who created it.
The construction uses an ephemeral X25519 key and XSalsa20-Poly1305. Ordinary
`crypto_box` uses the sender's private key but both parties know its shared
authentication secret; it is not a publicly verifiable signature. Sources:
[libsodium sealed boxes](https://doc.libsodium.org/public-key_cryptography/sealed_boxes),
[libsodium authenticated public-key encryption](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption).

| Candidate path | Useful property | Remaining obligation |
| --- | --- | --- |
| Maintained HPKE implementation, Auth mode | Standardized recipient encryption with sender-key authentication to the recipient | Verified keys, grant authority, context, replay/freshness; not a transferable writer signature |
| HPKE Base plus a separately signed grant | Standardized encryption and independently verifiable grant-author evidence | Review the composition and canonical signed bytes; authenticate recipient and signer keys and authority |
| Libsodium sealed box plus a separately signed grant | Established high-level anonymous encryption primitive with separate author proof | Same binding/authorization work; sealed-box encryption alone is insufficient |
| Raw X25519 plus handwritten KDF/AEAD framing | Flexible building blocks | Adds avoidable protocol-composition work; not recommended for this decision |

**Recommendation.** Prefer an established HPKE implementation over designing
new ECDH framing, subject to the implementation-review caveat below. If
independent writer signatures are selected, investigate reusing that verified
identity-signing facility for grant authorization with HPKE Base. If only
recipient-local sender authentication is required, Auth is another candidate.
Neither choice alone establishes that a signer is an authorized team grantor.
The selected composition, exact signed bytes, scope/version/epoch binding and
negative vectors must be frozen and reviewed separately; this note does not
specify them.

## Native/WASM implementation candidates and vetting limits

**Rust candidate.** `hpke` 0.13.0 documents pure-Rust single-shot encryption,
an explicit caller RNG and `info`/AAD inputs, and its upstream README describes
RFC known-answer tests. It explicitly warns that it has not been formally
audited; the mentioned Cloudflare review concerns version 0.8. This cannot be
represented as an audited current protocol implementation. Sources:
[hpke 0.13.0](https://docs.rs/hpke/0.13.0/hpke/),
[single-shot API](https://docs.rs/hpke/0.13.0/hpke/fn.single_shot_seal.html),
[versioned maintainer README](https://github.com/rozbb/rust-hpke/blob/v0.13.0/README.md).
This is an inspected candidate version, not a claim it is the newest or the
version to adopt. Pin/review the chosen release and dependency graph; prove
native/WASM entropy and interoperability rather than infer them from pure Rust.

**Libsodium alternative.** Upstream provides a C library and its own
WebAssembly/JavaScript wrapper project. However, libsodium's changelog records
removal of `crypto_pwhash_*` from Emscripten Sumo builds because of reserved
JavaScript memory. Do not assume `libsodium-wrappers-sumo` supplies Argon2id;
inspect the pinned distributed symbols/build or use a separately reviewed KDF
path. Native and browser artifact versions still need interop proof. Sources:
[upstream libsodium.js](https://github.com/jedisct1/libsodium.js),
[libsodium changelog, 1.0.18-stable](https://github.com/jedisct1/libsodium/blob/master/ChangeLog).

**Payload/wrapping candidate.** XChaCha20-Poly1305 has a 192-bit nonce suitable
for random generation, supports AAD and is available in libsodium and
RustCrypto. The Rust crate documents an earlier NCC Group audit and the
construction's lack of a final authoritative specification; that is not an
audit of Bitbid or every later dependency version. It is a reasonable candidate
for independently written multi-client ciphertexts, not an HPKE suite defined
by RFC 9180. AES-GCM remains another candidate but needs an explicit nonce/
usage-limit plan. Sources:
[libsodium XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction),
[RustCrypto chacha20poly1305 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/),
[AEAD nonce requirements, RFC 5116 §3.1](https://datatracker.ietf.org/doc/html/rfc5116#section-3.1).

**Recommendation.** Choose the security construction first, then a bounded
compatibility/review spike for exact native/WASM crates or C/JS bindings.
Using standard primitives reduces invention; it does not certify their
composition, packaging, random source or user interface.

## Identity/key verification and recovery

**Prior-art fact.** Bitwarden asks users to compare fingerprint phrases through
a secondary communication channel when onboarding or approving device login.
Source: [Bitwarden fingerprint verification](https://bitwarden.com/help/fingerprint-phrase/).

**Implications for the pending verification decision.** An OIDC identity and a
server-returned public key do not independently prove that key belongs to the
person. Proof of private-key possession or a self-signature can accompany a
substituted key too. Trusted-channel comparison must bind the intended
account/key version and the encryption/signing key bundle. TOFU leaves first
contact vulnerable and needs a durable trusted comparison point to detect
later changes. Displaying two fingerprints supplied by the same untrusted
service is insufficient. Key replacement/recovery must be treated as a trust
transition, with pending grants and deliberate re-verification under the
selected policy.

**Recovery recommendation.** Use a high-entropy client-generated recovery
secret to protect an independent recovery envelope for the selected user
root/keyring scope. A proposed 256-bit random value with transcription-error
detection is a candidate, not a frozen format. HKDF with a separate purpose
can derive a wrapping key from random recovery material; a human-chosen
recovery passphrase instead needs password hardening. Never send the recovery
secret to the host. Verify a restore before considering enrollment complete;
account recovery and team regrant remain distinct operations. Basis:
[HKDF applicability and context separation](https://www.rfc-editor.org/rfc/rfc5869.html),
[libsodium password-based key derivation](https://doc.libsodium.org/password_hashing/default_phf),
and the accepted [custody/recovery boundary](../split-core/team-web-execution.md).

**Important implication.** Deleting an old recovery wrapper does not invalidate
a copied old wrapper that still unlocks the same root. Replacing a compromised
recovery secret requires considering rotation of the secrets it exposed and
their accessible vault grants; routine uncompromised rewrapping and compromise
response are different transitions. A team admin may regrant team vaults to a
fresh verified user key; this need not restore the user's lost original root.

## Revocation, write integrity and freshness

**Symmetric-key fact and consequence.** With secret-key authenticated
encryption, the same secret permits encryption/authentication and decryption/
verification. Therefore a reader holding the shared data key can construct a
new valid ciphertext. A read-only API permission does not cryptographically
distinguish an authorized writer. Source:
[libsodium secretbox, Purpose](https://doc.libsodium.org/secret-key_cryptography/secretbox).

**Decision required.** Server-enforced read/write ACLs can suffice only within
an explicit trust model where the server enforces mutations. If clients must
reject reader-forged writes even with a malicious storage/API service, select
separate per-writer signatures and independently authenticated writer-role/key
state. Merely adding a signature and accepting a server-supplied writer list
does not establish that property. Signatures also need scope/version binding,
tombstones and strict verification behavior. Ed25519 is an implementation
candidate, with library-specific strict-verification choices to pin. Source:
[ed25519-dalek 2.2.0 strict verification](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict).

**Revocation implications, consistent with the accepted contract.** Server
denial is immediate; removal cannot retract copied plaintext, ciphertext or
keys. New vault epochs must exclude removed recipients. Rewrapping the same
item DEK under a new vault key cannot prevent an old reader using a cached old
DEK/wrapper to read future revisions encrypted under that DEK. Freshly
protected revisions need fresh content keys/ciphertexts, or direct encryption
under the fresh vault epoch. Rotation scope includes encrypted labels and all
affected objects, not just values. Eager re-encryption limits exposure of
current stored objects, while old snapshots remain readable to their old key
holders. These are key-knowledge deductions, not a claim of implemented
revocation or retroactive secrecy.

**Pending availability tradeoff.** Freezing affected-vault writes until an
authorized unlocked client completes rotation prevents ordinary new writes
under the revoked epoch, at an availability cost. Continuing writes during
that interval leaves their confidentiality dependent on the old key.
Whichever policy is selected must cover concurrent stale clients, retries,
partial migration, deletes, backups and restore; server ACL denial alone
cannot complete a cryptographic migration.

**Freshness limitation.** AEAD/signatures can authenticate old valid objects.
Epoch numbers, optimistic versions and hash chains cannot prove a first/fresh
client received the newest state when all checkpoints come from the same
malicious service. Memory-only state can reject known stale data while that
state survives, not establish cross-reload freshness or global fork agreement.
The contract must either disclose this malicious-store rollback/fork limit or
approve a separately trusted checkpoint/witness design and its availability/
metadata costs. Public trust checkpoints are a distinct policy question from
persisting decryption secrets; do not silently add localStorage/IndexedDB
state under the existing memory-only rule. Supporting primitive facts:
[HPKE replay limits, RFC 9180 §9.7.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3),
[secretbox replay/reordering limits](https://doc.libsodium.org/secret-key_cryptography/secretbox).
For the additional machinery involved, the primary
[C2SP witness specification](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md)
checks consistency against a prior checkpoint and signs accepted checkpoints.
It is prior art, not a ready Bitbid freshness protocol or a claim that a
signature alone proves recency.

## Gate outputs and evidence limits

Before ready implementation tickets, record the human choices above, exact
envelope domains/canonical encodings and algorithms, authenticated recipient
and writer trust rules, recovery replacement, rotation state transitions and
rollback/fork threat limits. Require cross-implementation positive vectors,
wrong key/version/context/signature and tampering negatives, bounded parsing/
KDF failures, key substitution, stale epochs, cached-DEK removal, rotation
races and account-versus-vault recovery tests. These are proposed verification
conditions, not completed checks.

No application dependency, environment setting, production secret, tracker or
runtime behavior was changed by this research. Primary-source retrieval
metadata/hashes and the research handoff are under this session's
`evidence/research-*` artifacts in the Wayfinder run; temporary evidence can
expire. Durable claims and source links are retained here. The project owner
still runs the required environment completeness/unset report at session
completion; this note introduces no new deployable setting.
