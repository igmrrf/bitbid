# Blockchain authority, finality and encrypted-record facts

**Adoption status, 2026-11-11:** Q1–Q8 were subsequently accepted in the [blockchain authority/synchronization contract](../split-core/blockchain-authority-sync.md). Its full required public-signature/state validation, separate backed-up EOA wallet, versioned no-upgrade-admin registry, per-vault publication, two-copy owner-controlled retention, finalized-current/historical-preview policy and trusted default-provider model supersede the pending-choice/proposal wording below. The original primary facts, alternatives and feasibility cautions remain research provenance; no endpoint, verifier, gas/capacity, provider, deployment or runtime feature is thereby qualified. Read the accepted contract and actual continuations for current authority.

Checked 2026-11-11 for [Define blockchain-authoritative teams and standalone client synchronization](https://github.com/igmrrf/bitbid/issues/57). This is primary-source research for a proposed execution contract, not an accepted product decision, endpoint/account qualification, live RPC probe, deployed registry or cryptographic audit. No provider mutation, transaction, deployment, purchase, secret read or runtime setting was performed or introduced.

The pending human choices include the registry's upgrade/migration policy, separate wallet backup versus designated wallet recovery, and the granularity of content publication heads. These sources do not decide those choices. Existing client-encrypted vault recovery is not automatically blockchain-wallet recovery.

## Polygon finality is milestone-based, not an invented confirmation count

Polygon's current documentation describes Heimdall v2 milestones as the mechanism for deterministic Polygon-chain finality. Validators agree on Bor block hashes; a milestone finalizes their agreed sequence. Ethereum checkpoints are a separate mechanism for withdrawal proofs and anchoring state. They are not the prerequisite for every ordinary Polygon-finalized application operation. The documented typical milestone latency is two to five seconds, not a guarantee for an account, endpoint, particular transaction or outage. The documented query is `eth_getBlockByNumber` with the `finalized` tag. [Polygon finality](https://docs.polygon.technology/pos/concepts/finality/finality)

**Design implication:** qualify an actual finalized block number and hash on each selected network/endpoint. Do not label `latest`, a fixed delay or an arbitrary number of descendants as equivalent to milestone finality. A mined receipt alone is insufficient. Verify receipt status, canonical inclusion and the selected finalized head before acknowledging an authority-changing operation as final. Halt current-authority actions when finality cannot be established. The chain's consensus and the correctness of the source reporting that chain remain explicit trust assumptions.

## Amoy, mainnet and provider capabilities must be checked separately

Polygon lists Amoy chain ID `80002` with Sepolia as its parent, and Polygon mainnet chain ID `137` with Ethereum as parent; both list POL as gas token. Its endpoint page directs applications to each provider's method documentation and warns that public RPCs may impose rate limits or traffic restrictions. An endpoint appearing in a public table is not an availability, throughput, archival-history or correctness guarantee. [Polygon RPC endpoints](https://docs.polygon.technology/pos/reference/rpc-endpoints)

**Qualification gate:** verify chain identity, selected registry address/deployed bytecode, finalized-tag behavior, stale/error responses, historical reads, log retention and actual request limits for the exact configured Amoy and mainnet providers. Qualify `safe` separately if used; this research did not establish Polygon-specific `safe` semantics or actual support on any selected endpoint. No public RPC was selected or tested here. Preserve existing endpoints until a deliberate configuration change is adopted; documentation freshness is not migration authorization.

## Logs support rebuilding a projection, with explicit history and reorg limits

Ethereum's execution interface specifies `eth_getLogs` filters by range or block hash, address and topics. Log records expose block hash/number, transaction hash/index, log index and a `removed` flag. The current interface also documents an unavailable-pruned-history error; it does not grant every provider unlimited historical access. [Ethereum execution API: eth_getLogs](https://ethereum.github.io/execution-apis/api/methods/eth_getLogs/)

**Proposed implementation rules:** start from the accepted registry deployment block; use bounded ranges/results/timeouts with adaptive chunk reduction, retry/backoff and explicit quota failure. Never treat a timed-out or truncated batch as a complete empty range. Commit a cursor only after validating and applying its complete batch. Persist chain/registry identity, height and block hash; use deterministic ordering and idempotent event identity, retaining block hashes to distinguish replaced branches. Recheck saved hashes, rewind to a verified common ancestor and replay after a pre-finality reorganization. A subscription's `removed` message is not a substitute for reconnect/backfill reconciliation. Deep inconsistency at an accepted finalized checkpoint must fail closed and be investigated. Concrete range/response/retry limits and archival access require provider qualification rather than invented universal values.

## Coherent reads need a named block and an honest RPC trust model

EIP-1898 defines block-hash parameters for calls including `eth_call`, `eth_getCode` and `eth_getProof`, with optional `requireCanonical`. This lets related reads target a coherent block despite reorganizations; it is a specification, not proof that the chosen Polygon provider implements every parameter. [EIP-1898](https://eips.ethereum.org/EIPS/eip-1898)

**Design implication:** bind security-relevant contract/wallet reads to the qualified accepted block identity where supported; reject unsupported or inconsistent behavior rather than silently falling back to unrelated `latest` reads. An ordinary JSON-RPC response is still a claim by its operator. Multiple endpoints can expose disagreement but do not constitute a cryptographic consensus proof. Any stronger verification promise requires a separately implemented and qualified authenticated-header/state-proof or local-node trust path. The D1 replica cannot upgrade an unverified response into authority.

## EIP-712 separates signing domains; the application still prevents replay

EIP-712 defines typed structured-data hashing and a domain containing fields such as protocol name/version, `chainId` and `verifyingContract`. It explicitly leaves replay handling and safe front-running behavior to the application. The chain and contract fields must actually participate in the verified domain; merely displaying them is insufficient. [EIP-712](https://eips.ethereum.org/EIPS/eip-712)

**Design implication:** specify an exact versioned domain and operation schema for each wallet proof or signed mutation. Bind the intended chain, registry, account/action and relevant keys/heads; enforce purpose, expiry and consumed nonce or expected-current-version constraints at the authority performing the action. Negative tests must cover another chain/registry, altered payload, stale version, expired proof, duplicate submission and a copied signature submitted first by another sender. The existing vault protocol's signatures are a distinct interface; adopting EIP-712 for wallet binding does not silently redefine its frozen bytes or signature semantics.

## Contract-wallet signatures are not recovered EOA signatures

ERC-1271 specifies `isValidSignature(hash, signature)` for contract accounts and requires success magic value `0x1626ba7e` without state modification. Validation can depend on time, contract state, authorized signers or a non-ECDSA scheme. Consequently an `ecrecover`-only path does not establish general contract-wallet support, and cached validity is not necessarily permanent. [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271)

**Design implication:** explicitly choose and test wallet scope. If contract wallets are supported, validate them on the intended chain at the relevant accepted state, bound execution resources and reject revert, malformed return and wrong magic values. Preserve distinctions between wallet authorization, the vault encryption/signing identity and optional web-login proof. Recovery/owner changes can change validity and must not inherit an old web-session assertion. Counterfactual/undeployed-wallet compatibility is not established by this research or by citing ERC-1271 alone.

## A CID identifies content; it does not prove permission or freshness

IPFS CIDs encode a content hash with format information. CID values are not generally a bare SHA-256 checksum of the reconstructed file: chunking and DAG structure matter. The same content needs the same import settings to produce the same CID. [IPFS content identifiers](https://docs.ipfs.tech/concepts/content-addressing/)

**Design implication:** freeze the allowed CID/codec/hash/import or verification profile and bounded record/DAG handling. Verify fetched bytes under that profile and separately verify the protocol's signatures, account/vault/epoch context and accepted chain head. A gateway returning bytes, a valid CID or a valid old signature does not by itself establish current permission or current content. If a separate canonical payload digest is anchored, define its exact bytes and algorithm instead of conflating it with the CID.

## Availability requires retained copies and an actual retrieval path

IPFS nodes can cache content and later garbage-collect it. Pinning protects data from collection on nodes that retain that pin; persistence depends on available nodes and their storage behavior. It is not automatic permanence for every CID. [IPFS persistence and pinning](https://docs.ipfs.tech/concepts/persistence/)

**Design implication:** require explicit retention and recovery arrangements for account backups, key grants, authority history and ciphertext, not just an on-chain pointer. Before publishing a new head, verify the complete required record closure is stored/pinned and retrievable through the selected independent path. Define missing-blob behavior, retries, retention responsibility and backup/export. A successful one-time fetch is evidence for that moment, not a future uptime promise. Restoring D1 alone cannot restore IPFS data that no node retains. Exact provider account access, pin behavior, capacity and failure recovery remain implementation gates.

## Public ciphertext still exposes metadata

IPFS is a public network. Content is public unless separately encrypted, and DHT activity exposes CIDs/provider identities and can reveal retrieval patterns. Transport encryption does not hide those public identifiers or replace content encryption. [IPFS privacy and encryption](https://docs.ipfs.tech/concepts/privacy-and-encryption/)

**Design implication:** encrypt sensitive labels, values and private record contents before publication; treat public CIDs and public on-chain relationships as observable. Do not promise that unpinning erases other copies or removes knowledge already gained by a former recipient. Client-side keys, current-authority checks, removal/write freeze and rotation retain their separate purposes. Availability and metadata trade-offs must be reflected in the accepted product contract.

## Evidence still required before implementation or release claims

- Human acceptance of registry migration/governance, wallet recovery, wallet scope, publication granularity and exact independent-client authority rules.
- Independent reconciliation of the proposed chain adapter with the frozen qualified protocol and current native/WASM WIP; any incompatible change needs explicit versioning and qualification.
- Exact source/schema/event/ABI/domain encodings, resource bounds, prerequisite tickets and recovery/failure tests before ready implementation.
- Selected Amoy and mainnet endpoint qualification for finalized/safe behavior, coherent calls, history/pruning, log completeness, limits and outages. Missing evidence stays a gate.
- Actual deployment identity and bytecode verification only after concrete authorization. No deployed team registry, account entitlement or chain activity is established here.
- Real complete-record retention/retrieval/restore tests with independently available ciphertext and key records. Local fixtures alone cannot prove provider availability.

These are research implications and qualification expectations. They neither accept the pending human choices nor authorize external action or change any previously frozen cryptographic/wire data.
