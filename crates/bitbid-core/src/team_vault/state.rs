use super::{Id, Result};
use super::{
    codec::*,
    protocol::{Authority, Snapshot, Verifier},
    *,
};
use std::collections::{BTreeMap, BTreeSet};

pub struct TrustedPeer {
    identity: VerifiedIdentity,
}
impl TrustedPeer {
    pub(super) fn new(identity: VerifiedIdentity) -> Self {
        Self { identity }
    }
    pub fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }
}
impl std::fmt::Debug for TrustedPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedPeer(<verified fingerprint>)")
    }
}
/// Saved schema pins contain genesis only. In-memory pins also preserve accepted heads.
type AcceptedHeads = (u64, D, BTreeMap<Id, (u64, D)>);
type ReplayResult<'a> = (Verifier<'a>, BTreeSet<(u64, D)>, BTreeSet<(Id, u64, D)>);
#[derive(Clone)]
pub struct TeamPin {
    pub(super) team: Id,
    pub(super) genesis: D,
    accepted: Option<AcceptedHeads>,
}
impl std::fmt::Debug for TeamPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TeamPin(<authenticated>)")
    }
}
impl TeamPin {
    pub(super) fn saved(team: Id, genesis: D) -> Self {
        Self {
            team,
            genesis,
            accepted: None,
        }
    }
    pub fn team_id(&self) -> Id {
        self.team
    }
    pub fn genesis_hash(&self) -> D {
        self.genesis
    }
}
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Authority(Digest),
    Snapshot(Digest),
    Import {
        authority: Digest,
        head: Digest,
        snapshot: Digest,
    },
}
pub struct RecordSet {
    pub(super) store: Store,
}
impl RecordSet {
    pub fn parse(records: &[&[u8]]) -> Result<Self> {
        ensure(records.len() <= LIST_MAX, "record count")?;
        let mut total = 0usize;
        let mut raw = Vec::new();
        raw.try_reserve_exact(records.len())
            .map_err(|_| "record allocation")?;
        for r in records {
            total = total.checked_add(r.len()).ok_or("record byte overflow")?;
            ensure(total <= EXPORT_MAX, "record byte budget")?;
            raw.push(copy(r)?);
        }
        Ok(Self {
            store: Store::load(&raw)?,
        })
    }
    pub fn record(&self, hash: Digest) -> Option<Record> {
        self.store.wires.get(&hash).cloned().map(Record)
    }
    pub fn identity(&self, key: Digest) -> Result<VerifiedIdentity> {
        let w = self
            .store
            .wires
            .values()
            .find(|w| w.kind == "identity" && w.signer == Some(key))
            .ok_or("missing identity")?;
        Record(w.clone()).verify_identity()
    }
    /// Creates live trusted state only when the creator identity is held locally.
    pub fn bootstrap(&self, genesis: Digest, creator: &Account) -> Result<VerifiedAuthority<'_>> {
        let mut v = Verifier::new(&self.store);
        v.apply(&genesis)?;
        let a = v.current.as_ref().ok_or("missing authority")?;
        ensure(
            a.actor == creator.identity().key_id(),
            "local genesis identity",
        )?;
        Ok(VerifiedAuthority { inner: v, genesis })
    }
    /// Checks signed history without asserting trusted team identity or live freshness.
    pub fn verify_proof(&self, operations: &[Operation]) -> Result<HistoricalProof<'_>> {
        let (v, _, _) = self.replay(operations)?;
        Ok(HistoricalProof { inner: v })
    }
    pub fn verify_pinned(
        &self,
        operations: &[Operation],
        pin: &TeamPin,
    ) -> Result<VerifiedAuthority<'_>> {
        let (v, authorities, heads) = self.replay(operations)?;
        let first = first_authority(operations)?;
        let a = v.current.as_ref().ok_or("missing authority")?;
        ensure(first == pin.genesis && a.team == pin.team, "genesis pin")?;
        if let Some((seq, hash, known_heads)) = &pin.accepted {
            ensure(
                authorities.contains(&(*seq, *hash)),
                "pinned authority rollback/fork",
            )?;
            for (vault, (seq, hash)) in known_heads {
                ensure(
                    heads.contains(&(*vault, *seq, *hash)),
                    "pinned snapshot rollback/fork",
                )?;
            }
        }
        Ok(VerifiedAuthority {
            inner: v,
            genesis: first,
        })
    }
    /// The peer fingerprint AND team/genesis must be confirmed over the trusted channel.
    pub fn verify_anchored(
        &self,
        operations: &[Operation],
        anchor: &Record,
        peer: &TrustedPeer,
        recipient: &VerifiedIdentity,
        expected_team: Id,
        expected_genesis: Digest,
    ) -> Result<VerifiedAuthority<'_>> {
        let (v, _, _) = self.replay(operations)?;
        let a = v.current.as_ref().ok_or("missing authority")?;
        ensure(anchor.kind() == Kind::TeamAnchor, "anchor kind")?;
        crypto::verify(&anchor.0, &peer.identity.inner)?;
        let h = fields(anchor.payload(), "team-anchor", 4)?;
        ensure(
            arr::<16>(h[0])? == expected_team
                && a.team == expected_team
                && arr::<32>(h[1])? == expected_genesis
                && first_authority(operations)? == expected_genesis
                && arr::<32>(h[2])? == a.hash
                && arr::<32>(h[3])? == recipient.key_id(),
            "anchor scope/head",
        )?;
        let (_, m) = a.actor(&peer.identity.key_id())?;
        ensure(m.role <= 2, "anchor current privileged peer")?;
        self.store
            .identity(&peer.identity.key_id(), &peer.identity.account_id())?;
        Ok(VerifiedAuthority {
            inner: v,
            genesis: expected_genesis,
        })
    }
    fn replay(&self, operations: &[Operation]) -> Result<ReplayResult<'_>> {
        ensure(
            !operations.is_empty() && operations.len() <= 4096,
            "proof bound",
        )?;
        let mut v = Verifier::new(&self.store);
        let mut authorities = BTreeSet::new();
        let mut heads = BTreeSet::new();
        for &op in operations {
            operate(&mut v, op)?;
            if let Some(a) = &v.current {
                authorities.insert((a.sequence, a.hash));
            }
            for (id, h) in &v.heads {
                heads.insert((*id, h.sequence, h.hash));
            }
        }
        Ok((v, authorities, heads))
    }
}
fn first_authority(ops: &[Operation]) -> Result<D> {
    match ops.first() {
        Some(Operation::Authority(h)) => Ok(*h),
        _ => Err("genesis first".into()),
    }
}
fn shadow<'a>(v: &Verifier<'a>) -> Verifier<'a> {
    Verifier {
        projection: None,
        store: v.store,
        current: v.current.clone(),
        heads: v.heads.clone(),
        plans: v.plans.clone(),
        used_vaults: v.used_vaults.clone(),
    }
}
fn operate(v: &mut Verifier<'_>, op: Operation) -> Result<()> {
    let mut next = shadow(v);
    match op {
        Operation::Authority(h) => next.apply(&h)?,
        Operation::Snapshot(h) => next.append(&h)?,
        Operation::Import {
            authority,
            head,
            snapshot,
        } => {
            let a = next.current.as_ref().ok_or("no current authority")?;
            let sn = Snapshot::parse(next.store.get(&snapshot, "snapshot")?)?;
            ensure(
                a.hash == authority && next.heads.get(&sn.vault).is_some_and(|s| s.hash == head),
                "restore authority/head CAS conflict",
            )?;
            next.append(&snapshot)?;
        }
    }
    // Bound the union of authenticated proof records, including shared identities once.
    let mut proofs = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for a in next.plans.values() {
        proofs.insert(a.hash);
        keys.extend(a.roster.values().map(|m| m.key));
        proofs.extend(a.acceptances.values().map(|r| r.hash));
    }
    for head in next.heads.values() {
        let mut hash = head.hash;
        loop {
            if !proofs.insert(hash) {
                break;
            }
            ensure(proofs.len() <= 4096, "proof union bound")?;
            let sn = Snapshot::parse(next.store.get(&hash, "snapshot")?)?;
            keys.insert(sn.signer);
            if sn.previous == [0; 32] {
                break;
            }
            hash = sn.previous;
        }
    }
    for key in keys {
        let w = next
            .store
            .wires
            .values()
            .find(|w| w.kind == "identity" && w.signer == Some(key))
            .ok_or("missing identity")?;
        proofs.insert(w.hash());
    }
    ensure(proofs.len() <= 4096, "proof union bound")?;
    *v = next;
    Ok(())
}
/// A validated, untrusted-to-team historical proof. Cannot open grants or become live state.
pub struct HistoricalProof<'a> {
    inner: Verifier<'a>,
}
impl HistoricalProof<'_> {
    pub fn authority_hash(&self) -> Option<D> {
        self.inner.current.as_ref().map(|a| a.hash)
    }
}
/// Trusted current state for this handle; every successor uses previous accepted authority/heads.
pub struct VerifiedAuthority<'a> {
    pub(super) inner: Verifier<'a>,
    genesis: D,
}
impl std::fmt::Debug for VerifiedAuthority<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedAuthority(<checked>)")
    }
}
impl<'a> VerifiedAuthority<'a> {
    pub fn apply(&mut self, operation: Operation) -> Result<()> {
        operate(&mut self.inner, operation)
    }
    pub fn hash(&self) -> D {
        self.current().hash
    }
    pub fn sequence(&self) -> u64 {
        self.current().sequence
    }
    pub fn team_id(&self) -> Id {
        self.current().team
    }
    pub fn plan_hash(&self) -> D {
        self.current().plan
    }
    pub fn snapshot(&self, vault: Id) -> Option<VerifiedSnapshot<'_>> {
        self.inner
            .heads
            .get(&vault)
            .map(|inner| VerifiedSnapshot { inner })
    }
    pub fn pin(&self) -> TeamPin {
        TeamPin {
            team: self.team_id(),
            genesis: self.genesis,
            accepted: Some((
                self.sequence(),
                self.hash(),
                self.inner
                    .heads
                    .iter()
                    .map(|(v, h)| (*v, (h.sequence, h.hash)))
                    .collect(),
            )),
        }
    }
    pub fn prepare_activation(&self, hash: Digest) -> Result<Activation> {
        let mut next = shadow(&self.inner);
        next.apply(&hash)?;
        let n = next.current.as_ref().ok_or("missing candidate")?;
        let disclosure = n
            .grants
            .iter()
            .filter(|(key, g)| self.current().grants.get(key) != Some(*g))
            .map(|(_, g)| (g.vault, g.epoch))
            .collect();
        Ok(Activation {
            stage: Stage::Local,
            payload: hash,
            previous: self.hash(),
            disclosure,
        })
    }
    pub(super) fn current(&self) -> &Authority {
        self.inner.current.as_ref().expect("accepted authority")
    }
}
pub struct VerifiedSnapshot<'a> {
    inner: &'a Snapshot,
}
impl VerifiedSnapshot<'_> {
    pub fn hash(&self) -> D {
        self.inner.hash
    }
    pub fn sequence(&self) -> u64 {
        self.inner.sequence
    }
    pub fn epoch(&self) -> u64 {
        self.inner.epoch
    }
    pub fn content_hashes(&self) -> impl Iterator<Item = (Id, D)> + '_ {
        self.inner.contents.iter().map(|(i, c)| (*i, c.hash))
    }
}
#[derive(PartialEq, Eq)]
enum Stage {
    Local,
    Sent,
    Committed,
    Abandoned,
}
pub struct Activation {
    stage: Stage,
    payload: D,
    previous: D,
    disclosure: BTreeSet<(Id, u64)>,
}
impl Activation {
    pub fn send(&mut self) -> Result<D> {
        ensure(self.stage == Stage::Local, "activation already sent/final")?;
        self.stage = Stage::Sent;
        Ok(self.payload)
    }
    pub fn reconcile(&mut self, observed: D) -> Result<()> {
        ensure(
            self.stage == Stage::Sent,
            "activation not awaiting reconciliation",
        )?;
        if observed == self.payload {
            self.stage = Stage::Committed;
            Ok(())
        } else if observed == self.previous {
            Err("previous head observed; disclosure remains possible".into())
        } else {
            Err("conflicting authority; reload/rebase required".into())
        }
    }
    pub fn abandon(&mut self) -> Result<Vec<(Id, u64)>> {
        ensure(
            matches!(self.stage, Stage::Local | Stage::Sent),
            "activation already final",
        )?;
        let v = if self.stage == Stage::Sent {
            self.disclosure.iter().copied().collect()
        } else {
            Vec::new()
        };
        self.stage = Stage::Abandoned;
        Ok(v)
    }
}
