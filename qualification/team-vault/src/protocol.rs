use crate::{codec::*, crypto};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub key: D,
    pub role: u8,
    pub status: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub epoch: u64,
    pub phase: u8,
    pub commitment: D,
    pub permissions: BTreeMap<Id, u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRef {
    pub account: Id,
    pub key: D,
    pub vault: Id,
    pub epoch: u64,
    pub hash: D,
    pub raw: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRef {
    pub epoch: u64,
    pub hash: D,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceRef {
    pub key: D,
    pub hash: D,
}
#[derive(Clone)]
pub struct Authority {
    pub hash: D,
    pub plan: D,
    pub team: Id,
    pub sequence: u64,
    pub previous: D,
    pub action: String,
    pub actor: D,
    pub roster: BTreeMap<Id, Member>,
    pub vaults: BTreeMap<Id, Vault>,
    pub grants: BTreeMap<(Id, Id, D), GrantRef>,
    pub snapshots: BTreeMap<Id, SnapshotRef>,
    pub acceptances: BTreeMap<Id, AcceptanceRef>,
}
fn byte(b: &[u8], range: std::ops::RangeInclusive<u8>) -> Result<u8> {
    let n = num(b, 1)? as u8;
    ensure(range.contains(&n), "enum")?;
    Ok(n)
}
fn id(b: &[u8]) -> Result<Id> {
    let a = arr(b)?;
    nonzero(&a)?;
    Ok(a)
}
pub fn encode_list(es: &[Vec<u8>]) -> Vec<u8> {
    let mut v = (es.len() as u32).to_be_bytes().to_vec();
    for e in es {
        v.extend((e.len() as u32).to_be_bytes());
        v.extend(e)
    }
    v
}
impl Authority {
    pub fn parse(w: &Wire, s: &Store) -> Result<Self> {
        ensure(w.kind == "authority", "authority kind")?;
        let f = fields(&w.payload, "authority", 4)?;
        let p = fields(f[0], "authority-plan", 7)?;
        let team = id(p[0])?;
        let sequence = num(p[1], 8)?;
        let previous = arr(p[2])?;
        let action = text(p[3], 32)?.to_owned();
        ensure(
            [
                "genesis",
                "invite",
                "activate",
                "promote",
                "demote",
                "replace-key",
                "remove",
                "new-vault",
                "vault-permission",
                "rotate",
                "transfer",
                "delete-team",
            ]
            .contains(&action.as_str()),
            "action",
        )?;
        let actor = arr(p[4])?;
        ensure(w.signer == Some(actor), "authority signer")?;
        let mut roster = BTreeMap::new();
        let mut last = None;
        for b in list(p[5])? {
            let m = fields(b, "member", 4)?;
            let a = id(m[0])?;
            ordered(&mut last, a)?;
            let key = arr(m[1])?;
            s.identity(&key, &a)?;
            roster.insert(
                a,
                Member {
                    key,
                    role: byte(m[2], 1..=3)?,
                    status: byte(m[3], 1..=3)?,
                },
            );
        }
        let mut vaults = BTreeMap::new();
        let mut last = None;
        for b in list(p[6])? {
            let v = fields(b, "vault-policy", 5)?;
            let a = id(v[0])?;
            ordered(&mut last, a)?;
            let mut permissions = BTreeMap::new();
            let mut prev = None;
            for b in list(v[4])? {
                let e = fields(b, "permission", 2)?;
                let a = id(e[0])?;
                ordered(&mut prev, a)?;
                permissions.insert(a, byte(e[1], 1..=2)?);
            }
            let epoch = num(v[1], 8)?;
            ensure(epoch > 0, "epoch zero")?;
            vaults.insert(
                a,
                Vault {
                    epoch,
                    phase: byte(v[2], 1..=2)?,
                    commitment: arr(v[3])?,
                    permissions,
                },
            );
        }
        let mut grants = BTreeMap::new();
        let mut last = None;
        for b in list(f[1])? {
            let g = fields(b, "grant-ref", 5)?;
            let account = id(g[0])?;
            let key = arr(g[1])?;
            let vault = id(g[2])?;
            let epoch = num(g[3], 8)?;
            ordered(&mut last, (vault, epoch, account, key))?;
            ensure(
                grants
                    .insert(
                        (vault, account, key),
                        GrantRef {
                            account,
                            key,
                            vault,
                            epoch,
                            hash: arr(g[4])?,
                            raw: b.to_vec(),
                        },
                    )
                    .is_none(),
                "grant identity",
            )?;
        }
        let mut snapshots = BTreeMap::new();
        let mut last = None;
        for b in list(f[2])? {
            let e = fields(b, "snapshot-ref", 3)?;
            let v = id(e[0])?;
            ordered(&mut last, v)?;
            snapshots.insert(
                v,
                SnapshotRef {
                    epoch: num(e[1], 8)?,
                    hash: arr(e[2])?,
                },
            );
        }
        let mut acceptances = BTreeMap::new();
        let mut last = None;
        for b in list(f[3])? {
            let e = fields(b, "acceptance-ref", 3)?;
            let a = id(e[0])?;
            let k = arr(e[1])?;
            ordered(&mut last, (a, k))?;
            ensure(
                acceptances
                    .insert(
                        a,
                        AcceptanceRef {
                            key: k,
                            hash: arr(e[2])?,
                        },
                    )
                    .is_none(),
                "acceptance identity",
            )?;
        }
        let a = Self {
            hash: w.hash(),
            plan: crypto::hash(f[0]),
            team,
            sequence,
            previous,
            action,
            actor,
            roster,
            vaults,
            grants,
            snapshots,
            acceptances,
        };
        a.invariants()?;
        Ok(a)
    }
    fn invariants(&self) -> Result<()> {
        for v in self.vaults.values() {
            for (a, m) in &self.roster {
                match (m.status, m.role) {
                    (2, 1 | 2) => ensure(
                        v.permissions.get(a) == Some(&2),
                        "all-vault privileged permission",
                    )?,
                    (1 | 3, _) => ensure(!v.permissions.contains_key(a), "inactive permission")?,
                    _ => (),
                }
            }
            for a in v.permissions.keys() {
                ensure(
                    self.roster.get(a).is_some_and(|m| m.status == 2),
                    "unknown/inactive permission",
                )?;
            }
        }
        Ok(())
    }
    pub fn actor(&self, key: &D) -> Result<(Id, &Member)> {
        self.roster
            .iter()
            .find(|(_, m)| m.key == *key && m.status == 2)
            .map(|(a, m)| (*a, m))
            .ok_or("inactive actor".into())
    }
    pub fn eligible(&self, v: &Id) -> BTreeSet<(Id, D)> {
        self.vaults[v]
            .permissions
            .keys()
            .filter_map(|a| {
                self.roster
                    .get(a)
                    .filter(|m| m.status == 2)
                    .map(|m| (*a, m.key))
            })
            .collect()
    }
    pub fn writer(&self, v: &Id, key: &D, label: bool) -> Result<()> {
        let (a, m) = self.actor(key)?;
        ensure(
            self.vaults
                .get(v)
                .is_some_and(|v| v.phase == 1 && v.permissions.get(&a) == Some(&2)),
            "writer permission/phase",
        )?;
        ensure(!label || m.role <= 2, "label privilege")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentRef {
    pub kind: u8,
    pub revision: u64,
    pub hash: D,
}
#[derive(Clone)]
pub struct Snapshot {
    pub hash: D,
    pub signer: D,
    pub team: Id,
    pub vault: Id,
    pub epoch: u64,
    pub sequence: u64,
    pub previous: D,
    pub plan: D,
    pub contents: BTreeMap<Id, ContentRef>,
}
impl Snapshot {
    pub fn parse(w: &Wire) -> Result<Self> {
        ensure(w.kind == "snapshot", "snapshot kind")?;
        let f = fields(&w.payload, "snapshot", 7)?;
        let mut contents = BTreeMap::new();
        let mut last = None;
        for b in list(f[6])? {
            let e = fields(b, "content-ref", 4)?;
            let i: Id = arr(e[0])?;
            let kind = byte(e[1], 1..=3)?;
            ordered(&mut last, (i, kind))?;
            ensure((i == [0; 16]) == (kind == 1), "label sentinel")?;
            let revision = num(e[2], 8)?;
            ensure(revision > 0, "revision zero")?;
            ensure(
                contents
                    .insert(
                        i,
                        ContentRef {
                            kind,
                            revision,
                            hash: arr(e[3])?,
                        },
                    )
                    .is_none(),
                "duplicate item_id",
            )?;
        }
        ensure(
            contents.get(&[0; 16]).is_some_and(|c| c.kind == 1),
            "missing label",
        )?;
        Ok(Self {
            hash: w.hash(),
            signer: w.signer.ok_or("snapshot signer")?,
            team: id(f[0])?,
            vault: id(f[1])?,
            epoch: num(f[2], 8)?,
            sequence: num(f[3], 8)?,
            previous: arr(f[4])?,
            plan: arr(f[5])?,
            contents,
        })
    }
}
pub struct Projection {
    pub vaults: BTreeSet<Id>,
    pub content: BTreeSet<D>,
    pub grants: BTreeSet<D>,
}
pub struct Verifier<'a> {
    pub projection: Option<Projection>,
    pub store: &'a Store,
    pub current: Option<Authority>,
    pub heads: BTreeMap<Id, Snapshot>,
    pub plans: BTreeMap<D, Authority>,
    pub used_vaults: BTreeSet<Id>,
}
impl<'a> Verifier<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self {
            projection: None,
            store,
            current: None,
            heads: BTreeMap::new(),
            plans: BTreeMap::new(),
            used_vaults: BTreeSet::new(),
        }
    }
    fn content(
        &self,
        snap: &Snapshot,
        i: &Id,
        c: &ContentRef,
        a: &Authority,
        activation_body: bool,
    ) -> Result<()> {
        let w = self.store.get(&c.hash, "content")?;
        let f = fields(&w.payload, "content", 2)?;
        let h = fields(f[0], "content-header", 8)?;
        ensure(
            id(h[0])? == snap.team
                && id(h[1])? == snap.vault
                && arr::<16>(h[2])? == *i
                && num(h[3], 8)? == snap.epoch
                && num(h[4], 8)? == c.revision
                && num(h[5], 1)? == u64::from(c.kind)
                && arr::<32>(h[6])? == a.plan,
            "content context",
        )?;
        arr::<24>(h[7])?;
        ensure(
            f[1].len() >= 16 && f[1].len() <= 1024 * 1024 + 16384,
            "content size",
        )?;
        let signer = w.signer.ok_or("content signer")?;
        ensure(
            !activation_body || signer == a.actor,
            "activation content actor",
        )?;
        a.writer(&snap.vault, &signer, c.kind == 1)
    }
    fn snapshot_relation(
        &self,
        snap: &Snapshot,
        old: Option<&Snapshot>,
        a: &Authority,
        activation: bool,
    ) -> Result<()> {
        ensure(
            snap.team == a.team
                && snap.plan == a.plan
                && a.vaults
                    .get(&snap.vault)
                    .is_some_and(|v| v.epoch == snap.epoch && v.phase == 1),
            "snapshot plan/epoch",
        )?;
        a.writer(&snap.vault, &snap.signer, false)?;
        let rotation = old.is_some_and(|b| b.epoch != snap.epoch);
        if let Some(b) = old {
            ensure(
                snap.previous == b.hash && snap.sequence == add(b.sequence)?,
                "snapshot succession",
            )?;
            ensure(
                b.contents.keys().all(|i| snap.contents.contains_key(i)),
                "silent item omission",
            )?;
            if rotation {
                ensure(
                    activation
                        && snap.epoch == add(b.epoch)?
                        && snap.contents.len() == b.contents.len()
                        && snap.signer == a.actor,
                    "atomic epoch replacement",
                )?;
            }
        } else {
            ensure(
                activation
                    && snap.sequence == 1
                    && snap.previous == [0; 32]
                    && snap.epoch == 1
                    && snap.contents.len() == 1
                    && snap.signer == a.actor,
                "vault creation snapshot",
            )?;
        }
        let mut changed = false;
        for (i, c) in &snap.contents {
            let b = old.and_then(|b| b.contents.get(i));
            if let Some(b) = b {
                if b == c {
                    ensure(!rotation, "retained ciphertext in rotation")?;
                    continue;
                }
                ensure(c.revision == add(b.revision)?, "item revision")?;
                if rotation {
                    ensure(c.kind == b.kind && c.hash != b.hash, "rotation kind/ref")?;
                } else {
                    ensure(!(b.kind == 3 && c.kind == 3), "retombstone")?;
                }
            } else {
                ensure(
                    c.revision == 1 && (old.is_none() || (*i != [0; 16] && c.kind == 2)),
                    "new item kind/revision",
                )?;
            }
            changed = true;
            if self
                .projection
                .as_ref()
                .is_none_or(|p| p.content.contains(&c.hash))
            {
                // Bind the body at its introduction/replacement snapshot, also
                // when replaying selected-export provenance. Ordinary later
                // edits under this same authority plan retain writer policy.
                self.content(snap, i, c, a, old.is_none() || rotation)?;
            }
            if c.kind == 1 {
                a.writer(&snap.vault, &snap.signer, true)?;
            }
        }
        ensure(changed, "empty snapshot mutation")?;
        Ok(())
    }
    pub fn append(&mut self, h: &D) -> Result<()> {
        let a = self.current.as_ref().ok_or("no authority")?;
        let sn = Snapshot::parse(self.store.get(h, "snapshot")?)?;
        let old = self.heads.get(&sn.vault).ok_or("unknown vault head")?;
        self.snapshot_relation(&sn, Some(old), a, false)?;
        self.heads.insert(sn.vault, sn);
        Ok(())
    }
    pub fn apply(&mut self, h: &D) -> Result<()> {
        let n = Authority::parse(self.store.get(h, "authority")?, self.store)?;
        ensure(
            !self.plans.contains_key(&n.plan),
            "duplicate finalized plan",
        )?;
        let mut expected_roster;
        let mut expected_vaults;
        let mut accepted = BTreeSet::new();
        let mut activated = BTreeSet::new();
        if let Some(p) = &self.current {
            ensure(
                p.action != "delete-team"
                    && n.team == p.team
                    && n.previous == p.hash
                    && n.sequence == add(p.sequence)?,
                "authority succession",
            )?;
            let (actor_id, actor) = p.actor(&n.actor)?;
            ensure(actor.role <= 2, "authority actor privilege")?;
            let diff = p
                .roster
                .keys()
                .chain(n.roster.keys())
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|a| p.roster.get(a) != n.roster.get(a))
                .collect::<Vec<_>>();
            expected_roster = p.roster.clone();
            expected_vaults = p.vaults.clone();
            let target = || -> Result<Id> {
                ensure(diff.len() == 1, "one roster target")?;
                Ok(diff[0])
            };
            match n.action.as_str() {
                "invite" => {
                    let t = target()?;
                    ensure(
                        p.roster.get(&t).is_none_or(|m| m.status == 3),
                        "invite active identity",
                    )?;
                    let m = n.roster.get(&t).ok_or("invite row")?;
                    ensure(
                        m.status == 1 && (m.role == 3 || (m.role == 2 && actor.role == 1)),
                        "invite role/status",
                    )?;
                    expected_roster.insert(t, m.clone());
                }
                "activate" => {
                    let t = target()?;
                    let old = p.roster.get(&t).ok_or("activation previous")?;
                    let m = n.roster.get(&t).ok_or("activation row")?;
                    ensure(
                        old.status == 1
                            && m.status == 2
                            && old.role == m.role
                            && old.key == m.key
                            && (m.role == 3 || actor.role == 1),
                        "activation role/key/status",
                    )?;
                    expected_roster.insert(t, m.clone());
                    for (v, pol) in &mut expected_vaults {
                        if m.role <= 2 {
                            pol.permissions.insert(t, 2);
                        } else if let Some(perm) =
                            n.vaults.get(v).and_then(|v| v.permissions.get(&t))
                        {
                            pol.permissions.insert(t, *perm);
                        }
                    }
                    accepted.insert(t);
                }
                "promote" | "demote" => {
                    ensure(actor.role == 1, "role change Owner")?;
                    let t = target()?;
                    let old = p.roster.get(&t).ok_or("role previous")?;
                    let m = n.roster.get(&t).ok_or("role row")?;
                    ensure(
                        old.status == 2 && m.status == 2 && old.key == m.key,
                        "role key/status",
                    )?;
                    ensure(
                        if n.action == "promote" {
                            old.role == 3 && m.role == 2
                        } else {
                            old.role < m.role && m.role <= 3
                        },
                        "role direction",
                    )?;
                    expected_roster.insert(t, m.clone());
                    for (v, pol) in &mut expected_vaults {
                        if m.role <= 2 {
                            pol.permissions.insert(t, 2);
                        } else {
                            pol.permissions.remove(&t);
                            if let Some(x) = n.vaults.get(v).and_then(|v| v.permissions.get(&t)) {
                                ensure(
                                    p.vaults[v].permissions.contains_key(&t),
                                    "demotion new access",
                                )?;
                                pol.permissions.insert(t, *x);
                            }
                        }
                    }
                    if n.action == "promote" {
                        accepted.insert(t);
                    }
                }
                "replace-key" => {
                    let t = target()?;
                    let old = p.roster.get(&t).ok_or("replacement previous")?;
                    let m = n.roster.get(&t).ok_or("replacement row")?;
                    ensure(
                        old.status == 2
                            && m.status == 2
                            && old.role == m.role
                            && old.key != m.key
                            && (old.role == 3 || actor.role == 1),
                        "replacement role/status",
                    )?;
                    let oi = self.store.identity(&old.key, &t)?;
                    let ni = self.store.identity(&m.key, &t)?;
                    ensure(ni.generation > oi.generation, "replacement generation")?;
                    expected_roster.insert(t, m.clone());
                    accepted.insert(t);
                }
                "remove" => {
                    let t = target()?;
                    let old = p.roster.get(&t).ok_or("removal previous")?;
                    let m = n.roster.get(&t).ok_or("removal row")?;
                    ensure(
                        old.status != 3
                            && m.status == 3
                            && m.role == old.role
                            && m.key == old.key
                            && (old.role == 3 || actor.role == 1),
                        "removal role/status",
                    )?;
                    expected_roster.insert(t, m.clone());
                    for v in expected_vaults.values_mut() {
                        v.permissions.remove(&t);
                    }
                }
                "transfer" => {
                    ensure(
                        actor.role == 1 && diff.len() == 2 && diff.contains(&actor_id),
                        "transfer actor/diff",
                    )?;
                    let t = *diff
                        .iter()
                        .find(|x| **x != actor_id)
                        .ok_or("transfer target")?;
                    let old = p.roster.get(&t).ok_or("transfer old target")?;
                    let m = n.roster.get(&t).ok_or("transfer new target")?;
                    let outgoing = n.roster.get(&actor_id).ok_or("transfer outgoing")?;
                    ensure(
                        old.status == 2
                            && old.role >= 2
                            && m.status == 2
                            && m.role == 1
                            && old.key == m.key
                            && outgoing.status == 2
                            && outgoing.key == actor.key
                            && (outgoing.role == 2 || outgoing.role == 3),
                        "transfer roles",
                    )?;
                    expected_roster.insert(t, m.clone());
                    expected_roster.insert(actor_id, outgoing.clone());
                    for (v, pol) in &mut expected_vaults {
                        pol.permissions.insert(t, 2);
                        if outgoing.role == 3 {
                            pol.permissions.remove(&actor_id);
                            if let Some(x) =
                                n.vaults.get(v).and_then(|v| v.permissions.get(&actor_id))
                            {
                                pol.permissions.insert(actor_id, *x);
                            }
                        }
                    }
                    accepted.insert(t);
                }
                "new-vault" => {
                    ensure(diff.is_empty(), "new vault roster")?;
                    let added = n
                        .vaults
                        .keys()
                        .filter(|v| !p.vaults.contains_key(*v))
                        .copied()
                        .collect::<Vec<_>>();
                    ensure(added.len() == 1, "one new vault")?;
                    let v = added[0];
                    ensure(!self.used_vaults.contains(&v), "vault ID reuse")?;
                    let pol = &n.vaults[&v];
                    ensure(pol.epoch == 1 && pol.phase == 1, "new vault epoch/phase")?;
                    expected_vaults.insert(v, pol.clone());
                    activated.insert(v);
                }
                "vault-permission" => {
                    ensure(diff.is_empty(), "permission roster")?;
                    let vd = p
                        .vaults
                        .keys()
                        .filter(|v| {
                            n.vaults
                                .get(*v)
                                .is_some_and(|x| x.permissions != p.vaults[*v].permissions)
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    ensure(vd.len() == 1, "one permission vault")?;
                    let v = vd[0];
                    let old = &p.vaults[&v].permissions;
                    let new = &n.vaults[&v].permissions;
                    let pd = old
                        .keys()
                        .chain(new.keys())
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .filter(|a| old.get(a) != new.get(a))
                        .collect::<Vec<_>>();
                    ensure(
                        pd.len() == 1
                            && p.roster
                                .get(&pd[0])
                                .is_some_and(|m| m.status == 2 && m.role == 3),
                        "ordinary permission target",
                    )?;
                    expected_vaults
                        .get_mut(&v)
                        .ok_or("permission vault")?
                        .permissions = new.clone();
                }
                "rotate" => {
                    ensure(diff.is_empty(), "rotation roster")?;
                    let vd = p
                        .vaults
                        .keys()
                        .filter(|v| n.vaults.get(*v) != p.vaults.get(*v))
                        .copied()
                        .collect::<Vec<_>>();
                    ensure(vd.len() == 1, "one rotated vault")?;
                    let v = vd[0];
                    let old = &p.vaults[&v];
                    let pol = n.vaults.get(&v).ok_or("rotation policy")?;
                    ensure(
                        pol.epoch == add(old.epoch)?
                            && pol.phase == 1
                            && pol.commitment != old.commitment
                            && pol.permissions == old.permissions,
                        "epoch replacement policy",
                    )?;
                    expected_vaults.insert(v, pol.clone());
                    activated.insert(v);
                }
                "delete-team" => {
                    ensure(actor.role == 1, "delete Owner")?;
                    for m in expected_roster.values_mut() {
                        m.status = 3;
                    }
                    expected_vaults.clear();
                }
                _ => return Err("non-genesis action".into()),
            }
            ensure(n.roster == expected_roster, "unlisted roster delta")?;
            ensure(n.vaults.keys().eq(expected_vaults.keys()), "vault key set")?;
            if !["rotate", "new-vault", "delete-team"].contains(&n.action.as_str()) {
                for (v, pol) in &mut expected_vaults {
                    let old = p.eligible(v);
                    let new = n.eligible(v);
                    if !old.is_subset(&new) {
                        pol.phase = 2;
                    }
                }
            }
            ensure(n.vaults == expected_vaults, "unlisted vault delta")?;
        } else {
            ensure(
                n.action == "genesis"
                    && n.sequence == 1
                    && n.previous == [0; 32]
                    && n.roster.len() == 1
                    && n.vaults.is_empty(),
                "genesis shape",
            )?;
            let (_, m) = n.actor(&n.actor)?;
            ensure(m.role == 1 && m.status == 2, "genesis Owner")?;
            expected_roster = n.roster.clone();
            expected_vaults = n.vaults.clone();
            let _ = (expected_roster, expected_vaults);
        }
        ensure(
            n.action == "delete-team" || n.roster.values().any(|m| m.status == 2 && m.role == 1),
            "last Owner",
        )?;
        ensure(n.snapshots.keys().eq(n.vaults.keys()), "snapshot exact set")?;
        let mut expected_grants = BTreeSet::new();
        for (v, pol) in &n.vaults {
            let eligible = n.eligible(v);
            let p = self.current.as_ref();
            if pol.phase == 1 {
                for (a, k) in eligible {
                    expected_grants.insert((*v, a, k));
                }
            } else if let Some(p) = p {
                for (key, g) in &p.grants {
                    if key.0 == *v && eligible.contains(&(g.account, g.key)) {
                        expected_grants.insert(*key);
                    }
                }
            }
        }
        ensure(
            n.grants.keys().copied().collect::<BTreeSet<_>>() == expected_grants,
            "grant exact set",
        )?;
        for (key, g) in &n.grants {
            let pol = &n.vaults[&g.vault];
            ensure(g.epoch == pol.epoch, "grant ref epoch")?;
            let retained = self
                .current
                .as_ref()
                .filter(|p| {
                    p.vaults
                        .get(&g.vault)
                        .is_some_and(|v| v.epoch == pol.epoch && v.commitment == pol.commitment)
                })
                .and_then(|p| p.grants.get(key));
            if let Some(old) = retained {
                ensure(old == g, "changed retained grant")?;
            } else {
                ensure(pol.phase == 1, "new frozen grant")?;
                if self
                    .projection
                    .as_ref()
                    .is_none_or(|p| p.grants.contains(&g.hash))
                {
                    self.grant(g, &n)?;
                }
            }
        }
        ensure(
            n.acceptances.keys().copied().collect::<BTreeSet<_>>() == accepted,
            "acceptance exact set",
        )?;
        for a in accepted {
            let ar = &n.acceptances[&a];
            let m = &n.roster[&a];
            ensure(ar.key == m.key, "acceptance recipient")?;
            let w = self.store.get(&ar.hash, "acceptance")?;
            let f = fields(&w.payload, "acceptance", 5)?;
            let refs = n
                .grants
                .values()
                .filter(|g| g.account == a && g.key == m.key)
                .map(|g| g.raw.clone())
                .collect::<Vec<_>>();
            let refs = encode_list(&refs);
            let set = crypto::hash(&t("recipient-grants", &[&refs]));
            ensure(
                w.signer == Some(m.key)
                    && id(f[0])? == n.team
                    && id(f[1])? == a
                    && arr::<32>(f[2])? == m.key
                    && arr::<32>(f[3])? == n.plan
                    && arr::<32>(f[4])? == set,
                "acceptance plan/ref binding",
            )?;
        }
        let mut heads = BTreeMap::new();
        for (v, r) in &n.snapshots {
            if self
                .projection
                .as_ref()
                .is_some_and(|p| !p.vaults.contains(v))
            {
                continue;
            }
            let sn = Snapshot::parse(self.store.get(&r.hash, "snapshot")?)?;
            ensure(
                sn.team == n.team
                    && sn.vault == *v
                    && sn.epoch == r.epoch
                    && r.epoch == n.vaults[v].epoch,
                "snapshot ref binding",
            )?;
            if activated.contains(v) {
                self.snapshot_relation(&sn, self.heads.get(v), &n, true)?;
            } else {
                ensure(
                    self.heads.get(v).is_some_and(|h| h.hash == sn.hash),
                    "unsealed or changed head",
                )?;
            }
            heads.insert(*v, sn);
        }
        self.used_vaults.extend(n.vaults.keys().copied());
        self.heads = heads;
        self.plans.insert(n.plan, n.clone());
        self.current = Some(n);
        Ok(())
    }
    pub fn grant(&self, g: &GrantRef, a: &Authority) -> Result<()> {
        let w = self.store.get(&g.hash, "grant")?;
        let f = fields(&w.payload, "grant", 3)?;
        let h = fields(f[0], "grant-header", 8)?;
        ensure(
            id(h[0])? == a.team
                && id(h[1])? == g.vault
                && num(h[2], 8)? == g.epoch
                && id(h[3])? == g.account
                && arr::<32>(h[4])? == g.key
                && arr::<32>(h[5])? == a.actor
                && w.signer == Some(a.actor)
                && arr::<32>(h[6])? == a.plan
                && arr::<32>(h[7])? == a.vaults[&g.vault].commitment,
            "grant context/authority",
        )?;
        arr::<32>(f[1])?;
        arr::<48>(f[2])?;
        Ok(())
    }
}
