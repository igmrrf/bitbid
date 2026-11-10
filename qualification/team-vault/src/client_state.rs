//! Executable local activation/CAS model; no server implementation is claimed.
use crate::{codec::*, protocol::*};
use std::collections::BTreeSet;
#[derive(Debug, PartialEq, Eq)]
pub enum Stage {
    Local,
    Sent,
    Committed,
    Abandoned,
}
pub struct Attempt {
    pub stage: Stage,
    pub payload: D,
    previous: D,
    disclosure: BTreeSet<(Id, u64)>,
}
impl Attempt {
    pub fn prepare(v: &Verifier<'_>, payload: D) -> Result<Self> {
        let mut shadow = Verifier {
            projection: None,
            store: v.store,
            current: v.current.clone(),
            heads: v.heads.clone(),
            plans: v.plans.clone(),
            used_vaults: v.used_vaults.clone(),
        };
        shadow.apply(&payload)?;
        let n = shadow.current.as_ref().ok_or("missing candidate")?;
        let previous = v.current.as_ref().map_or([0; 32], |a| a.hash);
        let disclosure = n
            .grants
            .iter()
            .filter(|(key, g)| v.current.as_ref().and_then(|a| a.grants.get(key)) != Some(*g))
            .map(|(_, g)| (g.vault, g.epoch))
            .collect();
        Ok(Self {
            stage: Stage::Local,
            payload,
            previous,
            disclosure,
        })
    }
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
    pub fn abandon(&mut self) -> Result<BTreeSet<(Id, u64)>> {
        ensure(
            self.stage == Stage::Local || self.stage == Stage::Sent,
            "activation already final",
        )?;
        let epochs = if self.stage == Stage::Sent {
            self.disclosure.clone()
        } else {
            BTreeSet::new()
        };
        self.stage = Stage::Abandoned;
        Ok(epochs)
    }
}
pub fn import_current(
    v: &mut Verifier<'_>,
    expected_authority: D,
    expected_head: D,
    snapshot: D,
) -> Result<()> {
    let a = v.current.as_ref().ok_or("no current authority")?;
    let sn = Snapshot::parse(v.store.get(&snapshot, "snapshot")?)?;
    ensure(
        a.hash == expected_authority
            && v.heads
                .get(&sn.vault)
                .is_some_and(|h| h.hash == expected_head),
        "restore authority/head CAS conflict",
    )?;
    v.append(&snapshot)
}
