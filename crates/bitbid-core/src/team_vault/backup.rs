//! Typed selected-data projection; omitted historical ciphertext is never called verified.
use super::{codec::*, crypto, protocol::*};
use hpke::{
    Deserializable, Serializable,
    kem::{Kem, X25519HkdfSha256},
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
fn binary_id(b: &[u8]) -> Result<Id> {
    let a = arr(b)?;
    nonzero(&a)?;
    Ok(a)
}
fn root<'a>(s: &'a Store, kind: &str, account: &Id, generation: u64) -> Result<&'a Wire> {
    let mut found = None;
    for w in s.wires.values().filter(|w| w.kind == kind) {
        let p = fields(&w.payload, kind, 2)?;
        let h = match kind {
            "pass-wrapper" => fields(p[0], "pass-header", 9)?,
            "recovery-wrapper" => fields(p[0], "recovery-header", 4)?,
            "trust-wrapper" => fields(p[0], "trust-header", 5)?,
            _ => return Err("wrapper root kind".into()),
        };
        ensure(
            arr::<16>(h[0])? == *account && num(h[1], 8)? == generation,
            "wrapper root scope",
        )?;
        ensure(found.is_none(), "multiple wrapper roots")?;
        found = Some(w);
    }
    found.ok_or("missing typed account root".into())
}
fn extend_to(v: &mut Verifier<'_>, vault: Id, target: D, required: &mut BTreeSet<D>) -> Result<()> {
    let current = v.heads.get(&vault).ok_or("missing accepted head")?.hash;
    let mut h = target;
    let mut path = Vec::new();
    while h != current {
        ensure(path.len() < 4096, "snapshot proof bound")?;
        let sn = Snapshot::parse(v.store.get(&h, "snapshot")?)?;
        ensure(
            sn.vault == vault && sn.previous != [0; 32],
            "snapshot lineage termination",
        )?;
        required.insert(h);
        path.push(h);
        h = sn.previous;
    }
    for h in path.iter().rev() {
        v.append(h)?;
    }
    Ok(())
}
pub struct ExportData {
    pub selected: usize,
    pub records: usize,
    pub sequence: u64,
    pub contents: Vec<(Id, Id, Id, super::Plaintext)>,
}
pub fn verify_export(bytes: &[u8], recovery: &D, passkey: &D) -> Result<ExportData> {
    let w = Wire::parse(bytes)?;
    ensure(w.kind == "export", "export kind")?;
    let f = fields(&w.payload, "export", 5)?;
    let account = binary_id(f[0])?;
    let generation = num(f[1], 8)?;
    ensure(generation > 0, "export generation")?;
    binary_id(f[2])?;
    let mut selected = BTreeMap::new();
    let mut last = None;
    for b in list(f[3])? {
        let e = fields(b, "selected-vault", 4)?;
        let team = binary_id(e[0])?;
        let vault = binary_id(e[1])?;
        ordered(&mut last, (team, vault))?;
        ensure(
            selected
                .insert((team, vault), (num(e[2], 8)?, arr::<32>(e[3])?))
                .is_none(),
            "selected vault identity",
        )?;
    }
    let mut raw = Vec::new();
    let mut last = None;
    for b in list(f[4])? {
        let e = fields(b, "export-record", 2)?;
        let h = arr::<32>(e[0])?;
        ordered(&mut last, h)?;
        ensure(
            crypto::hash(e[1]) == h && e[1].len() <= RECORD_MAX,
            "export record hash/bound",
        )?;
        raw.push(e[1].to_vec());
    }
    let s = Store::load(&raw)?;
    let key = w.signer.ok_or("export signer")?;
    let identity = s.identity(&key, &account)?;
    ensure(
        identity.generation == generation,
        "export identity generation",
    )?;
    crypto::verify(&w, identity)?;
    let iw = s
        .wires
        .values()
        .find(|w| w.kind == "identity" && w.signer == Some(key))
        .ok_or("root identity")?;
    let pw = root(&s, "pass-wrapper", &account, generation)?;
    let rw = root(&s, "recovery-wrapper", &account, generation)?;
    let tw = root(&s, "trust-wrapper", &account, generation)?;
    let r = fields(&rw.payload, "recovery-wrapper", 2)?;
    let rh = fields(r[0], "recovery-header", 4)?;
    ensure(arr::<32>(rh[2])? == key, "recovery key binding")?;
    let rk = crypto::recovery_key(recovery, &account, generation, &key)?;
    let rootbytes = crypto::open(&rk, rh[3], r[1], r[0])?;
    let accountroot = Zeroizing::new(arr::<32>(&rootbytes)?);
    let x = crypto::derive(&accountroot, &account, generation, "recipient-seed")?;
    let ed = crypto::derive(&accountroot, &account, generation, "signing-seed")?;
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&*x).map_err(|_| "root X25519")?;
    ensure(
        X25519HkdfSha256::sk_to_pk(&sk).to_bytes().as_slice() == identity.x
            && ed25519_dalek::SigningKey::from_bytes(&ed)
                .verifying_key()
                .to_bytes()
                == identity.ed,
        "recovered identity binding",
    )?;
    let p = fields(&pw.payload, "pass-wrapper", 2)?;
    let ph = fields(p[0], "pass-header", 9)?;
    ensure(
        arr::<32>(ph[2])? == key
            && num(ph[3], 4)? == 19
            && num(ph[4], 4)? == 65536
            && num(ph[5], 4)? == 3
            && num(ph[6], 4)? == 4,
        "pass profile/binding",
    )?;
    arr::<16>(ph[7])?;
    ensure(
        crypto::open(passkey, ph[8], p[1], p[0])?.as_slice() == accountroot.as_slice(),
        "wrapper root mismatch",
    )?;
    let th = fields(&tw.payload, "trust-wrapper", 2)?;
    let h = fields(th[0], "trust-header", 5)?;
    let seq = num(h[2], 8)?;
    ensure(
        seq > 0 && (seq != 1 || arr::<32>(h[3])? == [0; 32]),
        "trust sequence/genesis",
    )?;
    arr::<32>(h[3])?;
    let kt = crypto::derive(&accountroot, &account, generation, "trust-wrap")?;
    let trust = crypto::open(&kt, h[4], th[1], th[0])?;
    let tf = fields(&trust, "trust-state", 2)?;
    let mut pins = BTreeMap::new();
    let mut last = None;
    for b in list(tf[0])? {
        let e = fields(b, "team-pin", 2)?;
        let team = binary_id(e[0])?;
        ordered(&mut last, team)?;
        pins.insert(team, arr::<32>(e[1])?);
    }
    let mut last = None;
    for b in list(tf[1])? {
        let e = fields(b, "peer-pin", 3)?;
        let a = binary_id(e[0])?;
        let k = arr::<32>(e[1])?;
        arr::<32>(e[2])?;
        ordered(&mut last, (a, k))?;
    }
    let mut required = BTreeSet::from([iw.hash(), pw.hash(), rw.hash(), tw.hash()]);
    let teams = selected.keys().map(|x| x.0).collect::<BTreeSet<_>>();
    let mut plaintexts = Vec::new();
    let mut current_grants = BTreeSet::new();
    let mut current_content = BTreeSet::new();
    for team in teams {
        let mut candidates = BTreeMap::new();
        let mut plans = BTreeSet::new();
        for aw in s.wires.values().filter(|w| w.kind == "authority") {
            let a = Authority::parse(aw, &s)?;
            if a.team == team {
                ensure(
                    candidates.insert(a.sequence, a.clone()).is_none() && plans.insert(a.plan),
                    "authority fork/ambiguous plan",
                )?;
            }
        }
        let terminal = candidates
            .last_key_value()
            .ok_or("missing team proof")?
            .1
            .clone();
        ensure(terminal.action != "delete-team", "deleted export authority")?;
        let mut chain = Vec::new();
        let mut a = terminal.clone();
        loop {
            ensure(chain.len() < 4096, "authority proof bound")?;
            required.insert(a.hash);
            chain.push(a.clone());
            if a.previous == [0; 32] {
                ensure(
                    a.sequence == 1 && a.hash == *pins.get(&team).ok_or("missing team pin")?,
                    "genesis pin",
                )?;
                break;
            }
            let previous = Authority::parse(s.get(&a.previous, "authority")?, &s)?;
            ensure(
                previous.team == team && add(previous.sequence)? == a.sequence,
                "authority predecessor",
            )?;
            a = previous;
        }
        chain.reverse();
        ensure(chain.len() == candidates.len(), "extra authority branch")?;
        let vaults = selected
            .keys()
            .filter(|x| x.0 == team)
            .map(|x| x.1)
            .collect::<BTreeSet<_>>();
        for v in &vaults {
            let (epoch, head) = selected[&(team, *v)];
            let pol = terminal.vaults.get(v).ok_or("selected missing policy")?;
            ensure(
                pol.epoch == epoch
                    && terminal
                        .roster
                        .get(&account)
                        .is_some_and(|m| m.status == 2 && m.key == key)
                    && pol.permissions.contains_key(&account),
                "selected scope/recipient",
            )?;
            let sn = Snapshot::parse(s.get(&head, "snapshot")?)?;
            ensure(
                sn.team == team && sn.vault == *v && sn.epoch == epoch,
                "selected snapshot binding",
            )?;
            required.insert(head);
            current_content.extend(sn.contents.values().map(|c| c.hash));
            let gr = terminal
                .grants
                .get(&(*v, account, key))
                .ok_or("missing selected epoch grant")?;
            current_grants.insert(gr.hash);
            required.insert(gr.hash);
        }
        let mut verifier = Verifier::new(&s);
        verifier.projection = Some(Projection {
            vaults: vaults.clone(),
            content: current_content.clone(),
            grants: current_grants.clone(),
        });
        for next in &chain {
            if verifier.current.is_some() {
                for v in &vaults {
                    if verifier.heads.contains_key(v) {
                        let r = next.snapshots.get(v).ok_or("missing selected anchor")?;
                        let sn = Snapshot::parse(s.get(&r.hash, "snapshot")?)?;
                        let desired = if sn.plan == next.plan && next.action == "rotate" {
                            sn.previous
                        } else {
                            sn.hash
                        };
                        extend_to(&mut verifier, *v, desired, &mut required)?;
                    }
                }
            }
            verifier.apply(&next.hash)?;
            for m in next.roster.values() {
                let ih = s
                    .wires
                    .values()
                    .find(|w| w.kind == "identity" && w.signer == Some(m.key))
                    .ok_or("roster identity")?;
                required.insert(ih.hash());
            }
            for ar in next.acceptances.values() {
                required.insert(ar.hash);
            }
            for (v, r) in &next.snapshots {
                if vaults.contains(v) {
                    required.insert(r.hash);
                }
            }
        }
        for v in &vaults {
            let (_, head) = selected[&(team, *v)];
            extend_to(&mut verifier, *v, head, &mut required)?;
            let pol = &terminal.vaults[v];
            if pol.phase == 2 {
                ensure(head == terminal.snapshots[v].hash, "frozen head mutation")?;
            }
            let sn = &verifier.heads[v];
            for c in sn.contents.values() {
                required.insert(c.hash);
            }
            let gr = &terminal.grants[&(*v, account, key)];
            let gw = s.get(&gr.hash, "grant")?;
            let gf = fields(&gw.payload, "grant", 3)?;
            let gh = fields(gf[0], "grant-header", 8)?;
            let vault_key = crypto::hpke_open(&x, gf[1], &t("hpke-info", &[gf[0]]), gf[2], gf[0])?;
            let vault_key = Zeroizing::new(arr::<32>(&vault_key)?);
            ensure(
                crypto::hash(&t(
                    "vault-key-commitment",
                    &[&team, v, &pol.epoch.to_be_bytes(), &*vault_key],
                )) == pol.commitment
                    && arr::<32>(gh[7])? == pol.commitment,
                "selected grant commitment",
            )?;
            for (item, c) in &sn.contents {
                let cw = s.get(&c.hash, "content")?;
                let cf = fields(&cw.payload, "content", 2)?;
                let ch = fields(cf[0], "content-header", 8)?;
                let plain = crypto::open(&vault_key, ch[7], cf[1], cf[0])?;
                match c.kind {
                    1 => {
                        let x = fields(&plain, "vault-label", 1)?;
                        text(x[0], 4096)?;
                    }
                    2 => {
                        let x = fields(&plain, "secret", 2)?;
                        text(x[0], 4096)?;
                        text(x[1], 1024 * 1024)?;
                    }
                    3 => {
                        fields(&plain, "deleted", 0)?;
                    }
                    _ => return Err("content kind".into()),
                }
                plaintexts.push((team, *v, *item, super::Plaintext(plain)));
            }
        }
    }
    required.extend(current_content);
    required.extend(current_grants);
    let mut signers = Vec::new();
    for h in &required {
        let record = s.wires.get(h).ok_or("missing closure body")?;
        if let Some(k) = record.signer {
            signers.push(k);
        }
    }
    for k in signers {
        let iw = s
            .wires
            .values()
            .find(|w| w.kind == "identity" && w.signer == Some(k))
            .ok_or("closure signer identity")?;
        required.insert(iw.hash());
    }
    ensure(required.len() <= 4096 + 10000, "closure work bound")?;
    let proof_count = required
        .iter()
        .filter(|h| {
            s.wires.get(*h).is_some_and(|w| {
                ["identity", "authority", "snapshot", "acceptance"].contains(&w.kind.as_str())
            })
        })
        .count();
    ensure(proof_count <= 4096, "proof union bound")?;
    ensure(
        required == s.wires.keys().copied().collect(),
        "missing/unreferenced export record",
    )?;
    Ok(ExportData {
        selected: selected.len(),
        records: required.len(),
        sequence: seq,
        contents: plaintexts,
    })
}

pub fn recovery_code(token: &str) -> Result<(Id, u64, Zeroizing<D>)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let encoded = token
        .strip_prefix("bitbid-recovery1:")
        .ok_or("recovery code prefix")?;
    ensure(encoded.len() <= 1024, "recovery code bound")?;
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "recovery code base64")?,
    );
    ensure(
        URL_SAFE_NO_PAD.encode(&*bytes) == encoded && bytes.len() >= 16,
        "recovery code canonical",
    )?;
    let (code, checksum) = bytes.split_at(bytes.len() - 16);
    ensure(
        crypto::hash(&Zeroizing::new(t("recovery-checksum", &[code])))[..16] == *checksum,
        "recovery checksum",
    )?;
    let f = fields(code, "recovery-code", 3)?;
    let account = binary_id(f[0])?;
    let generation = num(f[1], 8)?;
    ensure(generation > 0, "recovery code generation")?;
    Ok((account, generation, Zeroizing::new(arr(f[2])?)))
}
pub fn verify_export_code(bytes: &[u8], code: &str, passkey: &D) -> Result<ExportData> {
    let (account, generation, recovery) = recovery_code(code)?;
    let w = Wire::parse(bytes)?;
    let f = fields(&w.payload, "export", 5)?;
    ensure(
        binary_id(f[0])? == account && num(f[1], 8)? == generation,
        "recovery code account/generation binding",
    )?;
    verify_export(bytes, &recovery, passkey)
}
