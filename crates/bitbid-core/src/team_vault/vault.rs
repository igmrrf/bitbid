use super::{Id, Result};
use super::{account::pass_header, codec::*, crypto, *};
use std::collections::BTreeSet;
use zeroize::Zeroizing;
/// Canonical secret plaintext owned by this guard. It is never serialized implicitly.
pub struct Content {
    kind: u8,
    bytes: Zeroizing<Vec<u8>>,
}
pub struct Plaintext(pub(super) Zeroizing<Vec<u8>>);
impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Content(<redacted>)")
    }
}
impl std::fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Plaintext(<redacted>)")
    }
}
impl Plaintext {
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Content {
    pub fn label(label: &str) -> Result<Self> {
        text(label.as_bytes(), 4096)?;
        Ok(Self {
            kind: 1,
            bytes: Zeroizing::new(t("vault-label", &[label.as_bytes()])),
        })
    }
    pub fn secret(name: &str, value: &str) -> Result<Self> {
        text(name.as_bytes(), 4096)?;
        text(value.as_bytes(), 1024 * 1024)?;
        Ok(Self {
            kind: 2,
            bytes: Zeroizing::new(t("secret", &[name.as_bytes(), value.as_bytes()])),
        })
    }
    pub fn deleted() -> Self {
        Self {
            kind: 3,
            bytes: Zeroizing::new(t("deleted", &[])),
        }
    }
}
pub struct VaultEpoch {
    key: Zeroizing<D>,
    team: Id,
    vault: Id,
    epoch: u64,
    published: u64,
    nonces: BTreeSet<[u8; 24]>,
}
impl std::fmt::Debug for VaultEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultEpoch(<redacted>)")
    }
}
impl VaultEpoch {
    pub fn generate(team: Id, vault: Id, epoch: u64, entropy: &mut impl Entropy) -> Result<Self> {
        nonzero(&team)?;
        nonzero(&vault)?;
        ensure(epoch > 0, "epoch zero")?;
        Ok(Self {
            key: crypto::random::<32>(entropy)?,
            team,
            vault,
            epoch,
            published: 0,
            nonces: BTreeSet::new(),
        })
    }
    pub fn commitment(&self) -> D {
        crypto::hash(&t(
            "vault-key-commitment",
            &[
                &self.team,
                &self.vault,
                &self.epoch.to_be_bytes(),
                &*self.key,
            ],
        ))
    }
    /// Creates an unverified immutable record; keep and retry its exact bytes.
    /// `observed_published` is an untrusted-to-authority conservative resource bound,
    /// not proof of global usage. It can only increase this handle's usage count.
    pub fn observe_published(&mut self, observed_published: u64) -> Result<()> {
        ensure(observed_published <= 1u64 << 32, "epoch usage limit")?;
        self.published = self.published.max(observed_published);
        Ok(())
    }
    pub fn encrypt(
        &mut self,
        author: &Account,
        plan: Digest,
        item: Id,
        revision: u64,
        content: Content,
        entropy: &mut impl Entropy,
    ) -> Result<Record> {
        ensure(
            revision > 0 && ((item == [0; 16]) == (content.kind == 1)),
            "content item/revision",
        )?;
        ensure(self.published < 1u64 << 32, "epoch usage limit")?;
        ensure(self.nonces.len() < LIST_MAX, "nonce ledger resource limit")?;
        let nonce = crypto::random::<24>(entropy)?;
        ensure(self.nonces.insert(*nonce), "nonce reused")?;
        let h = t(
            "content-header",
            &[
                &self.team,
                &self.vault,
                &item,
                &self.epoch.to_be_bytes(),
                &revision.to_be_bytes(),
                &[content.kind],
                &plan,
                &*nonce,
            ],
        );
        let ct = crypto::seal(&self.key, &*nonce, &content.bytes, &h)?;
        let result = author.sign_payload(Kind::Content, &t("content", &[&h, &ct]))?;
        self.published += 1;
        Ok(result)
    }
    /// First sharing/replacement requires a concrete trusted fingerprint capability.
    pub fn grant(
        &self,
        grantor: &Account,
        recipient: &TrustedPeer,
        plan: Digest,
        entropy: &mut impl Entropy,
    ) -> Result<Record> {
        let i = &recipient.identity().inner;
        let actor = grantor.identity().key_id();
        let commitment = self.commitment();
        let h = t(
            "grant-header",
            &[
                &self.team,
                &self.vault,
                &self.epoch.to_be_bytes(),
                &i.account,
                &i.key,
                &actor,
                &plan,
                &commitment,
            ],
        );
        let (enc, ct) = crypto::hpke_seal(&i.x, &t("hpke-info", &[&h]), &*self.key, &h, entropy)?;
        grantor.sign_payload(Kind::Grant, &t("grant", &[&h, &enc, &ct]))
    }
    pub fn open(state: &VerifiedAuthority<'_>, recipient: &Account, vault: Id) -> Result<Self> {
        let a = state.current();
        let i = recipient.identity();
        let pol = a.vaults.get(&vault).ok_or("missing vault")?;
        ensure(
            a.roster
                .get(&i.account_id())
                .is_some_and(|m| m.status == 2 && m.key == i.key_id())
                && pol.permissions.contains_key(&i.account_id()),
            "current recipient permission",
        )?;
        let g = a
            .grants
            .get(&(vault, i.account_id(), i.key_id()))
            .ok_or("missing selected epoch grant")?;
        let w = state.inner.store.get(&g.hash, "grant")?;
        let f = fields(&w.payload, "grant", 3)?;
        let h = fields(f[0], "grant-header", 8)?;
        ensure(
            arr::<16>(h[0])? == a.team
                && arr::<16>(h[1])? == vault
                && num(h[2], 8)? == pol.epoch
                && arr::<16>(h[3])? == i.account_id()
                && arr::<32>(h[4])? == i.key_id()
                && arr::<32>(h[7])? == pol.commitment,
            "grant recipient scope",
        )?;
        let key = crypto::hpke_open(
            recipient.recipient_secret(),
            f[1],
            &t("hpke-info", &[f[0]]),
            f[2],
            f[0],
        )?;
        let mut observed = BTreeSet::new();
        let mut wires = BTreeSet::new();
        let mut cursor = state
            .inner
            .heads
            .get(&vault)
            .ok_or("missing accepted head")?
            .hash;
        loop {
            let sn = protocol::Snapshot::parse(state.inner.store.get(&cursor, "snapshot")?)?;
            if sn.epoch != pol.epoch {
                break;
            }
            for c in sn.contents.values() {
                if wires.insert(c.hash) {
                    let cw = state.inner.store.get(&c.hash, "content")?;
                    let cf = fields(&cw.payload, "content", 2)?;
                    let ch = fields(cf[0], "content-header", 8)?;
                    let nonce = arr::<24>(ch[7])?;
                    ensure(observed.insert(nonce), "observed nonce reused")?;
                    ensure(observed.len() <= LIST_MAX, "nonce ledger resource limit")?;
                }
            }
            if sn.previous == [0; 32] {
                break;
            }
            cursor = sn.previous;
        }
        let out = Self {
            key: Zeroizing::new(arr(&key)?),
            team: a.team,
            vault,
            epoch: pol.epoch,
            published: wires.len() as u64,
            nonces: observed,
        };
        ensure(
            out.commitment() == pol.commitment,
            "decrypted epoch commitment",
        )?;
        Ok(out)
    }
    /// Complete local rotation: every selected plaintext/kind is preserved and revision incremented.
    /// Returned records remain proposals until the full new authority is verified atomically.
    pub fn reencrypt_current(
        &mut self,
        old: &VaultEpoch,
        state: &VerifiedAuthority<'_>,
        actor: &Account,
        new_plan: Digest,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<Record>> {
        ensure(
            self.team == old.team
                && self.vault == old.vault
                && self.epoch == add(old.epoch)?
                && self.commitment() != old.commitment(),
            "rotation key/context",
        )?;
        let (_, member) = state.current().actor(&actor.identity().key_id())?;
        ensure(member.role <= 2, "rotation actor privilege")?;
        let snapshot = state
            .inner
            .heads
            .get(&old.vault)
            .ok_or("missing accepted head")?;
        let mut out = Vec::new();
        out.try_reserve_exact(snapshot.contents.len())
            .map_err(|_| "rotation allocation")?;
        for (item, c) in &snapshot.contents {
            let revision = add(c.revision)?;
            let plain = old.open_content(state, *item)?;
            let content = Content {
                kind: c.kind,
                bytes: plain.0,
            };
            out.push(self.encrypt(actor, new_plan, *item, revision, content, entropy)?);
        }
        Ok(out)
    }
    /// Only selected current content may be opened; an arbitrary old ciphertext cannot select state.
    pub fn open_content(&self, state: &VerifiedAuthority<'_>, item: Id) -> Result<Plaintext> {
        let a = state.current();
        ensure(
            a.team == self.team
                && a.vaults
                    .get(&self.vault)
                    .is_some_and(|v| v.epoch == self.epoch && v.commitment == self.commitment()),
            "epoch state mismatch",
        )?;
        let sn = state
            .inner
            .heads
            .get(&self.vault)
            .ok_or("missing accepted head")?;
        let c = sn.contents.get(&item).ok_or("missing selected content")?;
        let w = state.inner.store.get(&c.hash, "content")?;
        let f = fields(&w.payload, "content", 2)?;
        let h = fields(f[0], "content-header", 8)?;
        let plain = crypto::open(&self.key, h[7], f[1], f[0])?;
        validate_plaintext(c.kind, &plain)?;
        Ok(Plaintext(plain))
    }
}
pub(super) fn validate_plaintext(kind: u8, plain: &[u8]) -> Result<()> {
    match kind {
        1 => {
            let f = fields(plain, "vault-label", 1)?;
            text(f[0], 4096)?;
        }
        2 => {
            let f = fields(plain, "secret", 2)?;
            text(f[0], 4096)?;
            text(f[1], 1024 * 1024)?;
        }
        3 => {
            fields(plain, "deleted", 0)?;
        }
        _ => return Err("content kind".into()),
    };
    Ok(())
}
/// Fully checked, readable historical projection. No conversion to live authority.
pub struct ReadableExport {
    selected: usize,
    records: usize,
    trust_sequence: u64,
    pub(super) contents: Vec<(Id, Id, Id, Plaintext)>,
}
impl std::fmt::Debug for ReadableExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadableExport(<redacted>)")
    }
}
impl ReadableExport {
    pub fn restore(
        wire: &Record,
        code: &RecoveryCode,
        passphrase: &str,
        budget: KdfBudget,
    ) -> Result<Self> {
        ensure(wire.kind() == Kind::Export, "export kind")?;
        // Preflight exact root slots/profile before the expensive KDF.
        let f = fields(wire.payload(), "export", 5)?;
        let account = arr::<16>(f[0])?;
        let generation = num(f[1], 8)?;
        let mut raw = Vec::new();
        for b in list(f[4])? {
            let r = fields(b, "export-record", 2)?;
            ensure(r[1].len() <= RECORD_MAX, "export record hash/bound")?;
            raw.push(Record::parse(r[1])?);
        }
        let key = wire.signer().ok_or("export signer")?;
        let mut identities = raw
            .iter()
            .filter(|r| r.kind() == Kind::Identity && r.signer() == Some(key));
        let identity = identities
            .next()
            .ok_or("root identity")?
            .verify_identity()?;
        ensure(identities.next().is_none(), "duplicate identity")?;
        ensure(
            identity.account_id() == account && identity.generation() == generation,
            "export identity generation",
        )?;
        let mut passes = raw.iter().filter(|r| r.kind() == Kind::PassWrapper);
        let pass = passes.next().ok_or("missing typed account root")?;
        ensure(passes.next().is_none(), "multiple wrapper roots")?;
        let (header, _) = pass_header(pass, &identity)?;
        let h = fields(header, "pass-header", 9)?;
        let restored = Account::recover(
            &identity,
            raw.iter()
                .find(|r| r.kind() == Kind::RecoveryWrapper)
                .ok_or("missing typed account root")?,
            code,
        )?;
        let _ = restored;
        let passkey = crypto::kdf(passphrase.as_bytes(), h[7], budget.bytes())?;
        let value =
            backup::verify_export_code(wire.as_bytes(), &code.expose_secret_code(), &passkey)?;
        Ok(Self {
            selected: value.selected,
            records: value.records,
            trust_sequence: value.sequence,
            contents: value.contents,
        })
    }
    pub fn selected_vaults(&self) -> usize {
        self.selected
    }
    pub fn record_count(&self) -> usize {
        self.records
    }
    pub fn trust_sequence(&self) -> u64 {
        self.trust_sequence
    }
    pub fn plaintexts(&self) -> impl Iterator<Item = (Id, Id, Id, &Plaintext)> {
        self.contents.iter().map(|(t, v, i, p)| (*t, *v, *i, p))
    }
    /// Explicit encrypted export construction; validation is still required before reading.
    pub fn seal(
        account: &Account,
        export_id: Id,
        selected: &[(Id, Id, u64, D)],
        records: &[Record],
    ) -> Result<Record> {
        nonzero(&export_id)?;
        ensure(
            records.len() <= LIST_MAX && selected.len() <= LIST_MAX,
            "export list bound",
        )?;
        let mut last = None;
        let mut selections = Vec::new();
        for (team, vault, epoch, hash) in selected {
            nonzero(team)?;
            nonzero(vault)?;
            ordered(&mut last, (*team, *vault))?;
            selections.push(t(
                "selected-vault",
                &[team, vault, &epoch.to_be_bytes(), hash],
            ));
        }
        let mut rows = records.iter().map(|r| (r.hash(), r)).collect::<Vec<_>>();
        rows.sort_by_key(|r| r.0);
        let mut last = None;
        let mut entries = Vec::new();
        let mut total = 0usize;
        for (hash, r) in rows {
            ensure(r.kind() != Kind::Export, "nested export")?;
            ordered(&mut last, hash)?;
            total = total
                .checked_add(r.as_bytes().len() + 128)
                .ok_or("export size overflow")?;
            ensure(total < EXPORT_MAX - 4096, "export byte budget")?;
            entries.push(t("export-record", &[&hash, r.as_bytes()]));
        }
        let i = account.identity();
        account.sign_payload(
            Kind::Export,
            &t(
                "export",
                &[
                    &i.account_id(),
                    &i.generation().to_be_bytes(),
                    &export_id,
                    &protocol::encode_list(&selections),
                    &protocol::encode_list(&entries),
                ],
            ),
        )
    }
}
