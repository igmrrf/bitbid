use super::{Id, Result};
use super::{codec::*, crypto, state::TeamPin, *};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signer;
use hpke::{
    Deserializable, Serializable,
    kem::{Kem, X25519HkdfSha256},
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub struct KdfBudget {
    bytes: usize,
}
impl KdfBudget {
    pub(super) const fn bytes(self) -> usize {
        self.bytes
    }
    pub const PRODUCTION: Self = Self {
        bytes: 65536 * 1024,
    };
    /// This caps resources; it cannot alter the fixed algorithm/profile.
    pub const fn limit_bytes(bytes: usize) -> Self {
        Self { bytes }
    }
}
pub struct Account {
    root: Zeroizing<D>,
    signing: Zeroizing<D>,
    recipient: Zeroizing<D>,
    identity: VerifiedIdentity,
    nonces: BTreeSet<[u8; 24]>,
    trust_head: Option<(u64, D)>,
}
impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Account(<redacted>)")
    }
}
pub struct RecoveryCode {
    account: Id,
    generation: u64,
    value: Zeroizing<D>,
}
impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}
impl RecoveryCode {
    pub fn parse(secret_token: &str) -> Result<Self> {
        let (account, generation, value) = backup::recovery_code(secret_token)?;
        Ok(Self {
            account,
            generation,
            value,
        })
    }
    /// Explicit secret export. Keep separate from encrypted backups and network payloads.
    pub fn expose_secret_code(&self) -> Zeroizing<String> {
        let code = Zeroizing::new(t(
            "recovery-code",
            &[&self.account, &self.generation.to_be_bytes(), &*self.value],
        ));
        let checksum = crypto::hash(&Zeroizing::new(t("recovery-checksum", &[&code])));
        let mut all = Zeroizing::new(code.to_vec());
        all.extend_from_slice(&checksum[..16]);
        Zeroizing::new(format!(
            "bitbid-recovery1:{}",
            URL_SAFE_NO_PAD.encode(&*all)
        ))
    }
}
#[derive(Clone, Debug)]
pub struct AccountBackup {
    pub identity: Record,
    pub pass_wrapper: Record,
    pub recovery_wrapper: Record,
}
/// Authenticated local pin state; only verified capabilities can add trusted pins.
pub struct TrustState {
    pub(super) teams: BTreeMap<Id, TeamPin>,
    peers: BTreeMap<(Id, D), D>,
}
impl Default for TrustState {
    fn default() -> Self {
        Self::new()
    }
}
impl TrustState {
    pub fn new() -> Self {
        Self {
            teams: BTreeMap::new(),
            peers: BTreeMap::new(),
        }
    }
    pub fn pin_team(&mut self, pin: TeamPin) -> Result<()> {
        if let Some(old) = self.teams.get(&pin.team) {
            ensure(old.genesis == pin.genesis, "genesis pin substitution")?;
        }
        self.teams.insert(pin.team, pin);
        Ok(())
    }
    pub fn pin_peer(&mut self, peer: &TrustedPeer) {
        let i = peer.identity();
        self.peers
            .insert((i.account_id(), i.key_id()), i.fingerprint());
    }
    pub fn team_pin(&self, team: Id) -> Option<&TeamPin> {
        self.teams.get(&team)
    }
    pub(super) fn permits(&self, i: &VerifiedIdentity) -> bool {
        self.peers.get(&(i.account_id(), i.key_id())) == Some(&i.fingerprint())
    }
}
impl std::fmt::Debug for TrustState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustState(<redacted>)")
    }
}
impl Account {
    pub fn generate(
        account_id: Id,
        generation: u64,
        entropy: &mut impl Entropy,
    ) -> Result<(Self, RecoveryCode)> {
        nonzero(&account_id)?;
        ensure(generation > 0, "generation")?;
        let root = crypto::random::<32>(entropy)?;
        let recovery = crypto::random::<32>(entropy)?;
        let a = Self::from_root(root, account_id, generation)?;
        Ok((
            a,
            RecoveryCode {
                account: account_id,
                generation,
                value: recovery,
            },
        ))
    }
    pub fn random_id(entropy: &mut impl Entropy) -> Result<Id> {
        let value = crypto::random::<16>(entropy)?;
        nonzero(&*value)?;
        Ok(*value)
    }
    fn from_root(root: Zeroizing<D>, account: Id, generation: u64) -> Result<Self> {
        let signing = crypto::derive(&root, &account, generation, "signing-seed")?;
        let recipient = crypto::derive(&root, &account, generation, "recipient-seed")?;
        let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&*recipient)
            .map_err(|_| "recipient secret")?;
        let public = X25519HkdfSha256::sk_to_pk(&sk).to_bytes();
        let ed = ed25519_dalek::SigningKey::from_bytes(&signing);
        let payload = t(
            "identity",
            &[
                &account,
                &generation.to_be_bytes(),
                &public,
                &ed.verifying_key().to_bytes(),
            ],
        );
        let key = crypto::hash(&payload);
        let signature = ed
            .sign(&t("signed-record", &[b"identity", &key, &payload]))
            .to_bytes();
        let wire = record(
            Kind::Identity,
            &t("signed-envelope", &[&key, &payload, &signature]),
        )?;
        let identity = wire.verify_identity()?;
        Ok(Self {
            root,
            signing,
            recipient,
            identity,
            nonces: BTreeSet::new(),
            trust_head: None,
        })
    }
    pub fn identity(&self) -> &VerifiedIdentity {
        &self.identity
    }
    pub(super) fn recipient_secret(&self) -> &D {
        &self.recipient
    }
    pub(super) fn nonce(&mut self, e: &mut impl Entropy) -> Result<[u8; 24]> {
        ensure(self.nonces.len() < LIST_MAX, "nonce ledger resource limit")?;
        let n = crypto::random::<24>(e)?;
        ensure(self.nonces.insert(*n), "nonce reused")?;
        Ok(*n)
    }
    /// Produces an untrusted signed record. Authority/scope always requires RecordSet verification.
    pub fn sign_payload(&self, kind: Kind, payload: &[u8]) -> Result<Record> {
        ensure(
            kind.signed() && kind != Kind::Identity,
            "signed record kind",
        )?;
        ensure(
            payload.len()
                <= if kind == Kind::Export {
                    EXPORT_MAX - 1024
                } else {
                    RECORD_MAX - 1024
                },
            "payload bound",
        )?;
        let key = self.identity.key_id();
        let signature = ed25519_dalek::SigningKey::from_bytes(&self.signing)
            .sign(&t(
                "signed-record",
                &[kind.label().as_bytes(), &key, payload],
            ))
            .to_bytes();
        record(kind, &t("signed-envelope", &[&key, payload, &signature]))
    }
    pub fn backup(
        &mut self,
        passphrase: &str,
        recovery: &RecoveryCode,
        entropy: &mut impl Entropy,
        budget: KdfBudget,
    ) -> Result<AccountBackup> {
        ensure(
            recovery.account == self.identity.account_id()
                && recovery.generation == self.identity.generation(),
            "recovery scope",
        )?;
        let pass_wrapper = self.wrap_passphrase(passphrase, entropy, budget)?;
        let n = self.nonce(entropy)?;
        let i = &self.identity.inner;
        let h = t(
            "recovery-header",
            &[&i.account, &i.generation.to_be_bytes(), &i.key, &n],
        );
        let k = crypto::recovery_key(&recovery.value, &i.account, i.generation, &i.key)?;
        let ct = crypto::seal(&k, &n, &*self.root, &h)?;
        let recovery_wrapper = record(Kind::RecoveryWrapper, &t("recovery-wrapper", &[&h, &ct]))?;
        Ok(AccountBackup {
            identity: self.identity.wire.clone(),
            pass_wrapper,
            recovery_wrapper,
        })
    }
    pub fn wrap_passphrase(
        &mut self,
        passphrase: &str,
        entropy: &mut impl Entropy,
        budget: KdfBudget,
    ) -> Result<Record> {
        ensure(passphrase.len() <= 1024, "KDF input")?;
        let salt = crypto::random::<16>(entropy)?;
        let n = self.nonce(entropy)?;
        let i = &self.identity.inner;
        let h = t(
            "pass-header",
            &[
                &i.account,
                &i.generation.to_be_bytes(),
                &i.key,
                &19u32.to_be_bytes(),
                &65536u32.to_be_bytes(),
                &3u32.to_be_bytes(),
                &4u32.to_be_bytes(),
                &*salt,
                &n,
            ],
        );
        let k = crypto::kdf(passphrase.as_bytes(), &*salt, budget.bytes)?;
        record(
            Kind::PassWrapper,
            &t(
                "pass-wrapper",
                &[&h, &crypto::seal(&k, &n, &*self.root, &h)?],
            ),
        )
    }
    pub fn unlock(
        identity: &VerifiedIdentity,
        wrapper: &Record,
        passphrase: &str,
        budget: KdfBudget,
    ) -> Result<Self> {
        let (header, cipher) = pass_header(wrapper, identity)?;
        let h = fields(header, "pass-header", 9)?;
        let k = crypto::kdf(passphrase.as_bytes(), h[7], budget.bytes)?;
        let root = crypto::open(&k, h[8], cipher, header)?;
        Self::bound_root(root, identity)
    }
    pub fn recover(
        identity: &VerifiedIdentity,
        wrapper: &Record,
        code: &RecoveryCode,
    ) -> Result<Self> {
        ensure(wrapper.kind() == Kind::RecoveryWrapper, "recovery kind")?;
        ensure(
            code.account == identity.account_id() && code.generation == identity.generation(),
            "recovery scope",
        )?;
        let f = fields(wrapper.payload(), "recovery-wrapper", 2)?;
        let h = fields(f[0], "recovery-header", 4)?;
        binding(&h, identity)?;
        arr::<24>(h[3])?;
        ensure(f[1].len() == 48, "root ciphertext width")?;
        let k = crypto::recovery_key(
            &code.value,
            &code.account,
            code.generation,
            &identity.key_id(),
        )?;
        Self::bound_root(crypto::open(&k, h[3], f[1], f[0])?, identity)
    }
    fn bound_root(root: Zeroizing<Vec<u8>>, identity: &VerifiedIdentity) -> Result<Self> {
        let a = Self::from_root(
            Zeroizing::new(arr(&root)?),
            identity.account_id(),
            identity.generation(),
        )?;
        ensure(
            a.identity.key_id() == identity.key_id(),
            "recovered identity binding",
        )?;
        Ok(a)
    }
    pub fn wrap_trust(&mut self, trust: &TrustState, entropy: &mut impl Entropy) -> Result<Record> {
        let (sequence, previous) = match self.trust_head {
            Some((s, h)) => (add(s)?, h),
            None => (1, [0; 32]),
        };
        let n = self.nonce(entropy)?;
        let i = &self.identity.inner;
        let h = t(
            "trust-header",
            &[
                &i.account,
                &i.generation.to_be_bytes(),
                &sequence.to_be_bytes(),
                &previous,
                &n,
            ],
        );
        let teams = trust
            .teams
            .iter()
            .map(|(team, p)| t("team-pin", &[team, &p.genesis]))
            .collect::<Vec<_>>();
        let peers = trust
            .peers
            .iter()
            .map(|((a, k), fp)| t("peer-pin", &[a, k, fp]))
            .collect::<Vec<_>>();
        ensure(
            teams.len() <= LIST_MAX && peers.len() <= LIST_MAX,
            "trust list bound",
        )?;
        let plain = Zeroizing::new(t(
            "trust-state",
            &[
                &protocol::encode_list(&teams),
                &protocol::encode_list(&peers),
            ],
        ));
        let k = crypto::derive(&self.root, &i.account, i.generation, "trust-wrap")?;
        let w = record(
            Kind::TrustWrapper,
            &t("trust-wrapper", &[&h, &crypto::seal(&k, &n, &plain, &h)?]),
        )?;
        self.trust_head = Some((sequence, w.hash()));
        Ok(w)
    }
    pub fn open_trust(&mut self, wrapper: &Record) -> Result<TrustState> {
        ensure(wrapper.kind() == Kind::TrustWrapper, "trust kind")?;
        let f = fields(wrapper.payload(), "trust-wrapper", 2)?;
        let h = fields(f[0], "trust-header", 5)?;
        let i = &self.identity.inner;
        ensure(
            arr::<16>(h[0])? == i.account && num(h[1], 8)? == i.generation,
            "trust scope",
        )?;
        let seq = num(h[2], 8)?;
        let previous = arr::<32>(h[3])?;
        arr::<24>(h[4])?;
        ensure(
            seq > 0 && (seq != 1 || previous == [0; 32]),
            "trust sequence/genesis",
        )?;
        if let Some((old, hash)) = self.trust_head {
            ensure(
                (seq == old && wrapper.hash() == hash) || (seq == add(old)? && previous == hash),
                "trust rollback/conflict",
            )?;
        }
        let k = crypto::derive(&self.root, &i.account, i.generation, "trust-wrap")?;
        let plain = crypto::open(&k, h[4], f[1], f[0])?;
        let p = fields(&plain, "trust-state", 2)?;
        let mut out = TrustState::new();
        let mut last = None;
        for b in list(p[0])? {
            let f = fields(b, "team-pin", 2)?;
            let team = arr::<16>(f[0])?;
            nonzero(&team)?;
            ordered(&mut last, team)?;
            out.teams.insert(team, TeamPin::saved(team, arr(f[1])?));
        }
        let mut last = None;
        for b in list(p[1])? {
            let f = fields(b, "peer-pin", 3)?;
            let a = arr::<16>(f[0])?;
            nonzero(&a)?;
            let key = arr(f[1])?;
            ordered(&mut last, (a, key))?;
            out.peers.insert((a, key), arr(f[2])?);
        }
        self.trust_head = Some((seq, wrapper.hash()));
        Ok(out)
    }
    pub fn pinned_peer(
        &self,
        trust: &TrustState,
        identity: VerifiedIdentity,
    ) -> Result<TrustedPeer> {
        ensure(trust.permits(&identity), "missing verified peer pin")?;
        Ok(TrustedPeer::new(identity))
    }
}
pub(super) fn record(kind: Kind, payload: &[u8]) -> Result<Record> {
    Record::parse(&t(
        "wire",
        &[
            &1u16.to_be_bytes(),
            &1u16.to_be_bytes(),
            kind.label().as_bytes(),
            payload,
        ],
    ))
}
fn binding(h: &[&[u8]], i: &VerifiedIdentity) -> Result<()> {
    ensure(
        arr::<16>(h[0])? == i.account_id()
            && num(h[1], 8)? == i.generation()
            && arr::<32>(h[2])? == i.key_id(),
        "wrapper identity binding",
    )
}
pub(super) fn pass_header<'a>(w: &'a Record, i: &VerifiedIdentity) -> Result<(&'a [u8], &'a [u8])> {
    ensure(w.kind() == Kind::PassWrapper, "pass kind")?;
    let f = fields(w.payload(), "pass-wrapper", 2)?;
    let h = fields(f[0], "pass-header", 9)?;
    binding(&h, i)?;
    ensure(
        num(h[3], 4)? == 19 && num(h[4], 4)? == 65536 && num(h[5], 4)? == 3 && num(h[6], 4)? == 4,
        "pass profile/binding",
    )?;
    arr::<16>(h[7])?;
    arr::<24>(h[8])?;
    ensure(f[1].len() == 48, "root ciphertext width")?;
    Ok((f[0], f[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixed(u8);
    impl Entropy for Fixed {
        fn fill(&mut self, b: &mut [u8]) -> Result<()> {
            b.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn authenticated_trust_duplicate_shape_and_profile_preflight() {
        let (mut a, _) = Account::generate([1; 16], 1, &mut Fixed(3)).unwrap();
        let i = a.identity.inner.clone();
        let key = crypto::derive(&a.root, &i.account, i.generation, "trust-wrap").unwrap();
        let entry = t("team-pin", &[&[8; 16], &[9; 32]]);
        let duplicate = protocol::encode_list(&[entry.clone(), entry]);
        let empty = protocol::encode_list(&[]);
        for plain in [
            t("trust-state", &[&duplicate, &empty]),
            t("trust-state", &[&empty, &empty, b"unknown critical field"]),
        ] {
            let nonce = [17; 24];
            let h = t(
                "trust-header",
                &[
                    &i.account,
                    &i.generation.to_be_bytes(),
                    &1u64.to_be_bytes(),
                    &[0; 32],
                    &nonce,
                ],
            );
            let cipher = crypto::seal(&key, &nonce, &plain, &h).unwrap();
            let wrapper = record(Kind::TrustWrapper, &t("trust-wrapper", &[&h, &cipher])).unwrap();
            assert!(a.open_trust(&wrapper).is_err());
        }
        let identity = a.identity().clone();
        let nonce = [3; 24];
        let salt = [4; 16];
        let h = t(
            "pass-header",
            &[
                &identity.account_id(),
                &identity.generation().to_be_bytes(),
                &identity.key_id(),
                &19u32.to_be_bytes(),
                &32u32.to_be_bytes(),
                &3u32.to_be_bytes(),
                &4u32.to_be_bytes(),
                &salt,
                &nonce,
            ],
        );
        let kp = crypto::kdf(b"public", &salt, 65536 * 1024).unwrap();
        let cipher = crypto::seal(&kp, &nonce, &*a.root, &h).unwrap();
        let wrapper = record(Kind::PassWrapper, &t("pass-wrapper", &[&h, &cipher])).unwrap();
        assert_eq!(
            Account::unlock(&identity, &wrapper, "public", KdfBudget::limit_bytes(0))
                .unwrap_err()
                .reason(),
            "pass profile/binding"
        );
    }
}
