//! Consumer-only synthetic frozen data; never linked by production.
use bitbid_core::team_vault::*;
use serde_json::{Value, json};
pub const CORPUS: &str =
    include_str!("../../../../qualification/team-vault/vectors/reference.json");
pub fn bytes(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
pub fn digest(v: &Value, k: &str) -> Digest {
    bytes(v, k).try_into().unwrap()
}
pub struct Fixed(pub Vec<u8>);
impl Entropy for Fixed {
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        if self.0.len() < b.len() {
            return Err(TeamVaultError::entropy_unavailable());
        }
        b.copy_from_slice(&self.0[..b.len()]);
        self.0.drain(..b.len());
        Ok(())
    }
}
pub struct Failed;
impl Entropy for Failed {
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        b.fill(42);
        Err(TeamVaultError::entropy_unavailable())
    }
}
pub fn account(c: &Value, key: Digest) -> Account {
    let v = &c["synthetic_test_material"][hex::encode(key)];
    let mut entropy = bytes(v, "root");
    entropy.extend([73; 32]);
    Account::generate(
        bytes(v, "account").try_into().unwrap(),
        v["generation"].as_u64().unwrap(),
        &mut Fixed(entropy),
    )
    .unwrap()
    .0
}
pub fn operation(v: &Value) -> Operation {
    let h = digest(v, "hash");
    match v["kind"].as_str().unwrap() {
        "authority" => Operation::Authority(h),
        "snapshot" => Operation::Snapshot(h),
        "restore" => Operation::Import {
            authority: digest(v, "expected_authority"),
            head: digest(v, "expected_head"),
            snapshot: h,
        },
        _ => panic!("fixture operation"),
    }
}
pub fn run() -> Value {
    let c: Value = serde_json::from_str(CORPUS).unwrap();
    let raw = c["records"]
        .as_object()
        .unwrap()
        .values()
        .map(|v| hex::decode(v.as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(raw.len(), 139);
    let refs = raw.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let records = RecordSet::parse(&refs).unwrap();
    // Exact identity derivation and pure signature wire interoperate with independently frozen bytes.
    for (key, _) in c["synthetic_test_material"].as_object().unwrap() {
        let id: Digest = hex::decode(key).unwrap().try_into().unwrap();
        let generated = account(&c, id);
        assert_eq!(
            generated.identity().record().as_bytes(),
            records.identity(id).unwrap().record().as_bytes()
        );
    }
    // Frozen full-profile wrapper bytes through public generation/wrapping, not a raw key constructor.
    let export = Record::parse(&bytes(&c["exports"][0], "wire")).unwrap();
    let ef = fields(export.payload(), "export", 5);
    let mut all = Vec::new();
    let mut pos = 4usize;
    let n = u32::from_be_bytes(ef[4][..4].try_into().unwrap()) as usize;
    for _ in 0..n {
        let len = u32::from_be_bytes(ef[4][pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        let row = fields(&ef[4][pos..pos + len], "export-record", 2);
        all.push(Record::parse(row[1]).unwrap());
        pos += len;
    }
    let identity = all
        .iter()
        .find(|r| r.kind() == Kind::Identity && r.signer() == export.signer())
        .unwrap()
        .verify_identity()
        .unwrap();
    let mut root = account(&c, identity.key_id());
    let code = RecoveryCode::parse(c["exports"][0]["recovery_code"].as_str().unwrap()).unwrap();
    let pw = all.iter().find(|r| r.kind() == Kind::PassWrapper).unwrap();
    let rw = all
        .iter()
        .find(|r| r.kind() == Kind::RecoveryWrapper)
        .unwrap();
    let ph = fields(fields(pw.payload(), "pass-wrapper", 2)[0], "pass-header", 9);
    let rh = fields(
        fields(rw.payload(), "recovery-wrapper", 2)[0],
        "recovery-header",
        4,
    );
    let entropy = [ph[7], ph[8], rh[3]].concat();
    let pass = String::from_utf8(bytes(&c["primitives"]["argon2"], "pass")).unwrap();
    let made = root
        .backup(&pass, &code, &mut Fixed(entropy), KdfBudget::PRODUCTION)
        .unwrap();
    assert_eq!(made.pass_wrapper.as_bytes(), pw.as_bytes());
    assert_eq!(made.recovery_wrapper.as_bytes(), rw.as_bytes());
    let mut lifecycle = 0;
    for case in c["cases"].as_array().unwrap() {
        let prefix = case["prefix"].as_array().unwrap();
        let genesis = digest(&prefix[0], "hash");
        let creator = account(&c, records.record(genesis).unwrap().signer().unwrap());
        let mut state = records.bootstrap(genesis, &creator).unwrap();
        for op in &prefix[1..] {
            state.apply(operation(op)).unwrap();
        }
        let prior = (state.hash(), state.sequence(), state.pin());
        let result = state.apply(operation(&case["operation"]));
        assert_eq!(
            result.is_ok(),
            case["accept"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
        if let Some(reason) = case["rejection"].as_str() {
            assert_eq!(
                result.as_ref().unwrap_err().reason(),
                reason,
                "{}",
                case["name"]
            );
        }
        if result.is_err() {
            assert_eq!((state.hash(), state.sequence()), (prior.0, prior.1));
        }
        lifecycle += 1;
    }
    assert_eq!(lifecycle, 54);
    // Same public selected grants/content before and after complete rotation preserve plaintext.
    let case = c["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "complete atomic rotation current objects")
        .unwrap();
    let prefix = case["prefix"].as_array().unwrap();
    let genesis = digest(&prefix[0], "hash");
    let owner = account(&c, records.record(genesis).unwrap().signer().unwrap());
    let mut state = records.bootstrap(genesis, &owner).unwrap();
    for op in &prefix[1..] {
        state.apply(operation(op)).unwrap();
    }
    let selected = |s: &VerifiedAuthority<'_>| {
        let pin = s.pin();
        let _ = pin;
        let mut out = Vec::new();
        for r in &raw {
            let w = Record::parse(r).unwrap();
            if w.kind() == Kind::Snapshot {
                let f = fields(w.payload(), "snapshot", 7);
                let vault: Id = f[1].try_into().unwrap();
                if let Some(sn) = s.snapshot(vault) {
                    let key = VaultEpoch::open(s, &owner, vault).unwrap();
                    for (i, _) in sn.content_hashes() {
                        out.push((
                            vault,
                            i,
                            key.open_content(s, i).unwrap().expose_bytes().to_vec(),
                        ));
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        out
    };
    let before = selected(&state);
    state.apply(operation(&case["operation"])).unwrap();
    assert_eq!(before, selected(&state));
    // Actual held-identity bootstrap, encrypted saved pin and observed current-head rollback checks.
    let pin = state.pin();
    let operations = prefix
        .iter()
        .map(operation)
        .chain(std::iter::once(operation(&case["operation"])))
        .collect::<Vec<_>>();
    assert!(records.verify_pinned(&operations, &pin).is_ok());
    assert!(records.verify_pinned(&operations[..1], &pin).is_err());
    let pass = String::from_utf8(bytes(&c["primitives"]["argon2"], "pass")).unwrap();
    let mut exports = 0;
    for case in c["exports"].as_array().unwrap() {
        let w = Record::parse(&bytes(case, "wire")).unwrap();
        let code = RecoveryCode::parse(case["recovery_code"].as_str().unwrap()).unwrap();
        let result = ReadableExport::restore(&w, &code, &pass, KdfBudget::PRODUCTION);
        assert_eq!(
            result.is_ok(),
            case["accept"].as_bool().unwrap(),
            "{} {:?}",
            case["name"],
            result.as_ref().err()
        );
        if let Some(reason) = case["rejection"].as_str() {
            assert_eq!(
                result.as_ref().unwrap_err().reason(),
                reason,
                "{}",
                case["name"]
            );
        }
        exports += 1;
    }
    assert_eq!(exports, 21);
    // Canonical transport mutation and real signature checks through public parsing/identity.
    for r in &raw {
        let w = Record::parse(r).unwrap();
        assert_eq!(Record::from_token(&w.to_token()).unwrap().as_bytes(), r);
        let mut trailing = r.clone();
        trailing.push(0);
        assert!(Record::parse(&trailing).is_err());
        if w.kind() == Kind::Identity {
            let mut tamper = r.clone();
            *tamper.last_mut().unwrap() ^= 1;
            assert!(Record::parse(&tamper).unwrap().verify_identity().is_err());
        }
    }
    json!({"pass":true,"records":raw.len(),"lifecycle":lifecycle,"exports":exports})
}
/// Test-only transcript reader for examining public metadata, never a verifier.
pub fn fields<'a>(b: &'a [u8], label: &str, n: usize) -> Vec<&'a [u8]> {
    let mut i = b"bitbid-team-v1/".len();
    assert_eq!(&b[i..i + 2], &(label.len() as u16).to_be_bytes());
    i += 2;
    assert_eq!(&b[i..i + label.len()], label.as_bytes());
    i += label.len();
    assert_eq!(&b[i..i + 2], &(n as u16).to_be_bytes());
    i += 2;
    let mut out = Vec::new();
    for _ in 0..n {
        let size = u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) as usize;
        i += 4;
        out.push(&b[i..i + size]);
        i += size;
    }
    assert_eq!(i, b.len());
    out
}
