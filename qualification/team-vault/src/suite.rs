use crate::{codec::*, crypto, protocol::Verifier};
use serde_json::{Value, json};
pub const CORPUS: &str = include_str!("../vectors/reference.json");
fn val(v: &Value, k: &str) -> Result<Vec<u8>> {
    hex::decode(v[k].as_str().ok_or("fixture field")?).map_err(|_| "fixture hex".into())
}
fn eq(a: &[u8], b: &[u8], why: &str) -> Result<()> {
    ensure(a == b, why)
}
fn reject<T>(r: Result<T>, why: &str) -> Result<()> {
    ensure(r.is_err(), why)
}
struct Fixed(Vec<u8>);
impl crypto::Entropy for Fixed {
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        ensure(b.len() == self.0.len(), "fixed entropy length")?;
        b.copy_from_slice(&self.0);
        Ok(())
    }
}
struct Failed;
impl crypto::Entropy for Failed {
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        b.fill(42);
        Err("injected entropy failure".into())
    }
}
fn decrypt_view(
    v: &Verifier<'_>,
    key: D,
    private: D,
) -> Result<std::collections::BTreeMap<(Id, Id), Vec<u8>>> {
    let a = v.current.as_ref().ok_or("decryption authority")?;
    let identity = v.store.identities.get(&key).ok_or("decryption identity")?;
    let mut plain = std::collections::BTreeMap::new();
    for (vault, head) in &v.heads {
        let g = a
            .grants
            .get(&(*vault, identity.account, key))
            .ok_or("decryption grant")?;
        let gw = v.store.get(&g.hash, "grant")?;
        let gf = fields(&gw.payload, "grant", 3)?;
        let value = crypto::hpke_open(&private, gf[1], &t("hpke-info", &[gf[0]]), gf[2], gf[0])?;
        let value = zeroize::Zeroizing::new(arr::<32>(&value)?);
        ensure(
            crypto::hash(&t(
                "vault-key-commitment",
                &[&a.team, vault, &head.epoch.to_be_bytes(), &*value],
            )) == a.vaults[vault].commitment,
            "decrypted epoch commitment",
        )?;
        for (item, c) in &head.contents {
            let cw = v.store.get(&c.hash, "content")?;
            let cf = fields(&cw.payload, "content", 2)?;
            let ch = fields(cf[0], "content-header", 8)?;
            plain.insert(
                (*vault, *item),
                crypto::open(&value, ch[7], cf[1], cf[0])?.to_vec(),
            );
        }
    }
    Ok(plain)
}
fn standard_kats() -> Result<()> {
    let a: Value = serde_json::from_str(include_str!("../vectors/rfc9106-argon2id-5.3.json"))
        .map_err(|_| "RFC JSON")?;
    let ad = val(&a, "associated_data")?;
    let secret = val(&a, "secret")?;
    let mut params = argon2::ParamsBuilder::new();
    params
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(argon2::AssociatedData::new(&ad).map_err(|_| "RFC AD")?);
    let argon = argon2::Argon2::new_with_secret(
        &secret,
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.build().map_err(|_| "RFC params")?,
    )
    .map_err(|_| "RFC secret")?;
    let mut output = [0; 32];
    argon
        .hash_password_into(&val(&a, "password")?, &val(&a, "salt")?, &mut output)
        .map_err(|_| "RFC Argon")?;
    eq(&output, &val(&a, "output")?, "RFC9106 KAT")?;
    let e: Value = serde_json::from_str(include_str!("../vectors/rfc8032-ed25519-test1.json"))
        .map_err(|_| "RFC Ed JSON")?;
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr(&val(&e, "seed")?)?);
    eq(
        &sk.verifying_key().to_bytes(),
        &val(&e, "public")?,
        "RFC Ed public",
    )?;
    let sig = sk.sign(&val(&e, "message")?).to_bytes();
    eq(&sig, &val(&e, "signature")?, "RFC Ed signature")?;
    sk.verifying_key()
        .verify_strict(&[], &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| "RFC Ed verify")?;
    let h: Value = serde_json::from_str(include_str!("../vectors/rfc9180-base-32-1-3.json"))
        .map_err(|_| "RFC HPKE JSON")?;
    let first = &h["encryptions"][0];
    let (enc, ct) = crypto::hpke_seal(
        &arr(&val(&h, "pkRm")?)?,
        &val(&h, "info")?,
        &val(first, "pt")?,
        &val(first, "aad")?,
        &mut Fixed(val(&h, "ikmE")?),
    )?;
    eq(&enc, &val(&h, "enc")?, "RFC9180 encapsulation")?;
    eq(&ct, &val(first, "ct")?, "RFC9180 encryption")?;
    let pt = crypto::hpke_open(
        &arr(&val(&h, "skRm")?)?,
        &enc,
        &val(&h, "info")?,
        &ct,
        &val(first, "aad")?,
    )?;
    eq(&pt, &val(first, "pt")?, "RFC9180 decryption")?;
    let x: Value = serde_json::from_str(include_str!(
        "../vectors/libsodium-xchacha20poly1305-ietf-tv1.json"
    ))
    .map_err(|_| "upstream XChaCha JSON")?;
    eq(
        &crypto::seal(
            &arr(&val(&x, "key")?)?,
            &val(&x, "nonce")?,
            &val(&x, "message")?,
            &val(&x, "aad")?,
        )?,
        &val(&x, "ciphertext_and_tag")?,
        "upstream libsodium XChaCha KAT",
    )?;
    Ok(())
}
fn primitives(v: &Value, full_kdf: bool) -> Result<()> {
    standard_kats()?;
    let p = &v["primitives"];
    let x = &p["xchacha"];
    let key = arr(&val(x, "key")?)?;
    let nonce = val(x, "nonce")?;
    let plain = val(x, "plaintext")?;
    let aad = val(x, "aad")?;
    let ct = crypto::seal(&key, &nonce, &plain, &aad)?;
    eq(&ct, &val(x, "ciphertext")?, "independent XChaCha")?;
    eq(
        &crypto::open(&key, &nonce, &ct, &aad)?,
        &plain,
        "XChaCha open",
    )?;
    let mut bad = ct.clone();
    bad[0] ^= 1;
    reject(
        crypto::open(&key, &nonce, &bad, &aad),
        "AEAD tamper accepted",
    )?;
    reject(
        crypto::open(&key, &nonce, &ct, b"wrong context"),
        "AEAD context accepted",
    )?;
    reject(crypto::open(&[0; 32], &nonce, &ct, &aad), "AEAD wrong key")?;
    reject(crypto::open(&key, &nonce, &ct[..15], &aad), "short tag")?;
    let h = &p["hpke"];
    let sk = arr(&val(h, "private")?)?;
    let enc = val(h, "enc")?;
    let info = val(h, "info")?;
    let aad = val(h, "aad")?;
    let hct = val(h, "ciphertext")?;
    eq(
        &crypto::hpke_open(&sk, &enc, &info, &hct, &aad)?,
        &val(h, "plaintext")?,
        "independent HPKE receiver",
    )?;
    let (re, rc) = crypto::hpke_seal(
        &arr(&val(h, "public")?)?,
        &info,
        &val(h, "plaintext")?,
        &aad,
        &mut Fixed(val(h, "ikm")?),
    )?;
    eq(&re, &enc, "independent HPKE sender enc")?;
    eq(&rc, &hct, "independent HPKE sender ct")?;
    for e in [vec![0; 32], vec![1; 32], vec![0; 31]] {
        reject(
            crypto::hpke_open(&sk, &e, &info, &hct, &aad),
            "invalid/low-order HPKE enc",
        )?;
    }
    reject(
        crypto::hpke_open(&sk, &enc, b"wrong info", &hct, &aad),
        "HPKE info",
    )?;
    reject(
        crypto::hpke_open(&[7; 32], &enc, &info, &hct, &aad),
        "HPKE wrong key",
    )?;
    reject(
        crypto::hpke_seal(&[0; 32], &info, &[1; 32], &aad, &mut Fixed(vec![3; 32])),
        "all-zero encapsulation DH",
    )?;
    reject(
        crypto::hpke_seal(
            &arr(&val(h, "public")?)?,
            &info,
            &[1; 32],
            &aad,
            &mut Failed,
        ),
        "HPKE entropy failure",
    )?;
    let d = &p["hkdf"];
    let root = arr(&val(d, "root")?)?;
    let account = arr(&val(d, "account")?)?;
    eq(
        &*crypto::derive(&root, &account, 1, "recipient-seed")?,
        &val(d, "recipient")?,
        "independent recipient HKDF",
    )?;
    eq(
        &*crypto::derive(&root, &account, 1, "signing-seed")?,
        &val(d, "signing")?,
        "independent signing HKDF",
    )?;
    let a = &p["argon2"];
    if full_kdf {
        eq(
            &*crypto::kdf(&val(a, "pass")?, &val(a, "salt")?, 64 * 1024 * 1024)?,
            &val(a, "output")?,
            "independent full production KDF",
        )?;
    }
    reject(
        crypto::kdf(&vec![0; 1025], &[0; 16], 64 * 1024 * 1024),
        "pass length",
    )?;
    reject(crypto::kdf(b"x", &[0; 15], 64 * 1024 * 1024), "salt length")?;
    reject(
        crypto::kdf(b"x", &[0; 16], 32 * 1024 * 1024),
        "injected budget",
    )?;
    reject(crypto::random::<32>(&mut Failed), "entropy failure")?;
    let r = crypto::random::<32>(&mut crypto::NativeEntropy)?;
    ensure(r.iter().any(|x| *x != 0), "secure entropy output")?;
    let mut usage = crypto::EpochUsage::default();
    usage.publish([1; 24], b"immutable")?;
    usage.publish([1; 24], b"immutable")?;
    ensure(usage.published == 1, "retry re-encrypted")?;
    reject(usage.publish([1; 24], b"other"), "nonce reuse")?;
    usage.published = 1u64 << 32;
    reject(usage.publish([2; 24], b"limit"), "usage overflow")?;
    Ok(())
}
fn operation(v: &mut Verifier<'_>, op: &Value) -> Result<()> {
    let h = arr(&val(op, "hash")?)?;
    match op["kind"].as_str() {
        Some("authority") => v.apply(&h),
        Some("snapshot") => v.append(&h),
        Some("restore") => crate::client_state::import_current(
            v,
            arr(&val(op, "expected_authority")?)?,
            arr(&val(op, "expected_head")?)?,
            h,
        ),
        _ => Err("unknown step".into()),
    }
}
pub fn run(full_kdf: bool) -> Result<Value> {
    let corpus: Value = serde_json::from_str(CORPUS).map_err(|_| "corpus JSON")?;
    primitives(&corpus, full_kdf)?;
    let raw = corpus["records"]
        .as_object()
        .ok_or("records")?
        .values()
        .map(|s| hex::decode(s.as_str().ok_or("record hex")?).map_err(|_| "hex".into()))
        .collect::<Result<Vec<_>>>()?;
    let store = Store::load(&raw)?;
    let mut results = Vec::new();
    for c in corpus["cases"].as_array().ok_or("cases")? {
        let mut verifier = Verifier::new(&store);
        for op in c["prefix"].as_array().ok_or("prefix")? {
            operation(&mut verifier, op).map_err(|e| format!("{} prefix: {e}", c["name"]))?;
        }
        let prior = (
            verifier.current.as_ref().map(|a| a.hash),
            verifier
                .heads
                .iter()
                .map(|(v, h)| (*v, h.hash))
                .collect::<Vec<_>>(),
        );
        let outcome = operation(&mut verifier, &c["operation"]);
        let accepted = outcome.is_ok();
        ensure(
            accepted == c["accept"].as_bool().ok_or("case expected")?,
            &format!("{} mismatch: {outcome:?}", c["name"]),
        )?;
        if let Some(expected) = c["rejection"].as_str() {
            ensure(
                outcome.as_ref().err().map(String::as_str) == Some(expected),
                "semantic regression rejected for unrelated reason",
            )?;
        }
        if !accepted {
            ensure(
                prior
                    == (
                        verifier.current.as_ref().map(|a| a.hash),
                        verifier
                            .heads
                            .iter()
                            .map(|(v, h)| (*v, h.hash))
                            .collect::<Vec<_>>(),
                    ),
                "failed transition mutated state",
            )?;
        }
        results.push(
            json!({"name":c["name"],"accepted":accepted,"rejection":outcome.err(),"pass":true}),
        );
    }
    let rotation = corpus["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|c| c["name"] == "complete atomic rotation current objects")
        .ok_or("rotation case")?;
    let mut rotating = Verifier::new(&store);
    for op in rotation["prefix"].as_array().ok_or("rotation prefix")? {
        operation(&mut rotating, op)?;
    }
    let owner = rotating.current.as_ref().ok_or("rotation state")?.actor;
    let private = arr(&val(
        &corpus["synthetic_test_material"][hex::encode(owner)],
        "x",
    )?)?;
    let before = decrypt_view(&rotating, owner, private)?;
    operation(&mut rotating, &rotation["operation"])?;
    let after = decrypt_view(&rotating, owner, private)?;
    ensure(before == after, "rotation changed current plaintext")?;
    let activation = corpus["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|c| c["name"] == "verified accepted Member activation")
        .ok_or("activation case")?;
    let mut pv = Verifier::new(&store);
    for op in activation["prefix"].as_array().ok_or("activation prefix")? {
        operation(&mut pv, op)?;
    }
    let previous = pv.current.as_ref().ok_or("pending authority")?.hash;
    let candidate = arr(&val(&activation["operation"], "hash")?)?;
    let mut local = crate::client_state::Attempt::prepare(&pv, candidate)?;
    ensure(
        pv.current.as_ref().ok_or("previous")?.hash == previous,
        "proposal activated before send",
    )?;
    ensure(
        local.abandon()?.is_empty(),
        "local cancellation disclosed key",
    )?;
    let mut sent = crate::client_state::Attempt::prepare(&pv, candidate)?;
    sent.send()?;
    reject(
        sent.reconcile(previous),
        "old head falsely reconciled disclosure",
    )?;
    ensure(
        !sent.abandon()?.is_empty(),
        "sent abandoned activation failed to require rotation",
    )?;
    let mut committed = crate::client_state::Attempt::prepare(&pv, candidate)?;
    committed.send()?;
    committed.reconcile(candidate)?;
    ensure(
        committed.stage == crate::client_state::Stage::Committed,
        "commit reconciliation",
    )?;
    reject(committed.abandon(), "committed activation cancelled")?;
    let mut exports = Vec::new();
    let passkey = arr(&val(&corpus["primitives"]["argon2"], "output")?)?;
    for c in corpus["exports"].as_array().ok_or("exports")? {
        let result = crate::backup::verify_export_code(
            &val(c, "wire")?,
            c["recovery_code"].as_str().ok_or("recovery code fixture")?,
            &passkey,
        );
        ensure(
            result.is_ok() == c["accept"].as_bool().ok_or("export expected")?,
            &format!("{} mismatch: {result:?}", c["name"]),
        )?;
        let rejection = result.as_ref().err().cloned();
        if let Some(expected) = c["rejection"].as_str() {
            ensure(
                rejection.as_deref() == Some(expected),
                "selected semantic regression rejected for unrelated reason",
            )?;
        }
        exports.push(
            json!({"name":c["name"],"accepted":result.is_ok(),"rejection":rejection,"result":result.ok(),"pass":true}),
        );
    }
    // Strict enrollment/signature negatives reach the actual chosen verifier.
    let enrolled = store.identities.values().next().ok_or("identity sample")?;
    let iw = store
        .wires
        .values()
        .find(|w| w.kind == "identity" && w.signer == Some(enrolled.key))
        .ok_or("identity wire")?;
    for public in [[0u8; 32], {
        let mut b = [0xff; 32];
        b[0] = 0xed;
        b[31] = 0x7f;
        b
    }] {
        let mut weak = enrolled.clone();
        weak.ed = public;
        reject(
            crypto::verify(iw, &weak),
            "weak/noncanonical enrollment accepted",
        )?;
    }
    let mut badsig = iw.signature()?;
    badsig[32..].fill(0xff);
    let mut signed = iw.clone();
    signed.bytes = t(
        "wire",
        &[
            &1u16.to_be_bytes(),
            &1u16.to_be_bytes(),
            b"identity",
            &t("signed-envelope", &[&enrolled.key, &iw.payload, &badsig]),
        ],
    );
    reject(
        crypto::verify(&signed, enrolled),
        "noncanonical scalar accepted",
    )?;
    badsig = iw.signature()?;
    badsig[0] ^= 1;
    signed.bytes = t(
        "wire",
        &[
            &1u16.to_be_bytes(),
            &1u16.to_be_bytes(),
            b"identity",
            &t("signed-envelope", &[&enrolled.key, &iw.payload, &badsig]),
        ],
    );
    reject(
        crypto::verify(&signed, enrolled),
        "signature tamper accepted",
    )?;
    let scalar_overflow = fields(&iw.payload, "identity", 4)?;
    let short = t(
        "identity",
        &[
            scalar_overflow[0],
            &[1],
            scalar_overflow[2],
            scalar_overflow[3],
        ],
    );
    let mut wrong = iw.clone();
    wrong.payload = short;
    reject(Identity::parse(&wrong), "wrong integer width accepted")?;
    // Actual framed records are mutated; this is separate from correctly signed semantic negatives above.
    let sample = store
        .wires
        .values()
        .find(|w| w.kind == "authority")
        .ok_or("sample")?;
    let mut altered = sample.clone();
    altered.kind = "snapshot".into();
    reject(
        crypto::verify(
            &altered,
            &store.identities[&sample.signer.ok_or("sample signer")?],
        ),
        "kind domain substitution",
    )?;
    let mut trailing = sample.bytes.clone();
    trailing.push(0);
    reject(Wire::parse(&trailing), "trailing accepted")?;
    for width in [0, 1, 15, 63] {
        reject(Wire::parse(&sample.bytes[..width]), "truncated accepted")?;
    }
    let three = t(
        "wire",
        &[&1u16.to_be_bytes(), &1u16.to_be_bytes(), b"unknown", b""],
    );
    reject(Wire::parse(&three), "unknown kind accepted")?;
    reject(token("bitbid-team1:AA=="), "padded transport")?;
    reject(token("bitbid2:AA"), "legacy dispatch")?;
    reject(list(&u32::MAX.to_be_bytes()), "unbounded list")?;
    reject(add(u64::MAX), "numeric overflow")?;
    Ok(
        json!({"pass":true,"schema_sha256":corpus["schema_sha256"],"corpus_sha256":hex::encode(crypto::hash(CORPUS.as_bytes())),"records":raw.len(),"primitive_profile_pass":true,"full_production_kdf":full_kdf,"transcripts":results,"exports":exports}),
    )
}
