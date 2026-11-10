use super::{Entropy, TeamVaultError, codec::*, crypto};
use serde_json::Value;
fn val(v: &Value, k: &str) -> Result<Vec<u8>> {
    hex::decode(v[k].as_str().ok_or("KAT field")?).map_err(|_| "KAT hex".into())
}
fn eq(a: &[u8], b: &[u8], why: &'static str) -> Result<()> {
    ensure(a == b, why)
}
struct Fixed(Vec<u8>);
impl Entropy for Fixed {
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        if b.len() != self.0.len() {
            return Err(TeamVaultError::entropy_unavailable());
        }
        b.copy_from_slice(&self.0);
        Ok(())
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn four_official_primitive_kats() {
    standard_kats().unwrap();
}
fn standard_kats() -> Result<()> {
    let a: Value = serde_json::from_str(include_str!(
        "../../../../qualification/team-vault/vectors/rfc9106-argon2id-5.3.json"
    ))
    .map_err(|_| "RFC JSON")?;
    let ad = val(&a, "associated_data")?;
    let secret = val(&a, "secret")?;
    let mut params = team_argon2::ParamsBuilder::new();
    params
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(team_argon2::AssociatedData::new(&ad).map_err(|_| "RFC AD")?);
    let argon = team_argon2::Argon2::new_with_secret(
        &secret,
        team_argon2::Algorithm::Argon2id,
        team_argon2::Version::V0x13,
        params.build().map_err(|_| "RFC params")?,
    )
    .map_err(|_| "RFC secret")?;
    let mut output = [0; 32];
    argon
        .hash_password_into(&val(&a, "password")?, &val(&a, "salt")?, &mut output)
        .map_err(|_| "RFC Argon")?;
    eq(&output, &val(&a, "output")?, "RFC9106 KAT")?;
    let e: Value = serde_json::from_str(include_str!(
        "../../../../qualification/team-vault/vectors/rfc8032-ed25519-test1.json"
    ))
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
    let h: Value = serde_json::from_str(include_str!(
        "../../../../qualification/team-vault/vectors/rfc9180-base-32-1-3.json"
    ))
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
        "../../../../qualification/team-vault/vectors/libsodium-xchacha20poly1305-ietf-tv1.json"
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
