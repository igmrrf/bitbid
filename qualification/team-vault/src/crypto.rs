use crate::codec::*;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
pub fn hash(b: &[u8]) -> D {
    Sha256::digest(b).into()
}
pub fn verify(w: &Wire, i: &Identity) -> Result<()> {
    ensure(w.signer == Some(i.key), "signer identity")?;
    let p = curve25519_dalek::edwards::CompressedEdwardsY(i.ed)
        .decompress()
        .ok_or("invalid signing point")?;
    ensure(
        p.compress().to_bytes() == i.ed && !p.is_small_order(),
        "noncanonical/weak signing key",
    )?;
    let sig = w.signature()?;
    let r = curve25519_dalek::edwards::CompressedEdwardsY(arr(&sig[..32])?)
        .decompress()
        .ok_or("invalid R")?;
    ensure(
        r.compress().to_bytes() == sig[..32] && !r.is_small_order(),
        "noncanonical/weak R",
    )?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&i.ed).map_err(|_| "ed key")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    vk.verify_strict(
        &t("signed-record", &[w.kind.as_bytes(), &i.key, &w.payload]),
        &sig,
    )
    .map_err(|_| "signature".into())
}
pub fn derive(root: &D, account: &Id, generation: u64, label: &str) -> Result<Zeroizing<D>> {
    let mut out = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<Sha256>::new(None, root)
        .expand(&t(label, &[account, &generation.to_be_bytes()]), &mut *out)
        .map_err(|_| "HKDF")?;
    Ok(out)
}
pub fn recovery_key(r: &D, account: &Id, generation: u64, key: &D) -> Result<Zeroizing<D>> {
    let mut out = Zeroizing::new([0; 32]);
    hkdf::Hkdf::<Sha256>::new(None, r)
        .expand(
            &t("recovery-wrap", &[account, &generation.to_be_bytes(), key]),
            &mut *out,
        )
        .map_err(|_| "HKDF")?;
    Ok(out)
}
pub fn kdf(pass: &[u8], salt: &[u8], budget: usize) -> Result<Zeroizing<D>> {
    ensure(pass.len() <= 1024 && salt.len() == 16, "KDF input")?;
    ensure(budget >= 65536 * 1024, "KDF allocation budget")?;
    let mut out = Zeroizing::new([0u8; 32]);
    let params = argon2::Params::new(65536, 3, 4, Some(32)).map_err(|_| "KDF params")?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    // Reserve fallibly before invoking the algorithm; no profile fallback.
    let mut blocks = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(65536)
        .map_err(|_| "KDF allocation")?;
    blocks.resize(65536, argon2::Block::default());
    a.hash_password_into_with_memory(pass, salt, &mut *out, &mut blocks)
        .map_err(|_| "KDF")?;
    Ok(out)
}
pub fn seal(key: &D, nonce: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    ensure(nonce.len() == 24, "nonce width")?;
    XChaCha20Poly1305::new(key.into())
        .encrypt((&arr::<24>(nonce)?).into(), Payload { msg: plain, aad })
        .map_err(|_| "AEAD".into())
}
pub fn open(key: &D, nonce: &[u8], cipher: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure(nonce.len() == 24 && cipher.len() >= 16, "nonce/tag width")?;
    XChaCha20Poly1305::new(key.into())
        .decrypt((&arr::<24>(nonce)?).into(), Payload { msg: cipher, aad })
        .map(Zeroizing::new)
        .map_err(|_| "AEAD authentication".into())
}
pub trait Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}
pub struct NativeEntropy;
impl Entropy for NativeEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        getrandom::fill(out).map_err(|_| "secure entropy unavailable".into())
    }
}
pub fn random<const N: usize>(e: &mut impl Entropy) -> Result<Zeroizing<[u8; N]>> {
    let mut b = Zeroizing::new([0; N]);
    e.fill(&mut *b)?;
    Ok(b)
}
#[derive(Default)]
pub struct EpochUsage {
    pub published: u64,
    pub nonces: std::collections::BTreeSet<[u8; 24]>,
    pub immutable: std::collections::BTreeSet<D>,
}
impl EpochUsage {
    pub fn publish(&mut self, nonce: [u8; 24], wire: &[u8]) -> Result<()> {
        let h = hash(wire);
        if self.immutable.contains(&h) {
            return Ok(());
        }
        ensure(self.published < 1u64 << 32, "epoch usage limit")?;
        ensure(self.nonces.insert(nonce), "nonce reused")?;
        self.published += 1;
        self.immutable.insert(h);
        Ok(())
    }
}

pub fn hpke_open(
    sk: &D,
    enc: &[u8],
    info: &[u8],
    cipher: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use hpke::{
        Deserializable, OpModeR,
        aead::ChaCha20Poly1305,
        kdf::HkdfSha256,
        kem::{Kem, X25519HkdfSha256},
    };
    let sk = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(sk).map_err(|_| "HPKE private")?;
    let enc =
        <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(enc).map_err(|_| "HPKE enc length")?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        cipher,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| "HPKE authentication/DH".into())
}
pub fn hpke_seal(
    pk: &D,
    info: &[u8],
    plain: &[u8],
    aad: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(Vec<u8>, Vec<u8>)> {
    use hpke::{
        Deserializable, OpModeS, Serializable,
        aead::ChaCha20Poly1305,
        kdf::HkdfSha256,
        kem::{Kem, X25519HkdfSha256},
    };
    struct Prefilled {
        b: Zeroizing<D>,
        offset: usize,
    }
    impl rand_core::TryRng for Prefilled {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            rand_core::utils::next_word_via_fill(self)
        }
        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            rand_core::utils::next_word_via_fill(self)
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> std::result::Result<(), Self::Error> {
            let end = self
                .offset
                .checked_add(out.len())
                .expect("HPKE RNG invariant");
            out.copy_from_slice(
                self.b
                    .get(self.offset..end)
                    .expect("HPKE exceeded prefetched entropy"),
            );
            self.offset = end;
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Prefilled {}
    let b = random::<32>(entropy)?;
    let mut rng = Prefilled { b, offset: 0 };
    let pk = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(pk).map_err(|_| "HPKE public")?;
    let (enc, ct) =
        hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &pk,
            info,
            plain,
            aad,
            &mut rng,
        )
        .map_err(|_| "HPKE DH/seal")?;
    ensure(rng.offset == 32, "HPKE entropy consumption")?;
    Ok((enc.to_bytes().to_vec(), ct))
}
