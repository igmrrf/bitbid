mod team_vault_support;
use bitbid_core::team_vault::*;
use team_vault_support::*;
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn frozen_public_protocol() {
    println!("{}", run());
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn guarded_account_entropy_wrappers_usage_and_real_failure() {
    assert!(Account::generate([1; 16], 1, &mut Failed).is_err());
    let (mut a, code) = Account::generate([1; 16], 1, &mut Fixed((1..=64).collect())).unwrap();
    let identity = a.identity().clone();
    let mut e = Fixed((1..=224).collect());
    let b = a
        .backup(
            "public synthetic passphrase",
            &code,
            &mut e,
            KdfBudget::PRODUCTION,
        )
        .unwrap();
    let recovered = Account::recover(
        &identity,
        &b.recovery_wrapper,
        &RecoveryCode::parse(&code.expose_secret_code()).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered.identity().key_id(), identity.key_id());
    let unlocked = Account::unlock(
        &identity,
        &b.pass_wrapper,
        "public synthetic passphrase",
        KdfBudget::PRODUCTION,
    )
    .unwrap();
    assert_eq!(unlocked.identity().key_id(), identity.key_id());
    assert!(Account::unlock(&identity, &b.pass_wrapper, "wrong", KdfBudget::PRODUCTION).is_err());
    assert!(
        Account::unlock(
            &identity,
            &b.pass_wrapper,
            "public synthetic passphrase",
            KdfBudget::limit_bytes(32 * 1024 * 1024)
        )
        .is_err()
    );
    let (replacement, _) = Account::generate([1; 16], 2, &mut Fixed(vec![7; 64])).unwrap();
    assert_ne!(replacement.identity().key_id(), identity.key_id());
    assert!(Account::recover(replacement.identity(), &b.recovery_wrapper, &code).is_err());
    let mut trust = TrustState::new();
    trust.pin_peer(&identity.verify_fingerprint(identity.fingerprint()).unwrap());
    let tw = a.wrap_trust(&trust, &mut e).unwrap();
    let restored = a.open_trust(&tw).unwrap();
    assert!(a.pinned_peer(&restored, identity.clone()).is_ok());
    assert!(identity.verify_fingerprint([0; 32]).is_err());
    let mut epoch = VaultEpoch::generate([2; 16], [3; 16], 1, &mut Fixed(vec![9; 32])).unwrap();
    let payload = Content::secret("name", "PRIVATE_SENTINEL").unwrap();
    assert_eq!(format!("{payload:?}"), "Content(<redacted>)");
    let w = epoch
        .encrypt(&a, [4; 32], [5; 16], 1, payload, &mut Fixed(vec![8; 24]))
        .unwrap();
    assert_eq!(w.hash(), Record::parse(w.as_bytes()).unwrap().hash());
    assert!(
        epoch
            .encrypt(
                &a,
                [4; 32],
                [5; 16],
                2,
                Content::deleted(),
                &mut Fixed(vec![8; 24])
            )
            .is_err()
    );
    assert!(
        epoch
            .encrypt(&a, [4; 32], [5; 16], 2, Content::deleted(), &mut Failed)
            .is_err()
    );
    epoch.observe_published(1u64 << 32).unwrap();
    assert!(
        epoch
            .encrypt(&a, [4; 32], [5; 16], 2, Content::deleted(), &mut e)
            .is_err()
    );
    assert_eq!(
        format!("{a:?} {code:?} {epoch:?}"),
        "Account(<redacted>) RecoveryCode(<redacted>) VaultEpoch(<redacted>)"
    );
    use std::error::Error;
    let err = TeamVaultError::entropy_unavailable();
    assert!(err.source().is_none());
    assert!(!format!("{err:?} {err}").contains("42"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn strict_enrollment_and_unknown_framing() {
    for public in [[0; 32], {
        let mut b = [0xff; 32];
        b[0] = 0xed;
        b[31] = 0x7f;
        b
    }] {
        let payload = transcript(
            "identity",
            &[&[1; 16], &1u64.to_be_bytes(), &[2; 32], &public],
        );
        use team_sha2::Digest as _;
        let key: [u8; 32] = team_sha2::Sha256::digest(&payload).into();
        let envelope = transcript("signed-envelope", &[&key, &payload, &[0; 64]]);
        let wire = transcript(
            "wire",
            &[
                &1u16.to_be_bytes(),
                &1u16.to_be_bytes(),
                b"identity",
                &envelope,
            ],
        );
        assert!(Record::parse(&wire).unwrap().verify_identity().is_err());
    }
    for (version, suite, kind) in [
        (2u16, 1u16, "identity"),
        (1, 2, "identity"),
        (1, 1, "unknown"),
    ] {
        let wire = transcript(
            "wire",
            &[
                &version.to_be_bytes(),
                &suite.to_be_bytes(),
                kind.as_bytes(),
                b"",
            ],
        );
        assert!(Record::parse(&wire).is_err());
    }
    assert!(Record::from_token("bitbid-team1:AA==").is_err());
    assert!(Record::from_token("bitbid2:AA").is_err());
}
fn transcript(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = b"bitbid-team-v1/".to_vec();
    out.extend((label.len() as u16).to_be_bytes());
    out.extend(label.as_bytes());
    out.extend((fields.len() as u16).to_be_bytes());
    for f in fields {
        out.extend((f.len() as u32).to_be_bytes());
        out.extend(*f)
    }
    out
}
