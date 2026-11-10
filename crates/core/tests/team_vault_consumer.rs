use bitbid_webapp_core::team_vault::*;
#[path = "../../../../bitsec/crates/bitbid-core/tests/team_vault_support/mod.rs"]
mod support;
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn public_facade_frozen_vectors() {
    let identity: Option<bitbid_core::team_vault::VerifiedIdentity> = None;
    let _: Option<VerifiedIdentity> = identity;
    assert_eq!(support::run()["pass"], true);
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
fn real_webcrypto_adapter() {
    let mut e = bitbid_webapp_core::team_entropy::BrowserEntropy;
    let a = Account::generate(Account::random_id(&mut e).unwrap(), 1, &mut e)
        .unwrap()
        .0;
    let b = Account::generate(Account::random_id(&mut e).unwrap(), 1, &mut e)
        .unwrap()
        .0;
    assert_ne!(a.identity().key_id(), b.identity().key_id());
}
