use bitbid_adapters::team_entropy::OsEntropy;
use bitbid_core::team_vault::{Account, Entropy};
#[test]
fn os_entropy_real_public_consumer() {
    let mut entropy = OsEntropy;
    let mut a = [0; 64];
    let mut b = [0; 64];
    entropy.fill(&mut a).unwrap();
    entropy.fill(&mut b).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0; 64]);
    let (account, _) =
        Account::generate(Account::random_id(&mut entropy).unwrap(), 1, &mut entropy).unwrap();
    account.identity().record().verify_identity().unwrap();
}
