//! Secure fallible OS entropy for the additive team-vault protocol Seam.
use bitbid_core::team_vault::{Entropy, Result, TeamVaultError};
#[derive(Default, Debug)]
pub struct OsEntropy;
impl Entropy for OsEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<()> {
        if team_getrandom::fill(destination).is_err() {
            destination.fill(0);
            return Err(TeamVaultError::entropy_unavailable());
        }
        Ok(())
    }
}
