//! Real browser WebCrypto entropy. No fallback; no backend error or partial output escapes.
use crate::team_vault::{Entropy, Result, TeamVaultError};
#[derive(Default, Debug)]
pub struct BrowserEntropy;
impl Entropy for BrowserEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<()> {
        if team_getrandom::fill(destination).is_err() {
            destination.fill(0);
            return Err(TeamVaultError::entropy_unavailable());
        }
        Ok(())
    }
}
