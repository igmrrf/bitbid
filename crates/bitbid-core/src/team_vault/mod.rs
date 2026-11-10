//! Pure version-one team-vault protocol; legacy wallet/token formats are separate.
//!
//! Trust is explicit: identity self-signatures prove possession; a trusted-channel
//! fingerprint or the creator's held account is needed to bootstrap a team.
//! Accepted heads detect rollback observed by this handle, not global freshness.
//! A readable historical export never becomes live authority. See the usage guide.
//!
//! Secret guards erase controlled allocations on drop, best effort. Borrowed input,
//! compiler temporaries, JS, OS and caller copies are outside that guarantee.
//! Standard library map allocations may abort on actual process OOM; checked byte
//! budgets and fallible owned buffers are not a process-wide allocator guarantee.
//!
//! ```compile_fail
//! use bitbid_core::team_vault::VerifiedAuthority;
//! let forged = VerifiedAuthority { };
//! ```
//! ```compile_fail
//! use bitbid_core::team_vault::Account;
//! fn copy_secret(a: Account) { let _ = a.clone(); }
//! ```
mod account;
mod backup;
mod codec;
mod crypto;
mod protocol;
mod state;
mod vault;

pub use account::{Account, AccountBackup, KdfBudget, RecoveryCode, TrustState};
use codec::{Identity, Wire};
pub use state::{
    Activation, HistoricalProof, Operation, RecordSet, TeamPin, TrustedPeer, VerifiedAuthority,
    VerifiedSnapshot,
};
use std::fmt;
pub use vault::{Content, Plaintext, ReadableExport, VaultEpoch};

pub type Id = [u8; 16];
pub type Digest = [u8; 32];
pub type Result<T> = std::result::Result<T, TeamVaultError>;
/// A finite validation reason, never an input/secret/backend error payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TeamVaultError(&'static str);
impl TeamVaultError {
    /// Adapter failure without retaining its source, including partially filled entropy.
    pub const fn entropy_unavailable() -> Self {
        Self("secure entropy unavailable")
    }
    pub fn reason(&self) -> &'static str {
        self.0
    }
}
impl From<&'static str> for TeamVaultError {
    fn from(s: &'static str) -> Self {
        Self(s)
    }
}
impl fmt::Display for TeamVaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("team-vault operation rejected")
    }
}
impl fmt::Debug for TeamVaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TeamVaultError(<redacted>)")
    }
}
impl std::error::Error for TeamVaultError {}
/// Host cryptographic entropy. On error callers discard the whole destination.
/// Implementations must never substitute a fallback PRNG; deterministic adapters are tests only.
pub trait Entropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Identity,
    Grant,
    Content,
    Authority,
    Snapshot,
    Acceptance,
    TeamAnchor,
    Export,
    PassWrapper,
    RecoveryWrapper,
    TrustWrapper,
}
impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Grant => "grant",
            Self::Content => "content",
            Self::Authority => "authority",
            Self::Snapshot => "snapshot",
            Self::Acceptance => "acceptance",
            Self::TeamAnchor => "team-anchor",
            Self::Export => "export",
            Self::PassWrapper => "pass-wrapper",
            Self::RecoveryWrapper => "recovery-wrapper",
            Self::TrustWrapper => "trust-wrapper",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "identity" => Ok(Self::Identity),
            "grant" => Ok(Self::Grant),
            "content" => Ok(Self::Content),
            "authority" => Ok(Self::Authority),
            "snapshot" => Ok(Self::Snapshot),
            "acceptance" => Ok(Self::Acceptance),
            "team-anchor" => Ok(Self::TeamAnchor),
            "export" => Ok(Self::Export),
            "pass-wrapper" => Ok(Self::PassWrapper),
            "recovery-wrapper" => Ok(Self::RecoveryWrapper),
            "trust-wrapper" => Ok(Self::TrustWrapper),
            _ => Err("unknown kind".into()),
        }
    }
    fn signed(self) -> bool {
        !matches!(
            self,
            Self::PassWrapper | Self::RecoveryWrapper | Self::TrustWrapper
        )
    }
}
/// Canonical, untrusted encrypted/public transport. Parsing confers no authority.
#[derive(Clone)]
pub struct Record(Wire);
impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("kind", &self.0.kind)
            .finish_non_exhaustive()
    }
}
impl Record {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Wire::parse(bytes)?))
    }
    pub fn from_token(token: &str) -> Result<Self> {
        Self::parse(&codec::token(token)?)
    }
    pub fn to_token(&self) -> String {
        use base64::Engine;
        format!(
            "bitbid-team1:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.as_bytes())
        )
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.bytes
    }
    pub fn hash(&self) -> Digest {
        self.0.hash()
    }
    pub fn kind(&self) -> Kind {
        Kind::parse(&self.0.kind).expect("parsed finite kind")
    }
    /// Only public canonical signed payload/ciphertext, never decrypted content.
    pub fn payload(&self) -> &[u8] {
        &self.0.payload
    }
    pub fn signer(&self) -> Option<Digest> {
        self.0.signer
    }
    pub fn verify_identity(&self) -> Result<VerifiedIdentity> {
        let i = Identity::parse(&self.0)?;
        crypto::verify(&self.0, &i)?;
        Ok(VerifiedIdentity {
            inner: i,
            wire: self.clone(),
        })
    }
}
#[derive(Clone)]
pub struct VerifiedIdentity {
    inner: Identity,
    wire: Record,
}
impl fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("account", &self.inner.account)
            .field("generation", &self.inner.generation)
            .finish_non_exhaustive()
    }
}
impl VerifiedIdentity {
    pub fn account_id(&self) -> Id {
        self.inner.account
    }
    pub fn generation(&self) -> u64 {
        self.inner.generation
    }
    pub fn key_id(&self) -> Digest {
        self.inner.key
    }
    pub fn fingerprint(&self) -> Digest {
        crypto::hash(&codec::t("fingerprint", &[self.wire.payload()]))
    }
    pub fn record(&self) -> &Record {
        &self.wire
    }
    /// `expected` must come from the authenticated trusted channel, never the host packet.
    pub fn verify_fingerprint(&self, expected: Digest) -> Result<TrustedPeer> {
        codec::ensure(self.fingerprint() == expected, "fingerprint mismatch")?;
        Ok(TrustedPeer::new(self.clone()))
    }
}

#[cfg(test)]
mod primitive_tests;
