//! Headless registry facts. Only the host's RPC port is consumed.
use serde_json::json;

use crate::{
    Error, Host,
    address::{bytes_to_hex, hex_to_bytes},
    registry::{encode_bytes32, get_secret_info_selector},
};

/// All eleven `getSecretInfo` tuple fields, including chain-computed flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryInfo {
    pub sender: [u8; 20],
    pub recipient: [u8; 20],
    pub ipfs_cid: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_reads: u32,
    pub read_count: u32,
    pub revoked: bool,
    pub is_public: bool,
    pub is_expired: bool,
    pub limit_reached: bool,
}

/// Read once at `latest`. Caller input errors precede any RPC; expiry and read
/// limits are returned verbatim, without consulting the clock or writing state.
pub fn read_registry_info(
    host: &Host,
    registry: &[u8; 20],
    secret_id: &str,
) -> Result<RegistryInfo, Error> {
    let id = encode_bytes32(secret_id).map_err(|e| Error::Invalid(e.to_string()))?;
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&get_secret_info_selector());
    calldata.extend_from_slice(&id);
    let result = host.rpc.call(
        "eth_call",
        json!([{"to": bytes_to_hex(registry), "data": bytes_to_hex(&calldata)}, "latest"]),
    )?;
    let hex = result
        .as_str()
        .ok_or_else(|| Error::Decode("eth_call returned non-string result".into()))?;
    let data = hex_to_bytes(hex).map_err(Error::Decode)?;
    decode_info(&data)
}

fn decode_info(data: &[u8]) -> Result<RegistryInfo, Error> {
    // This bound makes all fixed head slices below safe.
    if data.len() < 11 * 32 {
        return Err(Error::Decode(
            "registry tuple is shorter than eleven words".into(),
        ));
    }
    let word = |i: usize| &data[i * 32..(i + 1) * 32];
    let address = |i| {
        let mut out = [0; 20];
        out.copy_from_slice(&word(i)[12..]);
        out
    };
    let offset = pointer(word(2))?;
    let start = offset
        .checked_add(32)
        .ok_or_else(|| Error::Decode("CID offset overflow".into()))?;
    let length_word = data
        .get(offset..start)
        .ok_or_else(|| Error::Decode("CID length out of range".into()))?;
    let end = start
        .checked_add(pointer(length_word)?)
        .ok_or_else(|| Error::Decode("CID length overflow".into()))?;
    let cid = data
        .get(start..end)
        .ok_or_else(|| Error::Decode("CID body out of range".into()))?;
    let ipfs_cid = std::str::from_utf8(cid)
        .map_err(|e| Error::Decode(format!("CID is not UTF-8: {e}")))?
        .to_owned();
    Ok(RegistryInfo {
        sender: address(0),
        recipient: address(1),
        ipfs_cid,
        created_at: low_u64(word(3)),
        expires_at: low_u64(word(4)),
        max_reads: low_u64(word(5)) as u32,
        read_count: low_u64(word(6)) as u32,
        revoked: low_u64(word(7)) != 0,
        is_public: low_u64(word(8)) != 0,
        is_expired: low_u64(word(9)) != 0,
        limit_reached: low_u64(word(10)) != 0,
    })
}

// Preserve native low-word numeric/bool semantics; pointers instead reject
// nonzero high bytes so a huge ABI pointer cannot alias a small valid range.
fn low_u64(word: &[u8]) -> u64 {
    word[24..32].iter().fold(0, |v, b| (v << 8) | u64::from(*b))
}

fn pointer(word: &[u8]) -> Result<usize, Error> {
    if word[..24].iter().any(|b| *b != 0) {
        return Err(Error::Decode("CID pointer exceeds supported range".into()));
    }
    usize::try_from(low_u64(word))
        .map_err(|_| Error::Decode("CID pointer exceeds platform range".into()))
}
