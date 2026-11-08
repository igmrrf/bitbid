//! Decoding of BsecSecretRegistry JSON-RPC responses into plain records.
//!
//! Only two read paths are implemented: `eth_getLogs` over the `SecretShared`
//! event (enumeration) and `eth_call` to `getSecretInfo(bytes32)` (single record).
//!
//! Honesty rule: a JSON-RPC error, a missing result, or a short/malformed ABI
//! buffer is an `Err`. The decoder never fabricates a record or reports success.

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::address::{bytes_to_hex, checksum_address, hex_to_bytes, keccak256};

/// A single registry entry, normalized from either decode path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryRecord {
    /// `bytes32` secret id, normalized to `0x` + 64 lowercase hex.
    pub id: String,
    /// IPFS CID of the encrypted payload.
    pub cid: String,
    /// Creator / sender address (EIP-55 checksummed).
    pub owner: String,
    /// Recipient address (checksummed), or `0x000...0` for public secrets.
    pub recipient: String,
    /// Unix seconds at which the record expires.
    pub expires_at: u64,
    /// Maximum number of (non-public) reads allowed.
    pub max_reads: u32,
    /// Reads recorded so far.
    pub reads: u32,
    /// Whether the owner has revoked the record.
    pub revoked: bool,
    /// Unix seconds at which the record was created (0 when only a log was decoded).
    pub created_at: u64,
    /// Public secrets are readable by anyone and are not read-limited.
    pub is_public: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("invalid JSON-RPC response: {0}")]
    Json(String),
    #[error("JSON-RPC error: {0}")]
    Rpc(String),
    #[error("JSON-RPC response contains no result")]
    NoResult,
    #[error("unexpected JSON-RPC result shape: {0}")]
    Shape(&'static str),
    #[error("ABI decode error: {0}")]
    Abi(String),
}

/// keccak256 of the `SecretShared` event signature, as a 32-byte topic.
pub fn secret_shared_topic0() -> [u8; 32] {
    keccak256(b"SecretShared(bytes32,address,address,string,uint64,uint32,bool)")
}

/// 4-byte selector for `getSecretInfo(bytes32)`.
pub fn get_secret_info_selector() -> [u8; 4] {
    let h = keccak256(b"getSecretInfo(bytes32)");
    [h[0], h[1], h[2], h[3]]
}

/// Encode `getSecretInfo(bytes32)` calldata as a `0x` hex string.
pub fn encode_get_secret_info_calldata(id: &str) -> Result<String, DecodeError> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&get_secret_info_selector());
    out.extend_from_slice(&encode_bytes32(id)?);
    Ok(bytes_to_hex(&out))
}

/// Encode a secret id into a left-aligned `bytes32`, mirroring the CLI: a `0x` hex
/// string decoding to <= 32 bytes, or a raw UTF-8 id of <= 32 bytes.
pub fn encode_bytes32(id: &str) -> Result<[u8; 32], DecodeError> {
    let mut bytes = [0u8; 32];
    let raw = if id.starts_with("0x") || id.starts_with("0X") {
        hex_to_bytes(id).map_err(DecodeError::Abi)?
    } else {
        id.as_bytes().to_vec()
    };
    if raw.len() > 32 {
        return Err(DecodeError::Abi(format!(
            "secret id is {} bytes; max 32",
            raw.len()
        )));
    }
    bytes[..raw.len()].copy_from_slice(&raw);
    Ok(bytes)
}

fn rpc_result(body: &str) -> Result<Value, DecodeError> {
    let v: Value = serde_json::from_str(body).map_err(|e| DecodeError::Json(e.to_string()))?;
    if let Some(err) = v.get("error")
        && !err.is_null()
    {
        return Err(DecodeError::Rpc(err.to_string()));
    }
    v.get("result").cloned().ok_or(DecodeError::NoResult)
}

fn word(data: &[u8], idx: usize) -> Result<&[u8], DecodeError> {
    data.get(idx * 32..idx * 32 + 32)
        .ok_or_else(|| DecodeError::Abi(format!("word {} out of range", idx)))
}

fn word_u64(w: &[u8]) -> u64 {
    let mut acc = 0u64;
    for &b in &w[24..32] {
        acc = (acc << 8) | b as u64;
    }
    acc
}

fn word_offset(w: &[u8]) -> Result<usize, DecodeError> {
    if w[..24].iter().any(|b| *b != 0) {
        return Err(DecodeError::Abi("offset exceeds supported range".into()));
    }
    usize::try_from(word_u64(w))
        .map_err(|_| DecodeError::Abi("offset exceeds platform range".into()))
}

fn word_u32(w: &[u8]) -> u32 {
    let mut acc = 0u32;
    for &b in &w[28..32] {
        acc = (acc << 8) | b as u32;
    }
    acc
}

fn word_addr(w: &[u8]) -> [u8; 20] {
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..32]);
    a
}

fn address_from_topic(topic: &str) -> Result<String, DecodeError> {
    let bytes = hex_to_bytes(topic).map_err(DecodeError::Abi)?;
    if bytes.len() != 32 {
        return Err(DecodeError::Abi(format!(
            "topic is {} bytes, expected 32",
            bytes.len()
        )));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes[12..32]);
    Ok(checksum_address(&addr))
}

fn normalize_bytes32(hex: &str) -> Result<String, DecodeError> {
    let bytes = hex_to_bytes(hex).map_err(DecodeError::Abi)?;
    if bytes.len() != 32 {
        return Err(DecodeError::Abi(format!(
            "id is {} bytes, expected 32",
            bytes.len()
        )));
    }
    Ok(bytes_to_hex(&bytes))
}

fn decode_string_at(data: &[u8], offset: usize) -> Result<String, DecodeError> {
    let start = offset
        .checked_add(32)
        .ok_or_else(|| DecodeError::Abi("string offset overflow".into()))?;
    let len_word = data
        .get(offset..start)
        .ok_or_else(|| DecodeError::Abi("string length word out of range".into()))?;
    let len = word_offset(len_word)?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| DecodeError::Abi("string length overflow".into()))?;
    let body = data
        .get(start..end)
        .ok_or_else(|| DecodeError::Abi("string body out of range".into()))?;
    String::from_utf8(body.to_vec()).map_err(|e| DecodeError::Abi(format!("string not UTF-8: {e}")))
}

/// Decode an `eth_getLogs` JSON-RPC response for `SecretShared` logs.
///
/// Logs whose first topic is not the `SecretShared` signature are skipped (a
/// node may return logs from other events if the filter was loose). Any log that
/// *is* ours but is malformed fails the whole decode.
pub fn decode_get_logs_response(body: &str) -> Result<Vec<RegistryRecord>, DecodeError> {
    let result = rpc_result(body)?;
    let logs = result
        .as_array()
        .ok_or(DecodeError::Shape("getLogs result is not an array"))?;
    let expected_topic = secret_shared_topic0();
    let mut out = Vec::new();

    for log in logs {
        let topics = log
            .get("topics")
            .and_then(Value::as_array)
            .ok_or(DecodeError::Shape("log has no topics array"))?;
        let t0 = topics
            .first()
            .and_then(Value::as_str)
            .ok_or(DecodeError::Shape("log has no first topic"))?;
        let t0_bytes = hex_to_bytes(t0).map_err(DecodeError::Abi)?;
        if t0_bytes != expected_topic {
            continue;
        }
        if topics.len() < 4 {
            return Err(DecodeError::Shape(
                "SecretShared log needs 3 indexed topics",
            ));
        }
        let id = normalize_bytes32(topics[1].as_str().ok_or(DecodeError::Shape("topic[1]"))?)?;
        let owner = address_from_topic(topics[2].as_str().ok_or(DecodeError::Shape("topic[2]"))?)?;
        let recipient =
            address_from_topic(topics[3].as_str().ok_or(DecodeError::Shape("topic[3]"))?)?;

        let data_hex = log
            .get("data")
            .and_then(Value::as_str)
            .ok_or(DecodeError::Shape("log has no data"))?;
        let data = hex_to_bytes(data_hex).map_err(DecodeError::Abi)?;
        if data.len() < 4 * 32 {
            return Err(DecodeError::Abi(
                "SecretShared data shorter than 4 words".into(),
            ));
        }
        let cid_offset = word_offset(word(&data, 0)?)?;
        let expires_at = word_u64(word(&data, 1)?);
        let max_reads = word_u32(word(&data, 2)?);
        let is_public = word_u64(word(&data, 3)?) != 0;
        let cid = decode_string_at(&data, cid_offset)?;

        out.push(RegistryRecord {
            id,
            cid,
            owner,
            recipient,
            expires_at,
            max_reads,
            reads: 0,
            revoked: false,
            created_at: 0,
            is_public,
        });
    }
    Ok(out)
}

/// Decode an `eth_call` JSON-RPC response for `getSecretInfo(bytes32)`.
///
/// `id` is the id that was queried; it is not part of the return tuple and is
/// passed through verbatim (normalized to `0x` hex when it is a hex id).
pub fn decode_get_secret_info_response(
    body: &str,
    id: &str,
) -> Result<RegistryRecord, DecodeError> {
    let result = rpc_result(body)?;
    let hex = result.as_str().ok_or(DecodeError::Shape(
        "getSecretInfo result is not a hex string",
    ))?;
    let data = hex_to_bytes(hex).map_err(DecodeError::Abi)?;
    decode_get_secret_info(&data, id)
}

/// Decode raw `getSecretInfo` return bytes.
pub fn decode_get_secret_info(data: &[u8], id: &str) -> Result<RegistryRecord, DecodeError> {
    if data.len() < 32 * 11 {
        return Err(DecodeError::Abi(format!(
            "getSecretInfo return data too short ({} bytes)",
            data.len()
        )));
    }
    let sender = word_addr(word(data, 0)?);
    let recipient = word_addr(word(data, 1)?);
    let cid_offset = word_offset(word(data, 2)?)?;
    let created_at = word_u64(word(data, 3)?);
    let expires_at = word_u64(word(data, 4)?);
    let max_reads = word_u32(word(data, 5)?);
    let reads = word_u32(word(data, 6)?);
    let revoked = word_u64(word(data, 7)?) != 0;
    let is_public = word_u64(word(data, 8)?) != 0;
    let cid = decode_string_at(data, cid_offset)?;

    let normalized_id = if id.starts_with("0x") || id.starts_with("0X") {
        let bytes = hex_to_bytes(id).map_err(DecodeError::Abi)?;
        let mut padded = [0u8; 32];
        if bytes.len() > 32 {
            return Err(DecodeError::Abi("id longer than 32 bytes".into()));
        }
        padded[..bytes.len()].copy_from_slice(&bytes);
        bytes_to_hex(&padded)
    } else {
        id.to_string()
    };

    Ok(RegistryRecord {
        id: normalized_id,
        cid,
        owner: checksum_address(&sender),
        recipient: checksum_address(&recipient),
        expires_at,
        max_reads,
        reads,
        revoked,
        created_at,
        is_public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word_u128(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..32].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn word_addr(a: &[u8; 20]) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..32].copy_from_slice(a);
        w
    }

    fn push_word(buf: &mut Vec<u8>, w: &[u8; 32]) {
        buf.extend_from_slice(w);
    }

    /// Build a getSecretInfo return blob: 11 head words + dynamic CID tail at 352.
    fn get_info_return(sender: [u8; 20], recipient: [u8; 20], cid: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        push_word(&mut buf, &word_addr(&sender)); // 0 sender
        push_word(&mut buf, &word_addr(&recipient)); // 1 recipient
        push_word(&mut buf, &word_u128((11 * 32) as u128)); // 2 cid offset
        push_word(&mut buf, &word_u128(1_700_000_000)); // 3 created_at
        push_word(&mut buf, &word_u128(1_800_000_000)); // 4 expires_at
        push_word(&mut buf, &word_u128(3)); // 5 max_reads
        push_word(&mut buf, &word_u128(1)); // 6 read_count
        push_word(&mut buf, &word_u128(1)); // 7 revoked
        push_word(&mut buf, &word_u128(0)); // 8 is_public
        push_word(&mut buf, &word_u128(0)); // 9 is_expired
        push_word(&mut buf, &word_u128(0)); // 10 limit_reached
        assert_eq!(buf.len(), 11 * 32);
        push_word(&mut buf, &word_u128(cid.len() as u128));
        buf.extend_from_slice(cid.as_bytes());
        let pad = (32 - (cid.len() % 32)) % 32;
        buf.extend(std::iter::repeat_n(0u8, pad));
        buf
    }

    fn rpc_ok(result: serde_json::Value) -> String {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn decodes_get_secret_info_call() {
        let sender = [0xAAu8; 20];
        let recipient = [0xBBu8; 20];
        let id = format!("0x{}", "ab".repeat(32));
        let ret = get_info_return(sender, recipient, "QmTestCid123");
        let body = rpc_ok(serde_json::Value::String(bytes_to_hex(&ret)));
        let rec = decode_get_secret_info_response(&body, &id).unwrap();
        assert_eq!(rec.id, id);
        assert_eq!(rec.cid, "QmTestCid123");
        assert_eq!(rec.owner, checksum_address(&sender));
        assert_eq!(rec.recipient, checksum_address(&recipient));
        assert_eq!(rec.expires_at, 1_800_000_000);
        assert_eq!(rec.max_reads, 3);
        assert_eq!(rec.reads, 1);
        assert!(rec.revoked);
        assert!(!rec.is_public);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn decodes_get_logs_secret_shared() {
        let id = [0x11u8; 32];
        let owner = [0xAAu8; 20];
        let recipient = [0xBBu8; 20];
        let cid = "QmLogsCid";

        // data: 4 head words (offset=128, expires, maxReads, isPublic) + string tail.
        let mut data = Vec::new();
        push_word(&mut data, &word_u128(128));
        push_word(&mut data, &word_u128(1_900_000_000));
        push_word(&mut data, &word_u128(7));
        push_word(&mut data, &word_u128(0));
        push_word(&mut data, &word_u128(cid.len() as u128));
        data.extend_from_slice(cid.as_bytes());
        data.extend(std::iter::repeat_n(0u8, (32 - (cid.len() % 32)) % 32));

        let log = serde_json::json!({
            "address": "0x00000000000000000000000000000000000000cc",
            "topics": [
                bytes_to_hex(&secret_shared_topic0()),
                bytes_to_hex(&id),
                bytes_to_hex(&word_addr(&owner)),
                bytes_to_hex(&word_addr(&recipient)),
            ],
            "data": bytes_to_hex(&data),
        });
        let body = rpc_ok(serde_json::json!([log]));
        let recs = decode_get_logs_response(&body).unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.id, bytes_to_hex(&id));
        assert_eq!(r.cid, cid);
        assert_eq!(r.owner, checksum_address(&owner));
        assert_eq!(r.recipient, checksum_address(&recipient));
        assert_eq!(r.expires_at, 1_900_000_000);
        assert_eq!(r.max_reads, 7);
        assert_eq!(r.reads, 0);
        assert!(!r.revoked);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn skips_foreign_logs() {
        let log = serde_json::json!({
            "topics": [bytes_to_hex(&keccak256(b"OtherEvent(uint256)"))],
            "data": "0x",
        });
        let body = rpc_ok(serde_json::json!([log]));
        assert!(decode_get_logs_response(&body).unwrap().is_empty());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn rpc_error_is_err_not_a_record() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"boom"}}"#;
        assert!(matches!(
            decode_get_logs_response(body),
            Err(DecodeError::Rpc(_))
        ));
        assert!(matches!(
            decode_get_secret_info_response(body, "0x00"),
            Err(DecodeError::Rpc(_))
        ));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn missing_result_and_bad_json_are_err() {
        let body = r#"{"jsonrpc":"2.0","id":1}"#;
        assert_eq!(decode_get_logs_response(body), Err(DecodeError::NoResult));
        assert!(matches!(
            decode_get_logs_response("not json"),
            Err(DecodeError::Json(_))
        ));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn short_abi_buffer_is_err() {
        let body = rpc_ok(serde_json::Value::String("0x1234".into()));
        assert!(matches!(
            decode_get_secret_info_response(&body, "0x00"),
            Err(DecodeError::Abi(_))
        ));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn encode_bytes32_matches_cli_rules() {
        let mut expected = [0u8; 32];
        expected[..5].copy_from_slice(b"hello");
        assert_eq!(encode_bytes32("hello").unwrap(), expected);
        let id = format!("0x{}", "ab".repeat(32));
        assert_eq!(encode_bytes32(&id).unwrap(), [0xabu8; 32]);
        assert!(encode_bytes32(&"z".repeat(33)).is_err());
        assert!(
            encode_get_secret_info_calldata(&id)
                .unwrap()
                .starts_with("0x")
        );
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn rejects_oversized_abi_offsets_and_lengths() {
        let mut data = get_info_return([0; 20], [0; 20], "cid");
        data[2 * 32..3 * 32].fill(0xff);
        assert!(decode_get_secret_info(&data, "hello").is_err());
        let mut data = get_info_return([0; 20], [0; 20], "cid");
        data[11 * 32..12 * 32].fill(0xff);
        assert!(decode_get_secret_info(&data, "hello").is_err());
    }
}
