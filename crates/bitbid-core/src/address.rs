//! Hex and Keccak helpers shared by the seal and registry modules.
//!
//! Keccak-256 (not SHA3-256) is required because that is what the EVM and the
//! BsecSecretRegistry ABI use for function selectors, event topics, and EIP-55
//! checksummed addresses.

use sha3::{Digest, Keccak256};

/// Keccak-256 digest of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Lowercase, `0x`-prefixed hex of `bytes`.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// Decode an optional-`0x` hex string into bytes. Odd-length input is rejected.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.len() % 2 != 0 {
        return Err(format!("hex string has odd length: {}", t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

/// EIP-55 checksummed address from 20 bytes.
pub fn checksum_address(addr: &[u8; 20]) -> String {
    let lower = bytes_to_hex(addr);
    let lower = &lower[2..]; // strip 0x
    let hash = keccak256(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            out.push(ch);
        } else {
            let nibble = (hash[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if nibble >= 8 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch.to_ascii_lowercase());
            }
        }
    }
    out
}

/// Derive the 20-byte EVM address from a SEC1-encoded secp256k1 public key.
///
/// The last 20 bytes of keccak256 over the uncompressed key body (64 bytes after
/// the `0x04` prefix) are the address, per the EIP-55 / EVM convention.
pub fn address_from_pubkey(sec1: &[u8]) -> Result<[u8; 20], String> {
    let body: &[u8] = match sec1.first() {
        Some(0x04) => sec1.get(1..).ok_or("truncated uncompressed key")?,
        Some(0x02) | Some(0x03) => {
            // Decompress via k256 so compressed keys are accepted too.
            let pk = k256::PublicKey::from_sec1_bytes(sec1).map_err(|e| e.to_string())?;
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            return address_from_pubkey(pk.to_encoded_point(false).as_bytes());
        }
        _ => return Err("public key must start with 0x02, 0x03, or 0x04".into()),
    };
    if body.len() != 64 {
        return Err(format!(
            "uncompressed key body must be 64 bytes, got {}",
            body.len()
        ));
    }
    let hash = keccak256(body);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn address_from_known_pubkey() {
        // k256 private key = 1 -> generator point; derived address is well known.
        let pk = k256::SecretKey::from_slice(&{
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        })
        .unwrap();
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let sec1 = pk.public_key().to_encoded_point(false);
        let addr = address_from_pubkey(sec1.as_bytes()).unwrap();
        assert_eq!(
            bytes_to_hex(&addr),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        // Compressed form resolves to the same address.
        let comp = pk.public_key().to_encoded_point(true);
        assert_eq!(address_from_pubkey(comp.as_bytes()).unwrap(), addr);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn hex_roundtrip() {
        let bytes = [0x00u8, 0x01, 0xab, 0xff];
        assert_eq!(hex_to_bytes(&bytes_to_hex(&bytes)).unwrap(), bytes);
        assert_eq!(bytes_to_hex(&[0xde, 0xad]), "0xdead");
        assert!(hex_to_bytes("0xabc").is_err());
        assert!(hex_to_bytes("0xzz").is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn keccak_topic_matches_known_selector() {
        // keccak256("transfer(address,uint256)") starts with 0xa9059cbb.
        let h = keccak256(b"transfer(address,uint256)");
        assert_eq!(&h[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn checksum_address_eip55_vectors() {
        fn addr(hex: &str) -> [u8; 20] {
            let b = hex_to_bytes(hex).unwrap();
            let mut out = [0u8; 20];
            out.copy_from_slice(&b);
            out
        }
        assert_eq!(
            checksum_address(&addr("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }
}
