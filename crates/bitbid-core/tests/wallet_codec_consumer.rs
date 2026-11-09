//! Public API consumers run unchanged on native and the executed WASM target.
use bitbid_core::{
    RandomSource,
    wallet_codec::{self as codec, WalletCodecError, WalletFields},
};
use serde_json::Value;
use std::sync::Mutex;

struct RecordedEntropy {
    cursor: Mutex<usize>,
    calls: Mutex<Vec<usize>>,
    available: usize,
}
impl RecordedEntropy {
    fn new(available: usize) -> Self {
        Self {
            cursor: Mutex::new(0),
            calls: Mutex::new(Vec::new()),
            available,
        }
    }
    fn consumed(&self) -> usize {
        *self.cursor.lock().unwrap()
    }
}
impl RandomSource for RecordedEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        let mut cursor = self.cursor.lock().unwrap();
        assert!(
            *cursor + dest.len() <= self.available,
            "entropy unavailable"
        );
        self.calls.lock().unwrap().push(dest.len());
        for byte in dest {
            *byte = *cursor as u8;
            *cursor += 1;
        }
    }
    fn gen_key(&self) -> k256::SecretKey {
        panic!("wallet codecs must not request random keys")
    }
}
fn frozen() -> Value {
    serde_json::from_str(include_str!("vectors/wallet-codec-v1.json")).unwrap()
}
fn string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap()
}
fn fields(value: &Value) -> WalletFields<'_> {
    WalletFields {
        address: string(value, "address"),
        public_key: string(value, "public_key"),
        private_key: string(value, "private_key"),
        mnemonic: string(value, "mnemonic"),
        created_at: value["created_at"].as_u64().unwrap(),
        last_accessed: value["last_accessed"].as_u64().unwrap(),
        user_id: value["user_id"].as_str(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn frozen_kdf_including_short_salt_expansion() {
    let vector = frozen();
    for case in vector["kdf"].as_array().unwrap() {
        let salt = bitbid_core::address::hex_to_bytes(string(case, "salt_hex")).unwrap();
        let key = codec::derive_key(string(&vector, "password"), &salt).unwrap();
        assert_eq!(
            bitbid_core::address::bytes_to_hex(&key)[2..],
            *string(case, "key_hex")
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn frozen_ciphertext_and_decryption_with_exact_entropy_consumption() {
    let vector = frozen();
    let entropy = RecordedEntropy::new(28);
    let encrypted = codec::encrypt_wallet(
        string(&vector, "plaintext"),
        string(&vector, "password"),
        &entropy,
    )
    .unwrap();
    assert_eq!(encrypted, string(&vector, "encrypted"));
    assert_eq!(entropy.consumed(), 28);
    assert_eq!(*entropy.calls.lock().unwrap(), [16, 12]);
    assert_eq!(
        *codec::decrypt_wallet(&encrypted, string(&vector, "password")).unwrap(),
        string(&vector, "plaintext")
    );
    assert!(matches!(
        codec::decrypt_wallet(&encrypted, "wrong PUBLIC password"),
        Err(WalletCodecError::InvalidPassword)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn frozen_manual_json_all_flags_null_and_escaping() {
    let vector = frozen();
    let raw: Value = serde_json::from_str(string(&vector, "plaintext")).unwrap();
    let mut borrowed = fields(&raw);
    for case in vector["rendered"].as_array().unwrap() {
        let actual = codec::render_wallet_json(
            &borrowed,
            case["private"].as_bool().unwrap(),
            case["mnemonic"].as_bool().unwrap(),
        );
        assert_eq!(*actual, string(case, "json"));
    }
    borrowed.user_id = None;
    assert_eq!(
        *codec::render_wallet_json(&borrowed, true, true),
        string(&vector, "rendered_null")
    );
    // Worst-case control escaping, beyond the old 1024-byte headroom.
    let controls = "\u{1}".repeat(4096);
    borrowed.user_id = Some(&controls);
    let actual = codec::render_wallet_json(&borrowed, true, true);
    let parsed: Value = serde_json::from_str(&actual).unwrap();
    assert_eq!(parsed["user_id"], controls);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn frozen_mnemonic_hd_keys_and_checksum_address() {
    let vector = frozen();
    let entropy = RecordedEntropy::new(16);
    let mnemonic = codec::generate_mnemonic(&entropy).unwrap();
    assert_eq!(*mnemonic, string(&vector["derived"], "mnemonic"));
    assert_eq!(entropy.consumed(), 16);
    assert_eq!(*entropy.calls.lock().unwrap(), [16]);
    codec::validate_mnemonic(&mnemonic).unwrap();
    let keys = codec::derive_wallet_keys(&mnemonic).unwrap();
    assert_eq!(*keys.private_key, string(&vector["derived"], "private_key"));
    assert_eq!(keys.public_key, string(&vector["derived"], "public_key"));
    assert_eq!(keys.address, string(&vector["derived"], "address"));
    let private =
        bitbid_core::address::hex_to_bytes(string(&vector["scalar_one"], "private_key")).unwrap();
    let keys = codec::key_pair_from_private_key(&private).unwrap();
    assert_eq!(
        *keys.private_key,
        string(&vector["scalar_one"], "private_key")
    );
    assert_eq!(keys.public_key, string(&vector["scalar_one"], "public_key"));
    assert_eq!(keys.address, string(&vector["scalar_one"], "address"));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_format_base64_and_nonce_lengths_are_errors() {
    use base64::prelude::*;
    let vector = frozen();
    let encrypted = string(&vector, "encrypted");
    let parts: Vec<_> = encrypted.split(':').collect();
    let password = string(&vector, "password");
    for malformed in ["", ":", "a:b:c:d"] {
        assert!(matches!(
            codec::decrypt_wallet(malformed, password),
            Err(WalletCodecError::Format)
        ));
    }
    assert!(matches!(
        codec::decrypt_wallet(&format!("!:{}:{}", parts[1], parts[2]), password),
        Err(WalletCodecError::SaltBase64)
    ));
    assert!(matches!(
        codec::decrypt_wallet(&format!("{}:!:{}", parts[0], parts[2]), password),
        Err(WalletCodecError::NonceBase64)
    ));
    assert!(matches!(
        codec::decrypt_wallet(&format!("{}:{}:!", parts[0], parts[1]), password),
        Err(WalletCodecError::CiphertextBase64)
    ));
    // These inputs aborted the original optimized CLI before AEAD could fail.
    for len in [0, 1, 11, 13, 24] {
        let malformed = format!(
            "{}:{}:{}",
            parts[0],
            BASE64_STANDARD.encode(vec![0; len]),
            parts[2]
        );
        let error = codec::decrypt_wallet(&malformed, password).unwrap_err();
        assert!(matches!(error, WalletCodecError::NonceLength));
        assert_eq!(error.to_string(), "Invalid wallet nonce length");
        assert!(!error.to_string().contains(password));
    }
    let truncated = format!("{}:{}:", parts[0], parts[1]);
    assert!(matches!(
        codec::decrypt_wallet(&truncated, password),
        Err(WalletCodecError::InvalidPassword)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authenticated_non_utf8_is_rejected_without_lossy_decoding() {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit},
    };
    use base64::prelude::*;
    let salt = [0; 16];
    let nonce = [0; 12];
    let key = codec::derive_key("PUBLIC", &salt).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), [0xff, 0xfe].as_slice())
        .unwrap();
    let encrypted = format!(
        "{}:{}:{}",
        BASE64_STANDARD.encode(salt),
        BASE64_STANDARD.encode(nonce),
        BASE64_STANDARD.encode(ciphertext)
    );
    let error = codec::decrypt_wallet(&encrypted, "PUBLIC").unwrap_err();
    assert!(matches!(error, WalletCodecError::Utf8(_)));
    assert_eq!(
        error.to_string(),
        "UTF8 decode error: invalid utf-8 sequence of 1 bytes from index 0"
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn invalid_mnemonics_and_private_keys_are_rejected() {
    for mnemonic in [
        "",
        "PUBLIC invalid mnemonic",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
    ] {
        assert!(codec::validate_mnemonic(mnemonic).is_err());
        assert!(matches!(
            codec::derive_wallet_keys(mnemonic),
            Err(WalletCodecError::Mnemonic(_))
        ));
    }
    for key in [&[][..], &[1; 31][..], &[1; 33][..]] {
        assert!(matches!(
            codec::key_pair_from_private_key(key),
            Err(WalletCodecError::PrivateKeyLength)
        ));
    }
    for key in [[0; 32], [255; 32]] {
        assert!(matches!(
            codec::key_pair_from_private_key(&key),
            Err(WalletCodecError::PrivateKey(_))
        ));
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn failed_entropy_is_fail_stop_without_fallback() {
    assert!(
        std::panic::catch_unwind(|| codec::generate_mnemonic(&RecordedEntropy::new(0))).is_err()
    );
    assert!(
        std::panic::catch_unwind(|| codec::encrypt_wallet(
            "PUBLIC",
            "PUBLIC",
            &RecordedEntropy::new(16)
        ))
        .is_err()
    );
}
