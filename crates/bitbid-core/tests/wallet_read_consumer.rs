//! Real public consumers, executed unchanged on native and WASM.
use bitbid_core::{
    Clock, Host, Ipfs, IpfsError, RandomSource, Rpc, RpcError, Store, StoreError, StoreKey,
    WriteOpts,
    wallet_codec::{self, WalletCodecError},
    wallet_read::{WalletInfo, WalletReadError, read_wallet},
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

struct MemoryStore {
    bytes: Mutex<Option<Vec<u8>>>,
    calls: Mutex<Vec<StoreKey>>,
}
impl MemoryStore {
    fn new(bytes: Option<Vec<u8>>) -> Self {
        Self {
            bytes: Mutex::new(bytes),
            calls: Mutex::new(vec![]),
        }
    }
    fn replace(&self, bytes: Option<Vec<u8>>) {
        *self.bytes.lock().unwrap() = bytes;
    }
    fn assert_reads(&self, count: usize) {
        assert_eq!(*self.calls.lock().unwrap(), vec![StoreKey::Wallet; count]);
    }
}
impl Store for MemoryStore {
    fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
        self.calls.lock().unwrap().push(key.clone());
        Ok(self.bytes.lock().unwrap().clone())
    }
    fn write(&self, _: &StoreKey, _: &[u8], _: WriteOpts) -> Result<(), StoreError> {
        panic!("write forbidden")
    }
    fn exists(&self, _: &StoreKey) -> Result<bool, StoreError> {
        panic!("exists forbidden")
    }
    fn remove(&self, _: &StoreKey) -> Result<(), StoreError> {
        panic!("remove forbidden")
    }
}
struct Unused;
impl Ipfs for Unused {
    fn add(&self, _: &[u8], _: &str) -> Result<String, IpfsError> {
        panic!("IPFS forbidden")
    }
    fn cat(&self, _: &str) -> Result<Vec<u8>, IpfsError> {
        panic!("IPFS forbidden")
    }
}
impl Rpc for Unused {
    fn call(&self, _: &str, _: Value) -> Result<Value, RpcError> {
        panic!("RPC forbidden")
    }
}
impl Clock for Unused {
    fn now_unix(&self) -> i64 {
        panic!("clock forbidden")
    }
    fn sleep(&self, _: Duration) {
        panic!("sleep forbidden")
    }
}
impl RandomSource for Unused {
    fn fill_bytes(&self, _: &mut [u8]) {
        panic!("random forbidden")
    }
    fn gen_key(&self) -> k256::SecretKey {
        panic!("random key forbidden")
    }
}
struct PublicEntropy;
impl RandomSource for PublicEntropy {
    fn fill_bytes(&self, dest: &mut [u8]) {
        for (i, b) in dest.iter_mut().enumerate() {
            *b = i as u8;
        }
    }
    fn gen_key(&self) -> k256::SecretKey {
        panic!("not used")
    }
}
fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/wallet-codec-v1.json")).unwrap()
}
fn outer(data: &str, encrypted: bool) -> Vec<u8> {
    serde_json::to_vec(&json!({"encrypted":encrypted,"data":data,"last_accessed":9876})).unwrap()
}
fn success(result: Result<WalletInfo, WalletReadError>) -> WalletInfo {
    result.unwrap_or_else(|e| panic!("unexpected safe error {e}"))
}
fn failure(result: Result<WalletInfo, WalletReadError>) -> WalletReadError {
    match result {
        Ok(_) => panic!("expected failure"),
        Err(e) => e,
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn one_wallet_read_and_no_other_host_ports_for_encrypted_and_plain_fields() {
    let vector = vector();
    for encrypted in [false, true] {
        let data = vector[if encrypted { "encrypted" } else { "plaintext" }]
            .as_str()
            .unwrap();
        let bytes = outer(data, encrypted);
        let store = Arc::new(MemoryStore::new(Some(bytes.clone())));
        let unused = Arc::new(Unused);
        let host = Host {
            store: store.clone(),
            ipfs: unused.clone(),
            rpc: unused.clone(),
            clock: unused.clone(),
            random: unused,
        };
        let mut wallet = success(read_wallet(
            host.store.as_ref(),
            Some(vector["password"].as_str().unwrap()),
        ));
        let expected: Value = serde_json::from_str(vector["plaintext"].as_str().unwrap()).unwrap();
        assert_eq!(wallet.address, expected["address"]);
        assert_eq!(wallet.public_key, expected["public_key"]);
        assert_eq!(wallet.private_key, expected["private_key"]);
        assert_eq!(wallet.mnemonic, expected["mnemonic"]);
        assert_eq!(wallet.created_at, 1234567890);
        assert_eq!(wallet.last_accessed, 1234567891); // not outer9876
        assert_eq!(wallet.user_id.as_deref(), expected["user_id"].as_str());
        store.assert_reads(1);
        assert_eq!(*store.bytes.lock().unwrap(), Some(bytes));
        // A caller moves ownership into its own guard; it never needs Clone/Debug.
        let private = zeroize::Zeroizing::new(std::mem::take(&mut wallet.private_key));
        assert_eq!(&**private, expected["private_key"].as_str().unwrap());
        assert!(wallet.private_key.is_empty());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn read_returns_stored_strings_and_optional_user_id_without_key_validation() {
    let data = json!({"address":"stored address", "public_key":"stored public", "private_key":"PUBLIC not a key", "mnemonic":"PUBLIC not a mnemonic", "created_at":0,"last_accessed":u64::MAX});
    let store = MemoryStore::new(Some(outer(&data.to_string(), false)));
    let wallet = success(read_wallet(&store, Some("ignored for plaintext")));
    assert_eq!(wallet.address, "stored address");
    assert_eq!(wallet.public_key, "stored public");
    assert_eq!(wallet.private_key, "PUBLIC not a key");
    assert_eq!(wallet.mnemonic, "PUBLIC not a mnemonic");
    assert_eq!(wallet.created_at, 0);
    assert_eq!(wallet.last_accessed, u64::MAX);
    assert!(wallet.user_id.is_none());
    store.assert_reads(1);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn missing_utf8_outer_password_decrypt_and_inner_order_then_recovery() {
    let vector = vector();
    let store = MemoryStore::new(None);
    assert!(matches!(
        failure(read_wallet(&store, None)),
        WalletReadError::Missing
    ));
    store.replace(Some(vec![255]));
    assert!(matches!(
        failure(read_wallet(&store, None)),
        WalletReadError::Utf8
    ));
    store.replace(Some(b"{".to_vec()));
    assert_eq!(
        failure(read_wallet(&store, None)).to_string(),
        "EOF while parsing an object at line 1 column 1"
    );
    store.replace(Some(outer("malformed encrypted body", true)));
    assert!(matches!(
        failure(read_wallet(&store, None)),
        WalletReadError::PasswordRequired
    ));
    assert!(matches!(
        failure(read_wallet(&store, Some("PUBLIC"))),
        WalletReadError::Codec(WalletCodecError::Format)
    ));
    store.replace(Some(outer(vector["encrypted"].as_str().unwrap(), true)));
    assert!(matches!(
        failure(read_wallet(&store, Some("PUBLIC wrong"))),
        WalletReadError::Codec(WalletCodecError::InvalidPassword)
    ));
    store.replace(Some(outer("{", false)));
    assert_eq!(
        failure(read_wallet(&store, None)).to_string(),
        "EOF while parsing an object at line 1 column 1"
    );
    store.replace(Some(outer(vector["plaintext"].as_str().unwrap(), false)));
    assert_eq!(
        success(read_wallet(&store, None)).address,
        vector["derived"]["address"]
    );
    store.assert_reads(8);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_encrypted_inner_and_nonce_errors_stay_guarded_and_recover() {
    let store = MemoryStore::new(Some(outer("AAECAwQFBgc=:AA==:!", true)));
    assert!(matches!(
        failure(read_wallet(&store, Some("PUBLIC"))),
        WalletReadError::Codec(WalletCodecError::NonceLength)
    ));
    let encrypted = wallet_codec::encrypt_wallet(
        "{\"created_at\":\"PUBLIC password\"}",
        "PUBLIC",
        &PublicEntropy,
    )
    .unwrap();
    store.replace(Some(outer(&encrypted, true)));
    let error = failure(read_wallet(&store, Some("PUBLIC")));
    assert_eq!(error.legacy_exit_code(), 2);
    assert!(error.to_string().contains("string [redacted]"));
    assert!(!format!("{error:?}").contains("PUBLIC"));
    let encrypted = wallet_codec::encrypt_wallet(
        vector()["plaintext"].as_str().unwrap(),
        "PUBLIC",
        &PublicEntropy,
    )
    .unwrap();
    store.replace(Some(outer(&encrypted, true)));
    assert!(
        !success(read_wallet(&store, Some("PUBLIC")))
            .private_key
            .is_empty()
    );
    store.assert_reads(3);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn redaction_preserves_original_text_dependent_exits_without_leaking_payloads() {
    for (canary, code) in [
        ("PUBLIC opaque", 1),
        ("PUBLIC PASSWORD permission io mnemonic", 2),
        ("PUBLIC permission config mnemonic", 3),
        ("PUBLIC config mnemonic", 4),
        ("PUBLIC mnemonic", 5),
    ] {
        for encrypted in [false, true] {
            let raw = if encrypted {
                json!({"created_at":canary}).to_string()
            } else {
                json!({"encrypted":canary,"data":"{}","last_accessed":0}).to_string()
            };
            let bytes = if encrypted {
                let body = wallet_codec::encrypt_wallet(&raw, "PUBLIC", &PublicEntropy).unwrap();
                outer(&body, true)
            } else {
                raw.into_bytes()
            };
            let store = MemoryStore::new(Some(bytes));
            let error = failure(read_wallet(&store, Some("PUBLIC")));
            assert_eq!(error.legacy_exit_code(), code);
            let message = error.to_string();
            assert!(message.contains("invalid type: string [redacted]"));
            assert!(!message.contains(canary));
            assert!(!format!("{error:?}").contains(canary));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn static_schema_diagnostics_and_numeric_data_redaction() {
    for (data, expected) in [
        ("{}", "missing field `encrypted` at line 1 column 2"),
        (
            "{\"encrypted\":false,\"encrypted\":true}",
            "duplicate field `encrypted` at line 1 column 30",
        ),
    ] {
        let store = MemoryStore::new(Some(data.as_bytes().to_vec()));
        assert_eq!(failure(read_wallet(&store, None)).to_string(), expected);
    }
    // A real unrecognized Data diagnostic (short struct sequence) is sanitized,
    // while its historical WalletFile-influenced exit remains four.
    let store = MemoryStore::new(Some(b"[false]".to_vec()));
    let error = failure(read_wallet(&store, None));
    assert_eq!(
        error.to_string(),
        "Invalid wallet JSON data at line 1 column 7"
    );
    assert_eq!(error.legacy_exit_code(), 4);
    store.replace(Some(outer(vector()["plaintext"].as_str().unwrap(), false)));
    assert!(!success(read_wallet(&store, None)).private_key.is_empty());
    for value in [json!(-12345), json!(123.45), json!(true)] {
        let store = MemoryStore::new(Some(
            json!({"encrypted":false,"data":value,"last_accessed":0})
                .to_string()
                .into_bytes(),
        ));
        let error = failure(read_wallet(&store, None));
        assert!(error.to_string().contains("[redacted]"));
        assert!(!error.to_string().contains("123"));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn store_errors_discard_arbitrary_payloads_and_never_check_existence() {
    struct Denied(u8);
    impl Store for Denied {
        fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
            assert_eq!(key, &StoreKey::Wallet);
            Err(match self.0 {
                0 => StoreError::PermissionDenied("PUBLIC private password".into()),
                1 => StoreError::Io("PUBLIC private password".into()),
                2 => StoreError::NotFound("PUBLIC private password".into()),
                _ => StoreError::AlreadyExists("PUBLIC private password".into()),
            })
        }
        fn write(&self, _: &StoreKey, _: &[u8], _: WriteOpts) -> Result<(), StoreError> {
            panic!("write")
        }
        fn exists(&self, _: &StoreKey) -> Result<bool, StoreError> {
            panic!("exists")
        }
        fn remove(&self, _: &StoreKey) -> Result<(), StoreError> {
            panic!("remove")
        }
    }
    for n in 0..4 {
        let error = failure(read_wallet(&Denied(n), None));
        assert!(!format!("{error:?} {error}").contains("PUBLIC"));
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(error.legacy_exit_code(), if n == 0 { 3 } else { 1 });
    }
}
