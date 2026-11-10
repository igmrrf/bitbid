//! External native/WASM consumers; these adapters certify the interfaces only.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitbid_core::{
    Clock, Error, ErrorKind, Host, Ipfs, IpfsError, RandomSource, Rpc, RpcError, Store, StoreError,
    StoreKey, WriteOpts,
    address::{bytes_to_hex, hex_to_bytes},
    registry_read::{RegistryInfo, read_registry_info},
};
use serde_json::{Value, json};

// Fixed ABI bytes independent of core's encoder/decoder: eleven head words,
// offset 0x160, twelve-byte CID and padding. Expiry/limit flags intentionally
// differ from what a local time/read-count calculation might produce.
const ABI: &str = concat!(
    "0000000000000000000000001111111111111111111111111111111111111111",
    "0000000000000000000000002222222222222222222222222222222222222222",
    "0000000000000000000000000000000000000000000000000000000000000160",
    "0000000000000000000000000000000000000000000000000000000000000007",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "0000000000000000000000000000000000000000000000000000000000000009",
    "000000000000000000000000000000000000000000000000000000000000000a",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "000000000000000000000000000000000000000000000000000000000000000c",
    "516d54657374436964313233000000000000000000000000000000000000000000",
);

struct Unused;
impl Store for Unused {
    fn read(&self, _: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
        panic!("unused store")
    }
    fn write(&self, _: &StoreKey, _: &[u8], _: WriteOpts) -> Result<(), StoreError> {
        panic!("unused store")
    }
    fn exists(&self, _: &StoreKey) -> Result<bool, StoreError> {
        panic!("unused store")
    }
    fn remove(&self, _: &StoreKey) -> Result<(), StoreError> {
        panic!("unused store")
    }
}
impl Ipfs for Unused {
    fn add(&self, _: &[u8], _: &str) -> Result<String, IpfsError> {
        panic!("unused ipfs")
    }
    fn cat(&self, _: &str) -> Result<Vec<u8>, IpfsError> {
        panic!("unused ipfs")
    }
}
impl Clock for Unused {
    fn now_unix(&self) -> i64 {
        panic!("unused clock")
    }
    fn sleep(&self, _: Duration) {
        panic!("unused clock")
    }
}
impl RandomSource for Unused {
    fn fill_bytes(&self, _: &mut [u8]) {
        panic!("unused random")
    }
    fn gen_key(&self) -> k256::SecretKey {
        panic!("unused random")
    }
}

struct MemoryRpc {
    expected: Value,
    calls: Mutex<usize>,
    response: Mutex<Option<Result<Value, RpcError>>>,
}
impl Rpc for MemoryRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        assert_eq!(method, "eth_call");
        assert_eq!(params, self.expected);
        *self.calls.lock().unwrap() += 1;
        self.response
            .lock()
            .unwrap()
            .take()
            .expect("exactly one request")
    }
}
fn host_for(id_bytes: &[u8], response: Result<Value, RpcError>) -> (Host, Arc<MemoryRpc>) {
    // Selector is a literal golden value, not obtained from the core helper.
    let mut arg = [0; 32];
    arg[..id_bytes.len()].copy_from_slice(id_bytes);
    let rpc = Arc::new(MemoryRpc {
        expected: json!([{"to": "0xabababababababababababababababababababab",
            "data": format!("0x6a70f2b7{}", &bytes_to_hex(&arg)[2..])}, "latest"]),
        calls: Mutex::new(0),
        response: Mutex::new(Some(response)),
    });
    (
        Host {
            store: Arc::new(Unused),
            ipfs: Arc::new(Unused),
            rpc: rpc.clone(),
            clock: Arc::new(Unused),
            random: Arc::new(Unused),
        },
        rpc,
    )
}
fn read_result(result: Value) -> Result<RegistryInfo, Error> {
    let (host, rpc) = host_for(b"id", Ok(result));
    let read = read_registry_info(&host, &[0xab; 20], "id");
    assert_eq!(*rpc.calls.lock().unwrap(), 1);
    read
}
fn bytes() -> Vec<u8> {
    hex_to_bytes(ABI).unwrap()
}
fn set_low(data: &mut [u8], word: usize, value: u64) {
    data[word * 32 + 24..word * 32 + 32].copy_from_slice(&value.to_be_bytes());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn complete_read_has_exact_request_and_all_chain_facts() {
    let expected = RegistryInfo {
        sender: [0x11; 20],
        recipient: [0x22; 20],
        ipfs_cid: "QmTestCid123".into(),
        created_at: 7,
        expires_at: 3,
        max_reads: 9,
        read_count: 10,
        revoked: true,
        is_public: false,
        is_expired: false,
        limit_reached: true,
    };
    for (id, raw) in [
        ("id", b"id".as_slice()),
        ("0x6964", b"id"),
        ("0X6964", b"id"),
        ("🔑", "🔑".as_bytes()),
        ("", b""),
        (
            "12345678901234567890123456789012",
            b"12345678901234567890123456789012",
        ),
    ] {
        for public in [false, true] {
            let mut fixture = bytes();
            set_low(&mut fixture, 8, u64::from(public));
            let (host, rpc) = host_for(raw, Ok(json!(bytes_to_hex(&fixture))));
            let result = read_registry_info(&host.clone(), &[0xab; 20], id).unwrap();
            let mut wanted = expected.clone();
            wanted.is_public = public;
            assert_eq!(result, wanted);
            assert_eq!(*rpc.calls.lock().unwrap(), 1);
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn invalid_ids_fail_before_rpc() {
    for id in [
        "a".repeat(33),
        "🔑".repeat(9),
        format!("0x{}", "ff".repeat(33)),
        "0xz1".into(),
        "0x1".into(),
        "0xé".into(),
    ] {
        let (host, rpc) = host_for(b"", Ok(Value::Null));
        let err = read_registry_info(&host, &[0xab; 20], &id).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
        assert_eq!(err.kind(), ErrorKind::Invalid);
        assert_eq!(*rpc.calls.lock().unwrap(), 0);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rpc_failures_preserve_type_and_diagnostic() {
    for failure in [
        RpcError::Request("offline".into()),
        RpcError::Provider("null".into()),
        RpcError::Decode("bad JSON".into()),
    ] {
        let diagnostic = failure.to_string();
        let (host, rpc) = host_for(b"id", Err(failure));
        let err = read_registry_info(&host, &[0xab; 20], "id").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Chain);
        let Error::Rpc(inner) = err else {
            panic!("lost RPC error")
        };
        assert_eq!(inner.to_string(), diagnostic);
        assert_eq!(*rpc.calls.lock().unwrap(), 1);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn malformed_results_and_untrusted_ranges_fail_without_a_record() {
    let mut malformed = vec![
        Value::Null,
        json!(4),
        json!({"result": ABI}),
        json!([]),
        json!(""),
        json!("0x"),
        json!("0x0"),
        json!("0xzz"),
        json!("é"),
        json!("0x00"),
        json!(bytes_to_hex(&bytes()[..351])),
    ];
    for (index, value) in [(2, 416), (2, u64::MAX), (11, u64::MAX), (11, 1000)] {
        let mut fixture = bytes();
        set_low(&mut fixture, index, value);
        malformed.push(json!(bytes_to_hex(&fixture)));
    }
    for index in [2, 11] {
        let mut fixture = bytes();
        fixture[index * 32] = 1;
        malformed.push(json!(bytes_to_hex(&fixture)));
    }
    let mut invalid_utf8 = bytes();
    invalid_utf8[384] = 255;
    malformed.push(json!(bytes_to_hex(&invalid_utf8)));
    for result in malformed {
        let err = read_result(result).unwrap_err();
        assert!(matches!(err, Error::Decode(_)));
        assert_eq!(err.kind(), ErrorKind::Decode);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_low_word_and_bounded_offset_semantics_are_retained() {
    for low in [0, 2, u64::MAX] {
        let mut fixture = bytes();
        for index in 7..=10 {
            fixture[index * 32] = 255;
            set_low(&mut fixture, index, low);
        }
        let info = read_result(json!(bytes_to_hex(&fixture))).unwrap();
        assert_eq!(
            (
                info.revoked,
                info.is_public,
                info.is_expired,
                info.limit_reached
            ),
            (low != 0, low != 0, low != 0, low != 0)
        );
    }
    let mut fixture = bytes();
    for index in [0, 1, 3, 4, 5, 6, 7, 8, 9, 10] {
        fixture[index * 32] = 255;
    }
    set_low(&mut fixture, 5, 0x100000009);
    set_low(&mut fixture, 6, 0x20000000a);
    set_low(&mut fixture, 7, 2);
    set_low(&mut fixture, 8, 3);
    let info = read_result(json!(bytes_to_hex(&fixture))).unwrap();
    assert_eq!((info.sender, info.recipient), ([0x11; 20], [0x22; 20]));
    assert_eq!(
        (
            info.created_at,
            info.expires_at,
            info.max_reads,
            info.read_count
        ),
        (7, 3, 9, 10)
    );
    assert!(info.revoked && info.is_public && info.limit_reached);
    assert!(!info.is_expired); // nonzero high bytes alone do not make a native bool true
    // Native accepts bounded unaligned offsets and missing trailing padding.
    let mut unaligned = bytes();
    set_low(&mut unaligned, 2, 353);
    unaligned[352..].fill(0);
    unaligned[384] = 1;
    unaligned[385] = b'x';
    assert_eq!(
        read_result(json!(bytes_to_hex(&unaligned[..386])))
            .unwrap()
            .ipfs_cid,
        "x"
    );
    let mut in_head = bytes();
    in_head[..32].fill(0);
    set_low(&mut in_head, 2, 0);
    assert_eq!(
        read_result(json!(bytes_to_hex(&in_head))).unwrap().ipfs_cid,
        ""
    );
}

#[derive(Default)]
struct MemoryStore {
    entries: Mutex<HashMap<StoreKey, (Vec<u8>, WriteOpts)>>,
}
impl Store for MemoryStore {
    fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
        if *key == StoreKey::ProjectConfig {
            return Err(StoreError::PermissionDenied("read policy".into()));
        }
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(key)
            .map(|(b, _)| b.clone()))
    }
    fn write(&self, key: &StoreKey, bytes: &[u8], opts: WriteOpts) -> Result<(), StoreError> {
        if *key == StoreKey::ProjectConfig {
            return Err(StoreError::PermissionDenied("write policy".into()));
        }
        let mut entries = self.entries.lock().unwrap();
        if opts.create_new && entries.contains_key(key) {
            return Err(StoreError::AlreadyExists("key".into()));
        }
        entries.insert(key.clone(), (bytes.to_vec(), opts));
        Ok(())
    }
    fn exists(&self, key: &StoreKey) -> Result<bool, StoreError> {
        Ok(self.read(key)?.is_some())
    }
    fn remove(&self, key: &StoreKey) -> Result<(), StoreError> {
        if *key == StoreKey::ProjectConfig {
            return Err(StoreError::PermissionDenied("remove policy".into()));
        }
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn store_consumer_observes_absence_no_clobber_options_and_typed_failures() {
    let memory = MemoryStore::default();
    let store: &dyn Store = &memory;
    for key in [
        StoreKey::Wallet,
        StoreKey::NetworkConfig,
        StoreKey::SecretIndex,
        StoreKey::IpfsCache("cid".into()),
    ] {
        assert_eq!(store.read(&key).unwrap(), None);
        assert!(!store.exists(&key).unwrap());
        store.remove(&key).unwrap();
        let opts = WriteOpts {
            private: true,
            create_new: true,
        };
        store.write(&key, b"original", opts).unwrap();
        assert!(store.exists(&key).unwrap());
        assert!(matches!(
            store.write(&key, b"lost", opts),
            Err(StoreError::AlreadyExists(_))
        ));
        let (saved, requested) = memory.entries.lock().unwrap().get(&key).unwrap().clone();
        assert_eq!(saved, b"original");
        assert!(requested.private && requested.create_new);
        store
            .write(&key, b"replacement", WriteOpts::default())
            .unwrap();
        assert_eq!(store.read(&key).unwrap().unwrap(), b"replacement");
        let opts = memory.entries.lock().unwrap().get(&key).unwrap().1;
        assert!(!opts.private && !opts.create_new);
        store.remove(&key).unwrap();
        assert_eq!(store.read(&key).unwrap(), None);
        assert!(!store.exists(&key).unwrap());
        store.remove(&key).unwrap();
    }
    assert!(matches!(
        store.read(&StoreKey::ProjectConfig),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.exists(&StoreKey::ProjectConfig),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.write(&StoreKey::ProjectConfig, b"", WriteOpts::default()),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.remove(&StoreKey::ProjectConfig),
        Err(StoreError::PermissionDenied(_))
    ));
}

#[derive(Default)]
struct MemoryIpfs {
    content: Mutex<HashMap<String, Vec<u8>>>,
}
impl Ipfs for MemoryIpfs {
    fn add(&self, bytes: &[u8], name: &str) -> Result<String, IpfsError> {
        if name.is_empty() {
            return Err(IpfsError::Request("name required by test adapter".into()));
        }
        let cid = format!("test:{}", bytes_to_hex(bytes));
        self.content
            .lock()
            .unwrap()
            .insert(cid.clone(), bytes.to_vec());
        Ok(cid)
    }
    fn cat(&self, cid: &str) -> Result<Vec<u8>, IpfsError> {
        if !cid.starts_with("test:") {
            return Err(IpfsError::InvalidCid(cid.into()));
        }
        self.content
            .lock()
            .unwrap()
            .get(cid)
            .cloned()
            .ok_or_else(|| IpfsError::Request("unavailable".into()))
    }
}
struct FixedClock {
    sleeps: Mutex<Vec<Duration>>,
}
impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        123
    }
    fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
    }
}
struct FixedRandom;
impl RandomSource for FixedRandom {
    fn fill_bytes(&self, dest: &mut [u8]) {
        dest.fill(0x5a);
    }
    fn gen_key(&self) -> k256::SecretKey {
        k256::SecretKey::from_slice(&[1; 32]).unwrap()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn other_port_consumers_round_trip_content_time_and_valid_key_material() {
    let ipfs: Arc<dyn Ipfs> = Arc::new(MemoryIpfs::default());
    for content in [b"".as_slice(), &[0, 255, 128, 10]] {
        let cid = ipfs.add(content, "payload.bin").unwrap();
        assert_eq!(ipfs.cat(&cid).unwrap(), content);
        assert_eq!(ipfs.add(content, "renamed.bin").unwrap(), cid);
    }
    assert!(matches!(ipfs.add(b"x", ""), Err(IpfsError::Request(_))));
    assert!(matches!(ipfs.cat("invalid"), Err(IpfsError::InvalidCid(_))));
    assert!(matches!(
        ipfs.cat("test:missing"),
        Err(IpfsError::Request(_))
    ));
    let fixed = Arc::new(FixedClock {
        sleeps: Mutex::new(Vec::new()),
    });
    let clock: Arc<dyn Clock> = fixed.clone();
    assert_eq!(clock.now_unix(), 123);
    clock.sleep(Duration::ZERO);
    clock.sleep(Duration::from_millis(75));
    assert_eq!(
        *fixed.sleeps.lock().unwrap(),
        [Duration::ZERO, Duration::from_millis(75)]
    );
    assert_eq!(clock.now_unix(), 123);
    let random: Arc<dyn RandomSource> = Arc::new(FixedRandom);
    let mut nonce = [0; 12];
    random.fill_bytes(&mut nonce);
    random.fill_bytes(&mut []);
    assert_eq!(nonce, [0x5a; 12]);
    let key = random.gen_key();
    assert_eq!(key.to_bytes().as_slice(), &[1; 32]);
    // Use the trait's key in a real ECDH consumer, without OS entropy.
    let peer = k256::SecretKey::from_slice(&[2; 32]).unwrap();
    let shared = k256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.public_key().as_affine());
    let reverse =
        k256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), key.public_key().as_affine());
    assert_eq!(shared.raw_secret_bytes(), reverse.raw_secret_bytes());
    assert_eq!(random.gen_key().to_bytes(), key.to_bytes());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn list_policy_reads_real_host_before_filters_and_preserves_raw_facts() {
    use bitbid_core::registry_list::{ListQuery, list_indexed};
    let mut trace = Vec::new();
    let rows = list_indexed(
        [("hidden", true), ("0X6964", false), ("id", false)],
        ListQuery {
            user_address: "0X1111111111111111111111111111111111111111",
            filter_user: None,
            all: false,
            expired_only: true,
            active_only: false,
        },
        |id| {
            trace.push(id.to_owned());
            let raw = if id == "hidden" {
                b"hidden".as_slice()
            } else {
                b"id"
            };
            let (host, rpc) = host_for(raw, Ok(json!(bytes_to_hex(&bytes()))));
            let result = read_registry_info(&host, &[0xab; 20], id);
            assert_eq!(*rpc.calls.lock().unwrap(), 1);
            result.map(Some)
        },
    )
    .unwrap();
    assert_eq!(trace, ["hidden", "0X6964", "id"]);
    let expected = RegistryInfo {
        sender: [0x11; 20],
        recipient: [0x22; 20],
        ipfs_cid: "QmTestCid123".into(),
        created_at: 7,
        expires_at: 3,
        max_reads: 9,
        read_count: 10,
        revoked: true,
        is_public: false,
        is_expired: false,
        limit_reached: true,
    };
    assert_eq!(
        rows,
        [("0X6964".into(), expected.clone()), ("id".into(), expected)]
    );
}
