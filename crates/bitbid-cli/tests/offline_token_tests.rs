use assert_cmd::prelude::*;
use std::io::Write;
use std::process::{Command, Stdio};
fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../bitbid-core/tests/vectors/ipfs-v1.json"
    ))
    .unwrap()
}
#[test]
fn cli_opens_shared_frozen_token_without_wallet_or_network() {
    let v = vector();
    let tmp = assert_fs::TempDir::new().unwrap();
    let key = tmp.path().join("synthetic-key.txt");
    std::fs::write(&key, v["recipient_secret_hex"].as_str().unwrap()).unwrap();
    let mut legacy_json: serde_json::Value =
        serde_json::from_str(v["canonical_payload"].as_str().unwrap()).unwrap();
    legacy_json
        .as_object_mut()
        .unwrap()
        .remove("protocol_version");
    for input in [
        v["token"].as_str().unwrap().to_owned(),
        v["canonical_payload"].as_str().unwrap().to_owned(),
        legacy_json.to_string(),
    ] {
        let token = tmp.path().join("input.txt");
        std::fs::write(&token, input).unwrap();
        let output = Command::cargo_bin("bitbid")
            .unwrap()
            .current_dir(tmp.path())
            .env("BITBID_HOME", tmp.path().join("unused-wallet"))
            .args(["unseal", "--input"])
            .arg(&token)
            .arg("--key-file")
            .arg(&key)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, v["plaintext"].as_str().unwrap().as_bytes());
        assert!(!tmp.path().join("unused-wallet").exists());
    }
}
#[test]
fn cli_emits_random_shared_tokens_from_stdin_and_rejects_wrong_key() {
    let v = vector();
    let tmp = assert_fs::TempDir::new().unwrap();
    let mut tokens = vec![];
    for _ in 0..2 {
        let mut child = Command::cargo_bin("bitbid")
            .unwrap()
            .current_dir(tmp.path())
            .args(["seal", "--to", v["recipient_public_hex"].as_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"CLI/browser interoperability")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let share = String::from_utf8(out.stdout).unwrap();
        let key = bitbid_core::address::hex_to_bytes(v["recipient_secret_hex"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            bitbid_core::token::unseal_to_string(&share, &key).unwrap(),
            "CLI/browser interoperability"
        );
        tokens.push(share);
    }
    assert_ne!(tokens[0], tokens[1]);
    let input = tmp.path().join("token.txt");
    std::fs::write(&input, &tokens[0]).unwrap();
    let key = tmp.path().join("wrong-key.txt");
    std::fs::write(&key, format!("{}03", "00".repeat(31))).unwrap();
    let output = Command::cargo_bin("bitbid")
        .unwrap()
        .current_dir(tmp.path())
        .arg("unseal")
        .arg("--input")
        .arg(input)
        .arg("--key-file")
        .arg(key)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
}

#[test]
fn cli_rejects_malformed_tokens_and_keys_without_stdout_or_wallet() {
    let v = vector();
    let tmp = assert_fs::TempDir::new().unwrap();
    let token_path = tmp.path().join("token.txt");
    let key_path = tmp.path().join("key.txt");
    let wallet = tmp.path().join("unused-wallet");
    let unknown_version = v["canonical_payload"]
        .as_str()
        .unwrap()
        .replace("\"protocol_version\":1", "\"protocol_version\":2");
    for (input, key, expected_code) in [
        (
            "bitbid2:%%%",
            v["recipient_secret_hex"].as_str().unwrap(),
            1,
        ),
        (
            unknown_version.as_str(),
            v["recipient_secret_hex"].as_str().unwrap(),
            4,
        ),
        (
            "bitbid1:Ag==",
            v["recipient_secret_hex"].as_str().unwrap(),
            4,
        ),
        (v["token"].as_str().unwrap(), "not-hex", 4),
        (v["token"].as_str().unwrap(), "00", 1),
        (v["token"].as_str().unwrap(), &"00".repeat(32), 1),
    ] {
        std::fs::write(&token_path, input).unwrap();
        std::fs::write(&key_path, key).unwrap();
        let output = Command::cargo_bin("bitbid")
            .unwrap()
            .current_dir(tmp.path())
            .env("BITBID_HOME", &wallet)
            .args(["unseal", "--input"])
            .arg(&token_path)
            .arg("--key-file")
            .arg(&key_path)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected_code), "{input} / {key}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert!(!wallet.exists());
    }
    let output = Command::cargo_bin("bitbid")
        .unwrap()
        .current_dir(tmp.path())
        .env("BITBID_HOME", &wallet)
        .args(["seal", "--to", "invalid-public-key"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert!(!wallet.exists());
}
