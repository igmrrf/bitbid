//! Process-boundary regression for the malformed nonce release abort, with read-only state.
use assert_cmd::prelude::*;
use base64::prelude::*;
use std::{
    fs,
    process::{Command, Stdio},
};

#[test]
fn malformed_nonces_fail_without_panic_or_wallet_mutation() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../bitbid-core/tests/vectors/wallet-codec-v1.json"
    ))
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wallet.json");
    let parts: Vec<_> = vector["encrypted"].as_str().unwrap().split(':').collect();
    for length in [0, 1, 11, 13, 24] {
        let data = format!(
            "{}:{}:{}",
            parts[0],
            BASE64_STANDARD.encode(vec![0; length]),
            parts[2]
        );
        let bytes = serde_json::to_vec(
            &serde_json::json!({"encrypted":true,"data":data,"last_accessed":1234567891}),
        )
        .unwrap();
        fs::write(&path, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }
        let before = fs::metadata(&path).unwrap();
        let output = Command::cargo_bin("bitbid")
            .unwrap()
            .env("BITBID_HOME", temp.path())
            .env_remove("BSEC_HOME")
            .current_dir(temp.path())
            .stdin(Stdio::null())
            .args([
                "wallet",
                "info",
                "--password",
                vector["password"].as_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "Warning: Passing passwords via CLI flags may expose credentials in process lists.\nError getting wallet info: Invalid wallet nonce length\n"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let after = fs::metadata(&path).unwrap();
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(before.permissions().mode(), after.permissions().mode());
        }
    }
}
