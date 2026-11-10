//! Real CLI wiring, redacted failures with historical exits, and read-only recovery.
use assert_cmd::prelude::*;
use serde_json::{Value, json};
use std::{
    fs,
    process::{Command, Stdio},
};
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../bitbid-core/tests/vectors/wallet-codec-v1.json"
    ))
    .unwrap()
}
fn invoke(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("bitbid")
        .unwrap()
        .current_dir(home)
        .env("BITBID_HOME", home)
        .env_remove("BSEC_HOME")
        .stdin(Stdio::null())
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn cli_redacts_input_influenced_errors_without_changing_exits_then_recovers_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("wallet.json");
    let vector = vector();
    for (canary, code) in [
        ("PUBLIC opaque", 1),
        ("PUBLIC PASSWORD permission io mnemonic", 2),
        ("PUBLIC permission config mnemonic", 3),
        ("PUBLIC config mnemonic", 4),
        ("PUBLIC mnemonic", 5),
    ] {
        let bytes = json!({"encrypted":canary,"data":"{}","last_accessed":1}).to_string();
        fs::write(&file, &bytes).unwrap();
        let before = fs::metadata(&file).unwrap();
        let output = invoke(dir.path(), &["wallet", "info", "--json"]);
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("invalid type: string [redacted], expected a boolean"));
        assert!(!stderr.contains(canary));
        assert!(!stderr.contains("Enter wallet"));
        assert_eq!(fs::read(&file).unwrap(), bytes.as_bytes());
        assert_eq!(
            fs::metadata(&file).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
    }
    let bytes =
        json!({"encrypted":false,"data":vector["plaintext"],"last_accessed":42}).to_string();
    fs::write(&file, &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    }
    let before = fs::metadata(&file).unwrap();
    let output = invoke(
        dir.path(),
        &[
            "wallet",
            "info",
            "--json",
            "--show-private-key",
            "--show-mnemonic",
        ],
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        format!("{}\n", vector["plaintext"].as_str().unwrap()).as_bytes()
    );
    assert_eq!(fs::read(&file).unwrap(), bytes.as_bytes());
    let after = fs::metadata(&file).unwrap();
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(after.permissions().mode(), before.permissions().mode());
    }
    let exported = invoke(
        dir.path(),
        &["wallet", "export", "--private-key", "--mnemonic"],
    );
    assert!(exported.status.success());
    let expected = format!(
        "SECURITY WARNING: Keep your private key and mnemonic secret!\n------------------------------------------------------------\nPrivate Key: {}\nMnemonic: {}\n",
        vector["derived"]["private_key"].as_str().unwrap(),
        vector["derived"]["mnemonic"].as_str().unwrap()
    );
    assert_eq!(exported.stdout, expected.as_bytes());
}
#[test]
fn cli_read_failure_and_password_order_use_the_real_mapped_store() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("wallet.json");
    let absent = invoke(dir.path(), &["wallet", "info", "--json"]);
    assert_eq!(absent.status.code(), Some(1));
    assert_eq!(
        absent.stderr,
        b"Error getting wallet info: Wallet not found. Please run 'bitbid init' first.\n"
    );
    fs::create_dir(&file).unwrap();
    let directory = invoke(dir.path(), &["wallet", "info", "--json"]);
    assert_eq!(directory.status.code(), Some(1));
    assert_eq!(
        directory.stderr,
        b"Error getting wallet info: Wallet storage read failed\n"
    );
    fs::remove_dir(&file).unwrap();
    fs::write(
        &file,
        json!({"encrypted":true,"data":"PUBLIC malformed","last_accessed":1}).to_string(),
    )
    .unwrap();
    let password = invoke(dir.path(), &["wallet", "info", "--json"]);
    assert_eq!(password.status.code(), Some(2));
    assert_eq!(
        password.stderr,
        b"Error getting wallet info: Wallet is encrypted. Password is required.\n"
    );
    fs::write(&file, b"{").unwrap();
    let parse = invoke(dir.path(), &["wallet", "info", "--json"]);
    assert_eq!(parse.status.code(), Some(1));
    assert_eq!(
        parse.stderr,
        b"Error getting wallet info: EOF while parsing an object at line 1 column 1\n"
    );
}

#[cfg(unix)]
#[test]
fn native_presence_check_preserves_missing_for_denied_symlink_parent_and_loop() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "requires actual non-root denial"
    );
    let dir = tempfile::tempdir().unwrap();
    let app = dir.path().join("app");
    fs::create_dir(&app).unwrap();
    let target_parent = dir.path().join("PUBLIC-target-parent");
    fs::create_dir(&target_parent).unwrap();
    let target = target_parent.join("wallet.json");
    let bytes =
        json!({"encrypted":false,"data":vector()["plaintext"],"last_accessed":1}).to_string();
    fs::write(&target, &bytes).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
    let before = fs::metadata(&target).unwrap();
    let wallet = app.join("wallet.json");
    symlink(&target, &wallet).unwrap();
    struct Restore(std::path::PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    fs::set_permissions(&target_parent, fs::Permissions::from_mode(0o000)).unwrap();
    let restore = Restore(target_parent);
    let denied = invoke(&app, &["wallet", "info", "--json"]);
    drop(restore);
    assert_eq!(denied.status.code(), Some(1));
    assert_eq!(
        denied.stderr,
        b"Error getting wallet info: Wallet not found. Please run 'bitbid init' first.\n"
    );
    assert!(denied.stdout.is_empty());
    assert_eq!(fs::read(&target).unwrap(), bytes.as_bytes());
    let after = fs::metadata(&target).unwrap();
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
    assert_eq!(after.permissions().mode(), before.permissions().mode());
    fs::remove_file(&wallet).unwrap();
    symlink(&wallet, &wallet).unwrap();
    let looped = invoke(&app, &["wallet", "info", "--json"]);
    assert_eq!(looped.status.code(), Some(1));
    assert_eq!(looped.stderr, denied.stderr);
    assert!(looped.stdout.is_empty());
}
