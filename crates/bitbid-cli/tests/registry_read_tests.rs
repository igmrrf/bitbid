//! Actual CLI characterization. The same audited fixture accepts release/installed
//! binaries through --binary, without adding a production environment setting.
#[test]
fn actual_cli_preserves_registry_listing_and_never_rewrites_wallet() {
    let probe =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/registry_probe.py");
    let out = std::process::Command::new("python3")
        .arg(probe)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_bsec"))
        .output()
        .expect("run synthetic HTTP/CLI probe");
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
