//! Real CLI selection failures must stop before child execution and preserve state.
use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

fn cli(root: &Path, args: &[&str], settings: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bitbid"));
    command
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .env("HOME", root);
    for name in [
        "BITBID_HOME",
        "BSEC_HOME",
        "BITBID_PINATA_JWT",
        "BSEC_PINATA_JWT",
    ] {
        command.env_remove(name);
    }
    for (name, value) in settings {
        command.env(name, value);
    }
    command.output().unwrap()
}

#[test]
fn invalid_canonical_home_never_falls_back_and_json_stays_empty() {
    let tmp = TempDir::new().unwrap();
    let canonical = tmp.path().join("PATH-SENTINEL");
    let legacy = tmp.path().join("legacy");
    fs::write(&canonical, "untouched").unwrap();
    fs::create_dir(&legacy).unwrap();
    for args in [
        vec!["wallet", "info", "--json"],
        vec!["list", "--json"],
        vec!["config", "--show", "--json"],
    ] {
        let out = cli(
            tmp.path(),
            &args,
            &[("BITBID_HOME", &canonical), ("BSEC_HOME", &legacy)],
        );
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(stderr.ends_with("Configuration error: invalid BITBID_HOME.\n"));
        assert!(!stderr.contains("SENTINEL"));
        assert!(!stderr.contains("deprecated"));
        assert_eq!(fs::read(&canonical).unwrap(), b"untouched");
        assert_eq!(fs::read_dir(&legacy).unwrap().count(), 0);
    }
}

#[test]
fn invalid_canonical_project_blocks_child_even_with_explicit_flags() {
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join(".bitbid.json"), "CONTENT-SENTINEL").unwrap();
    fs::write(tmp.path().join(".bsec.json"), "{}").unwrap();
    fs::write(tmp.path().join("valid.env"), "X=valid\n").unwrap();
    let out = cli(
        tmp.path(),
        &[
            "run",
            "-e",
            "valid.env",
            "--",
            "/usr/bin/touch",
            "child-ran",
        ],
        &[],
    );
    assert_eq!(out.status.code(), Some(4));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .ends_with("Configuration error: invalid project configuration.\n")
    );
    assert!(!tmp.path().join("child-ran").exists());
    assert!(!tmp.path().join(".bitbid").exists());
    assert_eq!(
        fs::read(tmp.path().join(".bitbid.json")).unwrap(),
        b"CONTENT-SENTINEL"
    );
}

#[test]
fn valid_explicit_flags_override_valid_project_fields() {
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join(".bitbid.json"), r#"{"env_file":"old.env"}"#).unwrap();
    fs::write(tmp.path().join("old.env"), "N4_OVERRIDE=old\n").unwrap();
    fs::write(tmp.path().join("new.env"), "N4_OVERRIDE=new\n").unwrap();
    let out = cli(
        tmp.path(),
        &[
            "run",
            "-e",
            "new.env",
            "--",
            "/bin/sh",
            "-c",
            "printf %s \"$N4_OVERRIDE\"",
        ],
        &[],
    );
    assert!(out.status.success());
    assert_eq!(out.stdout, b"new");
    assert!(out.stderr.is_empty());
    assert!(!tmp.path().join(".bitbid").exists());
}

#[cfg(unix)]
#[test]
fn denied_directory_and_project_read_are_real_nonprivileged_failures() {
    use std::os::unix::fs::PermissionsExt;
    // The executing uid must actually experience denial, not merely inspect mode bits.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run permission fixtures as a nonprivileged user"
    );
    let tmp = TempDir::new().unwrap();
    let denied = tmp.path().join("denied");
    fs::create_dir(&denied).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o0)).unwrap();
    assert!(fs::read_dir(&denied).is_err());
    let out = cli(
        tmp.path(),
        &["wallet", "info", "--json"],
        &[("BITBID_HOME", &denied)],
    );
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(out.stdout.is_empty());
    let project = tmp.path().join(".bitbid.json");
    fs::write(&project, "{}").unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o0)).unwrap();
    assert!(fs::read(&project).is_err());
    let out = cli(
        tmp.path(),
        &["run", "--", "/usr/bin/touch", "child-ran"],
        &[],
    );
    fs::set_permissions(&project, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(!tmp.path().join("child-ran").exists());
}
