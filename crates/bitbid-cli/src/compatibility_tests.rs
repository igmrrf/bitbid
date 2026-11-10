//! Native-only resolver fixtures run in fresh processes so OS environment, cwd,
//! absence of retired warnings, and cached selection exercise their production boundaries.
use crate::{compat, ipfs, network_config, project_config, wallet};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

fn child(root: &Path, case: &str) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "compatibility_tests::fixture",
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .current_dir(root)
    .stdin(Stdio::null())
    .env("HOME", root)
    .env("N4_FIXTURE", case);
    for name in [
        "BITBID_HOME",
        "BSEC_HOME",
        "BITBID_PINATA_JWT",
        "BSEC_PINATA_JWT",
        "N4_CONFIG",
        "N4_EXPECT",
        "N4_ACTION",
    ] {
        cmd.env_remove(name);
    }
    cmd
}
fn assert_ok(out: Output, warnings: &str) {
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stderr, warnings.as_bytes());
}

#[test]
#[ignore = "isolated child fixture; invoked by parent tests"]
fn fixture() {
    let case = std::env::var("N4_FIXTURE").unwrap();
    let expected = std::env::var("N4_EXPECT").unwrap_or_default();
    match case.as_str() {
        "home" => {
            for _ in 0..3 {
                match wallet::get_app_dir() {
                    Ok(path) => assert_eq!(path, PathBuf::from(&expected)),
                    Err(error) => {
                        assert_eq!(error.to_string(), expected);
                        assert_eq!(
                            error
                                .downcast_ref::<crate::errors::BitbidError>()
                                .unwrap()
                                .exit_code(),
                            4
                        );
                    }
                }
            }
        }
        "home-cache" => {
            let selected = wallet::get_app_dir().unwrap();
            assert_eq!(selected, PathBuf::from(expected));
            fs::create_dir("changed-cwd").unwrap();
            std::env::set_current_dir("changed-cwd").unwrap();
            assert_eq!(wallet::get_app_dir().unwrap(), selected);
            fs::remove_dir(&selected).unwrap();
            fs::write(&selected, "replaced root").unwrap();
            assert!(wallet::get_app_dir().is_err());
        }
        "jwt" => {
            let mut config = network_config::NetworkConfig::default();
            config.ipfs.pinning_jwt = std::env::var("N4_CONFIG").ok();
            for _ in 0..3 {
                match ipfs::resolve_pinning_jwt(&config) {
                    Ok(value) => assert_eq!(value.as_deref().unwrap_or("DISABLED"), expected),
                    Err(error) => {
                        assert_eq!(error.to_string(), expected);
                        assert_eq!(
                            error
                                .downcast_ref::<crate::errors::BitbidError>()
                                .unwrap()
                                .exit_code(),
                            4
                        );
                    }
                }
            }
        }
        "project" => {
            let action = std::env::var("N4_ACTION").unwrap_or_default();
            for _ in 0..3 {
                match project_config::load_project_config() {
                    Ok(value) => assert_eq!(
                        value.and_then(|v| v.env_file).as_deref().unwrap_or("NONE"),
                        expected
                    ),
                    Err(error) => assert_eq!(error.to_string(), expected),
                }
            }
            let config = project_config::ProjectConfig {
                env_file: Some("saved.env".into()),
                ..Default::default()
            };
            if action == "save-denied" {
                assert_eq!(
                    project_config::save_project_config(&config)
                        .unwrap_err()
                        .to_string(),
                    "Configuration error: invalid project configuration."
                );
            }
            if action == "legacy-change" {
                fs::write(".bsec.json", "invalid retired config").unwrap();
                assert_eq!(
                    project_config::load_project_config()
                        .unwrap()
                        .and_then(|v| v.env_file)
                        .as_deref()
                        .unwrap_or("NONE"),
                    expected
                );
            }
            if action == "save" || action == "legacy-change" {
                project_config::save_project_config(&config).unwrap();
            }
            if action == "refuse" {
                assert_eq!(
                    project_config::save_project_config(&config)
                        .unwrap_err()
                        .to_string(),
                    expected
                );
            }
            if action == "switch" {
                fs::create_dir("other-cwd").unwrap();
                std::env::set_current_dir("other-cwd").unwrap();
                assert!(project_config::save_project_config(&config).is_err());
            }
            if action == "remove" {
                fs::remove_file(project_config::get_project_config_path().unwrap()).unwrap();
                assert!(project_config::save_project_config(&config).is_err());
            }
            if action == "replace" {
                let path = project_config::get_project_config_path().unwrap();
                fs::rename(&path, "retained-original.json").unwrap();
                fs::write(&path, "{}").unwrap();
                assert!(project_config::save_project_config(&config).is_err());
                assert_eq!(fs::read(&path).unwrap(), b"{}");
            }
            if action == "corrupt" {
                fs::write(project_config::get_project_config_path().unwrap(), "broken").unwrap();
                assert!(project_config::save_project_config(&config).is_err());
            }
        }
        "pinata-transport" => {
            let mut config = network_config::NetworkConfig::default();
            config.ipfs.pinning_jwt = std::env::var("N4_CONFIG").ok();
            match ipfs::resolve_pinning_jwt(&config) {
                Ok(Some(jwt)) => {
                    let certificate = fs::read(std::env::var("N4_CA").unwrap()).unwrap();
                    assert_eq!(
                        ipfs::pinata_transport_fixture(
                            &jwt,
                            &certificate,
                            &std::env::var("N4_PROXY").unwrap()
                        )
                        .unwrap_or_else(|error| panic!("{error:?}")),
                        expected
                    );
                }
                Ok(None) => assert_eq!(expected, "DISABLED"),
                Err(error) => assert_eq!(error.to_string(), expected),
            }
        }
        "upload" => match ipfs::upload_to_ipfs("{\"synthetic\":true}") {
            Ok(cid) => assert_eq!(cid, expected),
            Err(error) => {
                assert_eq!(error.to_string(), expected);
                assert_eq!(
                    error
                        .downcast_ref::<crate::errors::BitbidError>()
                        .unwrap()
                        .exit_code(),
                    4
                );
            }
        },
        "surfaces" => {
            for _ in 0..3 {
                wallet::get_app_dir().unwrap();
                project_config::load_project_config().unwrap();
                ipfs::resolve_pinning_jwt(&network_config::NetworkConfig::default()).unwrap();
            }
        }
        "cache" => {
            ipfs::assert_cache_file_containment();
            let dir = ipfs::get_ipfs_cache_dir().unwrap();
            assert_eq!(
                dir,
                PathBuf::from(std::env::var("HOME").unwrap()).join(".bitbid/ipfs_cache")
            );
        }
        _ => panic!("unknown fixture"),
    }
}

#[cfg(unix)]
fn nonunicode() -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(vec![0xff, 0xfe])
}
#[cfg(not(unix))]
fn nonunicode() -> OsString {
    OsString::from("invalid\nvalue")
}

#[test]
fn home_env_presence_cartesian_ignores_all_legacy_values() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    for name in ["valid path", "different"] {
        fs::create_dir(root.join(name)).unwrap();
    }
    fs::write(root.join("invalid-PATH-SENTINEL"), "not a directory").unwrap();
    let valid = root.join("valid path").into_os_string();
    let different = root.join("different").into_os_string();
    let values = [
        None,
        Some(valid.clone()),
        Some(different),
        Some(OsString::new()),
        Some(" \t ".into()),
        Some(root.join("invalid-PATH-SENTINEL").into_os_string()),
        Some(nonunicode()),
    ];
    for canonical in &values {
        for legacy in &values {
            let mut cmd = child(root, "home");
            if let Some(v) = canonical {
                cmd.env("BITBID_HOME", v);
            }
            if let Some(v) = legacy {
                cmd.env("BSEC_HOME", v);
            }
            let selected = canonical.as_ref();
            let expected = match selected {
                None => root.join(".bitbid").to_str().unwrap().to_owned(),
                Some(v) if v == &valid || v == values[2].as_ref().unwrap() => {
                    v.to_str().unwrap().to_owned()
                }
                _ => "Configuration error: invalid BITBID_HOME.".into(),
            };
            cmd.env("N4_EXPECT", expected);
            assert_ok(cmd.output().unwrap(), "");
        }
    }
    // Relative, spaces, and literal shell syntax are preserved rather than trimmed/expanded.
    for value in ["relative path", " leading and trailing ", "~literal"] {
        let mut cmd = child(root, "home");
        cmd.env("BITBID_HOME", value)
            .env("N4_EXPECT", root.join(value));
        assert_ok(cmd.output().unwrap(), "");
        assert!(root.join(value).is_dir());
    }
}

#[test]
fn jwt_env_config_cartesian_validates_header_and_never_falls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let values = [
        None,
        Some(OsString::from("TOKEN-SENTINEL")),
        Some(OsString::from("OTHER-SENTINEL")),
        Some(OsString::from(" opaque TOKEN-SENTINEL ")),
        Some(OsString::from("control\tTOKEN-SENTINEL")),
        Some(OsString::from("control\u{7f}TOKEN-SENTINEL")),
        Some(OsString::new()),
        Some(" \t ".into()),
        Some("INVALID\nTOKEN-SENTINEL".into()),
        Some(nonunicode()),
    ];
    for config in [
        None,
        Some(""),
        Some(" \t "),
        Some("CONFIG-SENTINEL"),
        Some("CONFIG\nSENTINEL"),
    ] {
        for canonical in &values {
            for legacy in &values {
                let mut cmd = child(tmp.path(), "jwt");
                if let Some(v) = canonical {
                    cmd.env("BITBID_PINATA_JWT", v);
                }
                if let Some(v) = legacy {
                    cmd.env("BSEC_PINATA_JWT", v);
                }
                if let Some(v) = config {
                    cmd.env("N4_CONFIG", v);
                }
                let config_wins = config.is_some_and(|v| !v.trim().is_empty());
                let selected = if config_wins {
                    config.map(OsString::from)
                } else {
                    canonical.clone()
                };
                let expected = match selected.as_ref().and_then(|v| v.to_str()) {
                    Some(v) if v.trim().is_empty() => "DISABLED",
                    Some(v) if !v.bytes().any(|byte| byte.is_ascii_control()) => v,
                    None if selected.is_none() => "DISABLED",
                    _ => "Configuration error: invalid Pinata credential.",
                };
                cmd.env("N4_EXPECT", expected);
                assert_ok(cmd.output().unwrap(), "");
            }
        }
    }
}

#[test]
fn project_native_save_selection_revalidation_and_alternate_preservation() {
    for (canonical, legacy, selected, warning) in [
        (None, None, ".bitbid.json", ""),
        (
            Some("{}"),
            Some("{\"env_file\":\"old.env\"}"),
            ".bitbid.json",
            "",
        ),
        (None, Some("{}"), ".bitbid.json", ""),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        if let Some(data) = canonical {
            fs::write(root.join(".bitbid.json"), data).unwrap();
        }
        if let Some(data) = legacy {
            fs::write(root.join(".bsec.json"), data).unwrap();
        }
        let alternate = root.join(if selected == ".bitbid.json" {
            ".bsec.json"
        } else {
            ".bitbid.json"
        });
        let alternate_before = fs::read(&alternate).ok();
        let mut cmd = child(root, "project");
        cmd.env("N4_EXPECT", "NONE").env("N4_ACTION", "save");
        assert_ok(cmd.output().unwrap(), warning);
        assert_eq!(fs::read(&alternate).ok(), alternate_before);
        let saved: project_config::ProjectConfig =
            serde_json::from_slice(&fs::read(root.join(selected)).unwrap()).unwrap();
        assert_eq!(saved.env_file.as_deref(), Some("saved.env"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(root.join(selected))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    for invalid in ["", "broken-CONTENT-SENTINEL", "[]", "{\"env_file\":4}"] {
        {
            let selected = ".bitbid.json";
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join(selected);
            fs::write(&path, invalid).unwrap();
            if selected == ".bitbid.json" {
                fs::write(tmp.path().join(".bsec.json"), "{}").unwrap();
            }
            let mut cmd = child(tmp.path(), "project");
            cmd.env(
                "N4_EXPECT",
                "Configuration error: invalid project configuration.",
            )
            .env("N4_ACTION", "refuse");
            assert_ok(cmd.output().unwrap(), "");
            assert_eq!(fs::read(&path).unwrap(), invalid.as_bytes());
        }
    }
    for action in ["switch", "remove", "corrupt", "replace"] {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(".bitbid.json"), "{}").unwrap();
        let mut cmd = child(tmp.path(), "project");
        cmd.env("N4_EXPECT", "NONE").env("N4_ACTION", action);
        assert_ok(cmd.output().unwrap(), "");
        if action != "switch" {
            assert!(!tmp.path().join(".bsec.json").exists());
        }
    }
}

#[test]
fn failed_home_discovery_is_a_configuration_error() {
    assert_eq!(
        compat::default_app_dir(None).unwrap_err(),
        "cannot determine home directory."
    );
}

pub(super) fn cache_path_fixture() {
    let tmp = tempfile::tempdir().unwrap();
    assert_ok(child(tmp.path(), "cache").output().unwrap(), "");
}

#[test]
fn retired_surfaces_are_ignored_without_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("legacy")).unwrap();
    fs::write(tmp.path().join(".bsec.json"), "{}").unwrap();
    let mut cmd = child(tmp.path(), "surfaces");
    cmd.env("BSEC_HOME", tmp.path().join("legacy"))
        .env("BSEC_PINATA_JWT", "opaque-TOKEN-SENTINEL");
    assert_ok(cmd.output().unwrap(), "");
    assert!(tmp.path().join(".bitbid").is_dir());
    assert_eq!(fs::read_dir(tmp.path().join("legacy")).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn native_save_follows_valid_symlink_and_refuses_unusable_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target.json");
    fs::write(&target, "{}").unwrap();
    symlink(&target, tmp.path().join(".bitbid.json")).unwrap();
    let mut cmd = child(tmp.path(), "project");
    cmd.env("N4_EXPECT", "NONE").env("N4_ACTION", "save");
    assert_ok(cmd.output().unwrap(), "");
    assert!(tmp.path().join(".bitbid.json").is_symlink());
    assert_eq!(
        fs::read_link(tmp.path().join(".bitbid.json")).unwrap(),
        target
    );
    assert!(fs::read_to_string(&target).unwrap().contains("saved.env"));
    assert!(!tmp.path().join(".bsec.json").exists());
    for kind in ["dir", "dangling", "fifo", "denied-read", "denied-write"] {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".bitbid.json");
        match kind {
            "dir" => fs::create_dir(&path).unwrap(),
            "dangling" => symlink("missing", &path).unwrap(),
            "fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => {
                assert_ne!(unsafe { libc::geteuid() }, 0);
                fs::write(&path, "{}").unwrap();
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if kind == "denied-read" { 0o0 } else { 0o400 }),
                )
                .unwrap();
            }
        }
        let mut cmd = child(tmp.path(), "project");
        cmd.env(
            "N4_EXPECT",
            if kind == "denied-write" {
                "NONE"
            } else {
                "Configuration error: invalid project configuration."
            },
        )
        .env(
            "N4_ACTION",
            if kind == "denied-write" {
                "save-denied"
            } else {
                "refuse"
            },
        );
        assert_ok(cmd.output().unwrap(), "");
        assert!(!tmp.path().join(".bsec.json").exists());
        if kind.starts_with("denied") {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"{}");
        }
    }
}

#[test]
fn cached_relative_home_remains_selected_and_revalidates_usability() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cmd = child(tmp.path(), "home-cache");
    cmd.env("BITBID_HOME", "relative-root")
        .env("BSEC_HOME", "retired-root")
        .env("N4_EXPECT", tmp.path().join("relative-root"));
    assert_ok(cmd.output().unwrap(), "");
    assert!(!tmp.path().join("retired-root").exists());
}

#[cfg(unix)]
#[test]
fn default_directory_cartesian_never_probes_retired_root() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    assert_ne!(unsafe { libc::geteuid() }, 0);
    for canonical in ["absent", "dir", "file", "dangling", "denied"] {
        for legacy in ["absent", "dir", "file", "dangling", "denied"] {
            let tmp = tempfile::tempdir().unwrap();
            let make = |name: &str, kind: &str| {
                let path = tmp.path().join(name);
                match kind {
                    "absent" => (),
                    "dir" | "denied" => {
                        fs::create_dir(&path).unwrap();
                        if kind == "denied" {
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o0)).unwrap();
                        }
                    }
                    "file" => fs::write(&path, "retained bytes").unwrap(),
                    "dangling" => symlink("missing", &path).unwrap(),
                    _ => unreachable!(),
                }
            };
            make(".bitbid", canonical);
            make(".bsec", legacy);
            let retired = tmp.path().join(".bsec");
            let before = fs::symlink_metadata(&retired)
                .ok()
                .map(|m| (m.permissions().mode(), m.modified().unwrap()));
            let mut cmd = child(tmp.path(), "home");
            cmd.env(
                "N4_EXPECT",
                if matches!(canonical, "absent" | "dir") {
                    tmp.path().join(".bitbid").to_str().unwrap().to_owned()
                } else {
                    "Configuration error: invalid application directory.".into()
                },
            );
            assert_ok(cmd.output().unwrap(), "");
            assert_eq!(
                fs::symlink_metadata(&retired)
                    .ok()
                    .map(|m| (m.permissions().mode(), m.modified().unwrap())),
                before
            );
            if legacy == "denied" {
                fs::set_permissions(&retired, fs::Permissions::from_mode(0o700)).unwrap();
            }
            if canonical == "denied" {
                fs::set_permissions(
                    tmp.path().join(".bitbid"),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            }
        }
    }
}

#[test]
fn malformed_retired_project_is_ignored_before_and_after_canonical_selection() {
    for canonical in [None, Some("{}"), Some("{\"env_file\":\"canonical.env\"}")] {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join(".bsec.json"), "retired malformed data").unwrap();
        if let Some(data) = canonical {
            fs::write(tmp.path().join(".bitbid.json"), data).unwrap();
        }
        let mut cmd = child(tmp.path(), "project");
        cmd.env(
            "N4_EXPECT",
            if canonical.is_some_and(|v| v.contains("canonical.env")) {
                "canonical.env"
            } else {
                "NONE"
            },
        )
        .env("N4_ACTION", "legacy-change");
        assert_ok(cmd.output().unwrap(), "");
    }
}
