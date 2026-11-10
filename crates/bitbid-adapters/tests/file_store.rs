#![cfg(unix)]
use bitbid_adapters::store::FileStore;
use bitbid_core::{Store, StoreError, StoreKey, WriteOpts};
use std::{
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{PermissionsExt, symlink},
    },
    process::Command,
    sync::{Arc, Barrier},
};

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}
fn chmod(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn store(path: &std::path::Path) -> FileStore {
    FileStore::new([(StoreKey::SecretIndex, path.to_owned())])
}

#[test]
fn explicit_mappings_round_trip_arbitrary_bytes_absence_and_removal() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("wallet");
    let config = dir.path().join("config");
    let index = dir.path().join("index");
    let store = FileStore::new([
        (StoreKey::Wallet, wallet.clone()),
        (StoreKey::NetworkConfig, config.clone()),
        (StoreKey::SecretIndex, index.clone()),
    ]);
    let bytes = [0, 255, 128, 13, 10, 0, 42];
    for key in [StoreKey::Wallet, StoreKey::NetworkConfig, StoreKey::SecretIndex] {
        assert_eq!(store.read(&key).unwrap(), None);
        assert!(!store.exists(&key).unwrap());
        store.remove(&key).unwrap();
        store.write(&key, &bytes, WriteOpts::default()).unwrap();
        let path = if key == StoreKey::Wallet {
            &wallet
        } else if key == StoreKey::NetworkConfig {
            &config
        } else {
            &index
        };
        chmod(path, 0o640);
        assert!(store.exists(&key).unwrap());
        assert_eq!(store.read(&key).unwrap(), Some(bytes.to_vec()));
        assert_eq!(mode(path), 0o640);
        store.write(&key, b"short", WriteOpts::default()).unwrap();
        assert_eq!(fs::read(path).unwrap(), b"short");
        assert_eq!(mode(path), 0o640);
        store
            .write(
                &key,
                b"private",
                WriteOpts {
                    private: true,
                    create_new: false,
                },
            )
            .unwrap();
        assert_eq!(mode(path), 0o600);
        assert_eq!(fs::read(path).unwrap(), b"private");
        store.remove(&key).unwrap();
        store.remove(&key).unwrap();
    }
}

#[test]
fn every_unconfigured_operation_fails_with_fixed_safe_payload() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::new([(StoreKey::ProjectConfig, dir.path().join("must-not-map"))]);
    for key in [
        StoreKey::Wallet,
        StoreKey::NetworkConfig,
        StoreKey::SecretIndex,
        StoreKey::ProjectConfig,
        StoreKey::IpfsCache("private-payload".into()),
    ] {
        let errors = [
            store.read(&key).unwrap_err(),
            store.exists(&key).unwrap_err(),
            store
                .write(&key, b"secret", WriteOpts::default())
                .unwrap_err(),
            store.remove(&key).unwrap_err(),
        ];
        for error in errors {
            assert!(matches!(error, StoreError::Io(ref text) if text == "unconfigured store key"));
        }
    }
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn links_are_followed_only_for_reads_and_unlinked_without_touching_target() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    let link = dir.path().join("link");
    fs::write(&victim, b"target").unwrap();
    chmod(&victim, 0o640);
    symlink(&victim, &link).unwrap();
    let store = store(&link);
    let key = StoreKey::SecretIndex;
    assert_eq!(store.read(&key).unwrap(), Some(b"target".to_vec()));
    assert!(store.exists(&key).unwrap());
    assert!(matches!(
        store.write(&key, b"bad", WriteOpts::default()),
        Err(StoreError::Io(_))
    ));
    assert!(matches!(
        store.write(
            &key,
            b"bad",
            WriteOpts {
                private: true,
                create_new: true
            }
        ),
        Err(StoreError::AlreadyExists(_))
    ));
    assert_eq!(fs::read(&victim).unwrap(), b"target");
    assert_eq!(mode(&victim), 0o640);
    store.remove(&key).unwrap();
    assert!(!link.exists());
    assert_eq!(fs::read(&victim).unwrap(), b"target");
    symlink(dir.path().join("missing"), &link).unwrap();
    assert_eq!(store.read(&key).unwrap(), None);
    assert!(!store.exists(&key).unwrap());
    assert!(matches!(
        store.write(&key, b"bad", WriteOpts::default()),
        Err(StoreError::Io(_))
    ));
    assert!(matches!(
        store.write(
            &key,
            b"bad",
            WriteOpts {
                private: false,
                create_new: true
            }
        ),
        Err(StoreError::AlreadyExists(_))
    ));
    store.remove(&key).unwrap();
    assert!(fs::symlink_metadata(&link).is_err());
    let parent_link = dir.path().join("parent");
    symlink(dir.path(), &parent_link).unwrap();
    let parent_store = FileStore::new([(key.clone(), parent_link.join("child"))]);
    parent_store
        .write(&key, b"parent symlink supported", WriteOpts::default())
        .unwrap();
    assert_eq!(
        fs::read(dir.path().join("child")).unwrap(),
        b"parent symlink supported"
    );
}

#[test]
fn nonregular_targets_and_missing_parents_do_not_mutate_or_block() {
    let dir = tempfile::tempdir().unwrap();
    let key = StoreKey::SecretIndex;
    let directory = dir.path().join("directory");
    fs::create_dir(&directory).unwrap();
    let fifo = dir.path().join("fifo");
    let raw = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: raw is a valid terminated owned path, mode contains permission bits.
    assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
    for path in [&directory, &fifo] {
        let store = store(path);
        assert!(matches!(store.read(&key), Err(StoreError::Io(_))));
        assert!(matches!(store.exists(&key), Err(StoreError::Io(_))));
        assert!(matches!(
            store.write(
                &key,
                b"bad",
                WriteOpts {
                    private: true,
                    create_new: false
                }
            ),
            Err(StoreError::Io(_))
        ));
        assert!(matches!(
            store.write(
                &key,
                b"bad",
                WriteOpts {
                    private: false,
                    create_new: true
                }
            ),
            Err(StoreError::AlreadyExists(_))
        ));
    }
    assert!(matches!(
        store(&directory).remove(&key),
        Err(StoreError::Io(_))
    ));
    store(&fifo).remove(&key).unwrap();
    assert!(directory.is_dir());
    let missing = dir.path().join("absent").join("child");
    let store = store(&missing);
    assert_eq!(store.read(&key).unwrap(), None);
    assert!(!store.exists(&key).unwrap());
    store.remove(&key).unwrap();
    assert!(matches!(
        store.write(&key, b"bad", WriteOpts::default()),
        Err(StoreError::NotFound(_))
    ));
    assert!(!missing.parent().unwrap().exists());
}

#[test]
fn real_nonroot_denial_is_typed_and_preserves_bytes_and_modes() {
    // SAFETY: geteuid has no preconditions or side effects.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "permission proof must run as a non-root uid"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("denied");
    let key = StoreKey::SecretIndex;
    fs::write(&path, b"unchanged").unwrap();
    chmod(&path, 0);
    assert_eq!(
        fs::read(&path).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let store = store(&path);
    assert!(matches!(
        store.read(&key),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.exists(&key),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.write(
            &key,
            b"bad",
            WriteOpts {
                private: true,
                create_new: false
            }
        ),
        Err(StoreError::PermissionDenied(_))
    ));
    assert_eq!(mode(&path), 0);
    chmod(&path, 0o600);
    assert_eq!(fs::read(&path).unwrap(), b"unchanged");
    let parent = dir.path().join("no-search");
    fs::create_dir(&parent).unwrap();
    let inside = parent.join("data");
    fs::write(&inside, b"original").unwrap();
    chmod(&parent, 0);
    let store = FileStore::new([(key.clone(), inside.clone())]);
    assert!(matches!(
        store.read(&key),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.exists(&key),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.write(&key, b"bad", WriteOpts::default()),
        Err(StoreError::PermissionDenied(_))
    ));
    assert!(matches!(
        store.remove(&key),
        Err(StoreError::PermissionDenied(_))
    ));
    chmod(&parent, 0o700);
    assert_eq!(fs::read(inside).unwrap(), b"original");
}

#[test]
fn create_new_has_one_atomic_winner_and_never_clobbers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("race");
    let store = Arc::new(store(&path));
    let gate = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0u8..8)
        .map(|i| {
            let store = store.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                (
                    i,
                    store.write(
                        &StoreKey::SecretIndex,
                        &[i],
                        WriteOpts {
                            private: true,
                            create_new: true,
                        },
                    ),
                )
            })
        })
        .collect();
    let mut winners = Vec::new();
    for thread in threads {
        let (i, result) = thread.join().unwrap();
        match result {
            Ok(()) => winners.push(i),
            Err(error) => assert!(matches!(error, StoreError::AlreadyExists(_))),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(fs::read(&path).unwrap(), winners);
    assert_eq!(mode(&path), 0o600);
    assert!(matches!(
        store.write(
            &StoreKey::SecretIndex,
            b"bad",
            WriteOpts {
                private: true,
                create_new: true
            }
        ),
        Err(StoreError::AlreadyExists(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), winners);
}

#[test]
fn ordinary_new_write_honors_umask_in_an_isolated_process() {
    const MARKER: &str = "BITBID_STORE_UMASK_TEST";
    if std::env::var_os(MARKER).is_some() {
        // SAFETY: only this isolated subprocess changes its process umask.
        unsafe {
            libc::umask(0o027);
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ordinary");
        store(&path)
            .write(&StoreKey::SecretIndex, b"data", WriteOpts::default())
            .unwrap();
        assert_eq!(mode(&path), 0o640);
        // Even an umask masking every creation bit must be followed by descriptor chmod.
        unsafe {
            libc::umask(0o777);
        }
        let private = dir.path().join("private");
        store(&private)
            .write(
                &StoreKey::SecretIndex,
                b"data",
                WriteOpts {
                    private: true,
                    create_new: true,
                },
            )
            .unwrap();
        assert_eq!(mode(&private), 0o600);
    } else {
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ordinary_new_write_honors_umask_in_an_isolated_process",
                "--nocapture",
            ])
            .env(MARKER, "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
