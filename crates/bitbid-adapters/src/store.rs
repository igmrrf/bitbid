//! Explicit native blob paths; selection and decoding remain the caller's policy.
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use bitbid_core::{Store, StoreError, StoreKey, WriteOpts};

/// A filesystem Store with no implicit home, environment, or parent creation.
///
/// Only Wallet, NetworkConfig and SecretIndex bindings are supported. Other
/// keys remain unconfigured even if supplied to `new`. Reads follow symlinks;
/// Unix writes refuse final symlinks, and removal unlinks the configured entry.
/// Writes are not atomic replacements: a later I/O error may leave partial data.
#[derive(Debug, Default)]
pub struct FileStore {
    paths: HashMap<StoreKey, PathBuf>,
}

impl FileStore {
    pub fn new(bindings: impl IntoIterator<Item = (StoreKey, PathBuf)>) -> Self {
        Self {
            paths: bindings
                .into_iter()
                .filter(|(key, _)| matches!(key, StoreKey::Wallet | StoreKey::NetworkConfig | StoreKey::SecretIndex))
                .collect(),
        }
    }

    fn path(&self, key: &StoreKey) -> Result<&Path, StoreError> {
        self.paths
            .get(key)
            .map(PathBuf::as_path)
            .ok_or_else(|| StoreError::Io("unconfigured store key".into()))
    }
}

fn io_error(error: io::Error) -> StoreError {
    match error.kind() {
        io::ErrorKind::NotFound => StoreError::NotFound("store target not found".into()),
        io::ErrorKind::PermissionDenied => {
            StoreError::PermissionDenied("store access denied".into())
        }
        io::ErrorKind::AlreadyExists => {
            StoreError::AlreadyExists("store entry already exists".into())
        }
        _ => StoreError::Io("store I/O failed".into()),
    }
}

fn regular(file: &File) -> Result<(), StoreError> {
    if file.metadata().map_err(io_error)?.is_file() {
        Ok(())
    } else {
        Err(StoreError::Io("store target is not a regular file".into()))
    }
}

fn open_read(path: &Path) -> Result<Option<File>, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    // A FIFO must fail the regular-file check rather than waiting for a writer.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    match options.open(path) {
        Ok(file) => {
            regular(&file)?;
            Ok(Some(file))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn open_write(path: &Path, opts: WriteOpts) -> Result<File, StoreError> {
    #[cfg(not(unix))]
    {
        if opts.private {
            return Err(StoreError::Io(
                "private storage permissions unsupported on this host".into(),
            ));
        }
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(StoreError::Io("store write refuses a symlink".into()));
        }
    }
    let mut options = OpenOptions::new();
    options.write(true);
    if opts.create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if opts.private { 0o600 } else { 0o666 });
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(io_error)?;
    regular(&file)?;
    #[cfg(unix)]
    if opts.private {
        use std::os::unix::fs::PermissionsExt;
        // Enforce privacy on the open descriptor before truncation or data.
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
    }
    Ok(file)
}

impl Store for FileStore {
    fn read(&self, key: &StoreKey) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(mut file) = open_read(self.path(key)?)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io_error)?;
        Ok(Some(bytes))
    }

    fn exists(&self, key: &StoreKey) -> Result<bool, StoreError> {
        Ok(open_read(self.path(key)?)?.is_some())
    }

    fn write(&self, key: &StoreKey, bytes: &[u8], opts: WriteOpts) -> Result<(), StoreError> {
        let path = self.path(key)?;
        let mut file = open_write(path, opts)?;
        file.set_len(0).map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)
    }

    fn remove(&self, key: &StoreKey) -> Result<(), StoreError> {
        let path = self.path(key)?;
        // macOS reports unlink(directory) as EPERM; classify the target as Io,
        // while retaining PermissionDenied for actual access denial.
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
            return Err(StoreError::Io("store target is not a regular file".into()));
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn private_descriptor_is_private_while_original_data_is_still_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        fs::write(&path, b"original bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let file = open_write(
            &path,
            WriteOpts {
                private: true,
                create_new: false,
            },
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"original bytes");
        // New private descriptors are also private before any write.
        let fresh = dir.path().join("fresh");
        let file = open_write(
            &fresh,
            WriteOpts {
                private: true,
                create_new: true,
            },
        )
        .unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
}
