//! Lazy canonical home selection. Values and paths never enter diagnostics.
use crate::errors::BitbidError;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static APP_DIR: OnceLock<std::result::Result<(PathBuf, &'static str), &'static str>> =
    OnceLock::new();

pub fn error(message: &str) -> anyhow::Error {
    BitbidError::ConfigError(message.into()).into()
}

/// Lexical presence includes dangling links, so unusable selected paths fail closed.
pub fn present(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn usable_dir(path: &Path) -> std::io::Result<()> {
    if !fs::metadata(path)?.is_dir() {
        return Err(std::io::Error::other("invalid directory"));
    }
    // Check both enumeration and traversal/create permission without touching data.
    let _ = fs::read_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("invalid directory"))?;
        // SAFETY: path is NUL-terminated and lives through the call.
        if unsafe { libc::access(path.as_ptr(), libc::R_OK | libc::W_OK | libc::X_OK) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn ensure_dir(path: &Path) -> std::io::Result<()> {
    if !present(path)? {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
    }
    usable_dir(path)
}

fn select_app_dir() -> std::result::Result<(PathBuf, &'static str), &'static str> {
    if let Some(value) = std::env::var_os("BITBID_HOME") {
        let message = "invalid BITBID_HOME.";
        let value = value.into_string().map_err(|_| message)?;
        if value.trim().is_empty() || value.contains('\0') {
            return Err(message);
        }
        let path = PathBuf::from(value);
        ensure_dir(&path).map_err(|_| message)?;
        return std::path::absolute(path)
            .map(|path| (path, message))
            .map_err(|_| message);
    }
    default_app_dir(dirs::home_dir()).map(|path| (path, "invalid application directory."))
}

pub(super) fn default_app_dir(home: Option<PathBuf>) -> std::result::Result<PathBuf, &'static str> {
    let home = home.ok_or("cannot determine home directory.")?;
    select_default_dir(&home)
}

fn select_default_dir(home: &Path) -> std::result::Result<PathBuf, &'static str> {
    let message = "invalid application directory.";
    let path = home.join(".bitbid");
    ensure_dir(&path).map_err(|_| message)?;
    Ok(path)
}

pub fn app_dir() -> Result<PathBuf> {
    match APP_DIR.get_or_init(select_app_dir) {
        Ok((path, message)) => {
            // Selection stays fixed, but a replaced/unusable root must fail before use.
            usable_dir(path).map_err(|_| error(message))?;
            Ok(path.clone())
        }
        Err(message) => Err(error(message)),
    }
}
