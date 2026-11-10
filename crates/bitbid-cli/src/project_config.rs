use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProjectConfig {
    pub secret_id: Option<String>,
    pub env_file: Option<String>,
    pub schema_file: Option<String>,
    pub network: Option<String>,
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    target: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn identity(path: &Path) -> Result<Option<FileIdentity>> {
    if !crate::compat::present(path).map_err(|_| invalid())? {
        return Ok(None);
    }
    let target = fs::canonicalize(path).map_err(|_| invalid())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).map_err(|_| invalid())?;
        Ok(Some(FileIdentity {
            target,
            device: metadata.dev(),
            inode: metadata.ino(),
        }))
    }
    #[cfg(not(unix))]
    {
        Ok(Some(FileIdentity { target }))
    }
}

struct Selection {
    path: PathBuf,
    identity: Option<FileIdentity>,
}
static SELECTED: OnceLock<std::result::Result<Mutex<Selection>, ()>> = OnceLock::new();
fn invalid() -> anyhow::Error {
    crate::compat::error("invalid project configuration.")
}

fn select_path() -> Result<PathBuf> {
    let cwd = std::env::current_dir().map_err(|_| invalid())?;
    Ok(cwd.join(".bitbid.json"))
}

pub fn get_project_config_path() -> Result<PathBuf> {
    let selected = SELECTED.get_or_init(|| {
        let path = select_path().map_err(|_| ())?;
        let identity = identity(&path).map_err(|_| ())?;
        Ok(Mutex::new(Selection { path, identity }))
    });
    let selected = selected
        .as_ref()
        .map_err(|_| invalid())?
        .lock()
        .map_err(|_| invalid())?;
    // Replacements, symlink retargeting, disappearance, cwd, or namespace changes
    // must not turn an earlier read into permission to overwrite a different file.
    if select_path()? != selected.path || identity(&selected.path)? != selected.identity {
        return Err(invalid());
    }
    Ok(selected.path.clone())
}

fn read_config(path: &Path) -> Result<Option<(ProjectConfig, Vec<u8>)>> {
    if !crate::compat::present(path).map_err(|_| invalid())? {
        return Ok(None);
    }
    if !fs::metadata(path).map_err(|_| invalid())?.is_file() {
        return Err(invalid());
    }
    let content = fs::read(path).map_err(|_| invalid())?;
    let config = serde_json::from_slice::<ProjectConfig>(&content).map_err(|_| invalid())?;
    Ok(Some((config, content)))
}

pub fn load_project_config() -> Result<Option<ProjectConfig>> {
    let path = get_project_config_path()?;
    Ok(read_config(&path)?.map(|(config, _)| config))
}

#[allow(dead_code)]
pub fn save_project_config(config: &ProjectConfig) -> Result<()> {
    use std::io::{Read, Seek, Write};
    let path = get_project_config_path()?;
    let existing = read_config(&path)?;
    let content = serde_json::to_vec_pretty(config).map_err(|_| invalid())?;
    if let Some((_, previous)) = existing {
        // Follow an existing valid link without replacing it. Open without truncation,
        // then validate this exact file and namespace again before changing any bytes.
        let target = fs::canonicalize(&path).map_err(|_| invalid())?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut file = options.open(&target).map_err(|_| invalid())?;
        if !file.metadata().map_err(|_| invalid())?.is_file() {
            return Err(invalid());
        }
        let mut current = Vec::new();
        file.read_to_end(&mut current).map_err(|_| invalid())?;
        if current != previous
            || get_project_config_path()? != path
            || fs::canonicalize(&path).map_err(|_| invalid())? != target
        {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let opened = file.metadata().map_err(|_| invalid())?;
            let selected = fs::metadata(&path).map_err(|_| invalid())?;
            if (opened.dev(), opened.ino()) != (selected.dev(), selected.ino()) {
                return Err(invalid());
            }
        }
        file.rewind().map_err(|_| invalid())?;
        file.set_len(0).map_err(|_| invalid())?;
        file.write_all(&content).map_err(|_| invalid())?;
        crate::wallet::set_private_file_permissions(&target);
    } else {
        // A concurrent appearance must fail without overwriting it.
        if get_project_config_path()? != path {
            return Err(invalid());
        }
        crate::wallet::write_secure_file_new(&path, &content).map_err(|_| invalid())?;
        // Record our own deliberate creation so subsequent calls remain in place.
        let selected = SELECTED
            .get()
            .ok_or_else(invalid)?
            .as_ref()
            .map_err(|_| invalid())?;
        selected.lock().map_err(|_| invalid())?.identity = identity(&path)?;
    }
    Ok(())
}
