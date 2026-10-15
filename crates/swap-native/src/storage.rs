//! Private, create-once local journals. No key material is printed.
use crate::Result;
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

pub fn create_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Err("refuse to overwrite existing private directory".into());
    }
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

pub fn write(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::File::open(path.parent().ok_or("no parent")?)?.sync_all()?;
    Ok(())
}

pub fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;
    let meta = path.symlink_metadata()?;
    if !meta.is_file() || meta.len() > limit || meta.permissions().mode() & 0o077 != 0 {
        return Err("private regular file with bounded length required".into());
    }
    Ok(std::fs::read(path)?)
}

pub fn json(path: &Path) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&read(path, 50_000_000)?)?)
}

pub fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    write(path, &serde_json::to_vec(value)?)
}

/// Publish a complete immutable file. The temporary name is private; a crash
/// leaves either no destination or the complete file. Never replace an existing
/// journal. Callers serialize their decisions with the source OS lock.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("no parent")?;
    let temp = parent.join(format!(
        ".pending-{}",
        hex::encode(rand::random::<[u8; 16]>())
    ));
    write(&temp, data)?;
    std::fs::hard_link(&temp, path)?;
    std::fs::File::open(parent)?.sync_all()?;
    std::fs::remove_file(temp)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn atomic_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    atomic_write(path, &serde_json::to_vec(value)?)
}
