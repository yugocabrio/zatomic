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
