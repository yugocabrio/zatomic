//! Durable local source-wallet decision. Cancellation and release share an OS
//! lock; the release decision reaches disk BEFORE any source signature exists.
//! This is not protection against a user deleting/rolling back the wallet files.
use crate::{Result, storage};
use serde_json::{Value, json};
use std::{fs::File, os::unix::fs::OpenOptionsExt, path::Path};

pub struct Guard {
    _lock: File,
    root: std::path::PathBuf,
    pub identity: Value,
}

pub fn init(root: &Path) -> Result<Value> {
    storage::create_dir(root)?;
    storage::write(&root.join("source.lock"), b"")?;
    let identity = json!({"version":1,"id":hex::encode(rand::random::<[u8;32]>())});
    storage::atomic_json(&root.join("source-setup.json"), &identity)?;
    Ok(identity)
}

impl Guard {
    pub fn open(root: &Path) -> Result<Self> {
        storage::read(&root.join("source.lock"), 0)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .mode(0o600)
            .open(root.join("source.lock"))?;
        lock.try_lock()
            .map_err(|_| "source operation already active")?;
        let identity = storage::json(&root.join("source-setup.json"))?;
        if identity["version"] != 1 || identity["id"].as_str().is_none_or(|s| s.len() != 64) {
            return Err("source setup identity invalid".into());
        }
        Ok(Self {
            _lock: lock,
            root: root.to_owned(),
            identity,
        })
    }

    pub fn active(&self) -> Result<()> {
        if self.root.join("source-cancelled.json").exists() {
            return Err("source setup permanently cancelled".into());
        }
        Ok(())
    }

    pub fn release(&self, consent: &Value) -> Result<()> {
        self.active()?;
        let path = self.root.join("source-release.json");
        let value = json!({"identity":self.identity,"consent":consent});
        if path.exists() {
            if storage::json(&path)? != value {
                return Err("source release decision changed".into());
            }
        } else {
            storage::atomic_json(&path, &value)?;
        }
        Ok(())
    }

    pub fn cancel(&self) -> Result<Value> {
        // A release marker is enough to forbid cancellation, even if the
        // signature file is missing or still being written. Fail closed also
        // on unexpected artifacts from a mixed or incomplete legacy workspace.
        for name in [
            "source-release.json",
            "swap/funding.hex",
            "coordinator-native-offline/funding.hex",
            "02-funded.json",
            "owners/bob/eth-intent-lock.json",
            "owners/bob-offline/eth-intent-lock.json",
            "owners/alice/eth-intent-claim.json",
            "owners/alice-offline/eth-intent-claim.json",
        ] {
            if self.root.join(name).exists() {
                return Err(
                    "possible source release or ETH lock; reconcile funding instead".into(),
                );
            }
        }
        let value = json!({"identity":self.identity,"unfunded_cancelled":true,
            "source_authorization_withheld":true});
        let path = self.root.join("source-cancelled.json");
        if path.exists() {
            if storage::json(&path)? != value {
                return Err("source cancellation receipt changed".into());
            }
        } else {
            storage::atomic_json(&path, &value)?;
        }
        Ok(
            json!({"unfunded_cancelled":true,"source_authorization_withheld":true,
            "swap_principal_locked":false,"new_native_transactions":0,"new_evm_transactions":0,
            "scope":"local setup cancellation; source-wallet/auxiliary/deployment setup may already exist"}),
        )
    }
}

pub fn for_terms(dir: &Path, terms: &Value) -> Result<Option<Guard>> {
    // Historical v2 fixtures did not have this guard. Their existing recovery
    // remains supported, but they cannot use the new cancellation operation.
    if terms.get("source_guard").is_none() {
        return Ok(None);
    }
    let guard = Guard::open(dir.parent().ok_or("no setup parent")?)?;
    guard.active()?;
    if guard.identity != terms["source_guard"] {
        return Err("source setup identity differs from signed terms".into());
    }
    Ok(Some(guard))
}
