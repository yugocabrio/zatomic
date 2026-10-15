//! Decode public transaction effects for a read-only network adapter.
//! Parsing and provider block membership are NOT signature/proof validation.
use crate::{Result, storage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::Path};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::{consensus::BranchId, value::BalanceError};

pub fn inspect(path: &Path) -> Result<Value> {
    let raw = hex::decode(storage::read(path, 4_000_000)?)?;
    let mut cursor = Cursor::new(&raw);
    let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
    if cursor.position() != raw.len() as u64
        || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != BranchId::Nu7
    {
        return Err("observed transaction requires complete v6/NU7 encoding".into());
    }
    let actions: Vec<_> = tx
        .ironwood_bundle()
        .map(|b| {
            b.actions()
                .iter()
                .map(|a| {
                    let note = a.encrypted_note();
                    json!({"nullifier":hex::encode(a.nullifier().to_bytes()),
                        "cmx":hex::encode(a.cmx().to_bytes()),
                        "ephemeral_key":hex::encode(note.epk_bytes),
                        "ciphertext":hex::encode(&note.enc_ciphertext.0[..52])})
                })
                .collect()
        })
        .unwrap_or_default();
    let inputs: Vec<_> = tx
        .transparent_bundle()
        .map(|b| {
            b.vin
                .iter()
                .map(|i| json!({"txid":i.prevout().txid().to_string(),"index":i.prevout().n()}))
                .collect()
        })
        .unwrap_or_default();
    let outputs: Vec<_> = tx
        .transparent_bundle()
        .map(|b| {
            b.vout.iter().map(|o| json!({"value_zatoshi":u64::from(o.value()),"script":hex::encode(&o.script_pubkey().0.0)})).collect()
        })
        .unwrap_or_default();
    // A transparent-input fee needs authenticated prevout values. Never
    // manufacture them from an unbound caller/provider-supplied fee field.
    let fee = tx.fee_paid::<BalanceError, _>(|_| Ok(None))?.map(u64::from);
    Ok(
        json!({"format":"latch-observed-transaction-v1", "version":6,"branch":"77190ad9",
        "scope":"decoded public effects, not signature/proof/chain validation",
        "txid":tx.txid().to_string(),"bytes_sha256":hex::encode(Sha256::digest(&raw)),
        "lock_time":tx.lock_time(),"expiry_height":u32::from(tx.expiry_height()),
        "fee_zatoshi_without_prevouts":fee,"ironwood_actions":actions,
        "transparent_inputs":inputs,"transparent_outputs":outputs}),
    )
}
