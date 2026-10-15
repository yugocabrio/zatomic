//! Portable, watch-only native recovery. Offline proving is NOT a broadcast
//! decision, a live unspent check, or evidence of public-chain acceptance.
use crate::{
    Result, compact_wallet, decode, err, funding_consent::hash, public_recovery, regtest_swap,
    storage, wallet,
};
use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use orchard::keys::{FullViewingKey, Scope};
use pczt::Pczt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Cursor, os::unix::fs::PermissionsExt, path::Path};
use zcash_primitives::transaction::{
    Transaction, TxVersion,
    txid::{TxIdDigester, to_txid},
};
use zcash_protocol::consensus::BranchId;

struct Accepted {
    bundle: Value,
    report: Value,
    joint: FullViewingKey,
    pending: Value,
    action: usize,
}

fn accepted(dir: &Path) -> Result<Accepted> {
    let report = public_recovery::inspect(dir)?;
    let bundle = storage::json(&dir.join("native-recovery.json"))?;
    if hash(&bundle)? != report["bundle_digest"] {
        return Err("portable bundle changed during verification".into());
    }
    let joint = FullViewingKey::from_bytes(&decode(
        &bundle["review"]["destinations"]["setup"]["destinations"],
        "joint_fvk",
    )?)
    .ok_or("portable joint FVK")?;
    let raw = hex::decode(
        bundle["review"]["funding_preview"]
            .as_str()
            .ok_or("F preview")?,
    )?;
    let tx = Transaction::read(Cursor::new(raw), BranchId::Nu7)?;
    let f = tx.ironwood_bundle().ok_or("F Ironwood")?;
    let notes: Vec<_> = (0..f.actions().len())
        .filter_map(|i| {
            f.decrypt_output_with_key(i, &joint.to_ivk(Scope::External))
                .map(|(n, _, _)| (i, n))
        })
        .collect();
    if notes.len() != 1 {
        return Err("exact portable funding note required".into());
    }
    Ok(Accepted {
        bundle,
        report,
        joint,
        pending: wallet::note_json(&notes[0].1),
        action: notes[0].0,
    })
}

fn unchanged(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() || path.is_symlink() {
        if storage::read(path, 1_000_000)? != bytes {
            return Err("immutable watch workspace changed".into());
        }
    } else {
        storage::atomic_write(path, bytes)?;
    }
    Ok(())
}

/// Initialize exclusively from one's portable export. The birthday is an
/// explicit trusted starting height BEFORE F; later exact-note lookup detects
/// an omitted F. A retry preserves every existing scan and the advanced head.
pub fn init(portable: &Path, output: &Path, birthday: u32) -> Result<Value> {
    if birthday < 4_465_026 {
        return Err("post-NU7 exclusive birthday required".into());
    }
    let a = accepted(portable)?;
    if !output.exists() {
        storage::create_dir(output)?;
    }
    let meta = output.symlink_metadata()?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err("private watch directory required".into());
    }
    // Never turn an existing spending wallet into a joint-FVK watch wallet:
    // wallet::fvk intentionally prefers joint-fvk.bin over spending-key.bin.
    // Only an empty new directory or our own interrupted initialization may be
    // resumed. Check BEFORE adding any file to an existing directory.
    if (std::fs::read_dir(output)?.next().is_some() && !output.join("watch-binding.json").exists())
        || output.join("spending-key.bin").exists()
        || output.join("spending-key.bin").is_symlink()
    {
        return Err("refuse to initialize recovery over an existing wallet/directory".into());
    }
    let binding = json!({"format":"latch-public-recovery-watch-v1", "bundle_digest":a.report["bundle_digest"],
        "role":a.report["role"],"birthday":birthday,"genesis":compact_wallet::TESTNET_GENESIS,
        "synthetic_inputs":a.report["synthetic_inputs"],"spending_keys_present":false});
    unchanged(
        &output.join("watch-binding.json"),
        &serde_json::to_vec(&binding)?,
    )?;
    for name in ["native-recovery.json", "owner-receipt.json"] {
        unchanged(
            &output.join(name),
            &storage::read(&portable.join(name), 1_000_000)?,
        )?;
    }
    unchanged(&output.join("joint-fvk.bin"), &a.joint.to_bytes())?;
    unchanged(
        &output.join("network.json"),
        &serde_json::to_vec(&json!({"genesis":compact_wallet::TESTNET_GENESIS}))?,
    )?;
    let head = output.join("head.json");
    if head.exists() || head.is_symlink() {
        let h = storage::json(&head)?;
        if h["genesis"] != compact_wallet::TESTNET_GENESIS || h["birthday"] != birthday {
            return Err("watch head changed identity/birthday".into());
        }
    } else {
        storage::atomic_json(
            &head,
            &json!({"genesis":compact_wallet::TESTNET_GENESIS,
            "birthday":birthday,"checkpoint":null}),
        )?;
    }
    Ok(
        json!({"format":"latch-public-recovery-watch-ready-v1","bundle_digest":a.report["bundle_digest"],
        "role":a.report["role"],"birthday":birthday,"synthetic_inputs":a.report["synthetic_inputs"],
        "spending_keys_exported":false,"broadcast":false,"live_chain_checked":false}),
    )
}

fn snapshot(a: &Accepted, dir: &Path, old: &Path, current: &Path) -> Result<Value> {
    let binding = storage::json(&dir.join("watch-binding.json"))?;
    let current = storage::json(current)?;
    if binding["format"] != "latch-public-recovery-watch-v1"
        || binding["bundle_digest"] != a.report["bundle_digest"]
        || binding["role"] != a.report["role"]
        || binding["synthetic_inputs"] != a.report["synthetic_inputs"]
        || binding["genesis"] != compact_wallet::TESTNET_GENESIS
        || current["genesis"] != compact_wallet::TESTNET_GENESIS
        || current["birthday_height"] != binding["birthday"]
        || wallet::fvk(dir)?.to_bytes() != a.joint.to_bytes()
    {
        return Err("watch bundle/network/birthday changed".into());
    }
    let mut result = compact_wallet::funding_snapshot(
        &storage::json(old)?,
        &current,
        &a.joint,
        &a.pending,
        a.report["funding_txid"].as_str().ok_or("F txid")?,
        a.action,
    )?;
    result["bundle_digest"] = a.report["bundle_digest"].clone();
    result["synthetic_inputs"] = a.report["synthetic_inputs"].clone();
    Ok(result)
}

pub fn select(dir: &Path, old: &Path, current: &Path, output: &Path) -> Result<Value> {
    let a = accepted(dir)?;
    let selected = snapshot(&a, dir, old, current)?;
    storage::atomic_json(output, &selected)?;
    Ok(
        json!({"file":output,"bundle_digest":a.report["bundle_digest"],"height":selected["height"],
        "anchor_height":selected["anchor_height"],"funding_confirmations":selected["funding_confirmations"],
        "synthetic_inputs":a.report["synthetic_inputs"],"live_chain_checked":false,"broadcast":false}),
    )
}

fn pczt(v: &Value, name: &str) -> Result<Pczt> {
    Pczt::parse(&hex::decode(v[name].as_str().ok_or("exit PCZT")?)?).map_err(|e| err(e).into())
}

/// Validate saved raw bytes again, independently of a proof.json/report. V6's
/// txid excludes authorizations/anchor: matching it alone would accept a broken
/// proof or signature. The refund's transparent authorization is fixed by the
/// fully verified portable bundle and must also match byte for byte.
fn verify_exit_bytes(a: &Accepted, raw: &[u8]) -> Result<Value> {
    let mode = match a.report["role"].as_str() {
        Some("alice") => "refund",
        Some("bob") => "claim",
        _ => return Err("portable exit role".into()),
    };
    let expected = pczt(&a.bundle["review"], mode)?;
    let message = regtest_swap::message(&expected)?;
    let effects = expected.into_effects().map_err(err)?;
    let expected_txid = to_txid(
        effects.version(),
        effects.consensus_branch_id(),
        &effects.digest(TxIdDigester),
    );
    let mut cursor = Cursor::new(raw);
    let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
    if cursor.position() != raw.len() as u64
        || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != BranchId::Nu7
        || tx.txid() != expected_txid
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
    {
        return Err("raw exit differs from agreed native effects".into());
    }
    if mode == "refund" {
        // accepted() already verifies this exact P2PKH signature against the
        // reserved value/script. The witness-independent digest is unchanged.
        let refund = regtest_swap::extract_checked(pczt(&a.bundle, "refund_check")?)?;
        let actual = tx.transparent_bundle().ok_or("raw refund auxiliary")?;
        let agreed = refund
            .transparent_bundle()
            .ok_or("agreed refund auxiliary")?;
        if actual.vin.len() != 1 || actual.vin[0].script_sig() != agreed.vin[0].script_sig() {
            return Err("raw refund auxiliary authorization changed".into());
        }
    } else if tx.transparent_bundle().is_some() {
        return Err("claim must be shielded only".into());
    }
    let bundle = tx.ironwood_bundle().ok_or("raw exit Ironwood")?;
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let mut validator = orchard::bundle::BatchValidator::new(&vk);
    validator.add_bundle(bundle, message).map_err(err)?;
    if !validator.validate(rand::rng()) {
        return Err("raw exit proof or signature invalid".into());
    }
    Ok(
        json!({"format":"latch-public-native-exit-check-v1","mode":mode,"role":a.report["role"],
        "genesis":compact_wallet::TESTNET_GENESIS,"bundle_digest":a.report["bundle_digest"],
        "txid":tx.txid().to_string(),"bytes_sha256":hex::encode(Sha256::digest(raw)),
        "anchor":hex::encode(bundle.anchor().to_bytes()),"lock_time":tx.lock_time(),
        "expiry_height":u32::from(tx.expiry_height()),"proof_and_signatures_verified":true,
        "agreed_effects_preserved":true,"synthetic_inputs":a.report["synthetic_inputs"],
        "spending_keys_read":false,"live_chain_checked":false,"broadcast":false,"send_authorized":false} ),
    )
}

pub fn inspect_exit(portable: &Path, transaction: &Path) -> Result<Value> {
    let a = accepted(portable)?;
    verify_exit_bytes(&a, &hex::decode(storage::read(transaction, 4_000_000)?)?)
}

fn adapted_claim(a: &Accepted, witness: &[u8; 32]) -> Result<(Pczt, Pczt)> {
    if a.report["role"] != "bob" {
        return Err("only Bob accepts a claim opening".into());
    }
    let pre = regtest_swap::parse_pre(&a.bundle["presignatures"]["claim"])?;
    let sig = pre.adapt(witness)?;
    let mut index = None;
    let p = pczt(&a.bundle["review"], "claim")?;
    for (i, action) in p.ironwood().actions().iter().enumerate() {
        if action.spend().spend_auth_sig().is_none() && index.replace(i).is_some() {
            return Err("ambiguous conditional spend".into());
        }
    }
    let index = index.ok_or("missing conditional spend")?;
    Ok((
        regtest_swap::apply(p, index, sig, pre.message)?,
        regtest_swap::apply(
            pczt(&a.bundle["review"], "claim_check")?,
            index,
            sig,
            pre.message,
        )?,
    ))
}

/// Accept an already observed candidate without any chain-finality dependency.
/// Verify canonical scalar, exact adaptor relation and actual native claim
/// authorization. Preserve privately before a caller performs further RPCs.
/// The pre-funding check proof is not a spend of a confirmed public note.
pub fn accept_opening(dir: &Path, input: &Path, output: &Path) -> Result<Value> {
    let a = accepted(dir)?;
    let witness: [u8; 32] = decode(&storage::json(input)?, "witness_le")?;
    let (_, checked) = adapted_claim(&a, &witness)?;
    let tx = regtest_swap::extract_checked(checked)?;
    let value = json!({"format":"latch-public-observed-opening-v1",
        "bundle_digest":a.report["bundle_digest"],"witness_le":hex::encode(witness),
        "synthetic_inputs":a.report["synthetic_inputs"]});
    unchanged(output, &serde_json::to_vec(&value)?)?;
    Ok(
        json!({"format":"latch-public-opening-accepted-v1","role":"bob",
        "bundle_digest":a.report["bundle_digest"],"claim_txid":tx.txid().to_string(),
        "native_claim_authorization_verified":true,"opening_file":output,
        "synthetic_inputs":a.report["synthetic_inputs"],"broadcast":false,
        "settlement_verified":false,"send_authorized":false}),
    )
}

/// Prepare a PRIVATE fully authorized exit. Always revalidate the original
/// checkpoints/bundle; a caller-supplied snapshot/report is not authority.
/// Bob supplies an already observed opening in a private file, never argv/RPC.
pub fn prove(
    dir: &Path,
    old: &Path,
    current: &Path,
    output: &Path,
    witness: Option<&Path>,
) -> Result<Value> {
    let a = accepted(dir)?;
    let selected = snapshot(&a, dir, old, current)?;
    if output.exists() || output.is_symlink() {
        return Err("new private proof directory required".into());
    }
    let (deferred, checked, mode) = match a.report["role"].as_str() {
        Some("alice") if witness.is_none() => (
            pczt(&a.bundle, "refund")?,
            pczt(&a.bundle, "refund_check")?,
            "refund",
        ),
        Some("bob") => {
            let opening = storage::json(witness.ok_or("Bob requires observed opening file")?)?;
            let (deferred, checked) = adapted_claim(&a, &decode(&opening, "witness_le")?)?;
            (deferred, checked, "claim")
        }
        _ => return Err("receipt role / opening mismatch".into()),
    };
    let expected = regtest_swap::extract_checked(checked)?;
    let tx = regtest_swap::reprove_exit(deferred, &selected["notes"][0])?;
    if tx.txid() != expected.txid() {
        return Err("reproof changed agreed effects".into());
    }
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    verify_exit_bytes(&a, &raw)?;
    let digest = hex::encode(Sha256::digest(&raw));
    storage::create_dir(output)?;
    storage::atomic_json(&output.join("snapshot.json"), &selected)?;
    storage::atomic_write(&output.join("transaction.hex"), hex::encode(raw).as_bytes())?;
    let report = json!({"format":"latch-public-native-exit-proof-v1","mode":mode,
        "bundle_digest":a.report["bundle_digest"],"snapshot_digest":hash(&selected)?,
        "txid":tx.txid().to_string(),"bytes_sha256":digest,"file":output.join("transaction.hex"),
        "lock_time":tx.lock_time(),"expiry_height":u32::from(tx.expiry_height()),
        "proof_and_signatures_verified":true,"agreed_effects_preserved":true,
        "synthetic_inputs":a.report["synthetic_inputs"],"spending_keys_read":false,
        "live_chain_checked":false,"broadcast":false,"execution_enabled":false,
        "scope":"private offline reproof; canonical unspent checks and outgoing recovery policy still required"});
    storage::atomic_json(&output.join("proof.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::tree::MerkleHashOrchard;
    use zcash_primitives::merkle_tree::write_commitment_tree;

    /// Explicitly synthetic provider transcript: valid encrypted outputs from
    /// the zero-authorized F preview, invented block hashes, no chain acceptance.
    /// Used only to exercise public-profile decryption/witness/reproof plumbing.
    #[test]
    #[ignore = "explicit private portable fixture/output required"]
    fn synthetic_compact_capture() -> Result<()> {
        let fixture = std::env::var("LATCH_WITNESS_FIXTURE")?;
        let output = std::env::var("LATCH_WITNESS_CAPTURES")?;
        let a = accepted(Path::new(&fixture))?;
        if a.report["synthetic_inputs"] != true {
            return Err("synthetic fixture required".into());
        }
        let output = Path::new(&output);
        storage::create_dir(output)?;
        let raw = hex::decode(
            a.bundle["review"]["funding_preview"]
                .as_str()
                .ok_or("preview")?,
        )?;
        let tx = Transaction::read(Cursor::new(raw), BranchId::Nu7)?;
        let mut tree = wallet::Tree::empty();
        let encode = |tree: &wallet::Tree| -> Result<String> {
            let mut bytes = Vec::new();
            write_commitment_tree(tree, &mut bytes)?;
            Ok(hex::encode(bytes))
        };
        let initial = encode(&tree)?;
        let mut actions = Vec::new();
        for action in tx.ironwood_bundle().ok_or("Ironwood")?.actions().iter() {
            tree.append(MerkleHashOrchard::from_cmx(action.cmx()))
                .map_err(err)?;
            let encrypted = action.encrypted_note();
            actions.push(json!({"nullifier":hex::encode(action.nullifier().to_bytes()),
                "cmx":hex::encode(action.cmx().to_bytes()),"ephemeral_key":hex::encode(encrypted.epk_bytes),
                "ciphertext":hex::encode(&encrypted.enc_ciphertext.0[..52])}));
        }
        let final_tree = encode(&tree)?;
        let birthday = 4_500_000u64;
        let hash = |i: u8| hex::encode([i; 32]);
        let mut capture = json!({"format":"latch-ironwood-compact-v1","genesis":compact_wallet::TESTNET_GENESIS,
            "branch":"77190ad9","initial_height":birthday,"initial_hash":hash(0),"initial_tree":initial,
            "height":birthday+1,"tip":hash(1),"final_tree":final_tree,
            "blocks":[{"height":birthday+1,"hash":hash(1),"previousblockhash":hash(0),
                "tree_size":tree.size(),"transactions":[{"index":1,"txid":tx.txid().to_string(),"actions":actions}]}]});
        storage::atomic_json(&output.join("funding.json"), &capture)?;
        capture["initial_height"] = json!(birthday + 1);
        capture["initial_hash"] = json!(hash(1));
        capture["initial_tree"] = json!(final_tree);
        capture["height"] = json!(birthday + 12);
        capture["tip"] = json!(hash(12));
        capture["blocks"] = json!((2..=12u8).map(|i| json!({"height":birthday+u64::from(i),
            "hash":hash(i),"previousblockhash":hash(i-1),"tree_size":tree.size(),"transactions":[]})).collect::<Vec<_>>());
        storage::atomic_json(&output.join("confirmed.json"), &capture)?;
        // The later actual nullifier removes the note from a resumed scanner.
        let mut spent = capture.clone();
        spent["initial_height"] = capture["height"].clone();
        spent["initial_hash"] = capture["tip"].clone();
        let action = &mut actions[0];
        action["nullifier"] = json!(hex::encode(
            wallet::parse_note(&a.pending)?
                .nullifier(&a.joint)
                .to_bytes()
        ));
        action["ephemeral_key"] = json!("00".repeat(32));
        action["ciphertext"] = json!("00".repeat(52));
        let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&decode(action, "cmx")?)
            .into_option()
            .ok_or("cmx")?;
        tree.append(MerkleHashOrchard::from_cmx(&cmx))
            .map_err(err)?;
        spent["height"] = json!(birthday + 13);
        spent["tip"] = json!(hash(13));
        spent["final_tree"] = json!(encode(&tree)?);
        spent["blocks"] = json!([{"height":birthday+13,"hash":hash(13),"previousblockhash":hash(12),
            "tree_size":tree.size(),"transactions":[{"index":1,"txid":hash(99),"actions":[action]}]}]);
        storage::atomic_json(&output.join("spent.json"), &spent)?;
        Ok(())
    }
}
