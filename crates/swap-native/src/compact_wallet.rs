//! Incremental Ironwood light-client scanning. The block provider/checkpoint is
//! trusted: hash continuity and tree consistency are NOT consensus validation.
use crate::{Result, decode, err, storage, wallet};
use incrementalmerkletree::witness::IncrementalWitness;
use orchard::{
    keys::Scope,
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain},
    tree::MerkleHashOrchard,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Cursor, path::Path};
use zcash_note_encryption::{EphemeralKeyBytes, try_compact_note_decryption};
use zcash_primitives::{
    merkle_tree::{read_incremental_witness, write_commitment_tree, write_incremental_witness},
    transaction::Transaction,
};
use zcash_protocol::consensus::BranchId;

pub const TESTNET_GENESIS: &str =
    "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38";
const FORMAT: &str = "latch-ironwood-compact-v1";
const MAX_BLOCKS: usize = 256;
const MAX_NOTES: usize = 256;
type Witness = IncrementalWitness<MerkleHashOrchard, 32>;
type Owned = BTreeMap<[u8; 32], (Value, Witness, [u8; 32])>;

fn number(v: &Value, name: &str) -> Result<u64> {
    v[name]
        .as_u64()
        .ok_or_else(|| format!("invalid {name}").into())
}
fn hash(v: &Value, name: &str) -> Result<String> {
    Ok(hex::encode(decode::<32>(v, name)?))
}
fn encode_tree(tree: &wallet::Tree) -> Result<String> {
    let mut bytes = Vec::new();
    write_commitment_tree(tree, &mut bytes)?;
    Ok(hex::encode(bytes))
}

fn same_tree(tree: &wallet::Tree, encoded: &Value) -> Result<bool> {
    let other = wallet::tree(encoded.as_str().ok_or("tree encoding")?)?;
    // Equivalent frontiers may retain different trailing empty parent slots.
    Ok(tree.root() == other.root() && tree.size() == other.size())
}

/// Revalidate persisted private note paths before either scanning or spending.
fn restore_notes(
    p: &Value,
    fvk: &orchard::keys::FullViewingKey,
    tree: &wallet::Tree,
) -> Result<Owned> {
    let height = number(p, "height")?;
    if p["anchor"] != hex::encode(tree.root().to_bytes()) {
        return Err("checkpoint anchor differs from its tree".into());
    }
    let mut owned = Owned::new();
    let notes = p["notes"].as_array().ok_or("checkpoint notes")?;
    if notes.len() > MAX_NOTES {
        return Err("owned note limit".into());
    }
    for data in notes {
        let note = wallet::parse_note(data)?;
        if fvk.scope_for_address(&note.recipient()).is_none() || number(data, "height")? > height {
            return Err("checkpoint contains foreign/future note".into());
        }
        let encoded = data["witness"].as_str().ok_or("witness encoding")?;
        if encoded.len() > 32_768 {
            return Err("witness size bound".into());
        }
        let raw = hex::decode(encoded)?;
        let mut cursor = Cursor::new(&raw);
        let w: Witness = read_incremental_witness(&mut cursor)?;
        let path = w.path().ok_or("witness path")?;
        if cursor.position() != raw.len() as u64
            || w.root() != tree.root()
            || u64::from(w.tip_position()) + 1 != tree.size() as u64
            || wallet::parse_path(data)?.root(note.commitment().into()) != tree.root().into()
            || number(data, "position")? != u64::from(path.position())
        {
            return Err("invalid persisted note witness".into());
        }
        // Bind the serialized witness itself to this leaf, not just its root.
        let merkle = orchard::tree::MerklePath::from_parts(
            u32::try_from(u64::from(path.position()))?,
            path.path_elems().try_into().map_err(|_| "witness depth")?,
        );
        if merkle.root(note.commitment().into()) != tree.root().into() {
            return Err("witness does not authenticate note".into());
        }
        if owned
            .insert(
                decode(data, "cmx")?,
                (data.clone(), w, note.nullifier(fvk).to_bytes()),
            )
            .is_some()
        {
            return Err("duplicate checkpoint note".into());
        }
    }
    Ok(owned)
}

pub fn scan(dir: &Path, capture: &Path, previous: Option<&Path>) -> Result<Value> {
    let v = storage::json(capture)?;
    let genesis = v["genesis"].as_str().ok_or("genesis")?;
    let activation = match genesis {
        TESTNET_GENESIS => 4_465_026,
        wallet::GENESIS => 2,
        _ => return Err("only pinned testnet/regtest supported".into()),
    };
    if v["format"] != FORMAT || v["branch"] != "77190ad9" {
        return Err("compact format/branch mismatch".into());
    }
    if dir.join("network.json").exists() {
        if storage::json(&dir.join("network.json"))?["genesis"] != genesis {
            return Err("wallet network mismatch".into());
        }
    } else if genesis != wallet::GENESIS {
        return Err("public wallet requires a pinned network".into());
    }
    let fvk = wallet::fvk(dir)?;
    let fingerprint = hex::encode(Sha256::digest(fvk.to_bytes()));
    let ivks = [Scope::External, Scope::Internal].map(|s| fvk.to_ivk(s).prepare());
    let mut tree = wallet::tree(v["initial_tree"].as_str().ok_or("initial tree")?)?;
    let mut height = number(&v, "initial_height")?;
    if height < activation || height > u32::MAX as u64 {
        return Err("checkpoint outside supported NU7 heights".into());
    }
    let mut tip = hash(&v, "initial_hash")?;
    let mut owned = Owned::new();
    let mut birthday_height = height;
    let mut birthday_hash = tip.clone();
    if let Some(path) = previous {
        let p = storage::json(path)?;
        if p["format"] != FORMAT
            || p["genesis"] != genesis
            || p["branch"] != v["branch"]
            || p["fvk_fingerprint"] != fingerprint
            || p["height"] != height
            || p["tip"] != tip
            || !same_tree(&tree, &p["tree"])?
        {
            return Err("checkpoint identity/continuity mismatch; preserve old state".into());
        }
        tree = wallet::tree(p["tree"].as_str().ok_or("saved tree")?)?;
        birthday_height = number(&p, "birthday_height")?;
        birthday_hash = hash(&p, "birthday_hash")?;
        if birthday_height < activation || birthday_height > height {
            return Err("invalid wallet birthday".into());
        }
        owned = restore_notes(&p, &fvk, &tree)?;
    }
    let blocks = v["blocks"].as_array().ok_or("compact blocks")?;
    if blocks.len() > MAX_BLOCKS {
        return Err("compact batch limit".into());
    }
    let mut actions = 0usize;
    let mut received = 0usize;
    let mut spent = 0usize;
    for b in blocks {
        if number(b, "height")? != height + 1 || hash(b, "previousblockhash")? != tip {
            return Err("compact block discontinuity/reorg; no checkpoint published".into());
        }
        let mut last_index = None;
        for tx in b["transactions"].as_array().ok_or("compact transactions")? {
            let index = number(tx, "index")?;
            if last_index.is_some_and(|last| index <= last) {
                return Err("transaction index order".into());
            }
            last_index = Some(index);
            let txid = hash(tx, "txid")?;
            for (i, a) in tx["actions"]
                .as_array()
                .ok_or("compact actions")?
                .iter()
                .enumerate()
            {
                actions += 1;
                if actions > 100_000 {
                    return Err("compact action limit".into());
                }
                let nf = Nullifier::from_bytes(&decode(a, "nullifier")?)
                    .into_option()
                    .ok_or("nullifier encoding")?;
                let cmx = ExtractedNoteCommitment::from_bytes(&decode(a, "cmx")?)
                    .into_option()
                    .ok_or("cmx encoding")?;
                let action = CompactAction::from_parts(
                    nf,
                    cmx,
                    EphemeralKeyBytes(decode(a, "ephemeral_key")?),
                    decode(a, "ciphertext")?,
                );
                let before = owned.len();
                owned.retain(|_, (_, _, n)| *n != nf.to_bytes());
                spent += before - owned.len();
                let leaf = MerkleHashOrchard::from_cmx(&cmx);
                for (_, w, _) in owned.values_mut() {
                    w.append(leaf).map_err(err)?;
                }
                tree.append(leaf).map_err(err)?;
                for ivk in &ivks {
                    if let Some((note, _)) = try_compact_note_decryption(
                        &IronwoodDomain::for_compact_action(&action),
                        ivk,
                        &action,
                    ) {
                        let mut data = wallet::note_json(&note);
                        data["txid"] = json!(txid);
                        data["action"] = json!(i);
                        data["height"] = b["height"].clone();
                        data["coinbase"] = json!(index == 0);
                        if owned.len() >= MAX_NOTES
                            || owned
                                .insert(
                                    cmx.to_bytes(),
                                    (
                                        data,
                                        Witness::from_tree(tree.clone()).ok_or("empty tree")?,
                                        note.nullifier(&fvk).to_bytes(),
                                    ),
                                )
                                .is_some()
                        {
                            return Err("duplicate/excessive owned notes".into());
                        }
                        received += 1;
                        break;
                    }
                }
            }
        }
        if number(b, "tree_size")? != tree.size() as u64 {
            return Err("compact tree size mismatch".into());
        }
        height += 1;
        tip = hash(b, "hash")?;
    }
    if v["height"] != height || v["tip"] != tip || !same_tree(&tree, &v["final_tree"])? {
        return Err("compact final checkpoint mismatch".into());
    }
    let mut notes = Vec::new();
    for (_, (mut data, witness, _)) in owned {
        let path = witness.path().ok_or("witness")?;
        data["position"] = json!(u64::from(path.position()));
        data["path"] = json!(
            path.path_elems()
                .iter()
                .map(|p| hex::encode(p.to_bytes()))
                .collect::<Vec<_>>()
        );
        let mut encoded = Vec::new();
        write_incremental_witness(&witness, &mut encoded)?;
        data["witness"] = json!(hex::encode(encoded));
        notes.push(data);
    }
    let state = json!({"format":FORMAT,"genesis":genesis,"branch":"77190ad9","fvk_fingerprint":fingerprint,
        "birthday_height":birthday_height,"birthday_hash":birthday_hash,"height":height,"tip":tip,
        "tree":encode_tree(&tree)?,"anchor":hex::encode(tree.root().to_bytes()),"notes":notes});
    let output = dir.join(format!("compact-{birthday_height}-{height}-{tip}.json"));
    if output.exists() {
        if storage::json(&output)? != state {
            return Err("existing compact checkpoint differs".into());
        }
    } else {
        storage::atomic_json(&output, &state)?;
    }
    Ok(
        json!({"scope":"trusted-provider compact scan; no consensus/finality proof", "file":output,
        "height":height,"tip":tip,"blocks":blocks.len(),"actions":actions,"received_notes":received,
        "spent_notes":spent,"unspent_notes":notes.len(),"tree_size":tree.size(),"broadcast":false}),
    )
}

/// Select a mature, still-unspent note with a historical witness. This is an
/// offline input package, not authorization or a claim of canonical finality.
/// The public adapter must recheck both block/tree identities and reserve inputs.
pub fn source_snapshot(
    dir: &Path,
    anchor_file: &Path,
    current_file: &Path,
    principal: u64,
    output: &Path,
) -> Result<Value> {
    const MIN_CONFIRMATIONS: u64 = 12;
    if principal <= 10_000 || principal > 2_100_000_000_000_000 - 10_000 {
        return Err("source principal range".into());
    }
    let old = storage::json(anchor_file)?;
    let current = storage::json(current_file)?;
    let genesis = current["genesis"].as_str().ok_or("genesis")?;
    let activation = match genesis {
        TESTNET_GENESIS => 4_465_026,
        wallet::GENESIS => 2,
        _ => return Err("source supports only pinned testnet/regtest".into()),
    };
    if storage::json(&dir.join("network.json"))?["genesis"] != genesis {
        return Err("source wallet network mismatch".into());
    }
    let fvk = wallet::fvk(dir)?;
    let fingerprint = hex::encode(Sha256::digest(fvk.to_bytes()));
    let height = number(&current, "height")?;
    let anchor_height = number(&old, "height")?;
    let birthday = number(&current, "birthday_height")?;
    if birthday < activation
        || birthday > anchor_height
        || anchor_height > height
        || height >= u64::from(u32::MAX)
        || height - anchor_height + 1 < MIN_CONFIRMATIONS
    {
        return Err("source anchor needs twelve observed confirmations".into());
    }
    let mut validated = Vec::new();
    for checkpoint in [&old, &current] {
        if checkpoint["format"] != FORMAT
            || checkpoint["branch"] != "77190ad9"
            || checkpoint["genesis"] != genesis
            || checkpoint["fvk_fingerprint"] != fingerprint
            || checkpoint["birthday_height"] != current["birthday_height"]
            || checkpoint["birthday_hash"] != current["birthday_hash"]
        {
            return Err("source checkpoint identity/lineage mismatch".into());
        }
        hash(checkpoint, "tip")?;
        hash(checkpoint, "birthday_hash")?;
        let tree = wallet::tree(checkpoint["tree"].as_str().ok_or("tree")?)?;
        validated.push(restore_notes(checkpoint, &fvk, &tree)?);
    }
    let mut selected = None;
    for (cmx, (data, _, _)) in &validated[0] {
        let Some((now, _, _)) = validated[1].get(cmx) else {
            continue;
        };
        // Height/txid/action metadata must not be silently reassigned between
        // captures; the commitment alone does not authenticate inclusion height.
        for field in [
            "recipient",
            "value",
            "rho",
            "rseed",
            "cmx",
            "position",
            "height",
            "coinbase",
            "txid",
            "action",
        ] {
            if data[field] != now[field] {
                return Err("source note metadata changed".into());
            }
        }
        let note = wallet::parse_note(data)?;
        let mined = number(data, "height")?;
        let coinbase = data["coinbase"].as_bool().ok_or("source coinbase type")?;
        hash(data, "txid")?;
        number(data, "action")?;
        if mined <= birthday || mined > anchor_height {
            return Err("source note height outside lineage".into());
        }
        if note.recipient() == fvk.address_at(0u32, Scope::External)
            && note.value().inner() > principal + 10_000
            && (!coinbase || mined + 100 <= height)
        {
            selected = Some(data.clone());
            break;
        }
    }
    let mut source = selected.ok_or("no mature unspent note at confirmed historical anchor")?;
    source
        .as_object_mut()
        .ok_or("source note")?
        .remove("witness");
    let snapshot = json!({"format":"latch-source-snapshot-v1", "genesis":genesis,
        "branch":"77190ad9", "fvk_fingerprint":fingerprint,
        "height":height,"tip":current["tip"],"tree":current["tree"],
        "anchor_height":anchor_height,"anchor_tip":old["tip"],"anchor_tree":old["tree"],
        "anchor":old["anchor"],"notes":[source],"principal_zatoshi":principal,
        "confirmation_policy":{"profile":"candidate-source-confirmations-v1","minimum":MIN_CONFIRMATIONS},
        "anchor_confirmations":height-anchor_height+1,
        "source_confirmations":height-number(&source,"height")?+1,
        "funding_authorized":false,"broadcast":false});
    storage::atomic_json(output, &snapshot)?;
    Ok(
        json!({"file":output,"height":height,"anchor_height":anchor_height,
        "anchor_confirmations":snapshot["anchor_confirmations"],
        "source_confirmations":snapshot["source_confirmations"],
        "principal_zatoshi":principal,"broadcast":false,"funding_authorized":false}),
    )
}

/// Convert an existing real regtest full capture into bounded compact batches.
/// Test/reproduction helper only; never synthesizes ciphertext or creates funds.
pub fn export_regtest(input: &Path, output: &Path) -> Result<Value> {
    let v = storage::json(input)?;
    if v["genesis"] != wallet::GENESIS || v["branch"] != "77190ad9" || v["initial_height"] != 2 {
        return Err("regtest full capture required".into());
    }
    storage::create_dir(output)?;
    let mut tree = wallet::tree(v["initial_tree"].as_str().ok_or("initial tree")?)?;
    let mut height = 2u64;
    let mut tip = hash(&v, "initial_hash")?;
    let mut files = Vec::new();
    let blocks = v["blocks"].as_array().ok_or("blocks")?;
    if blocks.len() > 10_000 {
        return Err("full capture size limit".into());
    }
    for chunk in blocks.chunks(MAX_BLOCKS) {
        let mut capture = json!({"format":FORMAT,"genesis":wallet::GENESIS,"branch":"77190ad9",
            "initial_height":height,"initial_hash":tip,"initial_tree":encode_tree(&tree)?});
        let mut compact_blocks = Vec::new();
        for b in chunk {
            if b["height"] != height + 1 || b["previousblockhash"] != tip {
                return Err("full capture discontinuity".into());
            }
            let mut transactions = Vec::new();
            for (index, encoded) in b["transactions"]
                .as_array()
                .ok_or("transactions")?
                .iter()
                .enumerate()
            {
                let raw = hex::decode(encoded.as_str().ok_or("tx bytes")?)?;
                if raw.len() > 2_000_000 {
                    return Err("transaction size limit".into());
                }
                let mut cursor = Cursor::new(&raw);
                let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
                if cursor.position() != raw.len() as u64
                    || tx.consensus_branch_id() != BranchId::Nu7
                {
                    return Err("full tx parse".into());
                }
                if let Some(bundle) = tx.ironwood_bundle() {
                    let mut actions = Vec::new();
                    for a in bundle.actions().iter() {
                        tree.append(MerkleHashOrchard::from_cmx(a.cmx()))
                            .map_err(err)?;
                        actions.push(json!({"nullifier":hex::encode(a.nullifier().to_bytes()),"cmx":hex::encode(a.cmx().to_bytes()),
                            "ephemeral_key":hex::encode(a.encrypted_note().epk_bytes),"ciphertext":hex::encode(&a.encrypted_note().enc_ciphertext.0[..52])}));
                    }
                    transactions.push(
                        json!({"index":index,"txid":tx.txid().to_string(),"actions":actions}),
                    );
                }
            }
            if b["tree_size"] != tree.size() as u64 {
                return Err("full capture tree size".into());
            }
            height += 1;
            tip = hash(b, "hash")?;
            compact_blocks.push(json!({"height":height,"hash":tip,"previousblockhash":b["previousblockhash"],"transactions":transactions,"tree_size":tree.size()}));
        }
        capture["blocks"] = json!(compact_blocks);
        capture["height"] = json!(height);
        capture["tip"] = json!(tip);
        capture["final_tree"] = json!(encode_tree(&tree)?);
        let path = output.join(format!("capture-{height}.json"));
        storage::atomic_json(&path, &capture)?;
        files.push(path);
    }
    if v["height"] != height || v["tip"] != tip || !same_tree(&tree, &v["final_tree"])? {
        return Err("full capture final tree".into());
    }
    Ok(json!({"captures":files,"height":height,"tip":tip}))
}
