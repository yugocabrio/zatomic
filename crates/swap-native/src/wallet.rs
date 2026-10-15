//! Bounded scanner for captures from OUR isolated validating node. Not SPV.
use crate::{Result, decode, err, random_key, storage};
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    Note,
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Cursor, path::Path};
use zcash_address::unified::{Address, Encoding, Receiver, Revision, Uitem};
use zcash_primitives::{merkle_tree::read_commitment_tree, transaction::Transaction};
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};

pub const GENESIS: &str = "029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327";
// Full captures remain capped at 50 MB by storage::json as well. This local
// history budget permits repeated mature-coin fixtures without resetting a
// node that may still contain recovery evidence.
const MAX_CAPTURE_BLOCKS: usize = 10_000;
pub type Tree = CommitmentTree<MerkleHashOrchard, 32>;
type Witness = IncrementalWitness<MerkleHashOrchard, 32>;

#[derive(Clone, Copy)]
pub struct Regtest;
impl Parameters for Regtest {
    fn network_type(&self) -> NetworkType {
        NetworkType::Regtest
    }
    fn activation_height(&self, upgrade: NetworkUpgrade) -> Option<BlockHeight> {
        Some(match upgrade {
            NetworkUpgrade::Overwinter
            | NetworkUpgrade::Sapling
            | NetworkUpgrade::Blossom
            | NetworkUpgrade::Heartwood
            | NetworkUpgrade::Canopy => 1u32.into(),
            _ => 2u32.into(),
        })
    }
}

pub fn init(dir: &Path) -> Result<Value> {
    storage::create_dir(dir)?;
    let key = random_key(&mut rand::rng());
    let fvk = FullViewingKey::from(&key);
    let secp = loop {
        let mut b = [0; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut b);
        if let Ok(k) = secp256k1::SecretKey::from_secret_bytes(b) {
            break k;
        }
    };
    let pk = secp256k1::PublicKey::from_secret_key(&secp);
    let transparent = zcash_transparent::address::TransparentAddress::from_pubkey(&pk);
    storage::write(&dir.join("spending-key.bin"), key.to_bytes())?;
    storage::write(&dir.join("aux-key.bin"), &secp.to_secret_bytes())?;
    let address = Address::try_from_items(
        Revision::R0,
        vec![Uitem::Data(Receiver::Orchard(
            fvk.address_at(0u32, Scope::External).to_raw_address_bytes(),
        ))],
    )?
    .encode(&NetworkType::Regtest);
    Ok(json!({"scope":"isolated regtest", "address":address,
        "aux_address":transparent.to_zcash_address(NetworkType::Regtest).to_string()}))
}

pub fn key(dir: &Path) -> Result<SpendingKey> {
    SpendingKey::from_bytes(
        storage::read(&dir.join("spending-key.bin"), 32)?
            .try_into()
            .map_err(|_| "key size")?,
    )
    .into_option()
    .ok_or_else(|| "invalid spending key".into())
}
pub fn fvk(dir: &Path) -> Result<FullViewingKey> {
    if dir.join("joint-fvk.bin").exists() {
        FullViewingKey::from_bytes(
            &storage::read(&dir.join("joint-fvk.bin"), 96)?
                .try_into()
                .map_err(|_| "FVK size")?,
        )
        .ok_or_else(|| "invalid joint FVK".into())
    } else {
        Ok(FullViewingKey::from(&key(dir)?))
    }
}
pub fn tree(encoded: &str) -> Result<Tree> {
    if encoded.is_empty() {
        return Ok(Tree::empty());
    }
    if encoded.len() > 16384 {
        return Err("tree encoding size".into());
    }
    let bytes = hex::decode(encoded)?;
    let mut cursor = Cursor::new(&bytes);
    let tree = read_commitment_tree(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing tree bytes".into());
    }
    Ok(tree)
}

pub fn note_json(note: &Note) -> Value {
    json!({"recipient":hex::encode(note.recipient().to_raw_address_bytes()),
        "value":note.value().inner(),"rho":hex::encode(note.rho().to_bytes()),
        "rseed":hex::encode(note.rseed().as_bytes()),"cmx":hex::encode(orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes())})
}
pub fn parse_note(v: &Value) -> Result<Note> {
    let recipient = orchard::Address::from_raw_address_bytes(&decode(v, "recipient")?)
        .into_option()
        .ok_or("recipient")?;
    let rho = Rho::from_bytes(&decode(v, "rho")?)
        .into_option()
        .ok_or("rho")?;
    let seed = RandomSeed::from_bytes(decode(v, "rseed")?, &rho)
        .into_option()
        .ok_or("rseed")?;
    let note = Note::from_parts(
        recipient,
        orchard::value::NoteValue::from_raw(v["value"].as_u64().ok_or("value")?),
        rho,
        seed,
        NoteVersion::V3,
    )
    .into_option()
    .ok_or("invalid note")?;
    if note_json(&note)["cmx"] != v["cmx"] {
        return Err("note commitment mismatch".into());
    }
    Ok(note)
}
pub fn parse_path(v: &Value) -> Result<MerklePath> {
    let nodes = v["path"]
        .as_array()
        .ok_or("path")?
        .iter()
        .map(|n| {
            let b: [u8; 32] = hex::decode(n.as_str().ok_or("node")?)?
                .try_into()
                .map_err(|_| "node size")?;
            MerkleHashOrchard::from_bytes(&b)
                .into_option()
                .ok_or_else(|| "node field".into())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(MerklePath::from_parts(
        u32::try_from(v["position"].as_u64().ok_or("position")?)?,
        nodes.try_into().map_err(|_| "path depth")?,
    ))
}

pub fn scan(dir: &Path, capture: &Path) -> Result<Value> {
    let v = storage::json(capture)?;
    if v["genesis"] != GENESIS || v["branch"] != "77190ad9" || v["initial_height"] != 2 {
        return Err("capture network mismatch".into());
    }
    let fvk = fvk(dir)?;
    let ivks = [Scope::External, Scope::Internal].map(|s| fvk.to_ivk(s));
    let mut tree = tree(v["initial_tree"].as_str().ok_or("initial tree")?)?;
    let expected = self::tree(v["final_tree"].as_str().ok_or("final tree")?)?;
    let mut height = 2u64;
    let mut previous = v["initial_hash"].as_str().ok_or("initial hash")?.to_owned();
    // A funding scan can use an older witness while still scanning every later
    // nullifier. Its clock and spendability view stay at the current tip.
    let anchor_height = v
        .get("anchor_height")
        .map(|h| h.as_u64().ok_or("anchor height"))
        .transpose()?;
    if anchor_height.is_some_and(|h| h < 2 || v["height"].as_u64().is_none_or(|tip| h >= tip)) {
        return Err("funding anchor must precede the capture tip".into());
    }
    let mut anchored = BTreeMap::<[u8; 32], Witness>::new();
    let mut anchor = tree.root();
    let mut anchor_tip = previous.clone();
    let blocks = v["blocks"].as_array().ok_or("blocks")?;
    if blocks.len() > MAX_CAPTURE_BLOCKS {
        return Err("capture history bound".into());
    }
    let mut owned: BTreeMap<[u8; 32], (Value, Witness, [u8; 32], bool)> = BTreeMap::new();
    for b in blocks {
        if b["height"] != height + 1 || b["previousblockhash"] != previous {
            return Err("broken capture chain".into());
        }
        for (txindex, txhex) in b["transactions"]
            .as_array()
            .ok_or("transactions")?
            .iter()
            .enumerate()
        {
            let encoded = txhex.as_str().ok_or("transaction")?;
            if encoded.len() > 4_000_000 {
                return Err("transaction size".into());
            }
            let raw = hex::decode(encoded)?;
            let mut cursor = Cursor::new(&raw);
            let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
            if cursor.position() != raw.len() as u64 || tx.consensus_branch_id() != BranchId::Nu7 {
                return Err("transaction parse/branch".into());
            }
            let Some(bundle) = tx.ironwood_bundle() else {
                continue;
            };
            for (i, a) in bundle.actions().iter().enumerate() {
                let leaf = MerkleHashOrchard::from_cmx(a.cmx());
                for (_, w, nf, spent) in owned.values_mut() {
                    if *nf == a.nullifier().to_bytes() {
                        if *spent {
                            return Err("double nullifier".into());
                        }
                        *spent = true;
                    }
                    w.append(leaf).map_err(err)?;
                }
                tree.append(leaf).map_err(err)?;
                for ivk in &ivks {
                    if let Some((note, _, _)) = bundle.decrypt_output_with_key(i, ivk) {
                        if note.version() != NoteVersion::V3 {
                            return Err("wrong note version".into());
                        }
                        let mut data = note_json(&note);
                        data["txid"] = json!(tx.txid().to_string());
                        data["action"] = json!(i);
                        data["height"] = b["height"].clone();
                        data["coinbase"] = json!(txindex == 0);
                        if owned
                            .insert(
                                a.cmx().to_bytes(),
                                (
                                    data,
                                    Witness::from_tree(tree.clone()).ok_or("empty tree")?,
                                    note.nullifier(&fvk).to_bytes(),
                                    false,
                                ),
                            )
                            .is_some()
                        {
                            return Err("duplicate note commitment".into());
                        }
                        break;
                    }
                }
            }
        }
        if b["tree_size"] != tree.size() as u64 {
            return Err("tree size mismatch".into());
        }
        height += 1;
        previous = b["hash"].as_str().ok_or("hash")?.to_owned();
        if anchor_height == Some(height) {
            anchor = tree.root();
            anchor_tip = previous.clone();
            for (cmx, (_, witness, _, spent)) in &owned {
                if !spent {
                    anchored.insert(*cmx, witness.clone());
                }
            }
        }
    }
    if tree.root() != expected.root()
        || tree.size() != expected.size()
        || v["tip"] != previous
        || v["height"] != height
    {
        return Err("final node tree mismatch".into());
    }
    let mut notes = Vec::new();
    for (cmx, (mut n, w, _, spent)) in owned {
        if spent {
            continue;
        }
        let witness = if anchor_height.is_some() {
            // Newer change is not yet present at the old anchor. Old notes
            // spent after that anchor have already been removed above.
            let Some(witness) = anchored.get(&cmx) else {
                continue;
            };
            witness
        } else {
            &w
        };
        let path = witness.path().ok_or("witness")?;
        n["position"] = json!(u64::from(path.position()));
        n["path"] = json!(
            path.path_elems()
                .iter()
                .map(|p| hex::encode(p.to_bytes()))
                .collect::<Vec<_>>()
        );
        notes.push(n);
    }
    let root = if anchor_height.is_some() {
        anchor
    } else {
        tree.root()
    };
    let mut result = json!({"genesis":GENESIS,"height":height,"tip":previous,"anchor":hex::encode(root.to_bytes()),"notes":notes});
    if hex::decode(&previous)?.len() != 32 {
        return Err("invalid capture tip hash".into());
    }
    let suffix = if let Some(h) = anchor_height {
        result["anchor_height"] = json!(h);
        result["anchor_tip"] = json!(anchor_tip);
        format!("-anchor-{h}")
    } else {
        String::new()
    };
    let output = dir.join(format!("scan-{height}-{previous}{suffix}.json"));
    if output.exists() {
        if storage::json(&output)? != result {
            return Err("existing scan differs for the same block hash".into());
        }
    } else {
        storage::atomic_json(&output, &result)?;
    }
    Ok(
        json!({"scope":"trusted local validating node capture", "height":height,"unspent_notes":notes.len(),"paths_match_node":true,"file":output}),
    )
}
