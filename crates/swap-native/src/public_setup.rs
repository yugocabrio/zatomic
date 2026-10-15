//! Owner-local, authenticated public-profile DKG. No transaction signing here.
//! Round2 contains a secret share: exchange privately over an encrypted channel.
//! One fresh DKG per accepted quote; each completed step is an atomic journal.
use crate::{
    Identifier, Result, compact_wallet::TESTNET_GENESIS, decode, err, evm_key,
    funding_consent::hash, keys, storage, trade, wallet,
};
use ff_old::{Field, PrimeField};
use group_old::{Curve, Group, GroupEncoding};
use orchard::keys::FullViewingKey;
use pasta_old::{arithmetic::CurveAffine, pallas};
use rand_core::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};

const DOMAIN: &[u8] = b"Latch public owner setup v1\0";

fn digest(payload: &Value) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(serde_json::to_vec(payload)?);
    Ok(h.finalize().into())
}
fn bytes(v: &Value, k: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(v[k].as_str().ok_or("missing setup bytes")?)?)
}
fn fvk(v: &Value, k: &str) -> Result<FullViewingKey> {
    FullViewingKey::from_bytes(&decode(v, k)?).ok_or_else(|| "invalid setup FVK".into())
}
fn point(v: &Value) -> Result<()> {
    let p = pallas::Point::from_bytes(&decode(v, "adaptor_point")?)
        .into_option()
        .ok_or("invalid adaptor point")?;
    if bool::from(p.is_identity()) {
        return Err("identity adaptor point".into());
    }
    let affine = p.to_affine();
    let c = affine.coordinates().unwrap();
    let big = |mut b: [u8; 32]| {
        b.reverse();
        format!("0x{}", hex::encode(b))
    };
    if v["point_x"] != big(c.x().to_repr()) || v["point_y"] != big(c.y().to_repr()) {
        return Err("adaptor coordinates changed".into());
    }
    Ok(())
}
fn envelope(dir: &Path, identity: &Value, payload: Value) -> Result<Value> {
    let signature = evm_key::sign_digest(&dir.join("ethereum"), digest(&payload)?)?;
    evm_key::verify(identity, &signature, digest(&payload)?)?;
    Ok(json!({"payload":payload,"signature":signature}))
}
fn verify(packet: &Value, owners: &Value, role: &str, quote: &str, kind: &str) -> Result<Value> {
    let p = &packet["payload"];
    let fields = match (kind, role) {
        ("round1", "alice") => 10,
        ("round1", "bob") => 6,
        ("round2", _) => 7,
        ("ready", _) => 5,
        _ => return Err("unknown setup message".into()),
    };
    if packet.as_object().is_none_or(|o| o.len() != 2)
        || p.as_object().is_none_or(|o| o.len() != fields)
        || p["format"] != "latch-public-setup-message-v1"
        || p["role"] != role
        || p["kind"] != kind
        || p["quote_digest"] != quote
    {
        return Err("setup message role/session/kind mismatch".into());
    }
    evm_key::verify(&owners[role], &packet["signature"], digest(p)?)?;
    Ok(p.clone())
}
fn base(role: &str, quote: &str, kind: &str) -> Value {
    json!({"format":"latch-public-setup-message-v1","role":role,"kind":kind,"quote_digest":quote})
}
fn joint(public: &keys::PublicKeyPackage, seed: &Value) -> Result<FullViewingKey> {
    let mut data = fvk(seed, "joint_seed_fvk")?.to_bytes();
    data[..32].copy_from_slice(&public.verifying_key().serialize().map_err(err)?);
    FullViewingKey::from_bytes(&data).ok_or_else(|| "invalid joint DKG key".into())
}

/// Offline authentication of the descriptor consumed by the graph builder.
/// It does not prove the owners retained secrets, or authorize any spend.
pub fn authenticate(v: &Value) -> Result<Value> {
    if v.as_object().is_none_or(|o| o.len() != 4)
        || v["format"] != "latch-authenticated-destinations-v1"
    {
        return Err("both authenticated destination receipts required".into());
    }
    let amounts = trade::verify_testnet(&v["trade"], true)?;
    let quote = hash(&v["trade"]["offer"]["payload"])?;
    let owners = &v["trade"]["offer"]["payload"]["owners"];
    let s = &v["setup"];
    if s.as_object().is_none_or(|o| o.len() != 9) || s["quote_digest"] != quote {
        return Err("setup binding schema/quote mismatch".into());
    }
    let roles = &s["destinations"];
    if roles.as_object().is_none_or(|o| o.len() != 7)
        || roles["format"] != "latch-graph-destinations-v1"
        || roles["native_genesis"] != TESTNET_GENESIS
        || roles["native_branch"] != "77190ad9"
        || roles["eth_chain_id"] != 11155111
    {
        return Err("setup destination network mismatch".into());
    }
    let public = keys::PublicKeyPackage::deserialize(&bytes(s, "public")?).map_err(err)?;
    let expected = [
        Identifier::try_from(1u16).map_err(err)?,
        Identifier::try_from(2u16).map_err(err)?,
    ];
    if public.verifying_shares().len() != 2
        || expected
            .iter()
            .any(|id| !public.verifying_shares().contains_key(id))
    {
        return Err("two-owner DKG required".into());
    }
    let j = fvk(roles, "joint_fvk")?;
    let a = fvk(roles, "alice_fvk")?;
    let b = fvk(roles, "bob_fvk")?;
    if j != joint(&public, s)? || a == b || j == a || j == b {
        return Err("DKG/destination mismatch".into());
    }
    point(s)?;
    decode::<32>(s, "round1_digest")?;
    decode::<32>(s, "round2_digest")?;
    if v["receipts"].as_object().is_none_or(|o| o.len() != 2) {
        return Err("two ready receipts required".into());
    }
    for role in ["alice", "bob"] {
        let p = verify(&v["receipts"][role], owners, role, &quote, "ready")?;
        if p.as_object().is_none_or(|o| o.len() != 5) || p["setup"] != *s {
            return Err("owner setup receipts disagree".into());
        }
    }
    Ok(
        json!({"destinations":roles,"quote_digest":quote,"principal_zatoshi":amounts.principal,
        "payout_zatoshi":amounts.payout,"eth_amount_wei":amounts.eth,
        "authenticated_setup_digest":hash(v)?,"funding_authorized":false}),
    )
}

pub fn inspect(path: &Path) -> Result<Value> {
    authenticate(&serde_json::from_slice(&storage::read(path, 200_000)?)?)
}

/// Caller runs this on the owner's machine. Native locking also protects direct
/// CLI use; the journal is never reset or overwritten on a changed peer packet.
pub fn run(dir: &Path, action: &str, incoming: Option<&Path>) -> Result<Value> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("setup.lock"))?;
    lock.try_lock().map_err(|_| "public owner setup is busy")?;
    let identity = storage::json(&dir.join("identity.json"))?;
    let role = identity["role"].as_str().ok_or("owner role")?;
    let (id, peer) = match role {
        "alice" => (1u16, "bob"),
        "bob" => (2u16, "alice"),
        _ => return Err("owner role".into()),
    };
    let trade = storage::json(&dir.join("accepted-trade.json"))?;
    trade::verify_testnet(&trade, true)?;
    let owners = &trade["offer"]["payload"]["owners"];
    if owners[role] != identity
        || owners[peer] != storage::json(&dir.join("trusted-peer.json"))?["identity"]
    {
        return Err("setup quote differs from locally pinned owners".into());
    }
    let quote = hash(&trade["offer"]["payload"])?;
    let native = dir.join("native");
    let mine = Identifier::try_from(id).map_err(err)?;
    let theirs = Identifier::try_from(3 - id).map_err(err)?;
    if action == "start" {
        let journal = dir.join("setup-round1.json");
        if journal.exists() {
            let old = storage::json(&journal)?;
            verify(&old["packet"], owners, role, &quote, "round1")?;
            return Ok(old["packet"].clone());
        }
        // An interrupted initialization is retained; do not regenerate keys in
        // a partially used directory or silently start another DKG.
        wallet::init_testnet(&native)?;
        let (secret, package) = keys::dkg::part1(mine, 2, 2, OsRng).map_err(err)?;
        let mut p = base(role, &quote, "round1");
        p["recipient_fvk"] = json!(hex::encode(wallet::fvk(&native)?.to_bytes()));
        p["package"] = json!(hex::encode(package.serialize().map_err(err)?));
        let mut state = json!({});
        if id == 1 {
            let t = loop {
                let t = pallas::Scalar::random(OsRng);
                if t != pallas::Scalar::ZERO {
                    break t;
                }
            };
            let target = shielded_swap_crypto::generator() * t;
            let affine = target.to_affine();
            let c = affine.coordinates().unwrap();
            let big = |mut b: [u8; 32]| {
                b.reverse();
                format!("0x{}", hex::encode(b))
            };
            p["adaptor_point"] = json!(hex::encode(target.to_bytes()));
            p["point_x"] = json!(big(c.x().to_repr()));
            p["point_y"] = json!(big(c.y().to_repr()));
            p["joint_seed_fvk"] = json!(hex::encode(
                FullViewingKey::from(&crate::random_key(&mut rand::rng())).to_bytes()
            ));
            state["witness_le"] = json!(hex::encode(t.to_repr()));
        }
        state["secret"] = json!(hex::encode(secret.serialize().map_err(err)?));
        state["packet"] = envelope(dir, &identity, p)?;
        storage::atomic_json(&journal, &state)?;
        return Ok(state["packet"].clone());
    }
    let first = storage::json(&dir.join("setup-round1.json"))?;
    let own_first = verify(&first["packet"], owners, role, &quote, "round1")?;
    if own_first["recipient_fvk"] != hex::encode(wallet::fvk(&native)?.to_bytes()) {
        return Err("own receiving key changed".into());
    }
    let packet: Value = serde_json::from_slice(&storage::read(
        incoming.ok_or("peer setup packet required")?,
        200_000,
    )?)?;
    if action == "round2" {
        let other = verify(&packet, owners, peer, &quote, "round1")?;
        if fvk(&other, "recipient_fvk")? == fvk(&own_first, "recipient_fvk")? {
            return Err("distinct native receivers required".into());
        }
        let mut ordered = json!({});
        ordered[role] = own_first.clone();
        ordered[peer] = other.clone();
        point(&ordered["alice"])?;
        fvk(&ordered["alice"], "joint_seed_fvk")?;
        let transcript = hash(&ordered)?;
        let path = dir.join("setup-round2.json");
        if path.exists() {
            let old = storage::json(&path)?;
            if old["packet"]["payload"]["round1_digest"] != transcript {
                return Err("peer round1 changed".into());
            }
            verify(&old["packet"], owners, role, &quote, "round2")?;
            return Ok(old["packet"].clone());
        }
        let peer1 =
            keys::dkg::round1::Package::deserialize(&bytes(&other, "package")?).map_err(err)?;
        let secret = keys::dkg::round1::SecretPackage::deserialize(&bytes(&first, "secret")?)
            .map_err(err)?;
        let (secret, out) =
            keys::dkg::part2(secret, &BTreeMap::from([(theirs, peer1)])).map_err(err)?;
        let mut p = base(role, &quote, "round2");
        p["to"] = json!(peer);
        p["round1_digest"] = json!(transcript);
        p["package"] = json!(hex::encode(out[&theirs].serialize().map_err(err)?));
        let state = json!({"secret":hex::encode(secret.serialize().map_err(err)?),"round1":ordered,
            "packet":envelope(dir,&identity,p)?});
        storage::atomic_json(&path, &state)?;
        return Ok(state["packet"].clone());
    }
    let second = storage::json(&dir.join("setup-round2.json"))?;
    let our_second = verify(&second["packet"], owners, role, &quote, "round2")?;
    let round1_digest = hash(&second["round1"])?;
    if second["round1"][role] != own_first || our_second["round1_digest"] != round1_digest {
        return Err("stored setup transcript changed".into());
    }
    if action == "finish" {
        let other = verify(&packet, owners, peer, &quote, "round2")?;
        if other["round1_digest"] != round1_digest || other["to"] != role {
            return Err("round2 transcript/recipient mismatch".into());
        }
        let mut ordered = json!({});
        ordered[role] = our_second;
        ordered[peer] = other.clone();
        let round2_digest = hash(&ordered)?;
        let path = dir.join("setup-complete.json");
        if path.exists() {
            let old = storage::json(&path)?;
            if old["packet"]["payload"]["setup"]["round2_digest"] != round2_digest {
                return Err("peer round2 changed".into());
            }
            verify(&old["packet"], owners, role, &quote, "ready")?;
            return Ok(old["packet"].clone());
        }
        let peer1 =
            keys::dkg::round1::Package::deserialize(&bytes(&second["round1"][peer], "package")?)
                .map_err(err)?;
        let peer2 =
            keys::dkg::round2::Package::deserialize(&bytes(&other, "package")?).map_err(err)?;
        let secret = keys::dkg::round2::SecretPackage::deserialize(&bytes(&second, "secret")?)
            .map_err(err)?;
        let (key, public) = keys::dkg::part3(
            &secret,
            &BTreeMap::from([(theirs, peer1)]),
            &BTreeMap::from([(theirs, peer2)]),
        )
        .map_err(err)?;
        let a = &second["round1"]["alice"];
        let b = &second["round1"]["bob"];
        let roles = json!({"format":"latch-graph-destinations-v1","native_genesis":TESTNET_GENESIS,
            "native_branch":"77190ad9","eth_chain_id":11155111,
            "joint_fvk":hex::encode(joint(&public,a)?.to_bytes()),
            "alice_fvk":a["recipient_fvk"],"bob_fvk":b["recipient_fvk"]});
        let setup = json!({"quote_digest":quote,"round1_digest":round1_digest,"round2_digest":round2_digest,
            "public":hex::encode(public.serialize().map_err(err)?),"destinations":roles,
            "joint_seed_fvk":a["joint_seed_fvk"],"adaptor_point":a["adaptor_point"],"point_x":a["point_x"],"point_y":a["point_y"]});
        let mut p = base(role, &quote, "ready");
        p["setup"] = setup;
        let state = json!({"key":hex::encode(key.serialize().map_err(err)?),"packet":envelope(dir,&identity,p)?});
        storage::atomic_json(&path, &state)?;
        return Ok(state["packet"].clone());
    }
    if action == "agree" {
        let complete = storage::json(&dir.join("setup-complete.json"))?;
        let own = verify(&complete["packet"], owners, role, &quote, "ready")?;
        let key = keys::KeyPackage::deserialize(&bytes(&complete, "key")?).map_err(err)?;
        let public =
            keys::PublicKeyPackage::deserialize(&bytes(&own["setup"], "public")?).map_err(err)?;
        if *key.identifier() != mine
            || *key.min_signers() != 2
            || key.verifying_key() != public.verifying_key()
            || public.verifying_shares().get(&mine) != Some(key.verifying_share())
        {
            return Err("local completed DKG share changed".into());
        }
        if id == 1 {
            let witness = pallas::Scalar::from_repr(decode(&first, "witness_le")?)
                .into_option()
                .ok_or("local witness encoding")?;
            if hex::encode((shielded_swap_crypto::generator() * witness).to_bytes())
                != own["setup"]["adaptor_point"]
            {
                return Err("local adaptor witness changed".into());
            }
        }
        let other = verify(&packet, owners, peer, &quote, "ready")?;
        if own["setup"] != other["setup"] {
            return Err("peer completed another DKG/destination binding".into());
        }
        let mut receipts = json!({});
        receipts[role] = complete["packet"].clone();
        receipts[peer] = packet;
        let output = json!({"format":"latch-authenticated-destinations-v1","trade":trade,"setup":own["setup"],"receipts":receipts});
        authenticate(&output)?;
        let path = dir.join("authenticated-destinations.json");
        if path.exists() {
            if storage::json(&path)? != output {
                return Err("destination agreement already pinned".into());
            }
        } else {
            storage::atomic_json(&path, &output)?;
        }
        return Ok(output);
    }
    Err("unknown public setup operation".into())
}
