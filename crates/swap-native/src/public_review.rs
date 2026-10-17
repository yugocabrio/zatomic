//! Private owner review packet, intentionally excluding F's source PCZT/witness.
//! Verification is not consent, a pre-signature, or a recoverable exit bundle.
use crate::{
    Result, compact_wallet::TESTNET_GENESIS, decode, err, funding_consent::hash, keys,
    participants, public_graph, public_setup, recovery_bundle, refund_lock::RefundLock,
    regtest_swap, storage, wallet,
};
use group_old::GroupEncoding;
use orchard::{
    circuit::{OrchardCircuitVersion, VerifyingKey},
    keys::{FullViewingKey, Scope},
};
use pczt::Pczt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

const EXITS: [(&str, &str); 4] = [
    ("claim", "claim.pczt"),
    ("refund", "refund.pczt"),
    ("claim_check", "claim-check.pczt"),
    ("refund_check", "refund-check.pczt"),
];
fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn bytes(v: &Value, k: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(v[k].as_str().ok_or("missing review bytes")?)?)
}
fn fvk(v: &Value, k: &str) -> Result<FullViewingKey> {
    FullViewingKey::from_bytes(&decode(v, k)?).ok_or_else(|| "review FVK encoding".into())
}
fn plan_digest(plan: &Value) -> Result<String> {
    let mut h = Sha256::new();
    h.update(b"Latch candidate execution plan v1\0");
    h.update(serde_json::to_vec(plan)?);
    Ok(hex::encode(h.finalize()))
}

pub struct Verified {
    pub report: Value,
    pub policy: Value,
}

/// Checks bytes and proving material locally, without trusting the preparer's
/// `proofs_verified` booleans or accessing its source wallet. Clock bounds/live
/// observations are separate policies; this function never permits funding.
pub fn verify(packet: &Value, own: Option<&FullViewingKey>, id: u16) -> Result<Verified> {
    if packet.as_object().is_none_or(|o| o.len() != 9)
        || packet["format"] != "latch-public-graph-review-v1"
    {
        return Err("review packet schema".into());
    }
    let descriptor = &packet["destinations"];
    let authenticated = public_setup::authenticate(descriptor)?;
    let roles = &authenticated["destinations"];
    let joint = fvk(roles, "joint_fvk")?;
    let public = keys::PublicKeyPackage::deserialize(&bytes(&descriptor["setup"], "public")?)
        .map_err(err)?;
    let graph = &packet["graph"];
    let plan = &packet["plan"];
    let lock = RefundLock::parse(graph)?;
    if graph["format"] != "latch-unsigned-testnet-graph-v1"
        || graph["native_genesis"] != TESTNET_GENESIS
        || graph["native_branch"] != "77190ad9"
        || graph["eth_chain_id"] != 11155111
        || graph["expiry_height"] != 0
        || graph["principal_zatoshi"] != authenticated["principal_zatoshi"]
        || graph["payout_zatoshi"] != authenticated["payout_zatoshi"]
        || graph["input_binding"]["destinations_sha256"] != hash(descriptor)?
        || graph["input_binding"]["quote_digest"] != authenticated["quote_digest"]
        || graph["input_binding"]["destinations_authenticated"] != true
        || !graph["input_binding"]["synthetic"].is_boolean()
        || graph["files"].as_object().is_none_or(|f| f.len() != 5)
        || graph["signature_messages"]
            .as_object()
            .is_none_or(|m| m.len() != 2)
        || graph["real_input_signatures"] != false
        || graph["funding_authorized"] != false
        || graph["participant_consents_present"] != false
        || graph["broadcast"] != false
        || lock.required_time().is_none()
        || plan["native_refund_lock"] != graph["refund_lock"]
        || plan["policy"]["native_genesis"] != TESTNET_GENESIS
        || plan["policy"]["native_branch"] != "77190ad9"
        || plan["policy"]["eth_chain_id"] != 11155111
    {
        return Err("graph/quote/destination/plan binding mismatch".into());
    }
    // Synthetic diagnostic drafts have no source reservation/plan binding.
    // Keep that explicit through all reports; never promote them to funding.
    let synthetic = graph["input_binding"]["synthetic"] == true;
    let plan_digest = plan_digest(plan)?;
    if !synthetic && graph["input_binding"]["plan_digest"] != plan_digest {
        return Err("graph was prepared for another timestamp plan".into());
    }
    decode::<32>(&graph["files"], "funding.pczt")?;
    let raw = bytes(packet, "funding_preview")?;
    let mut cursor = std::io::Cursor::new(&raw);
    let funding = Transaction::read(&mut cursor, BranchId::Nu7)?;
    if cursor.position() != raw.len() as u64
        || funding.txid().to_string() != graph["funding_txid"]
        || funding.version() != TxVersion::V6
        || funding.consensus_branch_id() != BranchId::Nu7
        || u32::from(funding.expiry_height()) != 0
        || funding.lock_time() != 0
        || funding.transparent_bundle().is_some()
        || funding.sapling_bundle().is_some()
        || funding.orchard_bundle().is_some()
    {
        return Err("funding preview domain/effects mismatch".into());
    }
    let f = funding
        .ironwood_bundle()
        .ok_or("missing preview Ironwood")?;
    if f.actions().len() != 2 {
        return Err("funding preview layout".into());
    }
    f.verify_proof(&VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
        .map_err(err)?;
    let notes = (0..f.actions().len())
        .filter_map(|i| f.decrypt_output_with_key(i, &joint.to_ivk(Scope::External)))
        .map(|(note, _, _)| note)
        .collect::<Vec<_>>();
    if notes.len() != 1
        || notes[0].value().inner()
            != authenticated["principal_zatoshi"]
                .as_u64()
                .ok_or("principal")?
    {
        return Err("exact pending note not found in F".into());
    }
    let mut pczt = std::collections::BTreeMap::new();
    for (field, name) in EXITS {
        let encoded = bytes(packet, field)?;
        if graph["files"][name] != sha(&encoded) {
            return Err("review exit hash mismatch".into());
        }
        let p = Pczt::parse(&encoded).map_err(err)?;
        public_graph::unsigned(&p, field.starts_with("refund"))?;
        pczt.insert(field, p);
    }
    let aux = &pczt["refund"].transparent().inputs()[0];
    if *aux.value() != 20_000 {
        return Err("dedicated refund coin value".into());
    }
    let mut policy = json!({"joint_fvk":roles["joint_fvk"],"pending":wallet::note_json(&notes[0]),"funding":packet["funding_preview"],
        "refund_lock":graph["refund_lock"],"trade":descriptor["trade"],"session":"00".repeat(32),
        "aux":{"txid_le":hex::encode(aux.prevout_txid()),"index":aux.prevout_index(),
            "value":aux.value(),"script":hex::encode(aux.script_pubkey())}});
    // v2 destinations carry receive addresses only; v1 carried FVKs. Copy
    // exactly what was authenticated so reviewed-policy digests stay stable.
    for field in ["alice_receiver", "bob_receiver", "alice_fvk", "bob_fvk"] {
        if let Some(value) = roles.get(field) {
            policy[field] = value.clone();
        }
    }
    policy["review_packet_digest"] = json!(hash(packet)?);
    policy["execution_plan_digest"] = json!(plan_digest);
    let mut contexts = json!({});
    for (mode, target) in [
        ("claim", decode(&descriptor["setup"], "adaptor_point")?),
        ("refund", shielded_swap_crypto::generator().to_bytes()),
    ] {
        policy["mode"] = json!(mode);
        let deferred = &pczt[mode];
        let checked = &pczt[if mode == "claim" {
            "claim_check"
        } else {
            "refund_check"
        }];
        if deferred.ironwood().anchor().is_some() || deferred.ironwood().zkproof().is_some() {
            return Err("exit must remain deferred".into());
        }
        recovery_bundle::verify_reproving_material(deferred, checked)?;
        regtest_swap::verify_claim_proof(checked.clone())?;
        let (context, index) =
            participants::validate_testnet(deferred.clone(), &policy, own, id, &public, target)?;
        for (i, action) in deferred.ironwood().actions().iter().enumerate() {
            if i != index {
                let key = orchard::primitives::redpallas::VerificationKey::<
                    orchard::primitives::redpallas::SpendAuth,
                >::try_from(*action.spend().rk())?;
                let sig = orchard::primitives::redpallas::Signature::from(
                    action
                        .spend()
                        .spend_auth_sig()
                        .ok_or("missing dummy signature")?,
                );
                key.verify(&context.message, &sig)?;
            }
        }
        if graph["signature_messages"][mode] != hex::encode(context.message) {
            return Err("exit signature message changed".into());
        }
        contexts[mode] = json!({"message":hex::encode(context.message),"index":index,
            "randomizer":hex::encode(context.randomizer),"adaptor_point":hex::encode(context.adaptor_point)});
    }
    policy.as_object_mut().unwrap().remove("mode");
    policy.as_object_mut().unwrap().remove("session");
    Ok(Verified {
        policy,
        report: json!({"format":"latch-public-graph-review-receipt-v1",
        "review_packet_digest":hash(packet)?,"graph_digest":hash(graph)?,"plan_digest":plan_digest,
        "funding_txid":graph["funding_txid"],"quote_digest":authenticated["quote_digest"],
        "contexts":contexts,"three_proofs_verified":true,"reproving_material_verified":true,
        "synthetic_inputs":synthetic,"source_private_pczt_disclosed":false,"funding_authorized":false,
        "signatures_created":false,"scope":"offline content review; not live observations, final consent or recovery receipt"}),
    })
}

pub fn export(graph_dir: &Path, destinations: &Path, plan: &Path, output: &Path) -> Result<Value> {
    let descriptor = storage::json(destinations)?;
    public_setup::authenticate(&descriptor)?;
    let graph = storage::json(&graph_dir.join("graph.json"))?;
    let raw = storage::read(&graph_dir.join("funding.pczt"), 1_000_000)?;
    if graph["files"]["funding.pczt"] != sha(&raw) {
        return Err("private source PCZT changed".into());
    }
    let funding = Pczt::parse(&raw).map_err(err)?;
    public_graph::unsigned(&funding, false)?;
    let mut preview = Vec::new();
    regtest_swap::unsigned_preview(&funding)?.write(&mut preview)?;
    let mut packet = json!({"format":"latch-public-graph-review-v1","graph":graph,
        "destinations":descriptor,"plan":storage::json(plan)?,"funding_preview":hex::encode(preview)});
    for (field, name) in EXITS {
        packet[field] = json!(hex::encode(storage::read(
            &graph_dir.join(name),
            1_000_000
        )?));
    }
    let report = verify(&packet, None, 1)?.report;
    storage::atomic_json(output, &packet)?;
    Ok(
        json!({"file":output,"review_packet_digest":report["review_packet_digest"],
        "source_private_pczt_disclosed":false,"funding_authorized":false,"synthetic_inputs":report["synthetic_inputs"]}),
    )
}

pub fn review(dir: &Path, input: &Path) -> Result<Value> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("setup.lock"))?;
    lock.try_lock().map_err(|_| "owner setup busy")?;
    let packet: Value = serde_json::from_slice(&storage::read(input, 200_000)?)?;
    if packet["destinations"] != storage::json(&dir.join("authenticated-destinations.json"))?
        || packet["destinations"]["trade"] != storage::json(&dir.join("accepted-trade.json"))?
    {
        return Err("review differs from local owner setup".into());
    }
    let identity = storage::json(&dir.join("identity.json"))?;
    let (role, id, peer) = match identity["role"].as_str() {
        Some("alice") => ("alice", 1, "bob"),
        Some("bob") => ("bob", 2, "alice"),
        _ => return Err("owner role".into()),
    };
    let owners = &packet["destinations"]["trade"]["offer"]["payload"]["owners"];
    if owners[role] != identity
        || owners[peer] != storage::json(&dir.join("trusted-peer.json"))?["identity"]
    {
        return Err("review owners changed".into());
    }
    let packet_path = dir.join("reviewed-graph-packet.json");
    if packet_path.exists() && storage::json(&packet_path)? != packet {
        return Err("owner already reviewed another graph".into());
    }
    let checked = verify(&packet, Some(&wallet::fvk(&dir.join("native"))?), id)?;
    // Persist both the exact reviewed packet and derived signing policy. A crash
    // before the receipt can only retry these identical bytes; never sign here.
    for (name, value) in [
        ("reviewed-graph-packet.json", packet),
        ("reviewed-graph-policy.json", checked.policy),
        ("graph-review.json", checked.report.clone()),
    ] {
        let path = dir.join(name);
        if path.exists() {
            if storage::json(&path)? != value {
                return Err("immutable graph review differs".into());
            }
        } else {
            storage::atomic_json(&path, &value)?;
        }
    }
    Ok(checked.report)
}
