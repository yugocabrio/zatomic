//! Offline public-profile native exit bundle. Never a funding authorization.
//! Source signs only the reserved R auxiliary. Each owner independently checks
//! the exact reviewed exits, saves them durably, then signs a receipt.
use crate::{
    Result, auxiliary::Auxiliary, decode, err, evm_key, funding_consent::hash, public_graph,
    public_presign, public_review, recovery_bundle, regtest_swap, storage, wallet,
};
use orchard::keys::FullViewingKey;
use pczt::{
    Pczt,
    roles::{signer::Signer, spend_finalizer::SpendFinalizer, updater::Updater},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};

const RECEIPT_DOMAIN: &[u8] = b"Latch public native recovery receipt v1\0";

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn pczt(v: &Value, name: &str) -> Result<Pczt> {
    Pczt::parse(&hex::decode(v[name].as_str().ok_or("recovery PCZT")?)?).map_err(|e| err(e).into())
}
fn alice(packet: &Value) -> Result<FullViewingKey> {
    FullViewingKey::from_bytes(&decode(
        &packet["destinations"]["setup"]["destinations"],
        "alice_fvk",
    )?)
    .ok_or_else(|| "recovery Alice FVK".into())
}
fn lock(path: &Path) -> Result<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    file.try_lock().map_err(|_| "recovery session busy")?;
    Ok(file)
}
fn immutable(path: &Path, value: &Value) -> Result<()> {
    if path.exists() {
        if storage::json(path)? != *value {
            return Err("immutable native recovery record changed".into());
        }
    } else {
        storage::atomic_json(path, value)?;
    }
    Ok(())
}
fn apply_refund(packet: &Value, review: &Value, presigned: &Value, field: &str) -> Result<Pczt> {
    let ctx = &review["contexts"]["refund"];
    regtest_swap::apply(
        pczt(packet, field)?,
        usize::try_from(ctx["index"].as_u64().ok_or("refund index")?)?,
        decode(presigned, "refund_spend_signature")?,
        decode(ctx, "message")?,
    )
}

/// Reconstruct the final PCZT from the EXACT reviewed private material, using
/// only the supplied, verified public auxiliary signature. Sighash/effects
/// equality alone would miss altered proof inputs or stripped binding keys.
fn reconstruct_refund(expected: Pczt, signed: &Pczt) -> Result<Pczt> {
    recovery_bundle::verify_auxiliary_signature(signed)?;
    let mut script = None;
    pczt::roles::verifier::Verifier::new(signed.clone())
        .with_transparent::<String, _>(|b| {
            use zcash_script::script::Evaluable;
            script = b.inputs()[0].script_sig().as_ref().map(|s| s.to_bytes());
            Ok(())
        })
        .map_err(err)?;
    let script = script.ok_or("missing auxiliary signature")?;
    // Bounds and canonical P2PKH shape were checked above.
    let end = 1 + usize::from(script[0]);
    let signature = secp256k1::ecdsa::Signature::from_der(&script[1..end - 1])?;
    let public = script[end + 1..].to_vec();
    let expected = Updater::new(expected)
        .update_transparent_with(|mut b| {
            b.update_input_with(0, |mut i| {
                i.set_hash160_preimage(public);
                Ok(())
            })
        })
        .map_err(err)?
        .finish();
    let mut signer = Signer::new(expected).map_err(err)?;
    signer
        .append_transparent_signature(0, signature)
        .map_err(err)?;
    let reconstructed = SpendFinalizer::new(signer.finish())
        .finalize_spends()
        .map_err(err)?;
    if reconstructed.clone().serialize().map_err(err)? != signed.clone().serialize().map_err(err)? {
        return Err("signed refund differs from reviewed material after finalization".into());
    }
    Ok(reconstructed)
}

/// Offline native validation only. Provisional anchors are not network anchors,
/// and a receipt neither proves an unspent source nor authorizes funding.
pub fn verify(bundle: &Value, own: &FullViewingKey, id: u16) -> Result<Value> {
    if bundle.as_object().is_none_or(|o| o.len() != 8)
        || bundle["format"] != "latch-public-native-recovery-v1"
        || bundle["funding_authorized"] != false
        || bundle["broadcast"] != false
    {
        return Err("native recovery bundle schema/domain".into());
    }
    let packet = &bundle["review"];
    let verified = public_review::verify(packet, own, id)?;
    public_presign::validate_result(packet, &verified.report, &bundle["presignatures"])?;
    if bundle["synthetic_inputs"] != verified.report["synthetic_inputs"] {
        return Err("recovery input provenance changed".into());
    }
    let refund = reconstruct_refund(
        apply_refund(packet, &verified.report, &bundle["presignatures"], "refund")?,
        &pczt(bundle, "refund")?,
    )?;
    let checked = reconstruct_refund(
        apply_refund(
            packet,
            &verified.report,
            &bundle["presignatures"],
            "refund_check",
        )?,
        &pczt(bundle, "refund_check")?,
    )?;
    recovery_bundle::verify_reproving_material(&refund, &checked)?;
    let _ = regtest_swap::extract_checked(checked)?;
    Ok(json!({"format":"latch-public-native-recovery-check-v1",
        "bundle_digest":hash(bundle)?,"review_packet_digest":verified.report["review_packet_digest"],
        "graph_digest":verified.report["graph_digest"],"execution_plan_digest":verified.report["plan_digest"],
        "funding_txid":packet["graph"]["funding_txid"],"synthetic_inputs":bundle["synthetic_inputs"],
        "conditional_claim_verified":true,"refund_shielded_and_auxiliary_signatures_verified":true,
        "exact_reviewed_reproving_material_verified":true,"native_exit_bundle_complete":true,
        "live_chain_checked":false,"funding_authorized":false,"broadcast":false}))
}

fn assemble(
    packet: Value,
    presigned: Value,
    key: &secp256k1::SecretKey,
    output: &Path,
) -> Result<Value> {
    let verified = public_review::verify(&packet, &alice(&packet)?, 1)?;
    public_presign::validate_result(&packet, &verified.report, &presigned)?;
    if output.exists() {
        let bundle = storage::json(output)?;
        if bundle["review"] != packet || bundle["presignatures"] != presigned {
            return Err("saved native bundle has different authorization".into());
        }
        let mut report = verify(&bundle, &alice(&packet)?, 1)?;
        report["file"] = json!(output);
        report["reused_bundle"] = json!(true);
        return Ok(report);
    }
    let mut bundle = json!({"format":"latch-public-native-recovery-v1",
        "synthetic_inputs":verified.report["synthetic_inputs"],
        "review":packet,"presignatures":presigned,"funding_authorized":false,"broadcast":false});
    for name in ["refund", "refund_check"] {
        let unsigned = apply_refund(
            &bundle["review"],
            &verified.report,
            &bundle["presignatures"],
            name,
        )?;
        let mut signer = Signer::new(unsigned).map_err(err)?;
        signer.sign_transparent(0, key).map_err(err)?;
        let signed = SpendFinalizer::new(signer.finish())
            .finalize_spends()
            .map_err(err)?;
        bundle[name] = json!(hex::encode(signed.serialize().map_err(err)?));
    }
    let mut report = verify(&bundle, &alice(&bundle["review"])?, 1)?;
    storage::atomic_json(output, &bundle)?;
    report["file"] = json!(output);
    report["reused_bundle"] = json!(false);
    Ok(report)
}

/// No alternate synthetic path here. The bank's existing immutable reservation
/// and single graph draft must match before touching its auxiliary key. This
/// does NOT touch the native source spending key or authorize F.
pub fn prepare(bank: &Path, folder: &Path, review_path: &Path, presigned: &Path) -> Result<Value> {
    let _lock = lock(&bank.join("sync.lock"))?;
    let manifest = public_graph::package(bank, folder)?;
    let draft = storage::json(&folder.join("graph-draft.json"))?;
    let name = draft["directory"]
        .as_str()
        .ok_or("reserved graph directory")?;
    if !name.starts_with("graph-") || Path::new(name).components().count() != 1 {
        return Err("reserved graph path".into());
    }
    let graph_dir = folder.join(name);
    if std::fs::canonicalize(&graph_dir)?.parent() != Some(std::fs::canonicalize(folder)?.as_path())
    {
        return Err("reserved graph outside package".into());
    }
    let graph_raw = storage::read(&graph_dir.join("graph.json"), 200_000)?;
    let graph: Value = serde_json::from_slice(&graph_raw)?;
    let packet = storage::json(review_path)?;
    let pre = storage::json(presigned)?;
    if graph != packet["graph"]
        || draft["graph_digest"] != sha(&graph_raw)
        || draft["destinations_sha256"] != hash(&packet["destinations"])?
        || graph["input_binding"]["synthetic"] != false
        || graph["input_binding"]["manifest_sha256"]
            != sha(&storage::read(&folder.join("manifest.json"), 50_000_000)?)
        || graph["input_binding"]["plan_digest"] != manifest["plan_digest"]
        || graph["principal_zatoshi"] != manifest["principal_zatoshi"]
        || packet["plan"] != storage::json(&folder.join("plan.json"))?
    {
        return Err("recovery graph differs from source reservation".into());
    }
    for (field, file) in [
        ("claim", "claim.pczt"),
        ("refund", "refund.pczt"),
        ("claim_check", "claim-check.pczt"),
        ("refund_check", "refund-check.pczt"),
    ] {
        let raw = storage::read(&graph_dir.join(file), 1_000_000)?;
        if packet[field] != hex::encode(&raw) || graph["files"][file] != sha(&raw) {
            return Err("reserved recovery PCZT changed".into());
        }
    }
    let raw = storage::read(&graph_dir.join("funding.pczt"), 1_000_000)?;
    if graph["files"]["funding.pczt"] != sha(&raw) {
        return Err("source PCZT changed".into());
    }
    let funding = Pczt::parse(&raw).map_err(err)?;
    public_graph::unsigned(&funding, false)?;
    let mut preview = Vec::new();
    regtest_swap::unsigned_preview(&funding)?.write(&mut preview)?;
    if packet["funding_preview"] != hex::encode(preview) {
        return Err("source preview changed".into());
    }
    let verified = public_review::verify(&packet, &alice(&packet)?, 1)?;
    public_presign::validate_result(&packet, &verified.report, &pre)?;
    let height = u32::try_from(
        storage::json(&folder.join("source.json"))?["height"]
            .as_u64()
            .ok_or("source height")?,
    )?;
    let aux = Auxiliary::load_reserved(
        bank,
        height,
        &storage::json(&folder.join("auxiliary-source.json"))?,
    )?;
    let r = pczt(&packet, "refund")?;
    let input = &r.transparent().inputs()[0];
    if manifest["selected_auxiliary_outpoint"]
        != json!({"txid":aux.txid.to_string(),"index":aux.index})
        || input.prevout_txid() != aux.txid.as_ref()
        || *input.prevout_index() != u32::try_from(aux.index)?
        || *input.value() != u64::from(aux.coin.value())
        || *input.script_pubkey() != aux.coin.script_pubkey().0.0
    {
        return Err("refund does not spend reserved own auxiliary".into());
    }
    immutable(
        &folder.join("native-recovery-intent.json"),
        &json!({"review_packet_digest":hash(&packet)?,"presignatures_digest":hash(&pre)?,
            "graph_digest":draft["graph_digest"],"funding_authorized":false}),
    )?;
    assemble(
        packet,
        pre,
        &aux.key,
        &folder.join("native-recovery-bundle.json"),
    )
}

/// Explicit no-chain diagnostic over the standard nonexistent input fixture.
/// Never accepted by prepare(), whose reservation provenance is mandatory.
pub fn synthetic(review: &Path, presigned: &Path, output: &Path) -> Result<Value> {
    let packet = storage::json(review)?;
    let r = pczt(&packet, "refund")?;
    if packet["graph"]["input_binding"]["synthetic"] != true
        || r.transparent().inputs().len() != 1
        || *r.transparent().inputs()[0].prevout_txid() != [0x13; 32]
        || *r.transparent().inputs()[0].prevout_index() != 0
        || *r.transparent().inputs()[0].value() != 20_000
    {
        return Err("only explicit nonexistent synthetic inputs allowed".into());
    }
    assemble(
        packet,
        storage::json(presigned)?,
        &secp256k1::SecretKey::from_secret_bytes([1; 32])?,
        output,
    )
}

fn receipt_digest(payload: &Value) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(RECEIPT_DOMAIN);
    h.update(serde_json::to_vec(payload)?);
    Ok(h.finalize().into())
}
fn payload(report: &Value, role: &str) -> Value {
    json!({"format":"latch-public-native-recovery-receipt-v1","role":role,
        "bundle_digest":report["bundle_digest"],"review_packet_digest":report["review_packet_digest"],
        "graph_digest":report["graph_digest"],"execution_plan_digest":report["execution_plan_digest"],
        "synthetic_inputs":report["synthetic_inputs"],"durably_saved":true,
        "native_exit_bundle_verified":true,"funding_authorized":false})
}
fn verify_receipt(receipt: &Value, report: &Value, owners: &Value, role: &str) -> Result<()> {
    if receipt.as_object().is_none_or(|o| o.len() != 2)
        || receipt["payload"] != payload(report, role)
    {
        return Err("native receipt role/bundle/plan mismatch".into());
    }
    evm_key::verify(
        &owners[role],
        &receipt["signature"],
        receipt_digest(&receipt["payload"])?,
    )
}

pub fn accept(dir: &Path, input: &Path) -> Result<Value> {
    let _lock = lock(&dir.join("setup.lock"))?;
    let bundle = storage::json(input)?;
    let packet = &bundle["review"];
    let identity = storage::json(&dir.join("identity.json"))?;
    let (role, id, peer) = match identity["role"].as_str() {
        Some("alice") => ("alice", 1, "bob"),
        Some("bob") => ("bob", 2, "alice"),
        _ => return Err("owner role".into()),
    };
    let owners = &packet["destinations"]["trade"]["offer"]["payload"]["owners"];
    if *packet != storage::json(&dir.join("reviewed-graph-packet.json"))?
        || packet["destinations"] != storage::json(&dir.join("authenticated-destinations.json"))?
        || packet["destinations"]["trade"] != storage::json(&dir.join("accepted-trade.json"))?
        || owners[role] != identity
        || owners[peer] != storage::json(&dir.join("trusted-peer.json"))?["identity"]
    {
        return Err("recovery differs from owner's reviewed graph/setup".into());
    }
    let report = verify(&bundle, &wallet::fvk(&dir.join("native"))?, id)?;
    // Bundle fsync precedes signing or returning a receipt. A crash in between
    // may resume only the same bundle; signed receipts are deterministic.
    immutable(&dir.join("public-native-recovery.json"), &bundle)?;
    let receipt_path = dir.join("public-native-recovery-receipt.json");
    if receipt_path.exists() {
        let receipt = storage::json(&receipt_path)?;
        verify_receipt(&receipt, &report, owners, role)?;
        return Ok(receipt);
    }
    let p = payload(&report, role);
    let signature = evm_key::sign_digest(&dir.join("ethereum"), receipt_digest(&p)?)?;
    let receipt = json!({"payload":p,"signature":signature});
    verify_receipt(&receipt, &report, owners, role)?;
    immutable(&receipt_path, &receipt)?;
    Ok(receipt)
}

pub fn receipts(bundle_path: &Path, receipts_path: &Path) -> Result<Value> {
    let bundle = storage::json(bundle_path)?;
    let receipts = storage::json(receipts_path)?;
    check_receipts(&bundle, &receipts)
}

pub(crate) fn check_receipts(bundle: &Value, receipts: &Value) -> Result<Value> {
    let mut report = verify(bundle, &alice(&bundle["review"])?, 1)?;
    if receipts.as_object().is_none_or(|o| o.len() != 2) {
        return Err("both recovery receipts required".into());
    }
    let owners = &bundle["review"]["destinations"]["trade"]["offer"]["payload"]["owners"];
    for role in ["alice", "bob"] {
        verify_receipt(&receipts[role], &report, owners, role)?;
    }
    report["both_owner_receipts_verified"] = json!(true);
    Ok(report)
}

/// Export no signing keys or source inputs. Both files are still PRIVATE: the
/// bundle contains viewing/proving data and a conditional spend presignature.
pub fn export(dir: &Path, output: &Path) -> Result<Value> {
    let saved = dir.join("public-native-recovery.json");
    let receipt = accept(dir, &saved)?;
    let bundle = storage::json(&saved)?;
    if !output.exists() {
        storage::create_dir(output)?;
    }
    immutable(&output.join("native-recovery.json"), &bundle)?;
    immutable(&output.join("owner-receipt.json"), &receipt)?;
    let report = inspect(output)?;
    immutable(&output.join("recovery-ready.json"), &report)?;
    Ok(report)
}

/// Fully self-contained offline check, including the owner's original signed
/// receipt. No own/peer/source setup directory, wallet key or RPC is read.
pub fn inspect(dir: &Path) -> Result<Value> {
    let bundle = storage::json(&dir.join("native-recovery.json"))?;
    let receipt = storage::json(&dir.join("owner-receipt.json"))?;
    let (role, id) = match receipt["payload"]["role"].as_str() {
        Some("alice") => ("alice", 1),
        Some("bob") => ("bob", 2),
        _ => return Err("portable recovery owner role".into()),
    };
    let packet = &bundle["review"];
    let own = FullViewingKey::from_bytes(&decode(
        &packet["destinations"]["setup"]["destinations"],
        &format!("{role}_fvk"),
    )?)
    .ok_or("portable receiving FVK")?;
    let mut report = verify(&bundle, &own, id)?;
    verify_receipt(
        &receipt,
        &report,
        &packet["destinations"]["trade"]["offer"]["payload"]["owners"],
        role,
    )?;
    report["role"] = json!(role);
    report["owner_receipt_verified"] = json!(true);
    report["spending_keys_exported"] = json!(false);
    report["private_exit_data"] = json!(true);
    report["scope"] = json!(
        "portable native exit data; live funding witness/re-proving and cross-chain release gates still required"
    );
    Ok(report)
}
