//! Real isolated-chain transaction graph. Local fixture setup, not a network protocol.
use crate::{
    PreSignature, Result, SignError, decode, err, random_key, storage,
    wallet::{self, Regtest},
};
use ff_old::{Field as OldField, PrimeField as OldPrimeField};
use group_old::GroupEncoding;
use incrementalmerkletree::Hashable;
use orchard::{
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey},
    tree::{MerkleHashOrchard, MerklePath},
};
use pczt::{
    Pczt,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, low_level_signer::Signer as LowSigner,
        prover::Prover, redactor::Redactor, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    },
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, convert::Infallible, path::Path};
use zcash_primitives::transaction::{
    Transaction,
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317::FeeRule,
    sighash::SignableInput,
    sighash_v6::v6_signature_hash,
    txid::TxIdDigester,
};
use zcash_protocol::{consensus::BranchId, memo::MemoBytes, value::Zatoshis};
use zcash_transparent::{address::TransparentAddress, bundle::OutPoint};

const PRINCIPAL: u64 = 1_010_000;
const PAYOUT: u64 = 1_000_000;

pub fn inspect(path: &Path) -> Result<Value> {
    let raw = hex::decode(storage::read(path, 4_000_000)?)?;
    let mut cursor = std::io::Cursor::new(&raw);
    let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
    if cursor.position() != raw.len() as u64 || tx.consensus_branch_id() != BranchId::Nu7 {
        return Err("unexpected transaction encoding/branch".into());
    }
    Ok(
        json!({"scope":"parsed local transaction; parsing alone is not verification", "txid":tx.txid().to_string(),
        "lock_time":tx.lock_time(),"expiry_height":u32::from(tx.expiry_height()),"file":path,
        "transparent_inputs":tx.transparent_bundle().map(|b|b.vin.len()).unwrap_or(0)}),
    )
}

fn builder(height: u32, anchor: orchard::Anchor) -> Builder<Regtest, ()> {
    Builder::new(
        Regtest,
        height.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    )
    .with_expiry_height(0u32.into())
}
fn message(pczt: &Pczt) -> Result<[u8; 32]> {
    let tx = pczt.clone().into_effects().map_err(err)?;
    Ok(
        v6_signature_hash(&tx, &SignableInput::Shielded, &tx.digest(TxIdDigester))
            .as_ref()
            .try_into()?,
    )
}
fn save_tx(path: &Path, tx: &Transaction) -> Result<()> {
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    storage::write(path, hex::encode(raw).as_bytes())
}
fn prove(pczt: Pczt) -> Result<Transaction> {
    let mut rng = rand::rng();
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let pczt = Prover::new(pczt)
        .create_ironwood_proof(&mut rng, &pk)
        .map_err(err)?
        .finish();
    // The refund's transparent scriptSig was finalized before funding. A
    // second finalization would request the already-cleared partial signatures.
    TransactionExtractor::new(pczt)
        .extract(&mut rng)
        .map_err(|e| err(e).into())
}
fn pre_json(pre: &PreSignature) -> Value {
    json!({"r_hat":hex::encode(pre.r_hat),"s_hat":hex::encode(pre.s_hat),"key":hex::encode(pre.key),
        "message":hex::encode(pre.message),"adaptor_point":hex::encode(pre.adaptor_point)})
}
fn parse_pre(v: &Value) -> Result<PreSignature> {
    Ok(PreSignature {
        r_hat: decode(v, "r_hat")?,
        s_hat: decode(v, "s_hat")?,
        key: decode(v, "key")?,
        message: decode(v, "message")?,
        adaptor_point: decode(v, "adaptor_point")?,
    })
}
fn presign(
    pczt: Pczt,
    pair: &mut crate::participants::Pair,
    policy: Value,
    target: [u8; 32],
) -> Result<(Pczt, PreSignature, usize)> {
    let before = message(&pczt)?;
    let pczt = Redactor::new(pczt)
        .redact_ironwood_with(|mut b| {
            b.clear_anchor();
            b.redact_actions(|mut a| a.clear_spend_witness());
        })
        .finish();
    if before != message(&pczt)? {
        return Err("deferred signature changed".into());
    }
    let (pre, index) = pair.sign(&pczt, policy, target)?;
    if pre.message != before {
        return Err("participant signed another transaction".into());
    }
    Ok((pczt, pre, index))
}
fn apply(pczt: Pczt, index: usize, sig: [u8; 64], digest: [u8; 32]) -> Result<Pczt> {
    if message(&pczt)? != digest {
        return Err("signature context mismatch".into());
    }
    Ok(LowSigner::new(pczt)
        .sign_ironwood_with::<SignError, _>(|_, bundle, _| {
            bundle.actions_mut()[index]
                .apply_signature(digest, orchard::primitives::redpallas::Signature::from(sig))
                .map_err(|e| SignError::Custom(err(e)))
        })
        .map_err(err)?
        .finish())
}

pub fn prepare(bank: &Path, scan: &Path, dir: &Path) -> Result<Value> {
    let snapshot = storage::json(scan)?;
    if snapshot["genesis"] != wallet::GENESIS {
        return Err("wrong source network".into());
    }
    let height = u32::try_from(snapshot["height"].as_u64().ok_or("height")?)?;
    let source = snapshot["notes"]
        .as_array()
        .ok_or("notes")?
        .iter()
        .find(|n| {
            n["value"].as_u64().is_some_and(|v| v > PRINCIPAL + 10_000)
                && (n["coinbase"] == false
                    || n["height"]
                        .as_u64()
                        .is_some_and(|h| h + 100 <= u64::from(height)))
        })
        .ok_or("no mature source note")?;
    let input = wallet::parse_note(source)?;
    let path = wallet::parse_path(source)?;
    let anchor = path.root(input.commitment().into());
    if hex::encode(anchor.to_bytes()) != snapshot["anchor"] {
        return Err("source path mismatch".into());
    }
    let alice_key = wallet::key(bank)?;
    let alice_fvk = FullViewingKey::from(&alice_key);
    // Verify source belongs to Alice before signing any spend.
    if input.recipient() != alice_fvk.address_at(0u32, Scope::External) {
        return Err("source receiver mismatch".into());
    }
    let auxkey = secp256k1::SecretKey::from_secret_bytes(
        storage::read(&bank.join("aux-key.bin"), 32)?
            .try_into()
            .map_err(|_| "aux key")?,
    )?;
    let auxpk = secp256k1::PublicKey::from_secret_key(&auxkey);
    let auxaddr = TransparentAddress::from_pubkey(&auxpk);
    let auxdata = storage::json(&bank.join("aux-source.json"))?;
    if auxdata["height"].as_u64().ok_or("aux height")? + 100 > u64::from(height) {
        return Err("immature aux coinbase".into());
    }
    let auxraw = hex::decode(auxdata["tx"].as_str().ok_or("aux tx")?)?;
    let auxtx = Transaction::read(&auxraw[..], BranchId::Nu7)?;
    let (auxindex, auxcoin) = auxtx
        .transparent_bundle()
        .ok_or("aux bundle")?
        .vout
        .iter()
        .enumerate()
        .find(|(_, c)| c.recipient_address() == Some(auxaddr))
        .ok_or("aux coin not Alice-owned")?;
    if u64::from(auxcoin.value()) < 10_000 {
        return Err("aux fee reserve".into());
    }
    storage::create_dir(dir)?;
    let mut pair = crate::participants::Pair::start(dir)?;
    let mut rng = rand::rng();
    let public = pair.public.clone();
    let mut fvkbytes = FullViewingKey::from(&random_key(&mut rng)).to_bytes();
    fvkbytes[..32].copy_from_slice(&public.verifying_key().serialize().map_err(err)?);
    let joint = FullViewingKey::from_bytes(&fvkbytes).ok_or("joint FVK")?;
    storage::write(&dir.join("joint-fvk.bin"), &fvkbytes)?;
    storage::write(
        &dir.join("frost-public.bin"),
        &public.serialize().map_err(err)?,
    )?;
    let receiver = pair.bob_fvk.clone();
    let refund_receiver = pair.alice_fvk.clone();
    let mut funding = builder(height + 1, anchor);
    funding
        .add_ironwood_spend::<Infallible>(alice_fvk.clone(), input, path)
        .map_err(err)?;
    funding
        .add_ironwood_output::<Infallible>(
            None,
            joint.address_at(0u32, Scope::External),
            Zatoshis::from_u64(PRINCIPAL)?,
            MemoBytes::empty(),
        )
        .map_err(err)?;
    funding
        .add_ironwood_output::<Infallible>(
            None,
            alice_fvk.address_at(0u32, Scope::External),
            Zatoshis::from_u64(input.value().inner() - PRINCIPAL - 10_000)?,
            MemoBytes::empty(),
        )
        .map_err(err)?;
    let funding = funding
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?;
    let output = funding
        .ironwood_meta
        .output_action_index(0)
        .ok_or("funding output")?;
    let pczt =
        IoFinalizer::new(Creator::build_from_parts(funding.pczt_parts).ok_or("funding parts")?)
            .finalize_io(&mut rng)
            .map_err(err)?;
    let real = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    let mut signer = Signer::new(pczt).map_err(err)?;
    for i in real {
        signer
            .sign_ironwood(&mut rng, i, &SpendAuthorizingKey::from(&alice_key))
            .map_err(err)?;
    }
    let funding = prove(signer.finish())?;
    let (pending, _, _) = funding
        .ironwood_bundle()
        .ok_or("funding bundle")?
        .decrypt_output_with_key(output, &joint.to_ivk(Scope::External))
        .ok_or("joint output")?;
    if pending.value().inner() != PRINCIPAL || funding.transparent_bundle().is_some() {
        return Err("funding privacy/amount".into());
    }
    let pending_json = wallet::note_json(&pending);
    storage::write_json(&dir.join("pending-note.json"), &pending_json)?;
    let dummy_path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
    );
    let dummy_anchor = dummy_path.root(pending.commitment().into());
    let mut claim = builder(height + 1, dummy_anchor);
    claim
        .add_ironwood_spend::<Infallible>(joint.clone(), pending, dummy_path.clone())
        .map_err(err)?;
    claim
        .add_ironwood_output::<Infallible>(
            None,
            receiver.address_at(0u32, Scope::External),
            Zatoshis::from_u64(PAYOUT)?,
            MemoBytes::empty(),
        )
        .map_err(err)?;
    let claim = claim
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?;
    let claim = IoFinalizer::new(Creator::build_from_parts(claim.pczt_parts).ok_or("claim parts")?)
        .finalize_io(&mut rng)
        .map_err(err)?;
    let refund_height = height + 20;
    let mut funding_raw = Vec::new();
    funding.write(&mut funding_raw)?;
    let policy = json!({"mode":"claim", "joint_fvk":hex::encode(joint.to_bytes()),
        "alice_fvk":hex::encode(refund_receiver.to_bytes()),"bob_fvk":hex::encode(receiver.to_bytes()),
        "pending":pending_json,"refund_height":refund_height,"funding":hex::encode(funding_raw),
        "aux":{"txid_le":hex::encode(auxtx.txid().as_ref()),"index":auxindex,"value":u64::from(auxcoin.value()),"script":hex::encode(&auxcoin.script_pubkey().0.0)}});
    let target = pair.point;
    storage::write_json(&dir.join("claim-policy.json"), &policy)?;
    let (claim, pre, claim_index) = presign(claim, &mut pair, policy.clone(), target)?;
    // The native principal stays shielded; only the dedicated auxiliary coin
    // appears in the refund's transparent bundle.
    let mut refund = builder(height + 1, dummy_anchor);
    refund
        .add_ironwood_spend::<Infallible>(joint.clone(), pending, dummy_path)
        .map_err(err)?;
    refund
        .add_ironwood_output::<Infallible>(
            None,
            refund_receiver.address_at(0u32, Scope::External),
            Zatoshis::from_u64(PAYOUT)?,
            MemoBytes::empty(),
        )
        .map_err(err)?;
    refund
        .add_transparent_p2pkh_input(
            auxpk,
            OutPoint::new(*auxtx.txid().as_ref(), auxindex as u32),
            auxcoin.clone(),
        )
        .map_err(err)?;
    refund
        .add_transparent_output(
            &auxaddr,
            Zatoshis::from_u64(u64::from(auxcoin.value()) - 5_000)?,
        )
        .map_err(err)?;
    let mut refund = refund
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?
        .pczt_parts;
    refund.lock_time = refund_height;
    let bundle = refund.transparent.as_mut().ok_or("refund transparent")?;
    let old = &bundle.inputs()[0];
    let new = zcash_transparent::pczt::Input::parse(
        *old.prevout_txid().as_ref(),
        *old.prevout_index(),
        Some(u32::MAX - 1),
        None,
        Some(refund_height),
        None,
        u64::from(*old.value()),
        auxcoin.script_pubkey().0.0.clone(),
        None,
        BTreeMap::new(),
        1,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .map_err(err)?;
    bundle.inputs_mut()[0] = new;
    let refund = IoFinalizer::new(Creator::build_from_parts(refund).ok_or("refund parts")?)
        .finalize_io(&mut rng)
        .map_err(err)?;
    let one = pasta_old::pallas::Scalar::ONE;
    let mut refund_policy = policy;
    refund_policy["mode"] = json!("refund");
    let (refund, refund_pre, refund_index) = presign(
        refund,
        &mut pair,
        refund_policy,
        shielded_swap_crypto::generator().to_bytes(),
    )?;
    let refund = apply(
        refund,
        refund_index,
        refund_pre.adapt(&one.to_repr())?,
        refund_pre.message,
    )?;
    let mut signer = Signer::new(refund).map_err(err)?;
    signer.sign_transparent(0, &auxkey).map_err(err)?;
    let refund = SpendFinalizer::new(signer.finish())
        .finalize_spends()
        .map_err(err)?;
    if refund.ironwood().anchor().is_some() {
        return Err("refund not deferred".into());
    }
    let effects = refund.clone().into_effects().map_err(err)?;
    if effects.lock_time() != refund_height
        || effects.transparent_bundle().ok_or("refund input")?.vin[0].sequence() == u32::MAX
    {
        return Err("refund lock ineffective".into());
    }
    // Publish files only after both independently checkable exit paths exist.
    storage::write(
        &dir.join("bob/claim.pczt"),
        &claim.serialize().map_err(err)?,
    )?;
    storage::write_json(&dir.join("bob/presignature.json"), &pre_json(&pre))?;
    storage::write(
        &dir.join("alice/refund.pczt"),
        &refund.serialize().map_err(err)?,
    )?;
    let terms = json!({"scope":"isolated regtest; independent local signer processes", "independent_signer_processes":true, "funding_txid":funding.txid().to_string(),
        "aux_outpoint":{"txid":auxtx.txid().to_string(),"index":auxindex,"value_zatoshi":u64::from(auxcoin.value())},
        "principal_zatoshi":PRINCIPAL,"payout_zatoshi":PAYOUT,"refund_height":refund_height,
        "point_x":pair.point_x,"point_y":pair.point_y,"claim_index":claim_index,
        "refund_index":refund_index,"pending_cmx":pending_json["cmx"],"source_tip":snapshot["tip"],
        "preauthorized_before_funding":true,"refund_transparent_auxiliary":true,"funding_and_claim_fully_shielded":true});
    storage::write_json(&dir.join("terms.json"), &terms)?;
    // This is the first point where the funding transaction becomes available
    // to the broadcast driver. No RPC exists in this Rust process.
    save_tx(&dir.join("funding.hex"), &funding)?;
    Ok(terms)
}

pub fn finish(dir: &Path, scan: &Path, mode: &str, witness: Option<&str>) -> Result<Value> {
    let terms = storage::json(&dir.join("terms.json"))?;
    let snapshot = storage::json(scan)?;
    if snapshot["genesis"] != wallet::GENESIS {
        return Err("wrong observed chain".into());
    }
    let source = snapshot["notes"]
        .as_array()
        .ok_or("notes")?
        .iter()
        .find(|n| n["cmx"] == terms["pending_cmx"])
        .ok_or("funding note absent/spent")?;
    if source["txid"] != terms["funding_txid"]
        || source["coinbase"] != false
        || source["value"] != PRINCIPAL
    {
        return Err("wrong funding note".into());
    }
    if snapshot["height"].as_u64().ok_or("height")?
        < source["height"].as_u64().ok_or("mined height")? + 1
    {
        return Err("need two funding confirmations".into());
    }
    let note = wallet::parse_note(source)?;
    let path = wallet::parse_path(source)?;
    let anchor = path.root(note.commitment().into());
    if snapshot["anchor"] != hex::encode(anchor.to_bytes()) {
        return Err("funding witness mismatch".into());
    }
    let (pczt, expected) = match mode {
        "claim" => {
            let pre = parse_pre(&storage::json(&dir.join("bob/presignature.json"))?)?;
            let t: [u8; 32] = hex::decode(witness.ok_or("claim witness required")?)?
                .try_into()
                .map_err(|_| "witness size")?;
            let p =
                Pczt::parse(&storage::read(&dir.join("bob/claim.pczt"), 100_000)?).map_err(err)?;
            (
                apply(
                    p,
                    terms["claim_index"].as_u64().ok_or("claim index")? as usize,
                    pre.adapt(&t)?,
                    pre.message,
                )?,
                pre.message,
            )
        }
        "refund" => {
            let p = Pczt::parse(&storage::read(&dir.join("alice/refund.pczt"), 100_000)?)
                .map_err(err)?;
            let digest = message(&p)?;
            (p, digest)
        }
        _ => return Err("mode must be claim or refund".into()),
    };
    if pczt.ironwood().anchor().is_some() {
        return Err("expected deferred transaction".into());
    }
    let witnesses = (0..pczt.ironwood().actions().len())
        .map(|i| (i, path.clone()))
        .collect::<Vec<_>>();
    let pczt = Updater::new(pczt)
        .set_ironwood_anchor(anchor)
        .map_err(err)?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(err)?
        .finish();
    if message(&pczt)? != expected {
        return Err("reanchoring changed authorization".into());
    }
    let tx = prove(pczt)?;
    save_tx(&dir.join(format!("{mode}-{}.hex", snapshot["height"])), &tx)?;
    Ok(
        json!({"scope":"actual regtest-funded native transaction, not yet broadcast", "mode":mode,
        "txid":tx.txid().to_string(),"lock_time":tx.lock_time(),"expiry_height":u32::from(tx.expiry_height()),
        "transparent_inputs":tx.transparent_bundle().map(|b|b.vin.len()).unwrap_or(0),
        "proof_and_signatures_verified":true,"prepared_before_funding":true,
        "file":dir.join(format!("{mode}-{}.hex",snapshot["height"]))}),
    )
}
