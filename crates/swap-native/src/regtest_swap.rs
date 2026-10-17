//! Real isolated-chain transaction graph. Local fixture setup, not a network protocol.
use crate::{
    PreSignature, Result, SignError, decode, err, random_key, storage,
    wallet::{self, Regtest},
};
use ff_old::{Field as OldField, PrimeField as OldPrimeField};
use group_old::GroupEncoding;
use incrementalmerkletree::Hashable;
use orchard::{
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendAuthorizingKey},
    tree::{MerkleHashOrchard, MerklePath},
};
use pczt::{
    Pczt,
    roles::{
        low_level_signer::Signer as LowSigner, prover::Prover, redactor::Redactor, signer::Signer,
        spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor, updater::Updater,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use zcash_primitives::transaction::{
    Transaction, sighash::SignableInput, sighash_v6::v6_signature_hash, txid::TxIdDigester,
};
use zcash_protocol::consensus::BranchId;

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
        "authorization_bytes_sha256":hex::encode(Sha256::digest(&raw)),
        "ironwood_anchor":tx.ironwood_bundle().map(|b|hex::encode(b.anchor().to_bytes())),
        "transparent_inputs":tx.transparent_bundle().map(|b|b.vin.len()).unwrap_or(0)}),
    )
}

/// The v6 txid of a PCZT's effects. It excludes anchors, proofs and
/// signatures, so it is fixed before any of them exist.
pub(crate) fn effects_txid(pczt: &Pczt) -> Result<zcash_protocol::TxId> {
    let tx = pczt.clone().into_effects().map_err(err)?;
    Ok(zcash_primitives::transaction::txid::to_txid(
        tx.version(),
        tx.consensus_branch_id(),
        &tx.digest(TxIdDigester),
    ))
}

pub(crate) fn message(pczt: &Pczt) -> Result<[u8; 32]> {
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
    storage::atomic_write(path, hex::encode(raw).as_bytes())
}

/// Show the exact funding effects/note without giving a peer a broadcastable
/// transaction before both exit bundles have been acknowledged. V6 txid does
/// not commit to these authorizing signatures; the funding outpoint stays fixed.
fn funding_preview(funding: &Transaction) -> Result<Transaction> {
    if funding.transparent_bundle().is_some()
        || funding.sapling_bundle().is_some()
        || funding.orchard_bundle().is_some()
    {
        return Err("funding preview requires Ironwood only".into());
    }
    let preview = funding
        .clone()
        .into_data()
        .map_bundles::<zcash_primitives::transaction::Authorized>(
            |t| t,
            |s| s,
            |bundle| {
                bundle.map(|b| {
                    b.map_authorization(
                        &mut (),
                        |_, _, _| orchard::primitives::redpallas::Signature::from([0u8; 64]),
                        |_, a| {
                            orchard::bundle::Authorized::from_parts(
                                a.proof().clone(),
                                orchard::primitives::redpallas::Signature::from([0u8; 64]),
                            )
                        },
                    )
                })
            },
        )
        .freeze()?;
    if preview.txid() != funding.txid() {
        return Err("funding preview changed txid".into());
    }
    Ok(preview)
}

/// Construct effect-identical preview bytes without ever generating a real
/// source spend signature. Proof verification is separate from authorization.
pub(crate) fn unsigned_preview(pczt: &Pczt) -> Result<Transaction> {
    let proof = orchard::Proof::new(pczt.ironwood().zkproof().clone().ok_or("funding proof")?);
    let effects = pczt.clone().into_effects().map_err(err)?;
    if effects.transparent_bundle().is_some()
        || effects.sapling_bundle().is_some()
        || effects.orchard_bundle().is_some()
    {
        return Err("source preview must be Ironwood only".into());
    }
    Ok(effects
        .map_bundles::<zcash_primitives::transaction::Authorized>(
            |_| None,
            |_| None,
            |bundle| {
                bundle.map(|b| {
                    b.map_authorization(
                        &mut (),
                        |_, _, _| orchard::primitives::redpallas::Signature::from([0u8; 64]),
                        |_, _| {
                            orchard::bundle::Authorized::from_parts(
                                proof.clone(),
                                orchard::primitives::redpallas::Signature::from([0u8; 64]),
                            )
                        },
                    )
                })
            },
        )
        .freeze()?)
}
pub(crate) fn prove_pczt(pczt: Pczt) -> Result<Pczt> {
    let mut rng = rand::rng();
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    Ok(Prover::new(pczt)
        .create_ironwood_proof(&mut rng, &pk)
        .map_err(err)?
        .finish())
}
fn prove(pczt: Pczt) -> Result<Transaction> {
    let pczt = prove_pczt(pczt)?;
    extract_checked(pczt)
}
pub(crate) fn extract_checked(pczt: Pczt) -> Result<Transaction> {
    let mut rng = rand::rng();
    // The refund's transparent scriptSig was finalized before funding. A
    // second finalization would request the already-cleared partial signatures.
    TransactionExtractor::new(pczt)
        .extract(&mut rng)
        .map_err(|e| err(e).into())
}

pub(crate) fn anchor_for_check(
    pczt: Pczt,
    path: MerklePath,
    anchor: orchard::Anchor,
) -> Result<Pczt> {
    let digest = message(&pczt)?;
    let witnesses = (0..pczt.ironwood().actions().len())
        .map(|i| (i, path.clone()))
        .collect::<Vec<_>>();
    let anchored = Updater::new(pczt)
        .set_ironwood_anchor(anchor)
        .map_err(err)?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(err)?
        .finish();
    if message(&anchored)? != digest {
        return Err("reanchoring changed authorization".into());
    }
    Ok(anchored)
}

/// Complete only the deferred proof. Existing authorizations must remain valid;
/// no signer, source wallet or peer participates in this operation.
pub(crate) fn reprove_exit(pczt: Pczt, source: &Value) -> Result<Transaction> {
    if pczt.ironwood().anchor().is_some() || pczt.ironwood().zkproof().is_some() {
        return Err("expected deferred exit".into());
    }
    let note = wallet::parse_note(source)?;
    let path = wallet::parse_path(source)?;
    let anchor = path.root(note.commitment().into());
    prove(anchor_for_check(pczt, path, anchor)?)
}

/// Check the conditional claim's circuit without asking Alice to reveal t.
/// Placeholder signatures below only satisfy the proof-verifier's data type;
/// they are NOT valid authorizations, never extracted and never serialized.
/// The adaptor pre-signature is separately verified before reaching this check.
pub(crate) fn verify_claim_proof(proven: Pczt) -> Result<()> {
    let proof = orchard::Proof::new(
        proven
            .ironwood()
            .zkproof()
            .clone()
            .ok_or("missing preflight proof")?,
    );
    let effects = proven.into_effects().map_err(err)?;
    let bundle = effects
        .ironwood_bundle()
        .ok_or("preflight Ironwood")?
        .clone();
    let for_proof_only = bundle.map_authorization(
        &mut (),
        |_, _, _| orchard::primitives::redpallas::Signature::from([0u8; 64]),
        |_, _| {
            orchard::bundle::Authorized::from_parts(
                proof,
                orchard::primitives::redpallas::Signature::from([0u8; 64]),
            )
        },
    );
    for_proof_only
        .verify_proof(&VerifyingKey::build(OrchardCircuitVersion::PostNu6_3))
        .map_err(|e| err(e).into())
}
pub(crate) fn pre_json(pre: &PreSignature) -> Value {
    json!({"r_hat":hex::encode(pre.r_hat),"s_hat":hex::encode(pre.s_hat),"key":hex::encode(pre.key),
        "message":hex::encode(pre.message),"adaptor_point":hex::encode(pre.adaptor_point)})
}
pub(crate) fn parse_pre(v: &Value) -> Result<PreSignature> {
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
pub(crate) fn apply(pczt: Pczt, index: usize, sig: [u8; 64], digest: [u8; 32]) -> Result<Pczt> {
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

struct AuxiliaryTransaction {
    coin: crate::auxiliary::Auxiliary,
    note: Value,
    /// Alice's private copy: signed A, its circuit check and its input note.
    packet: Value,
}

/// Build and sign Alice's auxiliary transaction A from her funding change. Like
/// the exits it stays deferred: no anchor or proof until a refund needs it.
fn auxiliary_transaction(
    funding: &Transaction,
    alice_key: &orchard::keys::SpendingKey,
    alice_fvk: &FullViewingKey,
    change_value: u64,
    dummy_path: &MerklePath,
    height: u32,
) -> Result<AuxiliaryTransaction> {
    let bundle = funding.ironwood_bundle().ok_or("funding bundle")?;
    let change = (0..bundle.actions().len())
        .filter_map(|i| bundle.decrypt_output_with_key(i, &alice_fvk.to_ivk(Scope::External)))
        .map(|(note, _, _)| note)
        .filter(|note| note.value().inner() == change_value)
        .collect::<Vec<_>>();
    let [change] = change[..] else {
        return Err("funding change output".into());
    };
    let key = crate::auxiliary::fresh_key();
    let address = zcash_transparent::address::TransparentAddress::from_pubkey(
        &secp256k1::PublicKey::from_secret_key(&key),
    );
    let built = crate::transaction_graph::auxiliary_funding(
        Regtest,
        height + 1,
        crate::transaction_graph::Source {
            fvk: alice_fvk.clone(),
            note: change,
            path: dummy_path.clone(),
        },
        &address,
    )?;
    let before = message(&built)?;
    let deferred = Redactor::new(built)
        .redact_ironwood_with(|mut b| {
            b.clear_anchor();
            b.redact_actions(|mut a| a.clear_spend_witness());
        })
        .finish();
    let real = deferred
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    if message(&deferred)? != before || real.len() != 1 {
        return Err("auxiliary deferral changed effects".into());
    }
    let mut signer = Signer::new(deferred).map_err(err)?;
    signer
        .sign_ironwood(rand::rng(), real[0], &SpendAuthorizingKey::from(alice_key))
        .map_err(err)?;
    let signed = signer.finish();
    let anchor = dummy_path.root(change.commitment().into());
    let checked = prove_pczt(anchor_for_check(
        signed.clone(),
        dummy_path.clone(),
        anchor,
    )?)?;
    let extracted = extract_checked(checked.clone())?;
    let coin = crate::auxiliary::Auxiliary::deferred(
        key,
        extracted.txid(),
        extracted.transparent_bundle(),
    )?;
    let note = wallet::note_json(&change);
    let packet = json!({"version":1,"auxiliary":hex::encode(signed.serialize().map_err(err)?),
        "auxiliary_check":hex::encode(checked.serialize().map_err(err)?),"note":note});
    Ok(AuxiliaryTransaction { coin, note, packet })
}

pub fn prepare(bank: &Path, scan: &Path, dir: &Path, pins: Option<&Path>) -> Result<Value> {
    prepare_inner(bank, scan, dir, pins, None)
}

/// Native-only isolated timestamp gate. Public chain funding remains disabled.
pub fn prepare_timestamp(bank: &Path, scan: &Path, dir: &Path, timestamp: u32) -> Result<Value> {
    prepare_inner(
        bank,
        scan,
        dir,
        None,
        Some(crate::refund_lock::RefundLock::timestamp(timestamp)?),
    )
}

fn prepare_inner(
    bank: &Path,
    scan: &Path,
    dir: &Path,
    pins: Option<&Path>,
    selected_lock: Option<crate::refund_lock::RefundLock>,
) -> Result<Value> {
    let pins = pins.map(storage::json).transpose()?;
    let trade = crate::trade::configured()?;
    if let Some(trade) = &trade
        && pins.as_ref() != Some(&trade["offer"]["payload"]["owners"])
    {
        return Err("OTC owners differ from source pins".into());
    }
    let mut selected = json!({});
    if let Some(trade) = &trade {
        selected["trade"] = trade.clone();
    }
    let amounts = crate::trade::amounts(&selected)?;
    let source_guard = if pins.is_some() {
        let guard = crate::source_guard::Guard::open(dir.parent().ok_or("setup parent")?)?;
        guard.active()?;
        Some(guard)
    } else {
        None
    };
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
            n["value"].as_u64().is_some_and(|v| {
                v > amounts.principal
                    + 10_000
                    + crate::auxiliary::COMPACT_VALUE
                    + crate::transaction_graph::AUXILIARY_FEE
            }) && !n["cmx"]
                .as_str()
                .is_some_and(|cmx| bank.join("reserved-notes").join(cmx).exists())
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
    if let Some(anchor_height) = snapshot.get("anchor_height") {
        let anchor_height = anchor_height.as_u64().ok_or("source anchor height")?;
        if anchor_height < 2
            || anchor_height >= u64::from(height)
            || source["height"].as_u64().is_none_or(|h| h > anchor_height)
            || hex::decode(snapshot["anchor_tip"].as_str().ok_or("source anchor tip")?)?.len() != 32
        {
            return Err("invalid historical source witness".into());
        }
    }
    let alice_key = wallet::key(bank)?;
    let alice_fvk = FullViewingKey::from(&alice_key);
    // Verify source belongs to Alice before signing any spend.
    if input.recipient() != alice_fvk.address_at(0u32, Scope::External) {
        return Err("source receiver mismatch".into());
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
    let receiver = pair.bob_receiver;
    let refund_receiver = pair.alice_receiver;
    let change_value = input.value().inner() - amounts.principal - 10_000;
    let (pczt, output) = crate::transaction_graph::funding(
        Regtest,
        height + 1,
        crate::transaction_graph::Source {
            fvk: alice_fvk.clone(),
            note: input,
            path,
        },
        &joint,
        amounts.principal,
    )?;
    // No real source signature is generated until the release gate succeeds.
    // Placeholder authorization fields are only for preview serialization.
    let pczt = prove_pczt(pczt)?;
    verify_claim_proof(pczt.clone())?;
    let unsigned_funding = pczt.clone().serialize().map_err(err)?;
    let funding = unsigned_preview(&pczt)?;
    let (pending, _, _) = funding
        .ironwood_bundle()
        .ok_or("funding bundle")?
        .decrypt_output_with_key(output, &joint.to_ivk(Scope::External))
        .ok_or("joint output")?;
    if pending.value().inner() != amounts.principal || funding.transparent_bundle().is_some() {
        return Err("funding privacy/amount".into());
    }
    let pending_json = wallet::note_json(&pending);
    storage::write_json(&dir.join("pending-note.json"), &pending_json)?;
    let dummy_path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
    );
    let dummy_anchor = dummy_path.root(pending.commitment().into());
    let auxiliary = auxiliary_transaction(
        &funding,
        &alice_key,
        &alice_fvk,
        change_value,
        &dummy_path,
        height,
    )?;
    let aux = &auxiliary.coin;
    let auxindex = aux.index;
    let auxcoin = &aux.coin;
    // The source wallet must keep this change unspent until the swap settles:
    // the refund's transparent input exists only once A spends it.
    std::fs::create_dir_all(bank.join("reserved-notes"))?;
    storage::write_json(
        &bank
            .join("reserved-notes")
            .join(auxiliary.note["cmx"].as_str().ok_or("cmx")?),
        &json!({"purpose":"refund auxiliary input","swap":dir}),
    )?;
    let claim = crate::transaction_graph::exit(
        Regtest,
        height + 1,
        crate::transaction_graph::Exit {
            joint: joint.clone(),
            note: pending,
            path: dummy_path.clone(),
            receiver,
            payout: amounts.payout,
        },
        None,
    )?;
    let refund_lock = selected_lock.unwrap_or(crate::refund_lock::RefundLock::Height(
        height.checked_add(20).ok_or("refund height overflow")?,
    ));
    let mut funding_raw = Vec::new();
    funding_preview(&funding)?.write(&mut funding_raw)?;
    let mut policy = json!({"mode":"claim", "joint_fvk":hex::encode(joint.to_bytes()),
        "alice_receiver":hex::encode(refund_receiver.to_raw_address_bytes()),"bob_receiver":hex::encode(receiver.to_raw_address_bytes()),
        "pending":pending_json,"funding":hex::encode(funding_raw),
        "aux":{"txid_le":hex::encode(aux.txid.as_ref()),"index":auxindex,"value":u64::from(auxcoin.value()),"script":hex::encode(&auxcoin.script_pubkey().0.0)}});
    refund_lock.attach(&mut policy);
    if let Some(trade) = &trade {
        policy["trade"] = trade.clone();
    }
    let target = pair.point;
    storage::write_json(&dir.join("claim-policy.json"), &policy)?;
    let (claim, pre, claim_index) = presign(claim, &mut pair, policy.clone(), target)?;
    // The native principal stays shielded; only the dedicated auxiliary coin
    // appears in the refund's transparent bundle.
    let refund = crate::transaction_graph::exit(
        Regtest,
        height + 1,
        crate::transaction_graph::Exit {
            joint: joint.clone(),
            note: pending,
            path: dummy_path.clone(),
            receiver: refund_receiver,
            payout: amounts.payout,
        },
        Some((aux, refund_lock)),
    )?;
    let one = pasta_old::pallas::Scalar::ONE;
    let mut refund_policy = policy.clone();
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
    signer.sign_transparent(0, &aux.key).map_err(err)?;
    let refund = SpendFinalizer::new(signer.finish())
        .finalize_spends()
        .map_err(err)?;
    if refund.ironwood().anchor().is_some() {
        return Err("refund not deferred".into());
    }
    let effects = refund.clone().into_effects().map_err(err)?;
    if effects.lock_time() != refund_lock.value()
        || effects.transparent_bundle().ok_or("refund input")?.vin[0].sequence() == u32::MAX
    {
        return Err("refund lock ineffective".into());
    }
    // Exercise both circuits before exposing funding.hex to the broadcaster.
    // The synthetic tree contains the exact pending note. It is not a chain
    // anchor. The checked PCZTs remain private bundle data, never broadcasts.
    // After mining, both paths are re-proved against the observed chain anchor.
    let claim_check = prove_pczt(anchor_for_check(
        claim.clone(),
        dummy_path.clone(),
        dummy_anchor,
    )?)?;
    verify_claim_proof(claim_check.clone())?;
    let refund_check = prove_pczt(anchor_for_check(refund.clone(), dummy_path, dummy_anchor)?)?;
    let _checked_refund = extract_checked(refund_check.clone())?;
    crate::recovery_bundle::verify_auxiliary_signature(&refund)?;
    let mut terms = json!({"scope":"isolated regtest; independent local signer processes", "independent_signer_processes":true, "funding_txid":funding.txid().to_string(),
        "aux_outpoint":{"txid":aux.txid.to_string(),"index":auxindex,"value_zatoshi":u64::from(auxcoin.value())},
        "principal_zatoshi":amounts.principal,"payout_zatoshi":amounts.payout,
        "point_x":pair.point_x,"point_y":pair.point_y,"claim_index":claim_index,
        "refund_index":refund_index,"pending_cmx":pending_json["cmx"],"source_tip":snapshot["tip"],
        "preauthorized_before_funding":true,"exit_circuits_verified_before_funding":true,
        "refund_proof_and_shielded_signatures_verified_before_funding":true,
        "refund_auxiliary_signature_verified_before_funding":true,
        "participant_bundles_acknowledged_before_funding":true,
        "funding_authorization_withheld_from_peer_until_acknowledgment":true,
        "refund_transparent_auxiliary":true,"refund_auxiliary_deferred":true,
        "funding_and_claim_fully_shielded":true});
    refund_lock.attach(&mut terms);
    if let Some(trade) = &trade {
        terms["trade"] = trade.clone();
    }
    if let Some(pins) = &pins {
        terms["source_guard"] = source_guard
            .as_ref()
            .ok_or("source guard missing")?
            .identity
            .clone();
        terms["owner_pins"] = pins.clone();
        terms["cross_chain_consent_required"] = json!(true);
    }
    if snapshot.get("anchor_height").is_some() {
        terms["source_height"] = json!(height);
        terms["funding_anchor_height"] = snapshot["anchor_height"].clone();
        terms["funding_anchor_tip"] = snapshot["anchor_tip"].clone();
        terms["funding_anchor"] = snapshot["anchor"].clone();
    }
    // Both participants verify and fsync their own complete recovery bundle.
    // The coordinator's copy alone is insufficient authorization to fund.
    let bundle = json!({"version":1,"native_genesis":wallet::GENESIS,"native_branch":"77190ad9",
        "policy":policy,"terms":terms,"claim":hex::encode(claim.clone().serialize().map_err(err)?),
        "refund":hex::encode(refund.clone().serialize().map_err(err)?),"presignature":pre_json(&pre),
        "claim_check":hex::encode(claim_check.serialize().map_err(err)?),
        "refund_check":hex::encode(refund_check.serialize().map_err(err)?)});
    let mut receipts = pair.deliver_bundle(bundle)?;
    // A goes to Alice alone. Bob needs only its txid, which R already commits
    // to; holding A would let him put Alice's change on chain.
    receipts["alice_auxiliary"] = pair.deliver_auxiliary(auxiliary.packet.clone())?;
    storage::write(
        &dir.join("aux-key.bin"),
        &auxiliary.coin.key.to_secret_bytes(),
    )?;
    storage::write_json(&dir.join("participant-receipts.json"), &receipts)?;
    // Independent operators receive and retain the complete bundle through
    // their authenticated service. Their private directories are not mounted
    // here. Keep convenience copies only for the existing local fixture.
    if std::env::var_os("LATCH_REMOTE_OWNERS").is_some() {
        if pins.is_none() || std::env::var_os("LATCH_SIGNER_COMMANDS").is_none() {
            return Err("remote owners require signed consent and configured transports".into());
        }
    } else {
        storage::write(
            &dir.join("bob/claim.pczt"),
            &claim.serialize().map_err(err)?,
        )?;
        storage::write_json(&dir.join("bob/presignature.json"), &pre_json(&pre))?;
        storage::write(
            &dir.join("alice/refund.pczt"),
            &refund.serialize().map_err(err)?,
        )?;
        storage::write(
            &dir.join("alice/auxiliary.pczt"),
            &crate::recovery_bundle::encoded(&auxiliary.packet, "auxiliary")?,
        )?;
        storage::write_json(
            &dir.join("watched-notes.json"),
            &crate::recovery_bundle::watched_notes(&auxiliary.packet)?,
        )?;
    }
    storage::write_json(&dir.join("terms.json"), &terms)?;
    if let Some(pins) = pins {
        storage::write(&dir.join("unsigned-funding.pczt"), &unsigned_funding)?;
        crate::funding_consent::stage(dir, pins, &unsigned_funding, &terms)?;
    } else {
        // Legacy fixture: requires both native receipts but no ETH consent.
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
        save_tx(&dir.join("funding.hex"), &extract_checked(signer.finish())?)?;
    }
    Ok(terms)
}

pub fn authorize_funding(bank: &Path, dir: &Path, packet: &Path) -> Result<Value> {
    let guard = crate::source_guard::for_terms(dir, &storage::json(&dir.join("terms.json"))?)?;
    let unsigned = storage::read(&dir.join("unsigned-funding.pczt"), 100_000)?;
    let consent = crate::funding_consent::verify(dir, packet, &unsigned)?;
    if let Some(guard) = &guard {
        guard.release(&consent)?;
    }
    // Revalidate even on replay; an existing file never bypasses consent checks.
    if dir.join("funding.hex").exists() {
        if storage::json(&dir.join("funding-consent.json"))? != consent {
            return Err("funding consent changed".into());
        }
        let existing = inspect(&dir.join("funding.hex"))?;
        if existing["txid"] != consent["funding_txid"] {
            return Err("persisted funding identity changed".into());
        }
        return Ok(existing);
    }
    let pczt = Pczt::parse(&unsigned).map_err(err)?;
    let real = pczt
        .ironwood()
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    if real.len() != 1 {
        return Err("expected one unsigned source spend".into());
    }
    let mut signer = Signer::new(pczt).map_err(err)?;
    signer
        .sign_ironwood(
            rand::rng(),
            real[0],
            &SpendAuthorizingKey::from(&wallet::key(bank)?),
        )
        .map_err(err)?;
    let funding = extract_checked(signer.finish())?;
    if funding.txid().to_string() != consent["funding_txid"] {
        return Err("authorized funding identity changed".into());
    }
    if dir.join("funding-consent.json").exists() {
        if storage::json(&dir.join("funding-consent.json"))? != consent {
            return Err("interrupted funding consent changed".into());
        }
    } else {
        storage::atomic_json(&dir.join("funding-consent.json"), &consent)?;
    }
    let mut raw = Vec::new();
    funding.write(&mut raw)?;
    storage::atomic_write(&dir.join("funding.hex"), hex::encode(raw).as_bytes())?;
    inspect(&dir.join("funding.hex"))
}

/// Put Alice's deferred auxiliary transaction on chain: re-prove A against the
/// current tree. Its effects, signature and txid were fixed at setup.
fn finish_auxiliary(dir: &Path, scan: &Path) -> Result<Value> {
    let terms = storage::json(&dir.join("terms.json"))?;
    let snapshot = storage::json(scan)?;
    if snapshot["genesis"] != wallet::GENESIS {
        return Err("wrong observed chain".into());
    }
    let watched = storage::json(&dir.join("watched-notes.json"))?;
    let watched = watched
        .as_array()
        .and_then(|w| w.first())
        .ok_or("watched note")?;
    let source = snapshot["notes"]
        .as_array()
        .ok_or("notes")?
        .iter()
        .find(|n| n["cmx"] == watched["cmx"] && n["value"] == watched["value"])
        .ok_or("refund auxiliary input absent or spent")?;
    let pczt =
        Pczt::parse(&storage::read(&dir.join("alice/auxiliary.pczt"), 100_000)?).map_err(err)?;
    let tx = reprove_exit(pczt, source)?;
    if tx.txid().to_string() != terms["aux_outpoint"]["txid"] {
        return Err("re-proving changed the auxiliary transaction".into());
    }
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    let output = dir.join(format!(
        "auxiliary-{}-{}.hex",
        snapshot["height"],
        hex::encode(Sha256::digest(&raw))
    ));
    storage::atomic_write(&output, hex::encode(raw).as_bytes())?;
    Ok(
        json!({"scope":"actual regtest refund auxiliary, not yet broadcast","mode":"auxiliary",
        "txid":tx.txid().to_string(),"lock_time":tx.lock_time(),"expiry_height":u32::from(tx.expiry_height()),
        "transparent_outputs":tx.transparent_bundle().map(|b|b.vout.len()).unwrap_or(0),
        "proof_and_signatures_verified":true,"prepared_before_funding":true,"file":output}),
    )
}

pub fn finish(dir: &Path, scan: &Path, mode: &str, witness: Option<&str>) -> Result<Value> {
    if mode == "auxiliary" {
        return finish_auxiliary(dir, scan);
    }
    let terms = storage::json(&dir.join("terms.json"))?;
    let amounts = crate::trade::amounts(&terms)?;
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
        || source["value"] != amounts.principal
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
    if mode == "refund"
        && pczt.clone().into_effects().map_err(err)?.lock_time()
            != crate::refund_lock::RefundLock::parse(&terms)?.value()
    {
        return Err("refund recovery lock differs from accepted terms".into());
    }
    if message(&pczt)? != expected {
        return Err("reanchoring changed authorization".into());
    }
    let tx = reprove_exit(pczt, source)?;
    // A v6 re-proof keeps effects/txid but changes authorization bytes. Preserve
    // every complete version, including a retry at the same height or anchor.
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    let output = dir.join(format!(
        "{mode}-{}-{}.hex",
        snapshot["height"],
        hex::encode(Sha256::digest(&raw))
    ));
    storage::atomic_write(&output, hex::encode(raw).as_bytes())?;
    Ok(
        json!({"scope":"actual regtest-funded native transaction, not yet broadcast", "mode":mode,
        "txid":tx.txid().to_string(),"lock_time":tx.lock_time(),"expiry_height":u32::from(tx.expiry_height()),
        "transparent_inputs":tx.transparent_bundle().map(|b|b.vin.len()).unwrap_or(0),
        "proof_and_signatures_verified":true,"prepared_before_funding":true,
        "file":output}),
    )
}
