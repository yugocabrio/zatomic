//! Independently verified, durable native exit bundles. Never public artifacts.
use crate::{Result, err, keys, participants, regtest_swap, storage, wallet};
use ff_old::PrimeField;
use group_old::{Curve, GroupEncoding};
use orchard::{keys::FullViewingKey, primitives::redpallas};
use pasta_old::arithmetic::CurveAffine;
use pczt::{Pczt, roles::redactor::Redactor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use zcash_primitives::transaction::{
    Transaction, sighash::SignableInput, sighash_v6::v6_signature_hash, txid::TxIdDigester,
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_transparent::{
    address::{Script, TransparentAddress},
    sighash::{SighashType, SignableInput as TransparentInput},
};

fn encoded(bundle: &Value, field: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        bundle[field]
            .as_str()
            .ok_or("bundle encoded field missing")?,
    )?)
}
fn pczt(bundle: &Value, field: &str) -> Result<Pczt> {
    Pczt::parse(&encoded(bundle, field)?).map_err(|e| err(e).into())
}
fn index(terms: &Value, field: &str) -> Result<usize> {
    let i = terms[field].as_u64().ok_or("bundle action index")?;
    if i >= 2 {
        return Err("bundle action index out of bounds".into());
    }
    Ok(i as usize)
}

/// A valid proof for the same public effects does not establish that the saved
/// exit includes the private inputs needed to re-prove it at the mined anchor.
/// Require identical material after removing only the temporary proof/witness.
fn verify_reproving_material(deferred: &Pczt, checked: &Pczt) -> Result<()> {
    let stripped = Redactor::new(checked.clone())
        .redact_ironwood_with(|mut b| {
            b.clear_anchor();
            b.clear_zkproof();
            b.redact_actions(|mut a| a.clear_spend_witness());
        })
        .finish();
    if stripped.serialize().map_err(err)? != deferred.clone().serialize().map_err(err)? {
        return Err("recovery proving material differs from checked exit".into());
    }
    let effects = deferred.clone().into_effects().map_err(err)?;
    let expected = effects
        .ironwood_bundle()
        .ok_or("recovery Ironwood effects")?
        .binding_validating_key();
    pczt::roles::verifier::Verifier::new(deferred.clone())
        .with_ironwood::<String, _>(|bundle| {
            let bad = |s: &str| pczt::roles::verifier::OrchardError::Custom(s.to_owned());
            let key = bundle
                .bsk()
                .as_ref()
                .ok_or_else(|| bad("missing binding key"))?;
            if redpallas::VerificationKey::from(key) != expected {
                return Err(bad("wrong binding key"));
            }
            if bundle.actions().iter().any(|a| a.spend().fvk().is_none()) {
                return Err(bad("missing re-proving viewing key"));
            }
            Ok(())
        })
        .map_err(err)?;
    Ok(())
}

pub fn digest(bundle: &Value) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"Latch recovery bundle v1\0");
    hash.update(serde_json::to_vec(bundle)?);
    Ok(hex::encode(hash.finalize()))
}

/// The PCZT extractor verifies shielded proofs/signatures, not scriptSig.
/// Our fixed refund permits exactly one compressed-key P2PKH SIGHASH_ALL input.
/// Verify that authorization explicitly before accepting the way out.
pub fn verify_auxiliary_signature(pczt: &Pczt) -> Result<()> {
    if pczt.transparent().inputs().len() != 1 {
        return Err("refund auxiliary shape".into());
    }
    let input = &pczt.transparent().inputs()[0];
    let mut script_sig = None;
    pczt::roles::verifier::Verifier::new(pczt.clone())
        .with_transparent::<String, _>(|bundle| {
            use zcash_script::script::Evaluable;
            script_sig = bundle.inputs()[0]
                .script_sig()
                .as_ref()
                .map(|s| s.to_bytes());
            Ok(())
        })
        .map_err(err)?;
    let script_sig = script_sig.ok_or("refund auxiliary signature missing")?;
    let length = *script_sig
        .first()
        .ok_or("empty refund auxiliary signature")? as usize;
    let end = 1 + length;
    if !(9..=73).contains(&length)
        || script_sig.len() != end + 34
        || script_sig[end] != 33
        || script_sig[end - 1] != SighashType::ALL.encode()
    {
        return Err("refund requires canonical P2PKH SIGHASH_ALL".into());
    }
    let signature = secp256k1::ecdsa::Signature::from_der(&script_sig[1..end - 1])?;
    if signature.serialize_der().as_ref() != &script_sig[1..end - 1] {
        return Err("refund noncanonical DER signature".into());
    }
    let public = secp256k1::PublicKey::from_slice(&script_sig[end + 1..])?;
    let script: Script = TransparentAddress::from_pubkey(&public).script().into();
    if script.0.0 != *input.script_pubkey() {
        return Err("refund auxiliary public key mismatch".into());
    }
    let effects = pczt.clone().into_effects().map_err(err)?;
    let signable = TransparentInput::from_parts(
        effects
            .transparent_bundle()
            .ok_or("refund transparent effects")?,
        SighashType::ALL,
        0,
        &script,
        &script,
        Zatoshis::from_u64(*input.value())?,
    )?;
    let sighash = v6_signature_hash(
        &effects,
        &SignableInput::Transparent(signable),
        &effects.digest(TxIdDigester),
    );
    signature.verify(
        secp256k1::Message::from_digest(sighash.as_ref().try_into()?),
        &public,
    )?;
    Ok(())
}

pub fn accept(
    dir: &Path,
    id: u16,
    own: &FullViewingKey,
    public: &keys::PublicKeyPackage,
    bundle: &Value,
) -> Result<Value> {
    if bundle["version"] != 1
        || bundle["native_genesis"] != wallet::GENESIS
        || bundle["native_branch"] != "77190ad9"
    {
        return Err("recovery bundle domain mismatch".into());
    }
    let mut policy = bundle["policy"].clone();
    let object = policy
        .as_object_mut()
        .ok_or("recovery policy object required")?;
    object.remove("mode");
    object.remove("session");
    if storage::json(&dir.join("agreement.json"))? != policy {
        return Err("recovery agreement changed".into());
    }
    let target: [u8; 32] = storage::read(&dir.join("claim-target.bin"), 32)?
        .try_into()
        .map_err(|_| "saved target length")?;
    policy["session"] = json!("00".repeat(32));
    policy["mode"] = json!("claim");
    let claim = pczt(bundle, "claim")?;
    let refund = pczt(bundle, "refund")?;
    if claim.ironwood().anchor().is_some() || refund.ironwood().anchor().is_some() {
        return Err("recovery transactions must remain deferred".into());
    }
    let (claim_context, ci) =
        participants::validate(claim.clone(), &policy, own, id, public, target)?;
    let terms = &bundle["terms"];
    if index(terms, "claim_index")? != ci {
        return Err("recovery claim index changed".into());
    }
    let pre = regtest_swap::parse_pre(&bundle["presignature"])?;
    pre.verify()?;
    if pre.adaptor_point != target
        || pre.message != claim_context.message
        || pre.key != *claim.ironwood().actions()[ci].spend().rk()
    {
        return Err("recovery pre-signature context changed".into());
    }
    for (i, action) in claim.ironwood().actions().iter().enumerate() {
        if i != ci {
            let key =
                redpallas::VerificationKey::<redpallas::SpendAuth>::try_from(*action.spend().rk())?;
            let signature = redpallas::Signature::from(
                action
                    .spend()
                    .spend_auth_sig()
                    .ok_or("claim dummy signature missing")?,
            );
            key.verify(&claim_context.message, &signature)?;
        }
    }
    let ri = index(terms, "refund_index")?;
    let unsigned_refund = Redactor::new(refund.clone())
        .redact_ironwood_with(|mut b| b.redact_action(ri, |mut a| a.clear_spend_auth_sig()))
        .finish();
    policy["mode"] = json!("refund");
    let (_, validated_ri) = participants::validate(
        unsigned_refund,
        &policy,
        own,
        id,
        public,
        shielded_swap_crypto::generator().to_bytes(),
    )?;
    if validated_ri != ri {
        return Err("recovery refund index changed".into());
    }
    verify_auxiliary_signature(&refund)?;
    let funding = encoded(&policy, "funding")?;
    let funding = Transaction::read(&funding[..], BranchId::Nu7)?;
    let amounts = crate::trade::amounts(&policy)?;
    if terms["funding_txid"] != funding.txid().to_string()
        || terms["pending_cmx"] != policy["pending"]["cmx"]
        || terms["refund_height"] != policy["refund_height"]
        || terms.get("trade") != policy.get("trade")
        || terms["principal_zatoshi"] != amounts.principal
        || terms["payout_zatoshi"] != amounts.payout
        || terms["aux_outpoint"]["index"] != policy["aux"]["index"]
        || terms["aux_outpoint"]["value_zatoshi"] != policy["aux"]["value"]
    {
        return Err("recovery funding/deadline/amount metadata changed".into());
    }
    let anchor_fields = [
        "source_height",
        "funding_anchor_height",
        "funding_anchor_tip",
        "funding_anchor",
    ];
    if anchor_fields.iter().any(|field| terms.get(field).is_some()) {
        let source_height = terms["source_height"].as_u64().ok_or("source height")?;
        let anchor_height = terms["funding_anchor_height"]
            .as_u64()
            .ok_or("funding anchor height")?;
        let root = funding.ironwood_bundle().ok_or("funding bundle")?.anchor();
        if anchor_height < 2
            || anchor_height >= source_height
            || terms["refund_height"].as_u64() != source_height.checked_add(20)
            || encoded(terms, "funding_anchor_tip")?.len() != 32
            || terms["funding_anchor"] != hex::encode(root.to_bytes())
        {
            return Err("recovery funding anchor metadata changed".into());
        }
    }
    let mut txid = encoded(&policy["aux"], "txid_le")?;
    txid.reverse();
    if terms["aux_outpoint"]["txid"] != hex::encode(txid) {
        return Err("recovery auxiliary outpoint changed".into());
    }
    let point = pasta_old::pallas::Point::from_bytes(&target)
        .into_option()
        .ok_or("recovery point")?
        .to_affine();
    let coords = point
        .coordinates()
        .into_option()
        .ok_or("identity recovery point")?;
    let big = |mut bytes: [u8; 32]| {
        bytes.reverse();
        format!("0x{}", hex::encode(bytes))
    };
    if terms["point_x"] != big(coords.x().to_repr())
        || terms["point_y"] != big(coords.y().to_repr())
    {
        return Err("recovery EVM point changed".into());
    }
    let checked_claim = pczt(bundle, "claim_check")?;
    let checked_refund = pczt(bundle, "refund_check")?;
    verify_reproving_material(&claim, &checked_claim)?;
    verify_reproving_material(&refund, &checked_refund)?;
    if regtest_swap::message(&checked_claim)? != regtest_swap::message(&claim)?
        || regtest_swap::message(&checked_refund)? != regtest_swap::message(&refund)?
    {
        return Err("recovery proof effects differ from exits".into());
    }
    regtest_swap::verify_claim_proof(checked_claim)?;
    // Verify the exact saved refund's authorizations, not a substitute checked
    // copy with the same effects. Sighash deliberately excludes authorization.
    if checked_refund
        .ironwood()
        .actions()
        .iter()
        .map(|a| a.spend().spend_auth_sig())
        .collect::<Vec<_>>()
        != refund
            .ironwood()
            .actions()
            .iter()
            .map(|a| a.spend().spend_auth_sig())
            .collect::<Vec<_>>()
    {
        return Err("recovery refund authorization differs from checked proof".into());
    }
    let _ = regtest_swap::extract_checked(checked_refund)?;
    let digest = digest(bundle)?;
    let saved = dir.join("recovery-bundle.json");
    if saved.exists() {
        if storage::json(&saved)? != *bundle {
            return Err("immutable recovery bundle changed".into());
        }
    } else {
        storage::write_json(&saved, bundle)?;
    }
    let receipt = json!({"participant":id,"bundle_digest":digest,"funding_txid":funding.txid().to_string(),
        "durably_saved":true,"claim_pre_signature_verified":true,"both_exit_proofs_verified":true,
        "refund_shielded_and_auxiliary_signatures_verified":true});
    let marker = dir.join("recovery-receipt.json");
    if marker.exists() {
        if storage::json(&marker)? != receipt {
            return Err("recovery receipt changed".into());
        }
    } else {
        storage::write_json(&marker, &receipt)?;
    }
    Ok(receipt)
}

/// Create a watch-only native recovery workspace from this participant's own
/// accepted bundle. No coordinator directory, peer files or signing key is
/// required by the resulting prover. The appropriate chain witness is supplied
/// later from an independently obtained node capture.
pub fn export(dir: &Path, output: &Path) -> Result<Value> {
    let manifest = storage::json(&dir.join("dkg-complete.json"))?;
    let id = u16::try_from(manifest["id"].as_u64().ok_or("participant id")?)?;
    if id != 1 && id != 2 {
        return Err("recovery participant id".into());
    }
    let own = wallet::fvk(dir)?;
    let public =
        keys::PublicKeyPackage::deserialize(&storage::read(&dir.join("frost-public.bin"), 16384)?)
            .map_err(err)?;
    let bundle = storage::json(&dir.join("recovery-bundle.json"))?;
    let receipt = accept(dir, id, &own, &public, &bundle)?;
    storage::create_dir(output)?;
    let role = if id == 1 { "alice" } else { "bob" };
    let destination = output.join(role);
    storage::create_dir(&destination)?;
    storage::write(
        &output.join("joint-fvk.bin"),
        &encoded(&bundle["policy"], "joint_fvk")?,
    )?;
    storage::write(&destination.join("joint-fvk.bin"), &own.to_bytes())?;
    storage::write_json(
        &output.join("pending-note.json"),
        &bundle["policy"]["pending"],
    )?;
    storage::write_json(&output.join("terms.json"), &bundle["terms"])?;
    if id == 1 {
        storage::write(
            &destination.join("refund.pczt"),
            &encoded(&bundle, "refund")?,
        )?;
    } else {
        storage::write(&destination.join("claim.pczt"), &encoded(&bundle, "claim")?)?;
        storage::write_json(
            &destination.join("presignature.json"),
            &bundle["presignature"],
        )?;
    }
    let ready = json!({"scope":"private watch-only native recovery bundle; no new signatures",
        "participant":id,"mode":if id==1 {"refund"} else {"claim"},
        "bundle_digest":receipt["bundle_digest"],"funding_txid":bundle["terms"]["funding_txid"],
        "spending_keys_exported":false,"private_exit_data":true});
    storage::write_json(&output.join("recovery-ready.json"), &ready)?;
    Ok(ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run explicitly against a fresh completed bundle fixture. No chain
    /// mutation or signing occurs; each altered bundle must fail before save.
    #[test]
    #[ignore = "requires LATCH_BUNDLE_FIXTURE pointing to a completed swap directory"]
    fn reject_corrupt_native_recovery_bundles() -> Result<()> {
        let swap = std::path::PathBuf::from(std::env::var("LATCH_BUNDLE_FIXTURE")?);
        let dir = swap.join("bob");
        let dir = if dir.join("native").is_dir() {
            dir.join("native")
        } else {
            dir
        };
        let original = storage::json(&dir.join("recovery-bundle.json"))?;
        let public = keys::PublicKeyPackage::deserialize(&storage::read(
            &dir.join("frost-public.bin"),
            16384,
        )?)
        .map_err(err)?;
        let own = wallet::fvk(&dir)?;
        let original_receipt = storage::json(&dir.join("recovery-receipt.json"))?;
        assert_eq!(accept(&dir, 2, &own, &public, &original)?, original_receipt);
        let mut cases = Vec::new();
        if original["terms"].get("trade").is_some() {
            let mut altered = original.clone();
            altered["terms"]["trade"]["offer"]["payload"]["payout_zatoshi"] = json!(1);
            altered["policy"]["trade"] = altered["terms"]["trade"].clone();
            cases.push(("changed signed OTC amount", altered));
            let mut altered = original.clone();
            altered["terms"].as_object_mut().unwrap().remove("trade");
            altered["policy"].as_object_mut().unwrap().remove("trade");
            cases.push(("OTC quote downgrade to fixed profile", altered));
        }
        if original["terms"].get("funding_anchor_height").is_some() {
            for (field, value) in [
                ("funding_anchor", json!("00".repeat(32))),
                ("funding_anchor_tip", json!("00")),
                (
                    "funding_anchor_height",
                    original["terms"]["source_height"].clone(),
                ),
                ("source_height", json!(0)),
            ] {
                let mut altered = original.clone();
                altered["terms"][field] = value;
                cases.push((field, altered));
            }
            let mut altered = original.clone();
            altered["terms"]
                .as_object_mut()
                .unwrap()
                .remove("funding_anchor_height");
            cases.push(("partial funding anchor metadata", altered));
        }
        let mut altered = original.clone();
        altered["native_branch"] = json!("00000000");
        cases.push(("network", altered));
        let mut altered = original.clone();
        altered["terms"]["funding_txid"] = json!("00".repeat(32));
        cases.push(("funding", altered));
        let mut altered = original.clone();
        altered["terms"]["refund_height"] = json!(1);
        cases.push(("deadline", altered));
        let mut altered = original.clone();
        altered["policy"]["bob_fvk"] = original["policy"]["alice_fvk"].clone();
        cases.push(("recipient", altered));
        let mut altered = original.clone();
        altered["presignature"]["s_hat"] = json!("00".repeat(32));
        cases.push(("adaptor signature", altered));
        let mut altered = original.clone();
        altered["terms"]["point_x"] = json!("0x0");
        cases.push(("EVM point", altered));
        let mut altered = original.clone();
        altered["terms"]["claim_index"] = json!(2);
        cases.push(("action index", altered));
        let mut altered = original.clone();
        altered["terms"]["aux_outpoint"]["txid"] = json!("00".repeat(32));
        cases.push(("auxiliary outpoint", altered));
        let unsigned = Redactor::new(pczt(&original, "refund")?)
            .redact_transparent_with(|mut b| b.redact_inputs(|mut i| i.clear_script_sig()))
            .finish();
        let mut altered = original.clone();
        altered["refund"] = json!(hex::encode(unsigned.serialize().map_err(err)?));
        cases.push(("missing auxiliary signature", altered));
        let unsigned = Redactor::new(pczt(&original, "refund")?)
            .redact_ironwood_with(|mut b| {
                b.redact_action(
                    index(&original["terms"], "refund_index").unwrap(),
                    |mut a| a.clear_spend_auth_sig(),
                )
            })
            .finish();
        let mut altered = original.clone();
        altered["refund"] = json!(hex::encode(unsigned.serialize().map_err(err)?));
        cases.push(("missing native authorization", altered));
        // Missing private proving data in BOTH copies must also fail: matching
        // public effects and a valid previous proof do not suffice to recover.
        for (name, remove_fvk) in [
            ("missing binding key", false),
            ("missing viewing key", true),
        ] {
            let mut altered = original.clone();
            for field in ["claim", "claim_check"] {
                let changed = Redactor::new(pczt(&original, field)?)
                    .redact_ironwood_with(|mut b| {
                        if remove_fvk {
                            b.redact_action(
                                index(&original["terms"], "claim_index").unwrap(),
                                |mut a| a.clear_spend_fvk(),
                            );
                        } else {
                            b.clear_bsk();
                        }
                    })
                    .finish();
                altered[field] = json!(hex::encode(changed.serialize().map_err(err)?));
            }
            cases.push((name, altered));
        }
        let claim = pczt(&original, "claim")?;
        let dummy = 1 - index(&original["terms"], "claim_index")?;
        let signature = claim.ironwood().actions()[dummy]
            .spend()
            .spend_auth_sig()
            .unwrap();
        let mut altered = original.clone();
        for field in ["claim", "claim_check"] {
            let mut raw = encoded(&original, field)?;
            let offset = raw
                .windows(signature.len())
                .position(|w| w == signature)
                .ok_or("test dummy signature")?;
            raw[offset + 63] ^= 1;
            altered[field] = json!(hex::encode(raw));
        }
        cases.push(("invalid claim dummy authorization", altered));
        let proof_pczt = pczt(&original, "claim_check")?;
        let proof = proof_pczt
            .ironwood()
            .zkproof()
            .as_ref()
            .ok_or("test proof")?;
        let mut encoded = encoded(&original, "claim_check")?;
        let offset = encoded
            .windows(proof.len())
            .position(|w| w == proof)
            .ok_or("proof bytes absent")?;
        encoded[offset + proof.len() / 2] ^= 1;
        let mut altered = original.clone();
        altered["claim_check"] = json!(hex::encode(encoded));
        cases.push(("invalid native proof", altered));
        for (attack, altered) in cases {
            assert!(
                accept(&dir, 2, &own, &public, &altered).is_err(),
                "accepted {attack}"
            );
            assert_eq!(
                storage::json(&dir.join("recovery-bundle.json"))?,
                original,
                "overwrote bundle on {attack}"
            );
            assert_eq!(
                storage::json(&dir.join("recovery-receipt.json"))?,
                original_receipt,
                "overwrote receipt on {attack}"
            );
        }
        Ok(())
    }
}
