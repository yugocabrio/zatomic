//! Private source authorization and exact-byte restart; never a sender.
//! The live wrapper retains sync.lock through fresh observations and passes
//! that same open lock description to this worker. It survives parent death.
use crate::{
    Result, err, funding_consent::hash, public_consent, public_graph, public_recovery,
    regtest_swap, storage, wallet,
};
use orchard::{
    circuit::{OrchardCircuitVersion, VerifyingKey},
    keys::SpendAuthorizingKey,
};
use pczt::{Pczt, roles::signer::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Cursor,
    os::{
        fd::{FromRawFd, RawFd},
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

fn sha(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

const SIGNED_AUXILIARY: &str = "auxiliary-signed.pczt";

/// Alice's refund auxiliary A must spend exactly F's change to this source.
/// The source signs it with F, and saves it first: R is spendable only via A.
fn sign_auxiliary(
    bank: &Path,
    graph_dir: &Path,
    preview: &Transaction,
    inspect_only: bool,
) -> Result<Value> {
    let deferred = public_graph::source_deferred_auxiliary(bank, graph_dir)?;
    let key = wallet::key(bank)?;
    let fvk = orchard::keys::FullViewingKey::from(&key);
    let note = wallet::parse_note(&deferred.record["change_note"])?;
    let action = usize::try_from(
        deferred.record["change_note"]["action"]
            .as_u64()
            .ok_or("change action")?,
    )?;
    let bundle = preview.ironwood_bundle().ok_or("funding preview")?;
    let (change, _, _) = bundle
        .decrypt_output_with_key(action, &fvk.to_ivk(orchard::keys::Scope::External))
        .ok_or("funding change not owned by this source")?;
    if wallet::note_json(&change)["cmx"] != deferred.record["change_note"]["cmx"]
        || deferred.record["funding_txid"] != preview.txid().to_string()
    {
        return Err("auxiliary does not spend this funding's change".into());
    }
    let message = regtest_swap::message(&deferred.unsigned)?;
    let mut real = Vec::new();
    pczt::roles::verifier::Verifier::new(deferred.unsigned.clone())
        .with_ironwood::<String, _>(|b| {
            let bad = |s: &str| pczt::roles::verifier::OrchardError::Custom(s.to_owned());
            for (i, a) in b.actions().iter().enumerate() {
                if a.spend().spend_auth_sig().is_none() {
                    if a.spend().fvk() != &Some(fvk.clone())
                        || a.spend().nullifier() != &note.nullifier(&fvk)
                    {
                        return Err(bad("auxiliary spends another note"));
                    }
                    a.spend().verify_nullifier(None).map_err(|e| bad(&err(e)))?;
                    a.spend().verify_rk(None).map_err(|e| bad(&err(e)))?;
                    real.push(i);
                }
            }
            Ok(())
        })
        .map_err(err)?;
    let [index] = real[..] else {
        return Err("auxiliary needs exactly one source spend".into());
    };
    let path = bank.join(SIGNED_AUXILIARY);
    let signed = if path.try_exists()? {
        Pczt::parse(&storage::read(&path, 1_000_000)?).map_err(err)?
    } else if inspect_only {
        return Ok(json!({"txid":deferred.record["txid"],"signed":false}));
    } else {
        let mut signer = Signer::new(deferred.unsigned.clone()).map_err(err)?;
        signer
            .sign_ironwood(rand::rng(), index, &SpendAuthorizingKey::from(&key))
            .map_err(err)?;
        signer.finish()
    };
    let signature = signed.ironwood().actions()[index]
        .spend()
        .spend_auth_sig()
        .ok_or("auxiliary signature missing")?;
    orchard::primitives::redpallas::VerificationKey::<orchard::primitives::redpallas::SpendAuth>::try_from(
        *signed.ironwood().actions()[index].spend().rk(),
    )?
    .verify(&message, &orchard::primitives::redpallas::Signature::from(signature))?;
    if regtest_swap::message(&signed)? != message
        || regtest_swap::effects_txid(&signed)?.to_string() != deferred.record["txid"]
    {
        return Err("signed auxiliary differs from the prepared one".into());
    }
    if !path.try_exists()? {
        storage::atomic_write(&path, &signed.serialize().map_err(err)?)?;
    }
    Ok(json!({"txid":deferred.record["txid"],"signed":true}))
}

fn inherited_lock(bank: &Path, fd: RawFd) -> Result<File> {
    if fd < 3 {
        return Err("inherited source lock descriptor required".into());
    }
    // dup validates the untrusted CLI integer before creating a Rust IO handle.
    // A BorrowedFd must already refer to a valid open descriptor. Duplicating
    // retains the same flock description, including after parent termination.
    unsafe extern "C" {
        fn dup(oldfd: std::ffi::c_int) -> std::ffi::c_int;
    }
    let duplicate = unsafe { dup(fd) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful dup returned a new, owned valid descriptor.
    let file = unsafe { File::from_raw_fd(duplicate) };
    let actual = file.metadata()?;
    let expected = bank.join("sync.lock").symlink_metadata()?;
    if !expected.is_file()
        || expected.permissions().mode() & 0o077 != 0
        || (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
    {
        return Err("source lock descriptor belongs to another wallet".into());
    }
    file.try_lock()
        .map_err(|_| "source wallet operation already active")?;
    Ok(file)
}

fn immutable(path: &Path, value: &Value) -> Result<()> {
    if path.try_exists()? {
        if storage::json(path)? != *value {
            return Err("source release decision changed".into());
        }
    } else {
        storage::atomic_json(path, value)?;
    }
    Ok(())
}

fn verify_bytes(unsigned: &Pczt, raw: &[u8], synthetic: bool) -> Result<Value> {
    let expected = regtest_swap::unsigned_preview(unsigned)?;
    let mut cursor = Cursor::new(raw);
    let tx = Transaction::read(&mut cursor, BranchId::Nu7)?;
    if cursor.position() != raw.len() as u64
        || tx.txid() != expected.txid()
        || tx.version() != TxVersion::V6
        || tx.consensus_branch_id() != BranchId::Nu7
        || tx.transparent_bundle().is_some()
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
    {
        return Err("source bytes differ from agreed funding effects".into());
    }
    let bundle = tx.ironwood_bundle().ok_or("source Ironwood bundle")?;
    if Some(bundle.anchor().to_bytes()) != *unsigned.ironwood().anchor() {
        return Err("source funding anchor changed".into());
    }
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let mut verifier = orchard::bundle::BatchValidator::new(&vk);
    verifier
        .add_bundle(bundle, regtest_swap::message(unsigned)?)
        .map_err(err)?;
    if !verifier.validate(rand::rng()) {
        return Err("source proof or authorization invalid".into());
    }
    Ok(
        json!({"format":"latch-public-source-bytes-v1","txid":tx.txid().to_string(),
        "bytes_sha256":sha(raw),"proof_and_signatures_verified":true,"agreed_effects_and_anchor_preserved":true,
        "synthetic_inputs":synthetic,"broadcast":false,"send_authorized":false}),
    )
}

/// Refund path only: re-prove Alice's signed auxiliary A at a confirmed
/// historical anchor from the source wallet's own checkpoints. Its effects,
/// signature and txid were fixed when the source released F.
pub fn prove_auxiliary(bank: &Path, old: &Path, current: &Path, output: &Path) -> Result<Value> {
    let reservation = storage::json(&bank.join("source-reservation.json"))?;
    let folder = bank.join(reservation["package"].as_str().ok_or("source package")?);
    let manifest = public_graph::package(bank, &folder)?;
    if !public_graph::deferred(&manifest) {
        return Err("this reservation has no deferred refund auxiliary".into());
    }
    let deferred =
        public_graph::source_deferred_auxiliary(bank, &public_recovery::graph_dir(&folder)?)?;
    let record = &deferred.record;
    let signed =
        Pczt::parse(&storage::read(&bank.join(SIGNED_AUXILIARY), 1_000_000)?).map_err(err)?;
    if regtest_swap::effects_txid(&signed)?.to_string() != record["txid"]
        || regtest_swap::message(&signed)? != regtest_swap::message(&deferred.unsigned)?
    {
        return Err("signed auxiliary differs from the prepared one".into());
    }
    let fvk = orchard::keys::FullViewingKey::from(&wallet::key(bank)?);
    let snapshot = crate::compact_wallet::funding_snapshot(
        &storage::json(old)?,
        &storage::json(current)?,
        &fvk,
        &record["change_note"],
        record["funding_txid"].as_str().ok_or("funding txid")?,
        usize::try_from(record["change_note"]["action"].as_u64().ok_or("action")?)?,
    )?;
    let tx = regtest_swap::reprove_exit(signed, &snapshot["notes"][0])?;
    if tx.txid().to_string() != record["txid"] || tx.consensus_branch_id() != BranchId::Nu7 {
        return Err("re-proving changed the auxiliary transaction".into());
    }
    let mut raw = Vec::new();
    tx.write(&mut raw)?;
    if !output.exists() {
        storage::create_dir(output)?;
    }
    let file = output.join(format!("auxiliary-{}.hex", sha(&raw)));
    if !file.exists() {
        storage::atomic_write(&file, hex::encode(&raw).as_bytes())?;
    }
    Ok(
        json!({"format":"latch-refund-auxiliary-version-v1","txid":record["txid"],
        "bytes_sha256":sha(&raw),"file":file,"height":snapshot["height"],
        "anchor_height":snapshot["anchor_height"],"change_confirmations":snapshot["funding_confirmations"],
        "proof_and_signature_verified":true,"broadcast":false}),
    )
}

/// The caller supplies only paths within its accepted private source workspace.
/// Synthetic mode is exposed exclusively by a separately named diagnostic CLI.
pub fn sign(
    bank: &Path,
    package: &Path,
    fd: RawFd,
    synthetic: bool,
    inspect_only: bool,
) -> Result<Value> {
    let _lock = inherited_lock(bank, fd)?;
    let out = bank.join("public-source-funding");
    let bundle_path = out.join("bundle.json");
    let proposal_path = out.join("proposal.json");
    let consents_path = out.join("consents.json");
    let checked = public_consent::verify(&bundle_path, &proposal_path, &consents_path)?;
    let bundle = storage::json(&bundle_path)?;
    let proposal = storage::json(&proposal_path)?;
    let agreement = &proposal["agreement"];
    if checked["synthetic_inputs"] != synthetic || bundle["synthetic_inputs"] != synthetic {
        return Err("source signing provenance mismatch".into());
    }
    if bank
        .join("public-source-cancelled.json")
        .symlink_metadata()
        .is_ok()
    {
        return Err("public source permanently cancelled".into());
    }
    let receiver = wallet::testnet_receivers(bank)?;
    let authority = storage::json(&bank.join("public-source-authority.json"))?;
    let binding = json!({"genesis":receiver["genesis"],"fvk_fingerprint":receiver["fvk_fingerprint"],
        "aux_script":receiver["aux_script"]});
    if authority["format"] != "latch-public-source-authority-v1"
        || authority["wallet"] != binding
        || authority["owners"] != agreement["owners"]
        || authority["owners_digest"] != hash(&authority["owners"])?
        || binding["genesis"] != agreement["native_genesis"]
        || receiver["aux_script"] != checked["native_auxiliary"]["aux_script"]
    {
        return Err("source wallet or approved owner pins differ".into());
    }
    let packet = &bundle["review"];
    let (funding_path, reservation) = if synthetic {
        if packet["graph"]["input_binding"]["synthetic"] != true {
            return Err("nonexistent diagnostic graph required".into());
        }
        (package.join("funding.pczt"), json!({"synthetic":true}))
    } else {
        let manifest = public_recovery::reserved_graph(bank, package, packet)?;
        let draft = storage::json(&package.join("graph-draft.json"))?;
        (
            package
                .join(draft["directory"].as_str().ok_or("reserved directory")?)
                .join("funding.pczt"),
            manifest,
        )
    };
    let unsigned_raw = storage::read(&funding_path, 1_000_000)?;
    if packet["graph"]["files"]["funding.pczt"] != sha(&unsigned_raw) {
        return Err("source unsigned funding bytes changed".into());
    }
    let unsigned = Pczt::parse(&unsigned_raw).map_err(err)?;
    public_graph::unsigned(&unsigned, false)?;
    let source_fvk = orchard::keys::FullViewingKey::from(&wallet::key(bank)?);
    pczt::roles::verifier::Verifier::new(unsigned.clone())
        .with_ironwood::<String, _>(|bundle| {
            let spend = bundle
                .actions()
                .iter()
                .find(|a| a.spend().spend_auth_sig().is_none())
                .ok_or_else(|| pczt::roles::verifier::OrchardError::Custom("source spend".into()))?
                .spend();
            if spend.fvk() != &Some(source_fvk.clone()) {
                return Err(pczt::roles::verifier::OrchardError::Custom(
                    "source key differs from funding spend".into(),
                ));
            }
            spend
                .verify_nullifier(None)
                .map_err(|e| pczt::roles::verifier::OrchardError::Custom(err(e)))?;
            spend
                .verify_rk(None)
                .map_err(|e| pczt::roles::verifier::OrchardError::Custom(err(e)))?;
            Ok(())
        })
        .map_err(err)?;
    let preview_tx = regtest_swap::unsigned_preview(&unsigned)?;
    let mut preview = Vec::new();
    preview_tx.write(&mut preview)?;
    if packet["funding_preview"] != hex::encode(preview) {
        return Err("source funding differs from owner-reviewed preview".into());
    }
    let deferred = packet["graph"]["refund_auxiliary"] == "deferred";
    if !synthetic && deferred != public_graph::deferred(&reservation) {
        return Err("graph and reservation disagree on the refund auxiliary".into());
    }
    let graph_dir = funding_path.parent().ok_or("graph directory")?;
    let intent = storage::json(&out.join("intent.json"))?;
    if intent["format"] != "latch-public-source-signing-intent-v1"
        || intent["agreement_digest"] != checked["agreement_digest"]
        || intent["bundle_digest"] != checked["bundle_digest"]
        || intent["authority_digest"] != hash(&authority)?
        || intent["synthetic_inputs"] != synthetic
        || intent["consents_digest"] != hash(&storage::json(&consents_path)?)?
    {
        return Err("source signing intent differs from accepted context".into());
    }
    let decision = json!({"format":"latch-public-source-release-v1","agreement_digest":checked["agreement_digest"],
        "bundle_digest":checked["bundle_digest"],"authority_digest":hash(&authority)?,"intent_digest":hash(&intent)?,
        "reservation_digest":hash(&reservation)?,"unsigned_funding_sha256":sha(&unsigned_raw),
        "funding_txid":agreement["native"]["funding_txid"],"synthetic_inputs":synthetic,
        "authorization_may_exist":true,"send_authorized":false});
    let marker = bank.join("public-source-release.json");
    let raw_path = bank.join("funding.hex");
    if raw_path.try_exists()? && !marker.try_exists()? {
        return Err("funding bytes without source decision".into());
    }
    // This fsync precedes ANY source signature. A crash afterward permanently
    // selects this funding graph; absence of raw bytes cannot permit cancel.
    if inspect_only {
        if marker.try_exists()? && storage::json(&marker)? != decision {
            return Err("source release decision changed".into());
        }
        if !raw_path.try_exists()? {
            return Ok(
                json!({"release_digest":hash(&decision)?,"private_source_authorization_saved":false,
                "release_marker_present":marker.try_exists()?,"intent_committed":true,
                "synthetic_inputs":synthetic,"broadcast":false,"send_authorized":false}),
            );
        }
    } else {
        immutable(&marker, &decision)?;
    }
    // A is signed and durable before F's signature exists, so a released F
    // always leaves Alice a usable refund input.
    let auxiliary = if deferred {
        sign_auxiliary(bank, graph_dir, &preview_tx, inspect_only)?
    } else {
        Value::Null
    };
    let (raw, reused) = if raw_path.try_exists()? {
        (hex::decode(storage::read(&raw_path, 4_000_000)?)?, true)
    } else {
        let index = unsigned
            .ironwood()
            .actions()
            .iter()
            .position(|a| a.spend().spend_auth_sig().is_none())
            .ok_or("source spend")?;
        let mut signer = Signer::new(unsigned.clone()).map_err(err)?;
        signer
            .sign_ironwood(
                rand::rng(),
                index,
                &SpendAuthorizingKey::from(&wallet::key(bank)?),
            )
            .map_err(err)?;
        let tx = regtest_swap::extract_checked(signer.finish())?;
        let mut raw = Vec::new();
        tx.write(&mut raw)?;
        // Verify BEFORE exposing a complete private output file.
        verify_bytes(&unsigned, &raw, synthetic)?;
        storage::atomic_write(&raw_path, hex::encode(&raw).as_bytes())?;
        (raw, false)
    };
    let checked_bytes = verify_bytes(&unsigned, &raw, synthetic)?;
    if checked_bytes["txid"] != agreement["native"]["funding_txid"] {
        return Err("source final funding identity changed".into());
    }
    let journal = json!({"format":"latch-public-source-outgoing-v1","release_digest":hash(&decision)?,
        "checked":checked_bytes});
    let journal_path = bank.join("public-source-outgoing.json");
    if inspect_only {
        if journal_path.try_exists()? && storage::json(&journal_path)? != journal {
            return Err("source outgoing journal differs from actual bytes".into());
        }
    } else {
        immutable(&journal_path, &journal)?;
    }
    Ok(
        json!({"release_digest":hash(&decision)?,"checked":checked_bytes,"raw_bytes_reused":reused,
        "refund_auxiliary":auxiliary,
        "private_source_authorization_saved":true,"outgoing_record_present":journal_path.try_exists()?,
        "live_observations_verified_by_native":false,
        "broadcast":false,"send_authorized":false}),
    )
}
