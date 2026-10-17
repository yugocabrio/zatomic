//! Offline testnet graph drafts. Produces proofs, never real input signatures.
//! A draft is not a recovery bundle or either participant's funding consent.
use crate::{
    Result,
    auxiliary::Auxiliary,
    compact_wallet::TESTNET_GENESIS,
    decode, err,
    refund_lock::RefundLock,
    regtest_swap, storage,
    transaction_graph::{self, Exit, Source},
    wallet,
};
use incrementalmerkletree::Hashable;
use orchard::{
    keys::{FullViewingKey, Scope},
    tree::{MerkleHashOrchard, MerklePath},
};
use pczt::Pczt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters, TEST_NETWORK};

const MEMBERS: [&str; 8] = [
    "anchor.json",
    "current.json",
    "plan.json",
    "source.json",
    "canonical.json",
    "auxiliary.json",
    "selected-auxiliary.json",
    "auxiliary-source.json",
];
/// v2 packages reserve only the source note: the refund's transparent coin is
/// created later by Alice's private auxiliary transaction from F's change.
const MEMBERS_V2: [&str; 5] = [
    "anchor.json",
    "current.json",
    "plan.json",
    "source.json",
    "canonical.json",
];
const AUXILIARY_RECORD: &str = "auxiliary.json";

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn amount(v: &Value, field: &str) -> Result<u64> {
    v[field]
        .as_u64()
        .ok_or_else(|| format!("integer {field} required").into())
}
fn parse_fvk(v: &Value, field: &str) -> Result<FullViewingKey> {
    FullViewingKey::from_bytes(&decode(v, field)?)
        .ok_or_else(|| "invalid destination viewing key".into())
}

/// Fail before prover work if any member differs from the wallet's durable
/// reservation. This only binds a historical private observation, not live UTXOs.
pub(crate) fn package(bank: &Path, folder: &Path) -> Result<Value> {
    let reservation = storage::json(&bank.join("source-reservation.json"))?;
    let raw = storage::read(&folder.join("manifest.json"), 50_000_000)?;
    let manifest: Value = serde_json::from_slice(&raw)?;
    let members: &[&str] = if deferred(&manifest) {
        &MEMBERS_V2
    } else {
        &MEMBERS
    };
    let formats = (
        reservation["format"].as_str().unwrap_or(""),
        manifest["format"].as_str().unwrap_or(""),
    );
    if !matches!(
        formats,
        ("latch-source-reservation-v1", "latch-source-inputs-v1")
            | ("latch-source-reservation-v2", "latch-source-inputs-v2")
    ) || (deferred(&manifest)
        && (manifest["selected_auxiliary_outpoint"] != Value::Null
            || manifest["refund_auxiliary"] != "deferred"))
        || reservation["genesis"] != TESTNET_GENESIS
        || manifest["genesis"] != TESTNET_GENESIS
        || reservation["manifest_sha256"] != sha(&raw)
        || folder.file_name().and_then(|s| s.to_str()) != reservation["package"].as_str()
        || std::fs::canonicalize(folder.parent().ok_or("package parent")?)?
            != std::fs::canonicalize(bank)?
        || manifest["files"]
            .as_object()
            .is_none_or(|files| files.len() != members.len())
    {
        return Err("public input reservation/package mismatch".into());
    }
    for name in members {
        if manifest["files"][name] != sha(&storage::read(&folder.join(name), 50_000_000)?) {
            return Err("reserved graph input changed".into());
        }
    }
    for name in [
        "plan_digest",
        "principal_zatoshi",
        "selected_note_commitment",
        "selected_auxiliary_outpoint",
    ] {
        if manifest[name] != reservation[name] {
            return Err("reservation inputs differ from manifest".into());
        }
    }
    if storage::json(&bank.join("network.json"))?["genesis"] != TESTNET_GENESIS {
        return Err("testnet source wallet required".into());
    }
    Ok(manifest)
}

pub(crate) fn deferred(manifest: &Value) -> bool {
    manifest["format"] == "latch-source-inputs-v2"
}

fn source_aux_key(bank: &Path) -> Result<secp256k1::SecretKey> {
    Ok(secp256k1::SecretKey::from_secret_bytes(
        storage::read(&bank.join("aux-key.bin"), 32)?
            .try_into()
            .map_err(|_| "aux key")?,
    )?)
}

/// Alice's deferred auxiliary transaction A as prepared with this graph: the
/// unsigned PCZT, its record, and the refund coin it creates for R.
pub(crate) struct DeferredAuxiliary {
    pub unsigned: Pczt,
    pub record: Value,
    pub coin: Auxiliary,
}

/// Key-free check of the saved A against its record: exact files, deferred,
/// no transparent input, one 20,000-zatoshi output, recorded txid and script.
pub(crate) fn deferred_record(graph_dir: &Path) -> Result<(Pczt, Value)> {
    let record = storage::json(&graph_dir.join(AUXILIARY_RECORD))?;
    let raw = storage::read(&graph_dir.join("auxiliary.pczt"), 1_000_000)?;
    let check = storage::read(&graph_dir.join("auxiliary-check.pczt"), 1_000_000)?;
    let unsigned = Pczt::parse(&raw).map_err(err)?;
    let effects = unsigned.clone().into_effects().map_err(err)?;
    let bundle = effects
        .transparent_bundle()
        .ok_or("auxiliary transparent output")?;
    if record["format"] != "latch-deferred-refund-auxiliary-v1"
        || record["files"]["auxiliary.pczt"] != sha(&raw)
        || record["files"]["auxiliary-check.pczt"] != sha(&check)
        || record["txid"] != regtest_swap::effects_txid(&unsigned)?.to_string()
        || record["index"] != 0
        || !bundle.vin.is_empty()
        || bundle.vout.len() != 1
        || u64::from(bundle.vout[0].value()) != crate::auxiliary::COMPACT_VALUE
        || record["script"] != hex::encode(&bundle.vout[0].script_pubkey().0.0)
        || unsigned.ironwood().anchor().is_some()
        || u32::from(effects.expiry_height()) != 0
        || effects.lock_time() != 0
    {
        return Err("deferred auxiliary changed".into());
    }
    Ok((unsigned, record))
}

pub(crate) fn deferred_auxiliary(
    key: secp256k1::SecretKey,
    graph_dir: &Path,
) -> Result<DeferredAuxiliary> {
    let (unsigned, record) = deferred_record(graph_dir)?;
    let effects = unsigned.clone().into_effects().map_err(err)?;
    // Fails unless A pays exactly this key's address.
    let coin = Auxiliary::deferred(
        key,
        regtest_swap::effects_txid(&unsigned)?,
        effects.transparent_bundle(),
    )?;
    Ok(DeferredAuxiliary {
        unsigned,
        record,
        coin,
    })
}

pub(crate) fn source_deferred_auxiliary(
    bank: &Path,
    graph_dir: &Path,
) -> Result<DeferredAuxiliary> {
    deferred_auxiliary(source_aux_key(bank)?, graph_dir)
}

pub(crate) fn unsigned(pczt: &Pczt, transparent: bool) -> Result<()> {
    // Dummy spends have valid signatures from the IO finalizer. Exactly one real
    // Ironwood spend must remain unsigned, as must the refund auxiliary.
    if pczt
        .ironwood()
        .actions()
        .iter()
        .filter(|a| a.spend().spend_auth_sig().is_none())
        .count()
        != 1
        || pczt.transparent().inputs().len() != usize::from(transparent)
        || pczt.transparent().outputs().len() != usize::from(transparent)
        || pczt.ironwood().actions().len() != 2
    {
        return Err("draft unexpectedly contains real input authorization".into());
    }
    pczt::roles::verifier::Verifier::new(pczt.clone())
        .with_transparent::<String, _>(|bundle| {
            if bundle
                .inputs()
                .iter()
                .any(|i| i.script_sig().is_some() || !i.partial_signatures().is_empty())
            {
                return Err(pczt::roles::verifier::TransparentError::Custom(
                    "draft auxiliary already signed".to_owned(),
                ));
            }
            Ok(())
        })
        .map_err(err)?;
    let tx = pczt.clone().into_effects().map_err(err)?;
    if tx.consensus_branch_id() != zcash_protocol::consensus::BranchId::Nu7
        || tx.version() != zcash_primitives::transaction::TxVersion::V6
        || u32::from(tx.expiry_height()) != 0
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
    {
        return Err("draft native transaction profile changed".into());
    }
    Ok(())
}

enum RefundCoin {
    /// A mined, reserved transparent coin (v1 packages, synthetic drafts).
    Reserved(Auxiliary),
    /// Created by Alice's auxiliary transaction from F's change, keyed by the
    /// source wallet's auxiliary key.
    Deferred(secp256k1::SecretKey),
}

struct Draft {
    source: Source,
    principal: u64,
    height: u32,
    joint: FullViewingKey,
    alice: orchard::Address,
    bob: orchard::Address,
    auxiliary: RefundCoin,
    lock: RefundLock,
}

/// Build the unsigned, deferred A from F's change and keep it out of the
/// reviewed graph: owners review R, which commits to A's txid.
fn build_auxiliary(
    key: secp256k1::SecretKey,
    preview: &zcash_primitives::transaction::Transaction,
    source_fvk: &FullViewingKey,
    change_value: u64,
    height: u32,
    output: &Path,
) -> Result<Auxiliary> {
    let bundle = preview.ironwood_bundle().ok_or("funding Ironwood")?;
    let found = (0..bundle.actions().len())
        .filter_map(|i| {
            bundle
                .decrypt_output_with_key(i, &source_fvk.to_ivk(Scope::External))
                .map(|(note, _, _)| (i, note))
        })
        .filter(|(_, note)| note.value().inner() == change_value)
        .collect::<Vec<_>>();
    let [(action, change)] = found[..] else {
        return Err("funding change output".into());
    };
    let path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
    );
    let address = zcash_transparent::address::TransparentAddress::from_pubkey(
        &secp256k1::PublicKey::from_secret_key(&key),
    );
    let built = transaction_graph::auxiliary_funding(
        TEST_NETWORK,
        height,
        Source {
            fvk: source_fvk.clone(),
            note: change,
            path: path.clone(),
        },
        &address,
    )?;
    let message = regtest_swap::message(&built)?;
    let unsigned_aux = pczt::roles::redactor::Redactor::new(built)
        .redact_ironwood_with(|mut b| {
            b.clear_anchor();
            b.redact_actions(|mut a| a.clear_spend_witness());
        })
        .finish();
    let anchor = path.root(change.commitment().into());
    let checked = regtest_swap::prove_pczt(regtest_swap::anchor_for_check(
        unsigned_aux.clone(),
        path,
        anchor,
    )?)?;
    regtest_swap::verify_claim_proof(checked.clone())?;
    if regtest_swap::message(&unsigned_aux)? != message {
        return Err("deferred auxiliary changed message".into());
    }
    let effects = unsigned_aux.clone().into_effects().map_err(err)?;
    let coin = Auxiliary::deferred(
        key,
        regtest_swap::effects_txid(&unsigned_aux)?,
        effects.transparent_bundle(),
    )?;
    let mut files = serde_json::Map::new();
    for (name, pczt) in [
        ("auxiliary.pczt", unsigned_aux),
        ("auxiliary-check.pczt", checked),
    ] {
        let bytes = pczt.serialize().map_err(err)?;
        storage::atomic_write(&output.join(name), &bytes)?;
        files.insert(name.into(), json!(sha(&bytes)));
    }
    let mut note = wallet::note_json(&change);
    note["action"] = json!(action);
    storage::atomic_json(
        &output.join(AUXILIARY_RECORD),
        &json!({"format":"latch-deferred-refund-auxiliary-v1","txid":coin.txid.to_string(),
            "index":0,"value_zatoshi":crate::auxiliary::COMPACT_VALUE,
            "script":hex::encode(&coin.coin.script_pubkey().0.0),"change_note":note,
            "funding_txid":preview.txid().to_string(),"files":files,
            "signed":false,"broadcast":false,
            "scope":"Alice's private refund auxiliary; sent only on the refund path"}),
    )?;
    Ok(coin)
}

fn build(draft: Draft, output: &Path, binding: Value) -> Result<Value> {
    storage::create_dir(output)?;
    let source_fvk = draft.source.fvk.clone();
    let change_value = draft
        .source
        .note
        .value()
        .inner()
        .checked_sub(draft.principal + 10_000)
        .ok_or("source note too small")?;
    let (funding, index) = transaction_graph::funding(
        TEST_NETWORK,
        draft.height,
        draft.source,
        &draft.joint,
        draft.principal,
    )?;
    unsigned(&funding, false)?;
    let funding = regtest_swap::prove_pczt(funding)?;
    unsigned(&funding, false)?;
    regtest_swap::verify_claim_proof(funding.clone())?;
    let preview = regtest_swap::unsigned_preview(&funding)?;
    let (pending, _, _) = preview
        .ironwood_bundle()
        .ok_or("funding Ironwood")?
        .decrypt_output_with_key(index, &draft.joint.to_ivk(Scope::External))
        .ok_or("pending output")?;
    if pending.value().inner() != draft.principal {
        return Err("pending amount mismatch".into());
    }
    let deferred = matches!(draft.auxiliary, RefundCoin::Deferred(_));
    let auxiliary = match draft.auxiliary {
        RefundCoin::Reserved(coin) => coin,
        RefundCoin::Deferred(key) => build_auxiliary(
            key,
            &preview,
            &source_fvk,
            change_value,
            draft.height,
            output,
        )?,
    };
    let path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
    );
    let mut files = serde_json::Map::new();
    let funding_bytes = funding.serialize().map_err(err)?;
    storage::atomic_write(&output.join("funding.pczt"), &funding_bytes)?;
    files.insert("funding.pczt".into(), json!(sha(&funding_bytes)));
    let mut messages = serde_json::Map::new();
    for (name, receiver, refund) in [
        ("claim", draft.bob, None),
        ("refund", draft.alice, Some((&auxiliary, draft.lock))),
    ] {
        let pczt = transaction_graph::exit(
            TEST_NETWORK,
            draft.height,
            Exit {
                joint: draft.joint.clone(),
                note: pending,
                path: path.clone(),
                receiver,
                payout: draft.principal - 10_000,
            },
            refund,
        )?;
        unsigned(&pczt, refund.is_some())?;
        let effects = pczt.clone().into_effects().map_err(err)?;
        if effects.lock_time() != refund.map(|(_, lock)| lock.value()).unwrap_or(0)
            || effects
                .transparent_bundle()
                .is_some_and(|bundle| bundle.vin[0].sequence() == u32::MAX)
        {
            return Err("draft refund lock ineffective or unexpected claim lock".into());
        }
        let message = regtest_swap::message(&pczt)?;
        let checked = regtest_swap::prove_pczt(pczt)?;
        unsigned(&checked, refund.is_some())?;
        regtest_swap::verify_claim_proof(checked.clone())?;
        // Remove only provisional chain witness/proof; preserve exactly the
        // effects to be reviewed and signed later by the actual owners.
        let deferred = pczt::roles::redactor::Redactor::new(checked.clone())
            .redact_ironwood_with(|mut b| {
                b.clear_anchor();
                b.clear_zkproof();
                b.redact_actions(|mut a| a.clear_spend_witness());
            })
            .finish();
        unsigned(&deferred, refund.is_some())?;
        if regtest_swap::message(&deferred)? != message {
            return Err("deferred draft changed message".into());
        }
        messages.insert(name.into(), json!(hex::encode(message)));
        for (suffix, pczt) in [("", deferred), ("-check", checked)] {
            let name = format!("{name}{suffix}.pczt");
            let bytes = pczt.serialize().map_err(err)?;
            storage::atomic_write(&output.join(&name), &bytes)?;
            files.insert(name, json!(sha(&bytes)));
        }
    }
    let mut graph = json!({"format":"latch-unsigned-testnet-graph-v1","native_genesis":TESTNET_GENESIS,
        "native_branch":"77190ad9","eth_chain_id":11155111,"input_binding":binding,
        "funding_txid":preview.txid().to_string(),"principal_zatoshi":draft.principal,
        "payout_zatoshi":draft.principal-10_000,"expiry_height":0,"files":files,
        "signature_messages":messages,"proofs_verified":true,"real_input_signatures":false,
        "exit_proof_anchors":"provisional tree containing the exact pending note; not chain anchors",
        "participant_consents_present":false,"live_revalidated":false,
        "funding_authorized":false,"broadcast":false,
        "scope":"unsigned native graph only; setup receipts do not authorize this graph or funding"});
    draft.lock.attach(&mut graph);
    // Reviewed by both owners: the refund's coin does not exist until Alice
    // sends her own auxiliary transaction, and only if she refunds.
    graph["refund_auxiliary"] = json!(if deferred { "deferred" } else { "reserved" });
    let digest = sha(&serde_json::to_vec(&graph)?);
    storage::atomic_json(&output.join("graph.json"), &graph)?;
    Ok(
        json!({"file":output.join("graph.json"),"graph_digest":digest,
        "principal_zatoshi":draft.principal,"payout_zatoshi":draft.principal-10_000,
        "three_native_proofs_verified":true,"real_input_signatures":false,
        "funding_authorized":false,"broadcast":false}),
    )
}

pub fn prepare(bank: &Path, folder: &Path, destinations: &Path, output: &Path) -> Result<Value> {
    let manifest = package(bank, folder)?;
    let source = storage::json(&folder.join("source.json"))?;
    let plan = storage::json(&folder.join("plan.json"))?;
    let authenticated = storage::json(destinations)?;
    let setup = crate::public_setup::authenticate(&authenticated)?;
    let roles = &setup["destinations"];
    let principal = amount(&manifest, "principal_zatoshi")?;
    let height = u32::try_from(amount(&source, "height")?)?;
    let lock = RefundLock::parse(&json!({"refund_lock":plan["native_refund_lock"]}))?;
    let mut hash = Sha256::new();
    hash.update(b"Latch candidate execution plan v1\0");
    hash.update(serde_json::to_vec(&plan)?);
    if source["format"] != "latch-source-snapshot-v1"
        || source["genesis"] != TESTNET_GENESIS
        || source["branch"] != "77190ad9"
        || source["principal_zatoshi"] != principal
        || setup["principal_zatoshi"] != principal
        || source["notes"]
            .as_array()
            .is_none_or(|notes| notes.len() != 1)
        || source["notes"][0]["cmx"] != manifest["selected_note_commitment"]
        || manifest["plan_digest"] != hex::encode(hash.finalize())
        || plan["policy"]["native_genesis"] != TESTNET_GENESIS
        || plan["policy"]["native_branch"] != "77190ad9"
        || plan["policy"]["eth_chain_id"] != 11155111
        || lock.required_time().is_none()
        || roles.as_object().is_none_or(|v| v.len() != 7)
        // Funded graphs only from address-only (v2) setups; v1 shared FVKs.
        || roles["format"] != "latch-graph-destinations-v2"
        || roles["native_genesis"] != TESTNET_GENESIS
        || roles["native_branch"] != "77190ad9"
        || roles["eth_chain_id"] != 11155111
    {
        return Err("public graph inputs/network/plan/destinations mismatch".into());
    }
    let fvk = FullViewingKey::from(&wallet::key(bank)?);
    let note = wallet::parse_note(&source["notes"][0])?;
    let path = wallet::parse_path(&source["notes"][0])?;
    if note.recipient() != fvk.address_at(0u32, Scope::External)
        || source["fvk_fingerprint"] != sha(&fvk.to_bytes())
        || source["anchor"] != hex::encode(path.root(note.commitment().into()).to_bytes())
    {
        return Err("reserved source ownership/path mismatch".into());
    }
    let auxiliary = if deferred(&manifest) {
        if note.value().inner()
            <= principal
                + 10_000
                + crate::auxiliary::COMPACT_VALUE
                + transaction_graph::AUXILIARY_FEE
        {
            return Err("source note leaves too little change for the refund auxiliary".into());
        }
        RefundCoin::Deferred(source_aux_key(bank)?)
    } else {
        let coin = Auxiliary::load_reserved(
            bank,
            height,
            &storage::json(&folder.join("auxiliary-source.json"))?,
        )?;
        if manifest["selected_auxiliary_outpoint"]
            != json!({"txid":coin.txid.to_string(),"index":coin.index})
        {
            return Err("reserved auxiliary outpoint mismatch".into());
        }
        RefundCoin::Reserved(coin)
    };
    let joint = parse_fvk(roles, "joint_fvk")?;
    let alice = crate::participants::receiver(roles, "alice")?;
    let bob = crate::participants::receiver(roles, "bob")?;
    let shared = joint.address_at(0u32, Scope::External);
    if shared == alice || shared == bob || alice == bob {
        return Err("distinct graph destinations required".into());
    }
    build(
        Draft {
            source: Source { fvk, note, path },
            principal,
            height: height.checked_add(1).ok_or("height overflow")?,
            joint,
            alice,
            bob,
            auxiliary,
            lock,
        },
        output,
        json!({"manifest_sha256":sha(&storage::read(&folder.join("manifest.json"),50_000_000)?),
            "plan_digest":manifest["plan_digest"],"destinations_sha256":hash_setup(&authenticated)?,
            "quote_digest":setup["quote_digest"],"destinations_authenticated":true,
            "synthetic":false,"live_revalidated":false}),
    )
}

fn hash_setup(setup: &Value) -> Result<String> {
    Ok(sha(&serde_json::to_vec(setup)?))
}

/// Explicit synthetic diagnostic, never an alternate input path to prepare().
pub fn synthetic(
    output: &Path,
    authenticated: Option<&Path>,
    deferred_coin: bool,
) -> Result<Value> {
    let mut rng = rand::rng();
    let mut binding = json!({"synthetic":true,"scope":"nonexistent note/UTXO; no chain acceptance or wallet reservation"});
    let (principal, joint, alice, bob) = if let Some(path) = authenticated {
        let descriptor = storage::json(path)?;
        let checked = crate::public_setup::authenticate(&descriptor)?;
        binding["destinations_sha256"] = json!(hash_setup(&descriptor)?);
        binding["quote_digest"] = checked["quote_digest"].clone();
        binding["destinations_authenticated"] = json!(true);
        let roles = &checked["destinations"];
        (
            amount(&checked, "principal_zatoshi")?,
            parse_fvk(roles, "joint_fvk")?,
            crate::participants::receiver(roles, "alice")?,
            crate::participants::receiver(roles, "bob")?,
        )
    } else {
        (
            1_010_000,
            FullViewingKey::from(&crate::random_key(&mut rng)),
            FullViewingKey::from(&crate::random_key(&mut rng)).address_at(0u32, Scope::External),
            FullViewingKey::from(&crate::random_key(&mut rng)).address_at(0u32, Scope::External),
        )
    };
    let source_key = crate::random_key(&mut rng);
    let source_fvk = FullViewingKey::from(&source_key);
    // A deferred draft needs change for the auxiliary transaction.
    let extra = if deferred_coin { 50_000 } else { 1 };
    let note = crate::note(&source_fvk, principal + 10_000 + extra, &mut rng);
    let path = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
    );
    let key = secp256k1::SecretKey::from_secret_bytes([1; 32])?;
    let public = secp256k1::PublicKey::from_secret_key(&key);
    let address = zcash_transparent::address::TransparentAddress::from_pubkey(&public);
    let auxiliary = if deferred_coin {
        RefundCoin::Deferred(key)
    } else {
        RefundCoin::Reserved(Auxiliary {
            key,
            public,
            address,
            txid: zcash_protocol::TxId::from_bytes([0x13; 32]),
            index: 0,
            coin: zcash_transparent::bundle::TxOut::new(
                zcash_protocol::value::Zatoshis::from_u64(20_000)?,
                address.script().into(),
            ),
        })
    };
    let height = u32::from(
        TEST_NETWORK
            .activation_height(NetworkUpgrade::Nu7)
            .ok_or("NU7")?,
    ) + 1;
    let mut report = build(
        Draft {
            source: Source {
                fvk: source_fvk,
                note,
                path,
            },
            principal,
            height,
            joint,
            alice,
            bob,
            auxiliary,
            lock: RefundLock::timestamp(1_800_000_000)?,
        },
        output,
        binding,
    )?;
    // Diagnostic-only nonexistent source. Retain its random key privately so
    // the source signing primitive can be exercised without a funded wallet.
    // This directory is never a public reservation and cannot pass prepare().
    let source = output.join("synthetic-source");
    storage::create_dir(&source)?;
    storage::write(&source.join("spending-key.bin"), source_key.to_bytes())?;
    storage::write(&source.join("aux-key.bin"), &[1; 32])?;
    storage::atomic_json(
        &source.join("network.json"),
        &json!({"genesis":TESTNET_GENESIS}),
    )?;
    report["synthetic"] = json!(true);
    Ok(report)
}
