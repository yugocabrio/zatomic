//! Complete offline public-profile agreement and conditional owner consent.
//! These signatures never substitute for live observation/release gates.
use crate::{Result, evm_key, funding_consent::hash, public_recovery, storage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};

const DOMAIN: &[u8] = b"Latch public cross-chain conditional consent v1\0";
const POLICY: &str = include_str!("../../../config/public-agreement-policy-v1.json");

fn u32_value(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .filter(|n| *n <= u64::from(u32::MAX))
        .ok_or_else(|| format!("uint32 {key} required").into())
}
fn digest(v: &Value) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(serde_json::to_vec(v)?);
    Ok(h.finalize().into())
}
fn immutable(path: &Path, v: &Value) -> Result<()> {
    if path.exists() {
        if storage::json(path)? != *v {
            return Err("immutable conditional agreement changed".into());
        }
    } else {
        storage::atomic_json(path, v)?;
    }
    Ok(())
}
fn hex_field(v: &str, length: usize) -> Result<()> {
    let bytes = hex::decode(v.strip_prefix("0x").ok_or("0x prefix required")?)?;
    if bytes.len() != length
        || bytes.iter().all(|b| *b == 0)
        || format!("0x{}", hex::encode(bytes)) != v
    {
        return Err("canonical nonzero contract/salt required".into());
    }
    Ok(())
}

/// Recompute the exact fixed candidate clock/fee policy even for direct native
/// callers. Current-time and chain observations are deliberately not fabricated.
fn validate_plan(plan: &Value, policy: &Value) -> Result<()> {
    let p = &policy["timestamp_policy"];
    let created = u32_value(plan, "created_at")?;
    let expiry = created
        .checked_add(u32_value(p, "eth_expiry_after_creation_seconds")?)
        .ok_or("time overflow")?;
    let refund = expiry
        .checked_add(u32_value(p, "native_refund_after_eth_expiry_seconds")?)
        .ok_or("time overflow")?;
    let mut fees = policy["fee_policy"].clone();
    let cap = plan["fee_policy"]["max_gas_price_wei"]
        .as_u64()
        .ok_or("gas cap integer")?;
    if cap == 0 || cap > fees["max_gas_price_wei"].as_u64().ok_or("policy gas cap")? {
        return Err("gas cap outside policy".into());
    }
    fees["max_gas_price_wei"] = json!(cap);
    let expected = json!({"policy":p,"created_at":created,"eth_expiry":expiry,
        "fund_before":expiry.checked_sub(u32_value(p,"funding_cutoff_before_expiry_seconds")?).ok_or("funding cutoff")?,
        "first_reveal_before":expiry.checked_sub(u32_value(p,"reveal_cutoff_before_expiry_seconds")?).ok_or("reveal cutoff")?,
        "native_refund_lock":{"kind":"timestamp","value":refund},"fee_policy":fees});
    if refund > u64::from(u32::MAX) || refund < 500_000_000 || *plan != expected {
        return Err("unsupported clock/fee policy or derived deadline".into());
    }
    let clock = u32_value(p, "clock_error_seconds")?;
    let native_work = [
        "secret_observation_seconds",
        "native_proof_seconds",
        "native_inclusion_seconds",
        "native_confirmation_seconds",
        "native_reorg_recovery_seconds",
    ]
    .into_iter()
    .try_fold(0u64, |n, k| {
        Ok::<_, Box<dyn std::error::Error>>(n + u32_value(p, k)?)
    })?;
    let reveal_work = 2 * clock
        + u32_value(p, "eth_inclusion_seconds")?
        + u32_value(p, "eth_settlement_seconds")?
        + u32_value(p, "eth_retry_seconds")?;
    if refund - u32_value(p, "native_early_header_seconds")? - clock <= expiry + clock + native_work
        || u32_value(p, "reveal_cutoff_before_expiry_seconds")? <= reveal_work
    {
        return Err("unsafe strict clock gap".into());
    }
    Ok(())
}

fn agreement(bundle: &Value, receipts: &Value, contract: &str, salt: &str) -> Result<Value> {
    hex_field(contract, 20)?;
    hex_field(salt, 32)?;
    let checked = public_recovery::check_receipts(bundle, receipts)?;
    let policy: Value = serde_json::from_str(POLICY)?;
    let packet = &bundle["review"];
    let plan = &packet["plan"];
    validate_plan(plan, &policy)?;
    let quote = &packet["destinations"]["trade"]["offer"]["payload"];
    let setup = &packet["destinations"]["setup"];
    // A zero-authorized F preview is sufficient to check its public fee, but
    // never to fund. Its complete proof/shape was verified by check_receipts.
    let raw = hex::decode(
        packet["funding_preview"]
            .as_str()
            .ok_or("funding preview")?,
    )?;
    let tx = zcash_primitives::transaction::Transaction::read(
        &raw[..],
        zcash_protocol::consensus::BranchId::Nu7,
    )?;
    if i64::from(
        *tx.ironwood_bundle()
            .ok_or("funding bundle")?
            .value_balance(),
    ) != 10_000
    {
        return Err("funding fee differs from fixed public profile".into());
    }
    Ok(
        json!({"format":"latch-public-cross-chain-agreement-v1","policy_digest":hash(&policy)?,
        "native_genesis":packet["graph"]["native_genesis"],"native_branch":packet["graph"]["native_branch"],
        "eth_chain_id":policy["escrow"]["chain_id"],"eth_genesis":policy["escrow"]["genesis"],
        "quote_digest":hash(quote)?,"owners":quote["owners"],"bundle_digest":checked["bundle_digest"],
        "native_receipts_digest":hash(receipts)?,"review_packet_digest":checked["review_packet_digest"],
        "graph_digest":checked["graph_digest"],"execution_plan_digest":checked["execution_plan_digest"],
        "execution_plan":plan,"native":{"funding_txid":packet["graph"]["funding_txid"],
            "principal_zatoshi":packet["graph"]["principal_zatoshi"],"payout_zatoshi":quote["payout_zatoshi"],
            "refund_lock":plan["native_refund_lock"],"funding_fee_zatoshi":10_000,
            "claim_fee_zatoshi":10_000,"refund_auxiliary_fee_zatoshi":5_000},
        "escrow":{"contract":contract,"salt":salt,"runtime_code_hash":policy["escrow"]["runtime_code_hash"],
            "creation_code_hash":policy["escrow"]["creation_code_hash"],"constructor_arguments":"0x"},
        "maker":quote["owners"]["bob"]["address"],"recipient":quote["owners"]["alice"]["address"],
        "amount_wei":quote["eth_amount_wei"],"point_x":setup["point_x"],"point_y":setup["point_y"],
        "eth_expiry":plan["eth_expiry"],"fee_policy":plan["fee_policy"],"observation_policy":policy["observation_policy"],
        "synthetic_inputs":bundle["synthetic_inputs"],"release_requires_live_checks":true,
        "scope":"offline conditional agreement; no deployment, chain observation or transaction release"}),
    )
}

pub fn stage(
    bundle: &Path,
    receipts: &Path,
    contract: &str,
    salt: &str,
    output: &Path,
) -> Result<Value> {
    let bundle = storage::json(bundle)?;
    let receipts = storage::json(receipts)?;
    let agreement = agreement(&bundle, &receipts, contract, salt)?;
    let proposal = json!({"format":"latch-public-consent-proposal-v1","agreement":agreement,"receipts":receipts});
    immutable(output, &proposal)?;
    Ok(
        json!({"file":output,"agreement_digest":hash(&proposal["agreement"])?,
        "both_native_receipts_verified":true,"conditional_consents_present":false,"funding_authorized":false}),
    )
}

fn validate(bundle: &Value, proposal: &Value) -> Result<Value> {
    let actual = &proposal["agreement"];
    let expected = agreement(
        bundle,
        &proposal["receipts"],
        actual["escrow"]["contract"]
            .as_str()
            .ok_or("escrow contract")?,
        actual["escrow"]["salt"].as_str().ok_or("escrow salt")?,
    )?;
    if proposal.as_object().is_none_or(|o| o.len() != 3)
        || proposal["format"] != "latch-public-consent-proposal-v1"
        || *actual != expected
    {
        return Err("conditional agreement differs from native/owner/clock/escrow policy".into());
    }
    Ok(expected)
}
fn payload(agreement: &Value, role: &str) -> Result<Value> {
    Ok(
        json!({"format":"latch-public-conditional-consent-v1","role":role,
        "agreement_digest":hash(agreement)?,"bundle_digest":agreement["bundle_digest"],
        "synthetic_inputs":agreement["synthetic_inputs"],"release_requires_live_checks":true}),
    )
}
fn verify_consent(consent: &Value, agreement: &Value, role: &str) -> Result<()> {
    if consent.as_object().is_none_or(|o| o.len() != 2)
        || consent["payload"] != payload(agreement, role)?
    {
        return Err("conditional consent role/agreement mismatch".into());
    }
    evm_key::verify(
        &agreement["owners"][role],
        &consent["signature"],
        digest(&consent["payload"])?,
    )
}

pub fn sign(dir: &Path, input: &Path) -> Result<Value> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("setup.lock"))?;
    lock.try_lock().map_err(|_| "owner session busy")?;
    let bundle = storage::json(&dir.join("public-native-recovery.json"))?;
    let proposal = storage::json(input)?;
    let identity = storage::json(&dir.join("identity.json"))?;
    let (role, peer) = match identity["role"].as_str() {
        Some("alice") => ("alice", "bob"),
        Some("bob") => ("bob", "alice"),
        _ => return Err("owner role".into()),
    };
    if bundle["review"] != storage::json(&dir.join("reviewed-graph-packet.json"))?
        || bundle["review"]["destinations"]["trade"]
            != storage::json(&dir.join("accepted-trade.json"))?
        || proposal["receipts"][role]
            != storage::json(&dir.join("public-native-recovery-receipt.json"))?
    {
        return Err("owner did not retain/accept this exact native bundle".into());
    }
    let agreement = validate(&bundle, &proposal)?;
    if agreement["owners"][role] != identity
        || agreement["owners"][peer] != storage::json(&dir.join("trusted-peer.json"))?["identity"]
    {
        return Err("consent identities differ from local pins".into());
    }
    immutable(&dir.join("public-consent-proposal.json"), &proposal)?;
    let saved = dir.join("public-conditional-consent.json");
    if saved.exists() {
        let consent = storage::json(&saved)?;
        verify_consent(&consent, &agreement, role)?;
        return Ok(consent);
    }
    let payload = payload(&agreement, role)?;
    let signature = evm_key::sign_digest(&dir.join("ethereum"), digest(&payload)?)?;
    let consent = json!({"payload":payload,"signature":signature});
    verify_consent(&consent, &agreement, role)?;
    immutable(&saved, &consent)?;
    Ok(consent)
}

pub fn verify(bundle: &Path, proposal: &Path, consents: &Path) -> Result<Value> {
    let bundle = storage::json(bundle)?;
    let agreement = validate(&bundle, &storage::json(proposal)?)?;
    let consents = storage::json(consents)?;
    if consents.as_object().is_none_or(|o| o.len() != 2) {
        return Err("both conditional consents required".into());
    }
    for role in ["alice", "bob"] {
        verify_consent(&consents[role], &agreement, role)?;
    }
    // derive the observer's exact public target from the already-verified R,
    // never from caller-selected receiving metadata or the source wallet key.
    let refund = pczt::Pczt::parse(&hex::decode(
        bundle["refund"].as_str().ok_or("signed refund PCZT")?,
    )?)
    .map_err(crate::err)?;
    let input = refund
        .transparent()
        .inputs()
        .first()
        .ok_or("refund auxiliary")?;
    let script = input.script_pubkey();
    if script.len() != 25 || script[..3] != [0x76, 0xa9, 0x14] || script[23..] != [0x88, 0xac] {
        return Err("refund auxiliary must use canonical P2PKH".into());
    }
    let address =
        zcash_transparent::address::TransparentAddress::PublicKeyHash(script[3..23].try_into()?);
    let auxiliary = json!({"genesis":agreement["native_genesis"],
        "aux_address":address.to_zcash_address(zcash_protocol::consensus::NetworkType::Test).to_string(),
        "aux_script":hex::encode(script),
        "txid":zcash_protocol::TxId::from_bytes(*input.prevout_txid()).to_string(),
        "index":input.prevout_index(),"value_zatoshi":input.value()});
    // Deliberately not a token usable by the existing source authorizer.
    Ok(
        json!({"format":"latch-public-conditional-consents-check-v1","agreement_digest":hash(&agreement)?,
        "bundle_digest":agreement["bundle_digest"],"both_owner_signatures_verified":true,
        "native_auxiliary":auxiliary,
        "synthetic_inputs":agreement["synthetic_inputs"],"live_observations_checked":false,
        "release_requires_live_checks":true,"funding_authorized":false,"broadcast":false}),
    )
}
