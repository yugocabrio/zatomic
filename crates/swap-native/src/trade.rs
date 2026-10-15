//! Agreed OTC amounts. Quotes authorize preparation, never a spend by themselves.
use crate::{Result, evm_key, funding_consent, storage, wallet};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use zcash_protocol::value::Zatoshis;

pub const CLAIM_FEE: u64 = 10_000;
pub const MAX_ETH: u64 = 10_000_000_000_000_000_000; // Explicit local-profile cap: 10 ETH.

pub struct Amounts {
    pub payout: u64,
    pub principal: u64,
    pub eth: u64,
}

fn digest(domain: &[u8], payload: &Value) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(serde_json::to_vec(payload)?);
    Ok(hash.finalize().into())
}

pub fn verify(packet: &Value, accepted: bool) -> Result<Amounts> {
    let offer = &packet["offer"];
    let p = &offer["payload"];
    if p.as_object().is_none_or(|p| p.len() != 10)
        || p["version"] != 1
        || p["native_genesis"] != wallet::GENESIS
        || p["native_branch"] != "77190ad9"
        || p["eth_chain_id"] != 31338
        || p["claim_fee_zatoshi"] != CLAIM_FEE
        || p["refund_aux_fee_zatoshi"] != 5_000
        || crate::decode::<32>(p, "quote_id").is_err()
    {
        return Err("unsupported OTC quote domain/schema/fees".into());
    }
    let pins = &p["owners"];
    for role in ["alice", "bob"] {
        if pins[role]["role"] != role || pins[role]["chain_id"] != 31338 {
            return Err("OTC owner domain".into());
        }
    }
    if pins["alice"]["public_key"] == pins["bob"]["public_key"]
        || pins["alice"]["address"] == pins["bob"]["address"]
    {
        return Err("OTC distinct owners required".into());
    }
    let payout = p["payout_zatoshi"]
        .as_u64()
        .ok_or("integer ZEC amount required")?;
    let principal = payout
        .checked_add(CLAIM_FEE)
        .ok_or("native amount overflow")?;
    Zatoshis::from_u64(
        principal
            .checked_add(CLAIM_FEE)
            .ok_or("source fee overflow")?,
    )?;
    let eth = p["eth_amount_wei"]
        .as_u64()
        .ok_or("integer ETH amount required")?;
    if payout == 0 || eth == 0 || eth > MAX_ETH {
        return Err("positive amounts within the isolated profile required".into());
    }
    evm_key::verify(
        &pins["alice"],
        &offer["signature"],
        digest(b"Latch OTC offer v1\0", p)?,
    )?;
    if accepted {
        let expected = json!({"version":1,"role":"bob","quote_digest":funding_consent::hash(p)?});
        if packet["acceptance"]["payload"] != expected {
            return Err("OTC acceptance differs".into());
        }
        evm_key::verify(
            &pins["bob"],
            &packet["acceptance"]["signature"],
            digest(b"Latch OTC acceptance v1\0", &expected)?,
        )?;
    }
    Ok(Amounts {
        payout,
        principal,
        eth,
    })
}

pub fn amounts(container: &Value) -> Result<Amounts> {
    match container.get("trade") {
        Some(trade) => verify(trade, true),
        None => Ok(Amounts {
            payout: 1_000_000,
            principal: 1_010_000,
            eth: 10_000_000_000_000_000,
        }),
    }
}

pub fn configured() -> Result<Option<Value>> {
    std::env::var_os("LATCH_TRADE_TERMS")
        .map(|p| {
            let value = storage::json(Path::new(&p))?;
            verify(&value, true)?;
            Ok(value)
        })
        .transpose()
}

pub fn inspect(path: &Path, accepted: bool) -> Result<Value> {
    let packet = storage::json(path)?;
    let a = verify(&packet, accepted)?;
    Ok(
        json!({"quote_digest":funding_consent::hash(&packet["offer"]["payload"])? ,
        "payout_zatoshi":a.payout,"principal_zatoshi":a.principal,"eth_amount_wei":a.eth,
        "alice_signature_verified":true,"bob_acceptance_verified":accepted,
        "scope":"isolated chain profile; quote alone never authorizes funding"}),
    )
}
