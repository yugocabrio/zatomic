//! Offline source-wallet release gate. Owner identity pins are provisioned by
//! the local fixture; independent operators must authenticate those separately.
//! Chain observations/deadlines belong to the source client, not this verifier.
use crate::{Result, storage};
use secp256k1::{
    Message, PublicKey,
    ecdsa::{self, RecoverableSignature, RecoveryId},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn hash(v: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(v)?)))
}

pub fn stage(dir: &Path, pins: Value, unsigned: &[u8], terms: &Value) -> Result<()> {
    for role in ["alice", "bob"] {
        let public: [u8; 65] = hex::decode(pins[role]["public_key"].as_str().ok_or("owner pin")?)?
            .try_into()
            .map_err(|_| "owner public key length")?;
        PublicKey::from_byte_array_uncompressed(public)?;
        if pins[role]["role"] != role || pins[role]["chain_id"] != 31338 {
            return Err("owner pin domain".into());
        }
    }
    if pins["alice"]["public_key"] == pins["bob"]["public_key"]
        || pins["alice"]["address"] == pins["bob"]["address"]
    {
        return Err("distinct owners required".into());
    }
    storage::write_json(
        &dir.join("funding-policy.json"),
        &json!({
            "pins":pins, "terms_digest":hash(terms)?,
            "unsigned_digest":hex::encode(Sha256::digest(unsigned)),
            "receipts_digest":hash(&storage::json(&dir.join("participant-receipts.json"))?)?
        }),
    )
}

pub fn verify(dir: &Path, packet_path: &Path, unsigned: &[u8]) -> Result<Value> {
    let policy = storage::json(&dir.join("funding-policy.json"))?;
    let terms = storage::json(&dir.join("terms.json"))?;
    let receipts = storage::json(&dir.join("participant-receipts.json"))?;
    let packet = storage::json(packet_path)?;
    let agreement = &packet["agreement"];
    let pins = &policy["pins"];
    if policy["terms_digest"] != hash(&terms)?
        || policy["receipts_digest"] != hash(&receipts)?
        || policy["unsigned_digest"] != hex::encode(Sha256::digest(unsigned))
        || agreement["native"] != terms
        || terms["owner_pins"] != *pins
        || agreement["consent_version"] != 1
        || agreement["eth_chain_id"] != 31338
        || agreement["amount_wei"] != 10_000_000_000_000_000u64
        || agreement["maker"] != pins["bob"]["address"]
        || agreement["recipient"] != pins["alice"]["address"]
    {
        return Err("source consent policy mismatch".into());
    }
    let agreement_digest = hash(agreement)?;
    for role in ["alice", "bob"] {
        let receipt = &receipts[role];
        let consent = &packet["consents"][role];
        let expected = json!({"role":role,"agreement_digest":agreement_digest,
            "bundle_digest":receipt["bundle_digest"],"version":1});
        if receipt["durably_saved"] != true
            || receipt["funding_txid"] != terms["funding_txid"]
            || consent["payload"] != expected
        {
            return Err("missing or changed owner consent".into());
        }
        let mut digest = Sha256::new();
        digest.update(b"Latch cross-chain funding consent v1\0");
        digest.update(serde_json::to_vec(&expected)?);
        let message = Message::from_digest(digest.finalize().into());
        let sig = &consent["signature"];
        let parity = sig["parity"].as_u64().ok_or("signature parity")?;
        if parity > 1 {
            return Err("signature parity".into());
        }
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&crate::decode::<32>(sig, "r")?);
        compact[32..].copy_from_slice(&crate::decode::<32>(sig, "s")?);
        let signature =
            RecoverableSignature::from_compact(&compact, RecoveryId::try_from(parity as i32)?)?;
        let public: [u8; 65] = hex::decode(pins[role]["public_key"].as_str().ok_or("public key")?)?
            .try_into()
            .map_err(|_| "public key length")?;
        let public = PublicKey::from_byte_array_uncompressed(public)?;
        // Standard verification also rejects high-S malleability.
        ecdsa::verify(&signature.to_standard(), message, &public)?;
        if signature.recover_ecdsa(message)? != public {
            return Err("consent signer mismatch".into());
        }
    }
    Ok(
        json!({"funding_txid":terms["funding_txid"],"agreement_digest":agreement_digest,
        "both_owner_signatures_verified":true,"version":1}),
    )
}
