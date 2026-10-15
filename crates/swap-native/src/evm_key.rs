//! Owner-local secp256k1 primitive. Policy lives in the EVM participant client.
//! Never expose this digest-signing command as a network signing service.
use crate::{Result, storage};
use rand::Rng;
use secp256k1::{
    Message, PublicKey, SecretKey,
    ecdsa::{self, RecoverableSignature, RecoveryId},
};
use serde_json::{Value, json};
use std::{io::Read, path::Path};

pub fn init(dir: &Path) -> Result<Value> {
    storage::create_dir(dir)?;
    let mut rng = rand::rng();
    let secret = loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_secret_bytes(bytes) {
            break key;
        }
    };
    storage::write(&dir.join("ethereum-key.bin"), &secret.to_secret_bytes())?;
    Ok(
        json!({"public_key":hex::encode(PublicKey::from_secret_key(&secret).serialize_uncompressed())}),
    )
}

fn sign(secret: &SecretKey, digest: [u8; 32]) -> Result<Value> {
    let message = Message::from_digest(digest);
    let signature = RecoverableSignature::sign_ecdsa_recoverable(message, secret);
    if signature.recover_ecdsa(message)? != PublicKey::from_secret_key(secret) {
        return Err("ECDSA self-verification failed".into());
    }
    let (id, bytes) = signature.serialize_compact();
    let parity = id.to_u8();
    if parity > 1 {
        return Err("unsupported rare Ethereum recovery id".into());
    }
    Ok(json!({"parity":parity,"r":hex::encode(&bytes[..32]),"s":hex::encode(&bytes[32..])}))
}

pub fn sign_stdin(dir: &Path) -> Result<Value> {
    let mut input = Vec::new();
    std::io::stdin().take(66).read_to_end(&mut input)?;
    if input.len() != 65 || input[64] != b'\n' {
        return Err("one 32-byte digest required on stdin".into());
    }
    let digest = hex::decode(&input[..64])?
        .try_into()
        .map_err(|_| "digest length")?;
    let bytes = storage::read(&dir.join("ethereum-key.bin"), 32)?
        .try_into()
        .map_err(|_| "Ethereum key length")?;
    sign(&SecretKey::from_secret_bytes(bytes)?, digest)
}

/// Verify a domain-separated application digest against the exact pinned key.
pub fn verify(public: &Value, sig: &Value, digest: [u8; 32]) -> Result<()> {
    let public = PublicKey::from_byte_array_uncompressed(crate::decode(public, "public_key")?)?;
    let parity = sig["parity"].as_u64().ok_or("signature parity")?;
    if parity > 1 {
        return Err("signature parity".into());
    }
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&crate::decode::<32>(sig, "r")?);
    bytes[32..].copy_from_slice(&crate::decode::<32>(sig, "s")?);
    let signature =
        RecoverableSignature::from_compact(&bytes, RecoveryId::try_from(parity as i32)?)?;
    let message = Message::from_digest(digest);
    ecdsa::verify(&signature.to_standard(), message, &public)?;
    if signature.recover_ecdsa(message)? != public {
        return Err("signature owner mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_eip155_signature_vector() -> Result<()> {
        // Public standard test vector, never a wallet or funded key.
        // https://eips.ethereum.org/EIPS/eip-155#example
        let key = SecretKey::from_secret_bytes([0x46; 32])?;
        let digest =
            hex::decode("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53")?
                .try_into()
                .unwrap();
        let result = sign(&key, digest)?;
        assert_eq!(result["parity"], 0);
        assert_eq!(
            result["r"],
            "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
        );
        assert_eq!(
            result["s"],
            "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
        Ok(())
    }
}
