//! End-to-end sealed messages between two pinned owners over an untrusted relay.
//!
//! Each owner holds a dedicated secp256k1 relay key, separate from its ETH key.
//! Its public half is in the operator manifest, so the fingerprint both owners
//! compare also pins it. A message key combines an ephemeral-static and a
//! static-static ECDH: only the recipient can open a message, only the pinned
//! sender (or the recipient) can produce one, and a later leak of the sender's
//! static key does not open earlier messages. The topic travels inside the
//! ciphertext. The relay learns sender, recipient, size and time only.
use crate::{Result, storage};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use rand::Rng;
use secp256k1::{PublicKey, SecretKey, ecdh::SharedSecret};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

const DOMAIN: &[u8] = b"latch-relay-envelope-v1";
const KEY_FILE: &str = "relay-key.bin";
const INPUT_LIMIT: u64 = 2_000_000;

fn random_secret() -> SecretKey {
    let mut rng = rand::rng();
    loop {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_secret_bytes(bytes) {
            return key;
        }
    }
}

/// Create this owner's relay key once; refuses to replace an existing key.
pub fn init(dir: &Path) -> Result<Value> {
    let key = random_secret();
    storage::write(&dir.join(KEY_FILE), &key.to_secret_bytes())?;
    Ok(json!({"relay_public_key":hex::encode(PublicKey::from_secret_key(&key).serialize())}))
}

fn own_key(dir: &Path) -> Result<SecretKey> {
    let bytes = storage::read(&dir.join(KEY_FILE), 32)?
        .try_into()
        .map_err(|_| "relay key length")?;
    Ok(SecretKey::from_secret_bytes(bytes)?)
}

fn role(value: &Value, field: &str) -> Result<u8> {
    match value[field].as_str() {
        Some("alice") => Ok(1),
        Some("bob") => Ok(2),
        _ => Err(format!("{field} must be alice or bob").into()),
    }
}

fn point(value: &Value, field: &str) -> Result<PublicKey> {
    Ok(PublicKey::from_byte_array_compressed(crate::decode::<33>(
        value, field,
    )?)?)
}

/// Header bound as AEAD associated data; the key derivation repeats it.
fn header(
    from: u8,
    to: u8,
    ephemeral: &PublicKey,
    sender: &PublicKey,
    recipient: &PublicKey,
) -> Vec<u8> {
    let mut data = DOMAIN.to_vec();
    data.extend([from, to]);
    data.extend(ephemeral.serialize());
    data.extend(sender.serialize());
    data.extend(recipient.serialize());
    data
}

fn cipher(
    header: &[u8],
    ephemeral_shared: SharedSecret,
    static_shared: SharedSecret,
) -> ChaCha20Poly1305 {
    let mut hash = Sha256::new();
    hash.update(header);
    hash.update(ephemeral_shared.to_secret_bytes());
    hash.update(static_shared.to_secret_bytes());
    let key: [u8; 32] = hash.finalize().into();
    ChaCha20Poly1305::new(&key.into())
}

fn input() -> Result<Value> {
    let mut raw = Vec::new();
    std::io::stdin()
        .take(INPUT_LIMIT + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > INPUT_LIMIT {
        return Err("relay input exceeds size limit".into());
    }
    Ok(serde_json::from_slice(&raw)?)
}

fn seal(own: &SecretKey, request: &Value) -> Result<Value> {
    let (from, to) = (role(request, "from")?, role(request, "to")?);
    let topic = request["topic"].as_str().ok_or("topic")?;
    if from == to || topic.is_empty() || !request["body"].is_object() {
        return Err("sealed message needs two owners, a topic and an object body".into());
    }
    let recipient = point(request, "peer")?;
    let sender = PublicKey::from_secret_key(own);
    let ephemeral_secret = random_secret();
    let ephemeral = PublicKey::from_secret_key(&ephemeral_secret);
    let header = header(from, to, &ephemeral, &sender, &recipient);
    let cipher = cipher(
        &header,
        SharedSecret::new(&recipient, &ephemeral_secret),
        SharedSecret::new(&recipient, own),
    );
    let nonce: [u8; 12] = rand::random();
    let plaintext = serde_json::to_vec(&json!({"topic":topic,"body":request["body"]}))?;
    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| "relay encryption failed")?;
    Ok(json!({"v":1,"from":request["from"],"to":request["to"],
        "epk":hex::encode(ephemeral.serialize()),"nonce":hex::encode(nonce),"ct":hex::encode(ciphertext)}))
}

/// Opens one envelope addressed to `own` from the pinned `sender`, or refuses.
fn open(own: &SecretKey, sender: &PublicKey, from: u8, to: u8, envelope: &Value) -> Result<Value> {
    if envelope["v"] != 1 || role(envelope, "from")? != from || role(envelope, "to")? != to {
        return Err("envelope is not addressed from the pinned peer to this owner".into());
    }
    let ephemeral = point(envelope, "epk")?;
    let nonce = crate::decode::<12>(envelope, "nonce")?;
    let ciphertext = hex::decode(envelope["ct"].as_str().ok_or("ciphertext")?)?;
    let header = header(
        from,
        to,
        &ephemeral,
        sender,
        &PublicKey::from_secret_key(own),
    );
    let cipher = cipher(
        &header,
        SharedSecret::new(&ephemeral, own),
        SharedSecret::new(sender, own),
    );
    let plaintext = cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &ciphertext,
                aad: &header,
            },
        )
        .map_err(|_| "relay envelope failed authentication")?;
    let message: Value = serde_json::from_slice(&plaintext)?;
    if !message["topic"].is_string() || !message["body"].is_object() {
        return Err("sealed message shape".into());
    }
    Ok(message)
}

/// stdin: {from, to, peer, topic, body}. `peer` is the recipient's pinned key.
pub fn seal_stdin(dir: &Path) -> Result<Value> {
    seal(&own_key(dir)?, &input()?)
}

/// stdin: {from, to, peer, envelopes}. `peer` is the sender's pinned key. An
/// envelope that fails to open yields null: the relay can drop or inject
/// messages, but cannot read or alter one.
pub fn open_stdin(dir: &Path) -> Result<Value> {
    let own = own_key(dir)?;
    let request = input()?;
    let (from, to) = (role(&request, "from")?, role(&request, "to")?);
    let sender = point(&request, "peer")?;
    let envelopes = request["envelopes"].as_array().ok_or("envelopes")?;
    Ok(json!({"messages":envelopes.iter()
        .map(|e| open(&own, &sender, from, to, e).unwrap_or(Value::Null))
        .collect::<Vec<_>>()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SecretKey, SecretKey, String, String) {
        let (a, b) = (random_secret(), random_secret());
        let hex_of = |k: &SecretKey| hex::encode(PublicKey::from_secret_key(k).serialize());
        let (pa, pb) = (hex_of(&a), hex_of(&b));
        (a, b, pa, pb)
    }

    fn sealed(a: &SecretKey, pb: &str) -> Value {
        seal(
            a,
            &json!({"from":"alice","to":"bob","peer":pb,"topic":"agreement",
            "body":{"principal_zatoshi":1_700_000,"funding_txid":"ab".repeat(32)}}),
        )
        .unwrap()
    }

    #[test]
    fn only_the_recipient_opens_a_message_from_the_pinned_sender() {
        let (a, b, pa, pb) = pair();
        let envelope = sealed(&a, &pb);
        let text = envelope.to_string();
        assert!(!text.contains("principal_zatoshi") && !text.contains(&"ab".repeat(32)));
        let alice = PublicKey::from_secret_key(&a);
        let opened = open(&b, &alice, 1, 2, &envelope).unwrap();
        assert_eq!(opened["topic"], "agreement");
        assert_eq!(opened["body"]["principal_zatoshi"], 1_700_000);
        // A third party, or the sender itself, cannot open it.
        let (eve, _, pe, _) = pair();
        assert!(open(&eve, &alice, 1, 2, &envelope).is_err());
        assert!(open(&a, &alice, 1, 2, &envelope).is_err());
        let _ = (pa, pe);
    }

    #[test]
    fn forged_or_altered_envelopes_are_refused() {
        let (a, b, _, pb) = pair();
        let alice = PublicKey::from_secret_key(&a);
        let envelope = sealed(&a, &pb);
        // Someone else using Bob's public key cannot pose as Alice.
        let (eve, _, _, _) = pair();
        let forged = sealed(&eve, &pb);
        assert!(open(&b, &alice, 1, 2, &forged).is_err());
        // Any changed byte, swapped direction or replaced ephemeral key fails.
        let mut changed = envelope.clone();
        let mut ct = hex::decode(changed["ct"].as_str().unwrap()).unwrap();
        ct[0] ^= 1;
        changed["ct"] = json!(hex::encode(ct));
        assert!(open(&b, &alice, 1, 2, &changed).is_err());
        let mut turned = envelope.clone();
        turned["from"] = json!("bob");
        turned["to"] = json!("alice");
        assert!(open(&b, &alice, 2, 1, &turned).is_err());
        let mut rekeyed = envelope.clone();
        rekeyed["epk"] = json!(hex::encode(
            PublicKey::from_secret_key(&random_secret()).serialize()
        ));
        assert!(open(&b, &alice, 1, 2, &rekeyed).is_err());
        // The same message sealed twice shares no ephemeral key or ciphertext.
        let again = sealed(&a, &pb);
        assert_ne!(again["epk"], envelope["epk"]);
        assert_ne!(again["ct"], envelope["ct"]);
    }
}
