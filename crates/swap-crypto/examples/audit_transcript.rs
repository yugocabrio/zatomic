//! Disposable transcript for the independent arithmetic checker, not a wallet.
//! Writes private synthetic material only to a new 0600 file; prints no shares.
use ff::{Field, PrimeField};
use group::GroupEncoding;
use pasta_curves::pallas;
use rand_core::OsRng;
use serde_json::json;
use shielded_swap_crypto::{Context, Identifier, Nonce, SigningSession, generator, keys};
use std::{collections::BTreeMap, io::Write, os::unix::fs::OpenOptionsExt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("private output path required")?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let a = Identifier::try_from(1u16)?;
    let b = Identifier::try_from(2u16)?;
    let (a1, ap1) = keys::dkg::part1(a, 2, 2, OsRng)?;
    let (b1, bp1) = keys::dkg::part1(b, 2, 2, OsRng)?;
    let ar = BTreeMap::from([(b, bp1)]);
    let br = BTreeMap::from([(a, ap1)]);
    let (a2, ap2) = keys::dkg::part2(a1, &ar)?;
    let (b2, bp2) = keys::dkg::part2(b1, &br)?;
    let (ak, public) = keys::dkg::part3(&a2, &ar, &BTreeMap::from([(b, bp2[&a].clone())]))?;
    let (bk, other) = keys::dkg::part3(&b2, &br, &BTreeMap::from([(a, ap2[&b].clone())]))?;
    if public != other {
        return Err("DKG public packages differ".into());
    }
    let keys = BTreeMap::from([(a, ak), (b, bk)]);
    let mut transcripts = Vec::new();
    for (index, alpha) in [
        pallas::Scalar::ZERO,
        pallas::Scalar::random(OsRng),
        -pallas::Scalar::ONE,
    ]
    .into_iter()
    .enumerate()
    {
        let witness = loop {
            let t = pallas::Scalar::random(OsRng);
            if t != pallas::Scalar::ZERO {
                break t;
            }
        };
        let context = Context {
            session: [index as u8 + 1; 32],
            message: [index as u8 + 9; 32],
            randomizer: alpha.to_repr(),
            adaptor_point: (generator() * witness).to_bytes(),
        };
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, key) in &keys {
            let (nonce, commitment) = Nonce::generate(key, &mut OsRng);
            nonces.insert(*id, nonce);
            commitments.insert(*id, commitment);
        }
        let signing = SigningSession::new(context.clone(), public.clone(), commitments.clone())?;
        let shares = nonces
            .into_iter()
            .map(|(id, nonce)| Ok((id, signing.sign(&keys[&id], nonce)?)))
            .collect::<shielded_swap_crypto::Result<BTreeMap<_, _>>>()?;
        let pre = signing.aggregate(&shares)?;
        let signature = pre.adapt(&witness.to_repr())?;
        pre.verify_final(&signature)?;
        let participants = commitments
            .iter()
            .map(|(id, c)| {
                Ok(json!({
                    "id":hex::encode(id.serialize()),
                    "hiding":hex::encode(c.hiding().serialize()?),
                    "binding":hex::encode(c.binding().serialize()?),
                    "verifying_share":hex::encode(public.verifying_shares()[id].serialize()?),
                    "signature_share":hex::encode(shares[id])
                }))
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        transcripts.push(json!({"session":hex::encode(context.session), "message":hex::encode(context.message),
            "randomizer":hex::encode(alpha.to_repr()), "adaptor_point":hex::encode(context.adaptor_point),
            "public_key":hex::encode(public.verifying_key().serialize()?),
            "randomized_key":hex::encode(pre.key), "r_hat":hex::encode(pre.r_hat),
            "s_hat":hex::encode(pre.s_hat), "signature":hex::encode(signature),
            "witness":hex::encode(witness.to_repr()), "participants":participants}));
    }
    serde_json::to_writer_pretty(
        &mut output,
        &json!({"version":1,
        "scope":"private disposable review transcript; never use for funds or publish",
        "current_native_verifier_passed":true, "transcripts":transcripts}),
    )?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    println!("Three disposable transcripts saved privately; native verification passed.");
    Ok(())
}
