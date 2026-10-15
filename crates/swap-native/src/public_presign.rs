//! Offline C/R spend authorization with owner-held shares and volatile nonces.
//! R is NOT recoverable yet: its transparent auxiliary authorization is absent.
use crate::{
    Context, Identifier, Nonce, Result, SigningSession, decode, err, funding_consent::hash, keys,
    participants, public_review, regtest_swap, storage, wallet,
};
use ff_old::{Field, PrimeField};
use group_old::GroupEncoding;
use orchard::keys::FullViewingKey;
use pczt::Pczt;
use rand_core::OsRng;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

fn bytes(v: &Value, k: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(v[k].as_str().ok_or("presign bytes")?)?)
}
fn emit(v: Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", serde_json::to_string(&v)?)?;
    out.flush()?;
    Ok(())
}

/// Only a private pipe/owner-controlled authenticated command transport. No
/// network listener or arbitrary digest signing is exposed by this command.
pub fn serve(dir: &Path) -> Result<()> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join("setup.lock"))?;
    lock.try_lock().map_err(|_| "public owner session busy")?;
    let packet = storage::json(&dir.join("reviewed-graph-packet.json"))?;
    let identity = storage::json(&dir.join("identity.json"))?;
    let (role, id, peer) = match identity["role"].as_str() {
        Some("alice") => ("alice", 1u16, "bob"),
        Some("bob") => ("bob", 2u16, "alice"),
        _ => return Err("owner role".into()),
    };
    if packet["destinations"] != storage::json(&dir.join("authenticated-destinations.json"))?
        || packet["destinations"]["trade"] != storage::json(&dir.join("accepted-trade.json"))?
        || packet["destinations"]["trade"]["offer"]["payload"]["owners"][role] != identity
        || packet["destinations"]["trade"]["offer"]["payload"]["owners"][peer]
            != storage::json(&dir.join("trusted-peer.json"))?["identity"]
    {
        return Err("public signer local acceptance changed".into());
    }
    let own = wallet::fvk(&dir.join("native"))?;
    let verified = public_review::verify(&packet, &own, id)?;
    if verified.report != storage::json(&dir.join("graph-review.json"))?
        || verified.policy != storage::json(&dir.join("reviewed-graph-policy.json"))?
    {
        return Err("owner did not review this exact graph/plan".into());
    }
    let setup = &packet["destinations"]["setup"];
    let complete = storage::json(&dir.join("setup-complete.json"))?;
    let key = keys::KeyPackage::deserialize(&bytes(&complete, "key")?).map_err(err)?;
    let public = keys::PublicKeyPackage::deserialize(&bytes(setup, "public")?).map_err(err)?;
    let mine = Identifier::try_from(id).map_err(err)?;
    let peer_id = Identifier::try_from(3 - id).map_err(err)?;
    if *key.identifier() != mine
        || *key.min_signers() != 2
        || key.verifying_key() != public.verifying_key()
        || public.verifying_shares().get(&mine) != Some(key.verifying_share())
    {
        return Err("public signer DKG share mismatch".into());
    }
    if id == 1 {
        let first = storage::json(&dir.join("setup-round1.json"))?;
        let witness = pasta_old::pallas::Scalar::from_repr(decode(&first, "witness_le")?)
            .into_option()
            .ok_or("witness encoding")?;
        if hex::encode((shielded_swap_crypto::generator() * witness).to_bytes())
            != setup["adaptor_point"]
        {
            return Err("owner adaptor witness mismatch".into());
        }
    }
    emit(json!({"format":"latch-public-reviewed-signer-v1","id":id,
        "review_packet_digest":hash(&packet)?,"public":setup["public"],"recipient_fvk":hex::encode(own.to_bytes())}))?;
    let mut input = BufReader::new(std::io::stdin().lock());
    let mut pending: Option<(Nonce, Context, [u8; 32])> = None;
    loop {
        let mut line = Vec::new();
        // Bound allocation before parsing a peer-controlled line.
        input.by_ref().take(200_001).read_until(b'\n', &mut line)?;
        if line.is_empty() {
            break;
        }
        if line.len() > 200_000 || line.last() != Some(&b'\n') {
            return Err("signer message size/framing".into());
        }
        let req: Value = serde_json::from_slice(&line)?;
        let response = match req["command"].as_str() {
            Some("commit") => {
                if pending.is_some() {
                    return Err("signing nonce already pending".into());
                }
                let mode = req["policy"]["mode"].as_str().ok_or("signing mode")?;
                if mode != "claim" && mode != "refund" {
                    return Err("only the reviewed exits may be signed".into());
                }
                let context = &verified.report["contexts"][mode];
                let token = decode(&req["policy"], "session")?;
                let mut expected = verified.policy.clone();
                expected["mode"] = json!(mode);
                expected["session"] = json!(hex::encode(token));
                if req["policy"] != expected
                    || req["pczt"] != packet[mode]
                    || req["adaptor_point"] != context["adaptor_point"]
                {
                    return Err("sign request differs from locally reviewed exit".into());
                }
                let c = Context {
                    session: token,
                    message: decode(context, "message")?,
                    randomizer: decode(context, "randomizer")?,
                    adaptor_point: decode(context, "adaptor_point")?,
                };
                // Burn the attempt before publishing any commitment. Secret
                // nonces never enter a file; restart needs a new attempt ID.
                storage::atomic_json(
                    &dir.join(format!("public-attempt-{}.json", hex::encode(token))),
                    &json!({"review_packet_digest":verified.report["review_packet_digest"],"mode":mode,"message":context["message"]}),
                )?;
                let (n, commitment) = Nonce::generate(&key, &mut OsRng);
                let response = json!({"commitment":hex::encode(commitment.serialize().map_err(err)?),
                    "message":context["message"],"alpha":context["randomizer"],"index":context["index"]});
                pending = Some((n, c, token));
                response
            }
            Some("sign") => {
                let (nonce, context, token) = pending.take().ok_or("nonce missing or consumed")?;
                storage::atomic_json(
                    &dir.join(format!("public-consumed-{}.json", hex::encode(token))),
                    &json!({"consumed_before_response":true}),
                )?;
                let ours = shielded_swap_crypto::round1::SigningCommitments::deserialize(&bytes(
                    &req, "ours",
                )?)
                .map_err(err)?;
                let theirs = shielded_swap_crypto::round1::SigningCommitments::deserialize(&bytes(
                    &req, "theirs",
                )?)
                .map_err(err)?;
                let session = SigningSession::new(
                    context,
                    public.clone(),
                    BTreeMap::from([(mine, ours), (peer_id, theirs)]),
                )?;
                json!({"share":hex::encode(session.sign(&key,nonce)?)})
            }
            _ => return Err("unsupported public signer request".into()),
        };
        emit(response)?;
    }
    Ok(())
}

pub fn prepare(input: &Path, output: &Path) -> Result<Value> {
    let packet = storage::json(input)?;
    let own = FullViewingKey::from_bytes(&decode(
        &packet["destinations"]["setup"]["destinations"],
        "alice_fvk",
    )?)
    .ok_or("Alice FVK")?;
    let verified = public_review::verify(&packet, &own, 1)?;
    let saved = output.join("exit-presignatures.json");
    if saved.exists() {
        let result = storage::json(&saved)?;
        validate_result(&packet, &verified.report, &result)?;
        return Ok(report(output, &result, true));
    }
    storage::create_dir(output)?;
    let mut pair = participants::Pair::public_review(output, &packet)?;
    let mut result = json!({"format":"latch-public-exit-presignatures-v1","review_packet_digest":hash(&packet)?,
        "graph_digest":verified.report["graph_digest"],"synthetic_inputs":verified.report["synthetic_inputs"],
        "refund_auxiliary_signed":false,"recovery_bundle_complete":false,"funding_authorized":false});
    for mode in ["claim", "refund"] {
        let pczt = Pczt::parse(&bytes(&packet, mode)?).map_err(err)?;
        let target = decode(&verified.report["contexts"][mode], "adaptor_point")?;
        let mut policy = verified.policy.clone();
        policy["mode"] = json!(mode);
        let (pre, index) = pair.sign(&pczt, policy, target)?;
        pre.verify()?;
        if pre.message != regtest_swap::message(&pczt)?
            || pre.key != *pczt.ironwood().actions()[index].spend().rk()
        {
            return Err("aggregate presignature context mismatch".into());
        }
        result[mode] = regtest_swap::pre_json(&pre);
        if mode == "refund" {
            let sig = pre.adapt(&pasta_old::pallas::Scalar::ONE.to_repr())?;
            orchard::primitives::redpallas::VerificationKey::<
                orchard::primitives::redpallas::SpendAuth,
            >::try_from(pre.key)?
            .verify(
                &pre.message,
                &orchard::primitives::redpallas::Signature::from(sig),
            )?;
            result["refund_spend_signature"] = json!(hex::encode(sig));
        }
    }
    validate_result(&packet, &verified.report, &result)?;
    storage::atomic_json(&saved, &result)?;
    Ok(report(output, &result, false))
}

fn report(output: &Path, result: &Value, reused: bool) -> Value {
    json!({"file":output.join("exit-presignatures.json"),"review_packet_digest":result["review_packet_digest"],
        "both_adaptor_presignatures_verified":true,"native_refund_spend_signature_verified":true,
        "reused_presignatures":reused,"refund_auxiliary_signed":false,"recovery_bundle_complete":false,"funding_authorized":false})
}

pub(crate) fn validate_result(packet: &Value, review: &Value, result: &Value) -> Result<()> {
    if result.as_object().is_none_or(|o| o.len() != 10)
        || result["format"] != "latch-public-exit-presignatures-v1"
        || result["review_packet_digest"] != hash(packet)?
        || result["graph_digest"] != review["graph_digest"]
        || result["synthetic_inputs"] != review["synthetic_inputs"]
        || result["refund_auxiliary_signed"] != false
        || result["recovery_bundle_complete"] != false
        || result["funding_authorized"] != false
    {
        return Err("saved presignature binding changed".into());
    }
    for mode in ["claim", "refund"] {
        let pre = regtest_swap::parse_pre(&result[mode])?;
        pre.verify()?;
        let ctx = &review["contexts"][mode];
        let pczt = Pczt::parse(&bytes(packet, mode)?).map_err(err)?;
        let index = usize::try_from(ctx["index"].as_u64().ok_or("real spend index")?)?;
        if pre.message != decode(ctx, "message")?
            || pre.adaptor_point != decode(ctx, "adaptor_point")?
            || pre.key
                != *pczt
                    .ironwood()
                    .actions()
                    .get(index)
                    .ok_or("real spend index")?
                    .spend()
                    .rk()
        {
            return Err("saved presignature context differs".into());
        }
        if mode == "refund" {
            let sig = pre.adapt(&pasta_old::pallas::Scalar::ONE.to_repr())?;
            if result["refund_spend_signature"] != hex::encode(sig) {
                return Err("saved refund signature changed".into());
            }
            orchard::primitives::redpallas::VerificationKey::<
                orchard::primitives::redpallas::SpendAuth,
            >::try_from(pre.key)?
            .verify(
                &pre.message,
                &orchard::primitives::redpallas::Signature::from(sig),
            )?;
        }
    }
    Ok(())
}
