//! Participant protocol over private pipes or an explicitly configured transport.
//! The optional transport command performs mutual TLS; neither is an OS sandbox.
use crate::{
    Context, Identifier, Nonce, PreSignature, Result, SigningSession, decode, err, keys, storage,
    wallet,
};
use ff::PrimeField;
use ff_old::{Field as OldField, PrimeField as OldPrimeField};
use group_old::{Curve, GroupEncoding};
use orchard::keys::{FullViewingKey, Scope};
use pasta_old::arithmetic::CurveAffine;
use pczt::{
    Pczt,
    roles::verifier::{OrchardError, Verifier},
};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use zcash_primitives::transaction::{
    TxVersion, sighash::SignableInput, sighash_v6::v6_signature_hash, txid::TxIdDigester,
};
use zcash_protocol::consensus::BranchId;
use zcash_script::script::Evaluable;

fn bytes(v: &Value, k: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(v[k].as_str().ok_or("missing encoded field")?)?)
}
fn fvk(v: &Value, k: &str) -> Result<FullViewingKey> {
    FullViewingKey::from_bytes(&decode(v, k)?).ok_or_else(|| "FVK encoding".into())
}
fn commitment(v: &Value, k: &str) -> Result<shielded_swap_crypto::round1::SigningCommitments> {
    shielded_swap_crypto::round1::SigningCommitments::deserialize(&bytes(v, k)?)
        .map_err(|e| err(e).into())
}

/// Both participants inspect the same effects; each authenticates their OWN
/// receiving key. A coordinator cannot change a payout and obtain both shares.
pub(crate) fn validate(
    pczt: Pczt,
    policy: &Value,
    own: &FullViewingKey,
    id: u16,
    public: &keys::PublicKeyPackage,
    target: [u8; 32],
) -> Result<(Context, usize)> {
    let joint = fvk(policy, "joint_fvk")?;
    if joint.to_bytes()[..32] != public.verifying_key().serialize().map_err(err)? {
        return Err("joint key not our DKG".into());
    }
    let alice = fvk(policy, "alice_fvk")?;
    let bob = fvk(policy, "bob_fvk")?;
    if own.to_bytes()
        != if id == 1 {
            alice.to_bytes()
        } else {
            bob.to_bytes()
        }
    {
        return Err("own receiver changed".into());
    }
    let is_claim = match policy["mode"].as_str() {
        Some("claim") => true,
        Some("refund") => false,
        _ => return Err("unknown signing mode".into()),
    };
    let recipient = if is_claim { &bob } else { &alice };
    if !is_claim && target != shielded_swap_crypto::generator().to_bytes() {
        return Err("refund must be immediately completable".into());
    }
    let amounts = crate::trade::amounts(policy)?;
    let pending = wallet::parse_note(&policy["pending"])?;
    if pending.value().inner() != amounts.principal
        || pending.recipient() != joint.address_at(0u32, Scope::External)
    {
        return Err("pending note policy".into());
    }
    // The signed child must spend an actual output of the exact prepared
    // funding transaction, not a coordinator-provided substitute note.
    let funding_raw = bytes(policy, "funding")?;
    let mut cursor = std::io::Cursor::new(&funding_raw);
    let funding = zcash_primitives::transaction::Transaction::read(&mut cursor, BranchId::Nu7)?;
    if cursor.position() != funding_raw.len() as u64
        || funding.version() != TxVersion::V6
        || funding.consensus_branch_id() != BranchId::Nu7
        || funding.transparent_bundle().is_some()
        || funding.sapling_bundle().is_some()
        || funding.orchard_bundle().is_some()
    {
        return Err("funding transaction domain/privacy".into());
    }
    let bundle = funding.ironwood_bundle().ok_or("funding Ironwood bundle")?;
    if bundle
        .actions()
        .iter()
        .any(|a| <[u8; 64]>::from(a.authorization()) != [0; 64])
        || <[u8; 64]>::from(bundle.authorization().binding_signature()) != [0; 64]
    {
        return Err("funding authorization must be withheld until recovery receipts".into());
    }
    let matched = (0..bundle.actions().len())
        .filter_map(|i| bundle.decrypt_output_with_key(i, &joint.to_ivk(Scope::External)))
        .filter(|(note, _, _)| wallet::note_json(note) == policy["pending"])
        .count();
    if matched != 1 {
        return Err("pending note does not match prepared funding".into());
    }
    let effects = pczt.clone().into_effects().map_err(err)?;
    if effects.version() != TxVersion::V6
        || effects.consensus_branch_id() != BranchId::Nu7
        || u32::from(effects.expiry_height()) != 0
        || effects.sapling_bundle().is_some()
        || effects.orchard_bundle().is_some()
        || pczt.ironwood().actions().len() != 2
    {
        return Err("unexpected transaction domain/layout".into());
    }
    if is_claim {
        if effects.transparent_bundle().is_some() || effects.lock_time() != 0 {
            return Err("claim must be shielded and immediately spendable".into());
        }
    } else {
        let lock = crate::refund_lock::RefundLock::parse(policy)?;
        if effects.lock_time() != lock.value() {
            return Err("refund lock changed".into());
        }
        Verifier::new(pczt.clone())
            .with_transparent::<String, _>(|b| {
                let bad = |s: &str| pczt::roles::verifier::TransparentError::Custom(s.to_owned());
                if b.inputs().len() != 1 || b.outputs().len() != 1 {
                    return Err(bad("refund auxiliary shape"));
                }
                let input = &b.inputs()[0];
                let output = &b.outputs()[0];
                let aux = &policy["aux"];
                if hex::encode(input.prevout_txid().as_ref()) != aux["txid_le"]
                    || *input.prevout_index() != aux["index"].as_u64().unwrap_or(u64::MAX) as u32
                    || *input.sequence() != Some(u32::MAX - 1)
                    // SpendFinalizer may strip these planning hints. The
                    // signed global lock above remains mandatory. Any retained
                    // hint must agree with its units and value.
                    || (input.required_time_lock_time().is_some()
                        && *input.required_time_lock_time() != lock.required_time())
                    || (input.required_height_lock_time().is_some()
                        && *input.required_height_lock_time() != lock.required_height())
                    || u64::from(*input.value()) != aux["value"].as_u64().unwrap_or(0)
                    || hex::encode(input.script_pubkey().to_bytes()) != aux["script"]
                    || hex::encode(output.script_pubkey().to_bytes()) != aux["script"]
                    || u64::from(*output.value()) + 5_000 != u64::from(*input.value())
                {
                    return Err(bad("refund auxiliary changed"));
                }
                Ok(())
            })
            .map_err(err)?;
    }
    let mut real = None;
    let mut paid = None;
    let mut alpha = None;
    Verifier::new(pczt)
        .with_ironwood::<String, _>(|bundle| {
            let bad = |s: &str| OrchardError::Custom(s.to_owned());
            bundle.verify_cross_address_restriction()?;
            for (i, a) in bundle.actions().iter().enumerate() {
                if a.spend().dummy_sk().is_some() {
                    return Err(bad("unfinalized dummy spend"));
                }
                a.verify_cv_net()?;
                a.spend().verify_nullifier(Some(&joint))?;
                a.spend().verify_rk(Some(&joint))?;
                a.output().verify_note_commitment(a.spend())?;
                let input = a
                    .spend()
                    .value()
                    .ok_or_else(|| bad("missing spend value"))?
                    .inner();
                let output = a
                    .output()
                    .value()
                    .ok_or_else(|| bad("missing output value"))?
                    .inner();
                if input > 0 {
                    if real.is_some()
                        || input != amounts.principal
                        || a.spend().nullifier() != &pending.nullifier(&joint)
                        || a.spend().spend_auth_sig().is_some()
                    {
                        return Err(bad("unexpected shared input"));
                    }
                    real = Some(i);
                    alpha = a.spend().alpha().map(|a| a.to_repr());
                } else if a.spend().spend_auth_sig().is_none() {
                    return Err(bad("unsigned dummy"));
                }
                if output > 0 {
                    if paid.is_some()
                        || output != amounts.payout
                        || *a.output().recipient()
                            != Some(recipient.address_at(0u32, Scope::External))
                    {
                        return Err(bad("recipient or payout changed"));
                    }
                    paid = Some(i);
                }
            }
            Ok(())
        })
        .map_err(err)?;
    let paid = paid.ok_or("missing payout")?;
    let (decrypted, _, _) = effects
        .ironwood_bundle()
        .ok_or("Ironwood missing")?
        .decrypt_output_with_key(paid, &recipient.to_ivk(Scope::External))
        .ok_or("payout ciphertext not decryptable")?;
    if decrypted.value().inner() != amounts.payout {
        return Err("decrypted payout changed".into());
    }
    let digest: [u8; 32] = v6_signature_hash(
        &effects,
        &SignableInput::Shielded,
        &effects.digest(TxIdDigester),
    )
    .as_ref()
    .try_into()?;
    Ok((
        Context {
            session: decode(policy, "session")?,
            message: digest,
            randomizer: alpha.ok_or("real alpha")?,
            adaptor_point: target,
        },
        real.ok_or("no real spend")?,
    ))
}

fn emit(value: Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", serde_json::to_string(&value)?)?;
    out.flush()?;
    Ok(())
}

/// No signing nonces are serialized. On interruption, the attempt is burned;
/// a new process uses a fresh attempt identifier and new nonces before funding.
pub fn serve(dir: &Path, id: u16) -> Result<()> {
    if id != 1 && id != 2 {
        return Err("participant id must be 1 or 2".into());
    }
    let accepted_trade = crate::trade::configured()?;
    let resumed = dir.exists();
    if !resumed {
        wallet::init(dir)?;
    }
    let own = wallet::fvk(dir)?;
    let my_id = Identifier::try_from(id).map_err(err)?;
    let peer_id = Identifier::try_from(3 - id).map_err(err)?;
    let mut r1 = None;
    let mut r2 = None;
    let mut peer_round1 = BTreeMap::new();
    let mut key = None;
    let mut public = None;
    let mut own_target = None;
    let mut hello = json!({"resumed":resumed,"recipient_fvk":hex::encode(own.to_bytes())});
    if resumed {
        let manifest = storage::json(&dir.join("dkg-complete.json"))?;
        if manifest["id"] != id || manifest["threshold"] != 2 {
            return Err("incomplete or wrong participant journal".into());
        }
        let k = keys::KeyPackage::deserialize(&storage::read(&dir.join("frost-share.bin"), 16384)?)
            .map_err(err)?;
        let p = keys::PublicKeyPackage::deserialize(&storage::read(
            &dir.join("frost-public.bin"),
            16384,
        )?)
        .map_err(err)?;
        if *k.identifier() != my_id
            || *k.min_signers() != 2
            || k.verifying_key() != p.verifying_key()
            || p.verifying_shares().get(&my_id) != Some(k.verifying_share())
            || p.verifying_shares().len() != 2
        {
            return Err("persisted key package mismatch".into());
        }
        hello["public"] = json!(hex::encode(p.serialize().map_err(err)?));
        key = Some(k);
        public = Some(p);
    } else {
        let (secret, package) = keys::dkg::part1(my_id, 2, 2, OsRng).map_err(err)?;
        r1 = Some(secret);
        hello["round1"] = json!(hex::encode(package.serialize().map_err(err)?));
    }
    if id == 1 {
        let t = if resumed {
            let saved = storage::json(&dir.join("witness.json"))?;
            let t = pasta_old::pallas::Scalar::from_repr(decode(&saved, "witness_le")?)
                .into_option()
                .ok_or("persisted witness encoding")?;
            if t == pasta_old::pallas::Scalar::ZERO {
                return Err("zero persisted witness".into());
            }
            t
        } else {
            loop {
                let t = pasta_old::pallas::Scalar::random(OsRng);
                if t != pasta_old::pallas::Scalar::ZERO {
                    break t;
                }
            }
        };
        let point = shielded_swap_crypto::generator() * t;
        own_target = Some(point.to_bytes());
        let affine = point.to_affine();
        let c = affine.coordinates().unwrap();
        let big = |mut b: [u8; 32]| {
            b.reverse();
            format!("0x{}", hex::encode(b))
        };
        if !resumed {
            storage::write_json(
                &dir.join("witness.json"),
                &json!({"witness_le":hex::encode(t.to_repr()),"witness_uint256":big(t.to_repr())}),
            )?;
        }
        hello["adaptor_point"] = json!(hex::encode(point.to_bytes()));
        hello["point_x"] = json!(big(c.x().to_repr()));
        hello["point_y"] = json!(big(c.y().to_repr()));
    }
    emit(hello)?;
    let input = std::io::stdin();
    let mut pending: Option<(Nonce, Context, [u8; 32])> = None;
    for line in input.lock().lines() {
        let line = line?;
        if line.len() > 200_000 {
            return Err("message size bound".into());
        }
        let request: Value = serde_json::from_str(&line)?;
        let response = match request["command"].as_str() {
            Some("dkg2") => {
                let peer = keys::dkg::round1::Package::deserialize(&bytes(&request, "package")?)
                    .map_err(err)?;
                peer_round1.insert(peer_id, peer);
                let (secret, messages) =
                    keys::dkg::part2(r1.take().ok_or("DKG round already consumed")?, &peer_round1)
                        .map_err(err)?;
                r2 = Some(secret);
                json!({"package":hex::encode(messages[&peer_id].serialize().map_err(err)?)})
            }
            Some("dkg3") => {
                let peer = keys::dkg::round2::Package::deserialize(&bytes(&request, "package")?)
                    .map_err(err)?;
                let (k, p) = keys::dkg::part3(
                    &r2.take().ok_or("missing DKG round2")?,
                    &peer_round1,
                    &BTreeMap::from([(peer_id, peer)]),
                )
                .map_err(err)?;
                storage::write(&dir.join("frost-share.bin"), &k.serialize().map_err(err)?)?;
                storage::write(&dir.join("frost-public.bin"), &p.serialize().map_err(err)?)?;
                storage::write_json(
                    &dir.join("dkg-complete.json"),
                    &json!({"id":id,"threshold":2}),
                )?;
                let response = json!({"public":hex::encode(p.serialize().map_err(err)?)});
                key = Some(k);
                public = Some(p);
                response
            }
            Some("commit") => {
                if request["policy"].get("trade") != accepted_trade.as_ref() {
                    return Err("signer policy differs from locally accepted OTC offer".into());
                }
                if pending.is_some() {
                    return Err("previous signing attempt still pending".into());
                }
                let target = decode(&request, "adaptor_point")?;
                if id == 1 && request["policy"]["mode"] == "claim" && Some(target) != own_target {
                    return Err("Alice witness point changed".into());
                }
                let pczt = Pczt::parse(&bytes(&request, "pczt")?).map_err(err)?;
                let (context, index) = validate(
                    pczt,
                    &request["policy"],
                    &own,
                    id,
                    public.as_ref().ok_or("DKG incomplete")?,
                    target,
                )?;
                if request["policy"]["mode"] == "claim" {
                    let target_path = dir.join("claim-target.bin");
                    if target_path.exists() {
                        if storage::read(&target_path, 32)? != target {
                            return Err("claim adaptor point changed".into());
                        }
                    } else {
                        storage::write(&target_path, &target)?;
                    }
                }
                // All signatures from this swap's fresh DKG key must use one
                // immutable agreement, including the other exit's deadline.
                let mut agreement = request["policy"].clone();
                let object = agreement.as_object_mut().ok_or("policy object required")?;
                object.remove("mode");
                object.remove("session");
                let agreement_path = dir.join("agreement.json");
                if agreement_path.exists() {
                    if storage::json(&agreement_path)? != agreement {
                        return Err("swap agreement changed".into());
                    }
                } else {
                    storage::write_json(&agreement_path, &agreement)?;
                }
                let token = context.session;
                // Durable reservation precedes revealing a nonce commitment.
                storage::write_json(
                    &dir.join(format!("attempt-{}.json", hex::encode(token))),
                    &json!({"message":hex::encode(context.message),"mode":request["policy"]["mode"]}),
                )?;
                let (n, c) = Nonce::generate(key.as_ref().ok_or("DKG incomplete")?, &mut OsRng);
                let response = json!({"commitment":hex::encode(c.serialize().map_err(err)?),"message":hex::encode(context.message),"alpha":hex::encode(context.randomizer),"index":index});
                pending = Some((n, context, token));
                response
            }
            Some("sign") => {
                let (n, context, token) =
                    pending.take().ok_or("nonce absent or already consumed")?;
                let ours = commitment(&request, "ours")?;
                let theirs = commitment(&request, "theirs")?;
                storage::write_json(
                    &dir.join(format!("consumed-{}.json", hex::encode(token))),
                    &json!({"consumed_before_response":true}),
                )?;
                let session = SigningSession::new(
                    context,
                    public.as_ref().ok_or("DKG incomplete")?.clone(),
                    BTreeMap::from([(my_id, ours), (peer_id, theirs)]),
                )?;
                let share = session.sign(key.as_ref().ok_or("DKG incomplete")?, n)?;
                json!({"share":hex::encode(share)})
            }
            Some("accept_bundle") => {
                if pending.is_some() {
                    return Err("cannot accept recovery bundle during signing".into());
                }
                crate::recovery_bundle::accept(
                    dir,
                    id,
                    &own,
                    public.as_ref().ok_or("DKG incomplete")?,
                    &request["bundle"],
                )?
            }
            Some("quit") => return Ok(()),
            _ => return Err("unknown participant command".into()),
        };
        emit(response)?;
    }
    Ok(())
}

struct Process {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Process {
    fn start(dir: &Path, id: u16) -> Result<(Self, Value)> {
        use std::os::unix::fs::OpenOptionsExt;
        let log = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(
                dir.parent()
                    .ok_or("participant parent")?
                    .join(format!("participant-{id}.log")),
            )?;
        let mut command = if let Some(path) = std::env::var_os("LATCH_SIGNER_COMMANDS") {
            // This local owner-controlled file is configuration, never supplied
            // by a network peer. Arguments are passed directly, without a shell.
            let configured = storage::json(Path::new(&path))?;
            let role = if id == 1 { "alice" } else { "bob" };
            let args = configured[role]
                .as_array()
                .ok_or("missing signer command array")?;
            if args.is_empty() || args.len() > 16 {
                return Err("invalid signer command length".into());
            }
            let args = args
                .iter()
                .map(|v| v.as_str().ok_or("signer argument must be a string"))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut command = Command::new(args[0]);
            command.args(&args[1..]);
            command
        } else {
            let mut command = Command::new(std::env::current_exe()?);
            command.arg("participant").arg(dir).arg(id.to_string());
            command
        };
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .spawn()?;
        let input = child.stdin.take().ok_or("participant stdin")?;
        let output = BufReader::new(child.stdout.take().ok_or("participant stdout")?);
        let mut p = Self {
            child,
            input,
            output,
        };
        let hello = p.read()?;
        Ok((p, hello))
    }
    fn read(&mut self) -> Result<Value> {
        let mut line = String::new();
        if self.output.read_line(&mut line)? == 0 {
            return Err("participant rejected request or exited".into());
        }
        if line.len() > 200_000 {
            return Err("participant response size".into());
        }
        Ok(serde_json::from_str(&line)?)
    }
    fn request(&mut self, value: Value) -> Result<Value> {
        writeln!(self.input, "{}", serde_json::to_string(&value)?)?;
        self.input.flush()?;
        self.read()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Pair {
    alice: Process,
    bob: Process,
    pub public: keys::PublicKeyPackage,
    pub alice_fvk: FullViewingKey,
    pub bob_fvk: FullViewingKey,
    pub point: [u8; 32],
    pub point_x: Value,
    pub point_y: Value,
}
impl Pair {
    pub fn start(dir: &Path) -> Result<Self> {
        let (mut alice, a) = Process::start(&dir.join("alice"), 1)?;
        let (mut bob, b) = Process::start(&dir.join("bob"), 2)?;
        let a2 = alice.request(json!({"command":"dkg2","package":b["round1"]}))?;
        let b2 = bob.request(json!({"command":"dkg2","package":a["round1"]}))?;
        let a3 = alice.request(json!({"command":"dkg3","package":b2["package"]}))?;
        let b3 = bob.request(json!({"command":"dkg3","package":a2["package"]}))?;
        if a3["public"] != b3["public"] {
            return Err("participant DKG disagreement".into());
        }
        Ok(Self {
            alice,
            bob,
            public: keys::PublicKeyPackage::deserialize(&bytes(&a3, "public")?).map_err(err)?,
            alice_fvk: fvk(&a, "recipient_fvk")?,
            bob_fvk: fvk(&b, "recipient_fvk")?,
            point: decode(&a, "adaptor_point")?,
            point_x: a["point_x"].clone(),
            point_y: a["point_y"].clone(),
        })
    }
    pub fn sign(
        &mut self,
        pczt: &Pczt,
        mut policy: Value,
        target: [u8; 32],
    ) -> Result<(PreSignature, usize)> {
        let mut token = [0; 32];
        OsRng.fill_bytes(&mut token);
        policy["session"] = json!(hex::encode(token));
        let request = json!({"command":"commit","pczt":hex::encode(pczt.clone().serialize().map_err(err)?),"policy":policy,"adaptor_point":hex::encode(target)});
        let a = self.alice.request(request.clone())?;
        let b = self.bob.request(request)?;
        if a["message"] != b["message"] || a["alpha"] != b["alpha"] || a["index"] != b["index"] {
            return Err("signer context disagreement".into());
        }
        let ac = commitment(&a, "commitment")?;
        let bc = commitment(&b, "commitment")?;
        let ia = Identifier::try_from(1u16).map_err(err)?;
        let ib = Identifier::try_from(2u16).map_err(err)?;
        let context = Context {
            session: token,
            message: decode(&a, "message")?,
            randomizer: decode(&a, "alpha")?,
            adaptor_point: target,
        };
        let session = SigningSession::new(
            context,
            self.public.clone(),
            BTreeMap::from([(ia, ac), (ib, bc)]),
        )?;
        let az = self
            .alice
            .request(json!({"command":"sign","ours":a["commitment"],"theirs":b["commitment"]}))?;
        let bz = self
            .bob
            .request(json!({"command":"sign","ours":b["commitment"],"theirs":a["commitment"]}))?;
        Ok((
            session.aggregate(&BTreeMap::from([
                (ia, decode(&az, "share")?),
                (ib, decode(&bz, "share")?),
            ]))?,
            a["index"].as_u64().ok_or("sign index")? as usize,
        ))
    }
    pub fn deliver_bundle(&mut self, bundle: Value) -> Result<Value> {
        let digest = crate::recovery_bundle::digest(&bundle)?;
        let request = json!({"command":"accept_bundle","bundle":bundle});
        let a = self.alice.request(request.clone())?;
        let b = self.bob.request(request)?;
        for (receipt, id) in [(&a, 1), (&b, 2)] {
            if receipt["participant"] != id
                || receipt["bundle_digest"] != digest
                || receipt["durably_saved"] != true
            {
                return Err("participant did not acknowledge exact recovery bundle".into());
            }
        }
        Ok(json!({"alice":a,"bob":b,"both_acknowledged_before_funding":true}))
    }
}
