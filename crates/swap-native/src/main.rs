//! Local native development CLI. Synthetic fixtures MUST NEVER be broadcast.
mod auxiliary;
mod compact_wallet;
mod evm_key;
mod funding_consent;
mod observed_transaction;
mod participants;
mod public_consent;
mod public_graph;
mod public_presign;
mod public_recovery;
mod public_review;
mod public_setup;
mod public_witness;
mod recovery_bundle;
mod refund_lock;
mod regtest_swap;
mod source_guard;
mod storage;
mod trade;
mod transaction_graph;
mod wallet;
use ff::{Field, PrimeField};
use ff_old::{Field as OldField, PrimeField as OldPrimeField};
use group_old::{Curve, GroupEncoding};
use incrementalmerkletree::Hashable;
use orchard::{
    Note,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    tree::{MerkleHashOrchard, MerklePath},
};
use pasta_curves::pallas;
use pasta_old::arithmetic::CurveAffine;
use pczt::roles::{
    creator::Creator,
    io_finalizer::IoFinalizer,
    low_level_signer::{OrchardParseError, Signer},
    prover::Prover,
    redactor::Redactor,
    tx_extractor::TransactionExtractor,
    updater::Updater,
    verifier::{OrchardError, Verifier},
};
use rand_core::OsRng;
use shielded_swap_crypto::{Context, Identifier, Nonce, PreSignature, SigningSession, keys};
use std::{collections::BTreeMap, convert::Infallible, path::Path, time::Instant};
use zcash_primitives::transaction::{
    Transaction, TxVersion,
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317::FeeRule,
    sighash::SignableInput,
    sighash_v6::v6_signature_hash,
    txid::TxIdDigester,
};
use zcash_protocol::{
    consensus::{BranchId, NetworkUpgrade, Parameters, TEST_NETWORK},
    memo::MemoBytes,
    value::Zatoshis,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

fn random_key(rng: &mut impl rand::CryptoRng) -> SpendingKey {
    loop {
        let mut b = [0; 32];
        rng.fill_bytes(&mut b);
        if let Some(k) = SpendingKey::from_bytes(b).into_option() {
            return k;
        }
    }
}

fn note(fvk: &FullViewingKey, value: u64, rng: &mut impl rand::CryptoRng) -> Note {
    loop {
        let rho = Rho::from_bytes(&pallas::Base::random(&mut *rng).to_repr()).unwrap();
        let mut b = [0; 32];
        rng.fill_bytes(&mut b);
        if let Some(seed) = RandomSeed::from_bytes(b, &rho).into_option()
            && let Some(n) = Note::from_parts(
                fvk.address_at(0u32, Scope::External),
                orchard::value::NoteValue::from_raw(value),
                rho,
                seed,
                NoteVersion::V3,
            )
            .into_option()
        {
            return n;
        }
    }
}

// Local fixture DKG, with separately held packages and actual peer-message maps.
// No combined ask is ever constructed. This is not independent-host execution.
fn dkg() -> Result<(
    BTreeMap<Identifier, keys::KeyPackage>,
    keys::PublicKeyPackage,
)> {
    let a = Identifier::try_from(1u16).map_err(err)?;
    let b = Identifier::try_from(2u16).map_err(err)?;
    let (a1, ap1) = keys::dkg::part1(a, 2, 2, OsRng).map_err(err)?;
    let (b1, bp1) = keys::dkg::part1(b, 2, 2, OsRng).map_err(err)?;
    let ar = BTreeMap::from([(b, bp1)]);
    let br = BTreeMap::from([(a, ap1)]);
    let (a2, ap2) = keys::dkg::part2(a1, &ar).map_err(err)?;
    let (b2, bp2) = keys::dkg::part2(b1, &br).map_err(err)?;
    let (ak, public) =
        keys::dkg::part3(&a2, &ar, &BTreeMap::from([(b, bp2[&a].clone())])).map_err(err)?;
    let (bk, other) =
        keys::dkg::part3(&b2, &br, &BTreeMap::from([(a, ap2[&b].clone())])).map_err(err)?;
    if public != other {
        return Err("DKG disagreement".into());
    }
    Ok((BTreeMap::from([(a, ak), (b, bk)]), public))
}

fn prepare(dir: &Path) -> Result<serde_json::Value> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if dir.exists() {
        return Err("fixture directory already exists; use a fresh path".into());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let mut rng = rand::rng();
    let (keys, public) = dkg()?;
    // nk/rivk are independent viewing material; replace ak with DKG public key.
    let mut fvk_bytes = FullViewingKey::from(&random_key(&mut rng)).to_bytes();
    fvk_bytes[..32].copy_from_slice(&public.verifying_key().serialize().map_err(err)?);
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).ok_or("invalid joint FVK")?;
    let receiver = FullViewingKey::from(&random_key(&mut rng));
    let input = note(&fvk, 1_010_000, &mut rng);
    let path1 = MerklePath::from_parts(
        0,
        std::array::from_fn(|i| MerkleHashOrchard::empty_root((i as u8).into())),
    );
    let anchor1 = path1.root(input.commitment().into());
    let height = TEST_NETWORK
        .activation_height(NetworkUpgrade::Nu7)
        .ok_or("NU7 height")?
        + 1;
    let mut builder = Builder::new(
        TEST_NETWORK,
        height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: Some(anchor1),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder = builder.with_expiry_height(0u32.into());
    builder
        .add_ironwood_spend::<Infallible>(fvk.clone(), input, path1)
        .map_err(err)?;
    builder
        .add_ironwood_output::<Infallible>(
            None,
            receiver.address_at(0u32, Scope::External),
            Zatoshis::from_u64(1_000_000)?,
            MemoBytes::empty(),
        )
        .map_err(err)?;
    let parts = builder
        .build_for_pczt(&mut rng, &FeeRule::standard())
        .map_err(err)?;
    let output_index = parts
        .ironwood_meta
        .output_action_index(0)
        .ok_or("output index")?;
    let pczt = IoFinalizer::new(Creator::build_from_parts(parts.pczt_parts).ok_or("PCZT parts")?)
        .finalize_io(&mut rng)
        .map_err(err)?;
    let index = pczt
        .ironwood()
        .actions()
        .iter()
        .position(|a| a.spend().spend_auth_sig().is_none())
        .ok_or("real spend")?;
    let mut alpha = None;
    let pczt = Verifier::new(pczt)
        .with_ironwood::<Infallible, _>(
            |bundle| -> std::result::Result<(), OrchardError<Infallible>> {
                bundle.verify_cross_address_restriction()?;
                for a in bundle.actions() {
                    a.verify_cv_net()?;
                    a.spend().verify_nullifier(Some(&fvk))?;
                    a.spend().verify_rk(Some(&fvk))?;
                    a.output().verify_note_commitment(a.spend())?;
                }
                alpha = bundle.actions()[index].spend().alpha().map(|a| a.to_repr());
                Ok(())
            },
        )
        .map_err(err)?
        .finish();
    let before = pczt.clone().into_effects().map_err(err)?;
    let message: [u8; 32] = v6_signature_hash(
        &before,
        &SignableInput::Shielded,
        &before.digest(TxIdDigester),
    )
    .as_ref()
    .try_into()?;
    // Strip ALL anchors and witnesses before producing any real spend signature.
    let pczt = Redactor::new(pczt)
        .redact_ironwood_with(|mut b| {
            b.clear_anchor();
            b.redact_actions(|mut a| a.clear_spend_witness());
        })
        .finish();
    if pczt.ironwood().anchor().is_some() {
        return Err("anchor not removed".into());
    }
    let after = pczt.clone().into_effects().map_err(err)?;
    let digest = v6_signature_hash(
        &after,
        &SignableInput::Shielded,
        &after.digest(TxIdDigester),
    );
    if digest.as_ref() != message {
        return Err("removing anchor changed signature digest".into());
    }
    let alpha = alpha.ok_or("alpha missing")?;
    let t = pasta_old::pallas::Scalar::random(OsRng);
    let target = shielded_swap_crypto::generator() * t;
    let context = Context {
        session: message,
        message,
        randomizer: alpha,
        adaptor_point: target.to_bytes(),
    };
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key) in &keys {
        let (n, c) = Nonce::generate(key, &mut OsRng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let session = SigningSession::new(context, public, commitments)?;
    let shares = nonces
        .into_iter()
        .map(|(id, n)| session.sign(&keys[&id], n).map(|s| (id, s)))
        .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
    let pre = session.aggregate(&shares)?;
    // Later tree contains an unrelated leaf; this tests a genuinely changed root.
    let sibling = MerkleHashOrchard::from_cmx(&note(&receiver, 7, &mut rng).commitment().into());
    let nodes = std::array::from_fn(|i| {
        if i == 0 {
            sibling
        } else {
            MerkleHashOrchard::empty_root((i as u8).into())
        }
    });
    let later_path = MerklePath::from_parts(0, nodes);
    let later_anchor = later_path.root(input.commitment().into());
    if anchor1 == later_anchor {
        return Err("anchor did not change".into());
    }
    let bob = serde_json::json!({"scope":"synthetic funding NEVER broadcast", "pczt":hex::encode(pczt.serialize().map_err(err)?),
        "r_hat":hex::encode(pre.r_hat),"s_hat":hex::encode(pre.s_hat),"key":hex::encode(pre.key),
        "message":hex::encode(pre.message),"adaptor_point":hex::encode(pre.adaptor_point),
        "index":index,"output_index":output_index,"anchor":hex::encode(later_anchor.to_bytes()),
        "path":nodes.iter().map(|n|hex::encode(n.to_bytes())).collect::<Vec<_>>(),"receiver_fvk":hex::encode(receiver.to_bytes())});
    let affine = target.to_affine();
    let coords = affine.coordinates().unwrap();
    let big = |mut b: [u8; 32]| {
        b.reverse();
        format!("0x{}", hex::encode(b))
    };
    let alice = serde_json::json!({"scope":"synthetic secret; never real funds", "witness_le":hex::encode(t.to_repr()),
        "witness_uint256":big(t.to_repr()),"point_x":big(coords.x().to_repr()),"point_y":big(coords.y().to_repr())});
    for (name, value) in [("bob.json", bob), ("alice.json", alice)] {
        use std::io::Write;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(name))?;
        out.write_all(serde_json::to_string_pretty(&value)?.as_bytes())?;
        out.sync_all()?;
    }
    Ok(
        serde_json::json!({"scope":"synthetic funding; no broadcast","dkg":"2-of-2, same host, no full ask",
        "presigned_without_anchor_witness_or_proof":true,"later_anchor_differs":true,"message":hex::encode(message)}),
    )
}

fn decode<const N: usize>(v: &serde_json::Value, key: &str) -> Result<[u8; N]> {
    Ok(hex::decode(v[key].as_str().ok_or("missing field")?)?
        .try_into()
        .map_err(|_| "wrong byte length")?)
}

#[derive(Debug)]
enum SignError {
    Parse(OrchardParseError),
    Custom(String),
}
impl From<OrchardParseError> for SignError {
    fn from(e: OrchardParseError) -> Self {
        Self::Parse(e)
    }
}
impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{e:?}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

fn complete(dir: &Path, witness: &str) -> Result<serde_json::Value> {
    let started = Instant::now();
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("bob.json"))?)?;
    let pre = PreSignature {
        r_hat: decode(&v, "r_hat")?,
        s_hat: decode(&v, "s_hat")?,
        key: decode(&v, "key")?,
        message: decode(&v, "message")?,
        adaptor_point: decode(&v, "adaptor_point")?,
    };
    let t: [u8; 32] = hex::decode(witness)?
        .try_into()
        .map_err(|_| "witness length")?;
    let sig = pre.adapt(&t)?;
    let pczt = pczt::Pczt::parse(&hex::decode(v["pczt"].as_str().ok_or("pczt")?)?).map_err(err)?;
    let index = v["index"].as_u64().ok_or("index")? as usize;
    let pczt = Signer::new(pczt)
        .sign_ironwood_with::<SignError, _>(|_, bundle, _| {
            bundle.actions_mut()[index]
                .apply_signature(
                    pre.message,
                    orchard::primitives::redpallas::Signature::from(sig),
                )
                .map_err(|e| SignError::Custom(err(e)))
        })
        .map_err(err)?
        .finish();
    if pczt.ironwood().anchor().is_some() {
        return Err("signed with anchor present".into());
    }
    let nodes = v["path"]
        .as_array()
        .ok_or("path")?
        .iter()
        .map(|x| {
            let b: [u8; 32] = hex::decode(x.as_str().ok_or("path item")?)?
                .try_into()
                .map_err(|_| "path length")?;
            MerkleHashOrchard::from_bytes(&b)
                .into_option()
                .ok_or_else(|| "invalid node".into())
        })
        .collect::<Result<Vec<_>>>()?;
    let path = MerklePath::from_parts(0, nodes.try_into().map_err(|_| "path depth")?);
    let anchor = orchard::Anchor::from_bytes(decode(&v, "anchor")?)
        .into_option()
        .ok_or("anchor encoding")?;
    // Dummy zero-value spends also need a syntactic witness for the prover;
    // their circuit membership constraint is disabled. The real spend uses
    // precisely the later note path.
    let witnesses = (0..pczt.ironwood().actions().len())
        .map(|i| (i, path.clone()))
        .collect::<Vec<_>>();
    let pczt = Updater::new(pczt)
        .set_ironwood_anchor(anchor)
        .map_err(err)?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(err)?
        .finish();
    let effects = pczt.clone().into_effects().map_err(err)?;
    if v6_signature_hash(
        &effects,
        &SignableInput::Shielded,
        &effects.digest(TxIdDigester),
    )
    .as_ref()
        != pre.message
    {
        return Err("later anchor invalidated pre-signature".into());
    }
    let mut rng = rand::rng();
    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);
    let proof_start = Instant::now();
    let pczt = Prover::new(pczt)
        .create_ironwood_proof(&mut rng, &pk)
        .map_err(err)?
        .finish();
    let proof_seconds = proof_start.elapsed().as_secs_f64();
    let tx = TransactionExtractor::new(pczt)
        .extract(&mut rng)
        .map_err(err)?;
    let mut bytes = Vec::new();
    tx.write(&mut bytes)?;
    let parsed = Transaction::read(&bytes[..], BranchId::Nu7)?;
    if parsed.version() != TxVersion::V6 || parsed.consensus_branch_id() != BranchId::Nu7 {
        return Err("wrong native rules".into());
    }
    let vk = VerifyingKey::build(OrchardCircuitVersion::PostNu6_3);
    let bundle = parsed.ironwood_bundle().ok_or("no Ironwood")?;
    let mut validator = orchard::bundle::BatchValidator::new(&vk);
    validator.add_bundle(bundle, pre.message).map_err(err)?;
    if !validator.validate(&mut rng) {
        return Err("native verifier rejected".into());
    }
    let receiver =
        FullViewingKey::from_bytes(&decode(&v, "receiver_fvk")?).ok_or("receiver FVK")?;
    let oi = v["output_index"].as_u64().ok_or("output index")? as usize;
    let (output, _, _) = bundle
        .decrypt_output_with_key(oi, &receiver.to_ivk(Scope::External))
        .ok_or("receiver could not decrypt")?;
    if output.value().inner() != 1_000_000 {
        return Err("wrong output amount".into());
    }
    std::fs::write(dir.join("synthetic-claim.hex"), hex::encode(&bytes))?;
    Ok(
        serde_json::json!({"scope":"synthetic note/proof, NEVER broadcast", "native_proof_and_adapted_signature_valid":true,
        "preauthorization_without_anchor_witness_proof":true,"later_anchor_changed":true,
        "recipient_decrypted_expected_amount":true,"shielded_principal":true,"transparent_components":false,
        "transaction_bytes":bytes.len(),"txid":tx.txid().to_string(),"proof_seconds":proof_seconds,
        "total_seconds":started.elapsed().as_secs_f64(),"chain_acceptance":false}),
    )
}

fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let value = match a.get(1).map(String::as_str) {
        Some("otc-verify-offer") if a.len() == 3 => trade::inspect(Path::new(&a[2]), false)?,
        Some("otc-verify-acceptance") if a.len() == 3 => trade::inspect(Path::new(&a[2]), true)?,
        Some("testnet-otc-verify-offer" | "testnet-otc-verify-acceptance") if a.len() == 3 => {
            let packet = storage::json(Path::new(&a[2]))?;
            let amounts = trade::verify_testnet(&packet, a[1].ends_with("acceptance"))?;
            serde_json::json!({"quote_digest":funding_consent::hash(&packet["offer"]["payload"])?,
                "principal_zatoshi":amounts.principal,"payout_zatoshi":amounts.payout,
                "eth_amount_wei":amounts.eth,"funding_authorized":false})
        }
        Some("testnet-owner-setup") if a.len() == 4 || a.len() == 5 => {
            public_setup::run(Path::new(&a[2]), &a[3], a.get(4).map(Path::new))?
        }
        Some("testnet-setup-verify") if a.len() == 3 => public_setup::inspect(Path::new(&a[2]))?,
        Some("testnet-export-review") if a.len() == 6 => public_review::export(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            Path::new(&a[5]),
        )?,
        Some("testnet-owner-review") if a.len() == 4 => {
            public_review::review(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("testnet-owner-signer") if a.len() == 3 => {
            public_presign::serve(Path::new(&a[2]))?;
            return Ok(());
        }
        Some("testnet-presign-review") if a.len() == 4 => {
            public_presign::prepare(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("testnet-prepare-recovery") if a.len() == 6 => public_recovery::prepare(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            Path::new(&a[5]),
        )?,
        Some("check-public-recovery-synthetic") if a.len() == 5 => {
            public_recovery::synthetic(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]))?
        }
        Some("testnet-owner-recovery") if a.len() == 4 => {
            public_recovery::accept(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("testnet-recovery-receipts") if a.len() == 4 => {
            public_recovery::receipts(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("testnet-export-recovery") if a.len() == 4 => {
            public_recovery::export(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("testnet-inspect-recovery") if a.len() == 3 => {
            public_recovery::inspect(Path::new(&a[2]))?
        }
        Some("testnet-recovery-watch") if a.len() == 5 => {
            public_witness::init(Path::new(&a[2]), Path::new(&a[3]), a[4].parse()?)?
        }
        Some("testnet-recovery-snapshot") if a.len() == 6 => public_witness::select(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            Path::new(&a[5]),
        )?,
        Some("testnet-recovery-prove") if a.len() == 6 || a.len() == 7 => public_witness::prove(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            Path::new(&a[5]),
            a.get(6).map(Path::new),
        )?,
        Some("testnet-stage-agreement") if a.len() == 7 => public_consent::stage(
            Path::new(&a[2]),
            Path::new(&a[3]),
            &a[4],
            &a[5],
            Path::new(&a[6]),
        )?,
        Some("testnet-owner-consent") if a.len() == 4 => {
            public_consent::sign(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("testnet-check-consents") if a.len() == 5 => {
            public_consent::verify(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]))?
        }
        Some("testnet-check-reserved-graph") if a.len() == 5 => {
            public_recovery::check_reserved_graph(
                Path::new(&a[2]),
                Path::new(&a[3]),
                Path::new(&a[4]),
            )?
        }
        Some("check-source-spend") if a.len() == 4 => {
            public_recovery::check_source_spend(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("evm-key-init") if a.len() == 3 => evm_key::init(Path::new(&a[2]))?,
        Some("evm-sign-digest") if a.len() == 3 => evm_key::sign_stdin(Path::new(&a[2]))?,
        Some("regtest-init") if a.len() == 3 => wallet::init(Path::new(&a[2]))?,
        Some("testnet-wallet-init") if a.len() == 3 => wallet::init_testnet(Path::new(&a[2]))?,
        Some("testnet-wallet-receivers") if a.len() == 3 => {
            wallet::testnet_receivers(Path::new(&a[2]))?
        }
        Some("compact-scan") if a.len() == 4 || a.len() == 5 => {
            compact_wallet::scan(Path::new(&a[2]), Path::new(&a[3]), a.get(4).map(Path::new))?
        }
        Some("compact-source-snapshot") if a.len() == 7 => compact_wallet::source_snapshot(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            a[5].parse()?,
            Path::new(&a[6]),
        )?,
        Some("testnet-unsigned-graph") if a.len() == 6 => public_graph::prepare(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            Path::new(&a[5]),
        )?,
        Some("check-unsigned-graph-synthetic") if a.len() == 3 || a.len() == 4 => {
            public_graph::synthetic(Path::new(&a[2]), a.get(3).map(Path::new))?
        }
        Some("regtest-export-compact") if a.len() == 4 => {
            compact_wallet::export_regtest(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("regtest-scan") if a.len() == 4 => wallet::scan(Path::new(&a[2]), Path::new(&a[3]))?,
        Some("regtest-compact-aux") if a.len() == 4 => {
            auxiliary::compact(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("regtest-prepare") if a.len() == 5 => {
            regtest_swap::prepare(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]), None)?
        }
        Some("regtest-prepare-timestamp") if a.len() == 6 => regtest_swap::prepare_timestamp(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            a[5].parse()?,
        )?,
        Some("regtest-setup-init") if a.len() == 3 => source_guard::init(Path::new(&a[2]))?,
        Some("regtest-cancel-setup") if a.len() == 3 => {
            source_guard::Guard::open(Path::new(&a[2]))?.cancel()?
        }
        Some("regtest-commit-funding") if a.len() == 4 => {
            let dir = Path::new(&a[2]);
            let guard = source_guard::for_terms(dir, &storage::json(&dir.join("terms.json"))?)?
                .ok_or("source guard required")?;
            let consent = funding_consent::verify(
                dir,
                Path::new(&a[3]),
                &storage::read(&dir.join("unsigned-funding.pczt"), 100_000)?,
            )?;
            guard.release(&consent)?;
            consent
        }
        Some("regtest-stage") if a.len() == 6 => regtest_swap::prepare(
            Path::new(&a[2]),
            Path::new(&a[3]),
            Path::new(&a[4]),
            Some(Path::new(&a[5])),
        )?,
        Some("regtest-authorize-funding") if a.len() == 5 => {
            regtest_swap::authorize_funding(Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]))?
        }
        Some("regtest-check-consent") if a.len() == 4 => funding_consent::verify(
            Path::new(&a[2]),
            Path::new(&a[3]),
            &storage::read(&Path::new(&a[2]).join("unsigned-funding.pczt"), 100_000)?,
        )?,
        Some("regtest-finish") if a.len() == 5 || a.len() == 6 => regtest_swap::finish(
            Path::new(&a[2]),
            Path::new(&a[3]),
            &a[4],
            a.get(5).map(String::as_str),
        )?,
        Some("participant") if a.len() == 4 => {
            participants::serve(Path::new(&a[2]), a[3].parse()?)?;
            return Ok(());
        }
        Some("regtest-inspect") if a.len() == 3 => regtest_swap::inspect(Path::new(&a[2]))?,
        Some("inspect-transaction") if a.len() == 3 => {
            observed_transaction::inspect(Path::new(&a[2]))?
        }
        Some("regtest-export-recovery") if a.len() == 4 => {
            recovery_bundle::export(Path::new(&a[2]), Path::new(&a[3]))?
        }
        Some("prepare-synthetic") if a.len() == 3 => prepare(Path::new(&a[2]))?,
        Some("complete-synthetic") if a.len() == 4 => complete(Path::new(&a[2]), &a[3])?,
        _ => {
            return Err(
                "usage: prepare-synthetic DIRECTORY | complete-synthetic DIRECTORY WITNESS_LE_HEX"
                    .into(),
            );
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
