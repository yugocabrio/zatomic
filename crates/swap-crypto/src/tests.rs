use super::*;
use ff::Field;
use rand_core::OsRng;

fn keygen() -> (
    BTreeMap<Identifier, keys::KeyPackage>,
    keys::PublicKeyPackage,
) {
    let a = Identifier::try_from(1u16).unwrap();
    let b = Identifier::try_from(2u16).unwrap();
    let (a1, ap1) = keys::dkg::part1(a, 2, 2, OsRng).unwrap();
    let (b1, bp1) = keys::dkg::part1(b, 2, 2, OsRng).unwrap();
    let a_receives = BTreeMap::from([(b, bp1)]);
    let b_receives = BTreeMap::from([(a, ap1)]);
    let (a2, ap2) = keys::dkg::part2(a1, &a_receives).unwrap();
    let (b2, bp2) = keys::dkg::part2(b1, &b_receives).unwrap();
    let (ak, public) =
        keys::dkg::part3(&a2, &a_receives, &BTreeMap::from([(b, bp2[&a].clone())])).unwrap();
    let (bk, other) =
        keys::dkg::part3(&b2, &b_receives, &BTreeMap::from([(a, ap2[&b].clone())])).unwrap();
    assert_eq!(public, other);
    (BTreeMap::from([(a, ak), (b, bk)]), public)
}

fn fixture() -> (PreSignature, [u8; 32]) {
    let (keys, public) = keygen();
    let t = pallas::Scalar::random(OsRng);
    let ctx = Context {
        session: [1; 32],
        message: [2; 32],
        randomizer: pallas::Scalar::random(OsRng).to_repr(),
        adaptor_point: (generator() * t).to_bytes(),
    };
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key) in &keys {
        let (n, c) = Nonce::generate(key, &mut OsRng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let session = SigningSession::new(ctx, public, commitments).unwrap();
    let shares = nonces
        .into_iter()
        .map(|(id, nonce)| (id, session.sign(&keys[&id], nonce).unwrap()))
        .collect();
    let pre = session.aggregate(&shares).unwrap();
    let mut single = shares.clone();
    single.pop_first();
    assert!(session.aggregate(&single).is_err());
    let mut corrupt = shares;
    corrupt.first_entry().unwrap().get_mut()[0] ^= 1;
    assert!(session.aggregate(&corrupt).is_err());
    (pre, t.to_repr())
}

#[test]
fn dkg_rerandomized_adaptor_passes_current_native_verifier_and_extracts() {
    for _ in 0..8 {
        let (pre, t) = fixture();
        pre.verify().unwrap();
        let signature = pre.adapt(&t).unwrap();
        pre.verify_final(&signature).unwrap();
        assert_eq!(pre.extract(&signature).unwrap(), t);
        let mut incomplete = signature;
        incomplete[32..].copy_from_slice(&pre.s_hat);
        assert!(pre.verify_final(&incomplete).is_err());
    }
}

#[test]
fn wrong_witness_transaction_key_point_and_encoding_reject() {
    let (pre, t) = fixture();
    assert!(pre.adapt(&[0; 32]).is_err());
    assert!(pre.adapt(&[255; 32]).is_err());
    let sig = pre.adapt(&t).unwrap();
    let mut wrong = pre.clone();
    wrong.message[0] ^= 1;
    assert!(wrong.verify().is_err());
    assert!(wrong.verify_final(&sig).is_err());
    let mut wrong = pre.clone();
    wrong.key = generator().to_bytes();
    assert!(wrong.verify().is_err());
    let mut wrong = pre.clone();
    wrong.adaptor_point = generator().to_bytes();
    assert!(wrong.verify().is_err());
    let mut wrong = pre.clone();
    wrong.adaptor_point = [0; 32];
    assert!(wrong.verify().is_err());
    let mut wrong = pre.clone();
    wrong.s_hat = [255; 32];
    assert!(wrong.verify().is_err());
    let mut badsig = sig;
    badsig[42] ^= 1;
    assert!(pre.extract(&badsig).is_err());
}

#[test]
fn nonce_substitution_and_missing_participant_reject() {
    let (keys, public) = keygen();
    let ctx = Context {
        session: [3; 32],
        message: [4; 32],
        randomizer: [0; 32],
        adaptor_point: generator().to_bytes(),
    };
    let commitments = keys
        .iter()
        .map(|(id, k)| (*id, Nonce::generate(k, &mut OsRng).1))
        .collect::<BTreeMap<_, _>>();
    let mut missing = commitments.clone();
    missing.pop_first();
    assert!(SigningSession::new(ctx.clone(), public.clone(), missing).is_err());
    let session = SigningSession::new(ctx, public, commitments).unwrap();
    let key = keys.first_key_value().unwrap().1;
    assert!(
        session
            .sign(key, Nonce::generate(key, &mut OsRng).0)
            .is_err()
    );
}
