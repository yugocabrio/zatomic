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

/// A malicious co-signer shifts its hiding commitment by -T. Its own share can
/// then never verify, but the honest holder's raw share alone would let it
/// finish a valid native signature without t. The holder must check first.
#[test]
fn shifted_peer_nonce_cannot_obtain_witness_free_signature() {
    let (keys, public) = keygen();
    let alice = Identifier::try_from(1u16).unwrap();
    let bob = Identifier::try_from(2u16).unwrap();
    let t = pallas::Scalar::random(OsRng);
    let point = generator() * t;
    let ctx = Context {
        session: [7; 32],
        message: [8; 32],
        randomizer: pallas::Scalar::random(OsRng).to_repr(),
        adaptor_point: point.to_bytes(),
    };
    let (alice_nonce, alice_commitment) = Nonce::generate(&keys[&alice], &mut OsRng);
    let (d, e) = (pallas::Scalar::random(OsRng), pallas::Scalar::random(OsRng));
    let commitment =
        |p: pallas::Point| round1::NonceCommitment::deserialize(&p.to_bytes()).unwrap();
    let shifted = round1::SigningCommitments::new(
        commitment(generator() * d - point),
        commitment(generator() * e),
    );
    let session = SigningSession::new(
        ctx.clone(),
        public,
        BTreeMap::from([(alice, alice_commitment), (bob, shifted)]),
    )
    .unwrap();
    let rho = scalar(
        &session
            .factors
            .get(&bob)
            .unwrap()
            .serialize()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let lambda = frost_core::derive_interpolating_value(&bob, &session.package).unwrap();
    let alpha = scalar(&ctx.randomizer).unwrap();
    // Everything Bob can compute for his committed nonce; it is off by -t.
    let bob_part =
        d + rho * e + lambda * session.challenge * (keys[&bob].signing_share().to_scalar() + alpha);
    assert!(session.verify_share(&bob, &bob_part.to_repr()).is_err());

    // Enforced path: the holder refuses before producing any share.
    assert!(
        session
            .sign_after_peer(&keys[&alice], alice_nonce, &bob, &bob_part.to_repr())
            .is_err()
    );

    // Unprotected path, shown to justify the order: a released raw share is
    // enough for Bob to complete a native-valid signature without knowing t.
    let (fresh_nonce, fresh_commitment) = Nonce::generate(&keys[&alice], &mut OsRng);
    let session = SigningSession::new(
        ctx.clone(),
        session.public.clone(),
        BTreeMap::from([
            (alice, fresh_commitment),
            (
                bob,
                round1::SigningCommitments::new(
                    commitment(generator() * d - point),
                    commitment(generator() * e),
                ),
            ),
        ]),
    )
    .unwrap();
    let rho = scalar(
        &session
            .factors
            .get(&bob)
            .unwrap()
            .serialize()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let bob_part =
        d + rho * e + lambda * session.challenge * (keys[&bob].signing_share().to_scalar() + alpha);
    let alice_share = session.sign(&keys[&alice], fresh_nonce).unwrap();
    let mut forged = [0; 64];
    forged[..32].copy_from_slice(&session.r_hat.to_bytes());
    forged[32..].copy_from_slice(&(scalar(&alice_share).unwrap() + bob_part).to_repr());
    let key: [u8; 32] = session
        .randomized_key
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let vk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(key).unwrap();
    assert!(
        vk.verify(&ctx.message, &reddsa::Signature::from(forged))
            .is_ok()
    );
}

#[test]
fn peer_first_release_order_signs_honest_sessions() {
    let (keys, public) = keygen();
    let alice = Identifier::try_from(1u16).unwrap();
    let bob = Identifier::try_from(2u16).unwrap();
    let t = pallas::Scalar::random(OsRng);
    let ctx = Context {
        session: [9; 32],
        message: [10; 32],
        randomizer: pallas::Scalar::random(OsRng).to_repr(),
        adaptor_point: (generator() * t).to_bytes(),
    };
    let (an, ac) = Nonce::generate(&keys[&alice], &mut OsRng);
    let (bn, bc) = Nonce::generate(&keys[&bob], &mut OsRng);
    let session =
        SigningSession::new(ctx, public, BTreeMap::from([(alice, ac), (bob, bc)])).unwrap();
    let bz = session.sign(&keys[&bob], bn).unwrap();
    let mut wrong = bz;
    wrong[0] ^= 1;
    assert!(session.verify_share(&bob, &wrong).is_err());
    assert!(
        session
            .sign_after_peer(
                &keys[&alice],
                Nonce::generate(&keys[&alice], &mut OsRng).0,
                &alice,
                &bz
            )
            .is_err()
    );
    let az = session
        .sign_after_peer(&keys[&alice], an, &bob, &bz)
        .unwrap();
    let pre = session
        .aggregate(&BTreeMap::from([(alice, az), (bob, bz)]))
        .unwrap();
    let signature = pre.adapt(&t.to_repr()).unwrap();
    assert_eq!(pre.extract(&signature).unwrap(), t.to_repr());
}
