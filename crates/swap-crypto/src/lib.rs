//! Experimental, strictly 2-of-2 RedPallas adaptor signatures.
//!
//! FROST DKG/nonces are reused from Zcash Foundation. The adaptor extension is
//! ours, unaudited, and NOT covered by upstream FROST's security claims. Bytes
//! cross the old FROST/current native-verifier boundary; Rust curve types do not.
use std::collections::BTreeMap;

use ff::PrimeField;
use group::{Group, GroupEncoding};
use pasta_curves::pallas;
use rand_core::{CryptoRng, RngCore};
use reddsa_frost::frost::redpallas::{self as frost, Ciphersuite};

pub use frost::{Identifier, keys, round1};
pub type Result<T> = std::result::Result<T, String>;
type C = frost::PallasBlake2b512;

pub fn generator() -> pallas::Point {
    <frost::PallasGroup as frost::Group>::generator()
}

fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn point(bytes: &[u8; 32]) -> Result<pallas::Point> {
    let p = Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
        .ok_or("noncanonical point")?;
    if bool::from(p.is_identity()) {
        return Err("identity point".into());
    }
    Ok(p)
}

fn scalar(bytes: &[u8; 32]) -> Result<pallas::Scalar> {
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*bytes))
        .ok_or("noncanonical scalar".into())
}

/// One-use nonce ownership. No Clone, Debug or serialization implementation.
/// Durable storage must persist consumption BEFORE any share leaves a process.
pub struct Nonce(round1::SigningNonces);

impl Nonce {
    pub fn generate(
        key: &keys::KeyPackage,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Self, round1::SigningCommitments) {
        let (n, c) = round1::commit(key.signing_share(), rng);
        (Self(n), c)
    }
}

/// Public signing context. `session` identifies a fresh attempt; it does not
/// replace application validation of transaction effects and canonical terms.
/// The native client independently computes `message` and pins its full policy.
#[derive(Clone)]
pub struct Context {
    pub session: [u8; 32],
    pub message: [u8; 32],
    pub randomizer: [u8; 32],
    pub adaptor_point: [u8; 32],
}

pub struct SigningSession {
    context: Context,
    public: keys::PublicKeyPackage,
    package: frost::SigningPackage,
    factors: frost_core::BindingFactorList<C>,
    randomized_key: frost_core::VerifyingKey<C>,
    r_hat: pallas::Point,
    challenge: pallas::Scalar,
}

impl SigningSession {
    pub fn new(
        context: Context,
        public: keys::PublicKeyPackage,
        commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    ) -> Result<Self> {
        if public.verifying_shares().len() != 2
            || commitments.len() != 2
            || !commitments.keys().eq(public.verifying_shares().keys())
        {
            return Err("exactly the two agreed participants are required".into());
        }
        let t = point(&context.adaptor_point)?;
        let alpha = scalar(&context.randomizer)?;
        let rk = public.verifying_key().to_element() + generator() * alpha;
        if bool::from(rk.is_identity()) {
            return Err("identity randomized key".into());
        }
        let randomized_key = frost_core::VerifyingKey::new(rk);
        let package = frost::SigningPackage::new(commitments, &context.message);
        let mut prefix = b"ShieldedSwap/adaptor/v1".to_vec();
        prefix.extend_from_slice(&context.session);
        prefix.extend_from_slice(&context.adaptor_point);
        prefix.extend_from_slice(&context.randomizer);
        let factors = frost_core::compute_binding_factor_list(&package, &randomized_key, &prefix)
            .map_err(error)?;
        let r = frost_core::compute_group_commitment(&package, &factors).map_err(error)?;
        let r_hat = r.to_element() + t;
        if bool::from(r_hat.is_identity()) {
            return Err("identity adapted nonce".into());
        }
        let mut challenge_bytes = r_hat.to_bytes().to_vec();
        challenge_bytes.extend_from_slice(&rk.to_bytes());
        challenge_bytes.extend_from_slice(&context.message);
        let challenge = C::H2(&challenge_bytes);
        Ok(Self {
            context,
            public,
            package,
            factors,
            randomized_key,
            r_hat,
            challenge,
        })
    }

    /// Consumes the nonce even on error. Signers must first validate transaction
    /// effects and recovery terms independently; this is a cryptographic layer.
    pub fn sign(&self, key: &keys::KeyPackage, nonce: Nonce) -> Result<[u8; 32]> {
        if *key.min_signers() != 2
            || key.verifying_key() != self.public.verifying_key()
            || self.public.verifying_shares().get(key.identifier()) != Some(key.verifying_share())
        {
            return Err("key is not an agreed 2-of-2 participant".into());
        }
        if self.package.signing_commitments().get(key.identifier()) != Some(nonce.0.commitments()) {
            return Err("nonce commitment mismatch".into());
        }
        let lambda = frost_core::derive_interpolating_value(key.identifier(), &self.package)
            .map_err(error)?;
        let rho = scalar(
            &self
                .factors
                .get(key.identifier())
                .ok_or("missing binding factor")?
                .serialize()
                .try_into()
                .map_err(|_| "binding scalar length")?,
        )?;
        let z = nonce.0.hiding().to_scalar()
            + rho * nonce.0.binding().to_scalar()
            + lambda
                * self.challenge
                * (key.signing_share().to_scalar() + scalar(&self.context.randomizer)?);
        Ok(z.to_repr())
    }

    /// Release order for the adaptor-witness holder. A peer whose hiding
    /// commitment is shifted by -T makes Rhat's discrete log known to itself,
    /// so the holder's raw share would complete the native signature WITHOUT
    /// the witness. Such a peer cannot produce a share that verifies here.
    /// The holder therefore checks the peer's share before releasing its own.
    /// Consumes the nonce even on error.
    pub fn sign_after_peer(
        &self,
        key: &keys::KeyPackage,
        nonce: Nonce,
        peer: &Identifier,
        peer_share: &[u8; 32],
    ) -> Result<[u8; 32]> {
        if peer == key.identifier() {
            return Err("peer share must come from the other participant".into());
        }
        self.verify_share(peer, peer_share)?;
        self.sign(key, nonce)
    }

    /// `z G == D + rho E + lambda c (Y + alpha G)` for one participant.
    pub fn verify_share(&self, id: &Identifier, share: &[u8; 32]) -> Result<pallas::Scalar> {
        let z = scalar(share)?;
        let alpha = scalar(&self.context.randomizer)?;
        let rho = self.factors.get(id).ok_or("missing binding factor")?;
        let r = self
            .package
            .signing_commitments()
            .get(id)
            .ok_or("unknown participant")?
            .to_group_commitment_share(rho)
            .to_element();
        let lambda = frost_core::derive_interpolating_value(id, &self.package).map_err(error)?;
        let y = self
            .public
            .verifying_shares()
            .get(id)
            .ok_or("unknown participant")?
            .to_element()
            + generator() * alpha;
        if generator() * z != r + y * (lambda * self.challenge) {
            return Err("invalid signature share".into());
        }
        Ok(z)
    }

    pub fn aggregate(&self, shares: &BTreeMap<Identifier, [u8; 32]>) -> Result<PreSignature> {
        if shares.len() != 2 || !shares.keys().eq(self.public.verifying_shares().keys()) {
            return Err("both signature shares are required".into());
        }
        let mut total = pallas::Scalar::zero();
        for (id, bytes) in shares {
            total += self.verify_share(id, bytes)?;
        }
        let pre = PreSignature {
            r_hat: self.r_hat.to_bytes(),
            s_hat: total.to_repr(),
            key: self
                .randomized_key
                .serialize()
                .map_err(error)?
                .try_into()
                .map_err(|_| "key length")?,
            message: self.context.message,
            adaptor_point: self.context.adaptor_point,
        };
        pre.verify()?;
        Ok(pre)
    }
}

#[derive(Clone)]
pub struct PreSignature {
    pub r_hat: [u8; 32],
    pub s_hat: [u8; 32],
    pub key: [u8; 32],
    pub message: [u8; 32],
    pub adaptor_point: [u8; 32],
}

impl PreSignature {
    pub fn verify(&self) -> Result<()> {
        let r = point(&self.r_hat)?;
        let vk = point(&self.key)?;
        let t = point(&self.adaptor_point)?;
        let mut bytes = self.r_hat.to_vec();
        bytes.extend_from_slice(&self.key);
        bytes.extend_from_slice(&self.message);
        let c = C::H2(&bytes);
        if generator() * scalar(&self.s_hat)? != r - t + vk * c {
            return Err("invalid pre-signature".into());
        }
        Ok(())
    }

    pub fn adapt(&self, witness: &[u8; 32]) -> Result<[u8; 64]> {
        self.verify()?;
        let t = scalar(witness)?;
        if generator() * t != point(&self.adaptor_point)? {
            return Err("wrong witness".into());
        }
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&self.r_hat);
        signature[32..].copy_from_slice(&(scalar(&self.s_hat)? + t).to_repr());
        self.verify_final(&signature)?;
        Ok(signature)
    }

    pub fn verify_final(&self, signature: &[u8; 64]) -> Result<()> {
        let vk = reddsa::VerificationKey::<reddsa::orchard::SpendAuth>::try_from(self.key)
            .map_err(error)?;
        vk.verify(&self.message, &reddsa::Signature::from(*signature))
            .map_err(error)
    }

    pub fn extract(&self, signature: &[u8; 64]) -> Result<[u8; 32]> {
        self.verify()?;
        self.verify_final(signature)?;
        if signature[..32] != self.r_hat {
            return Err("different signature nonce".into());
        }
        let s = scalar(signature[32..].try_into().map_err(|_| "signature length")?)?;
        let t = s - scalar(&self.s_hat)?;
        if generator() * t != point(&self.adaptor_point)? {
            return Err("witness mismatch".into());
        }
        Ok(t.to_repr())
    }
}

#[cfg(test)]
mod tests;
