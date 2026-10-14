use ff::PrimeField;
use group::Curve;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use shielded_swap_crypto::generator;

fn be(mut le: [u8; 32]) -> String {
    le.reverse();
    format!("0x{}", hex::encode(le))
}

fn main() {
    let mut scalars = vec![
        pallas::Scalar::from(1),
        pallas::Scalar::from(2),
        -pallas::Scalar::from(1),
    ];
    for i in 1..=12u8 {
        let mut le =
            std::array::from_fn(|j| i.wrapping_mul(17).wrapping_add((j as u8).wrapping_mul(37)));
        le[31] &= 0x3f;
        scalars.push(pallas::Scalar::from_repr(le).unwrap());
    }
    let vectors: Vec<_> = scalars.into_iter().map(|s| {
        let a = (generator() * s).to_affine();
        let c = a.coordinates().unwrap();
        serde_json::json!({"scalar":be(s.to_repr()), "x":be(c.x().to_repr()), "y":be(c.y().to_repr())})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "source":"pasta_curves 0.5.2; RedPallas SpendAuth generator, NOT default Pallas generator",
        "base_modulus":pallas::Base::MODULUS,"scalar_modulus":pallas::Scalar::MODULUS,
        "scope":"public deterministic fixtures; never use for real funds", "vectors":vectors
    })).unwrap());
}
