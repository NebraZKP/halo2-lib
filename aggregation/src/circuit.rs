use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2_base::Context;
use serde::{Deserialize, Serialize};

pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    /// Public inputs
    pub pi: Vec<Fr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVerificationKey {
    pub alpha: [String; 2],
    pub beta: [[String; 2]; 2],
    pub gamma: [[String; 2]; 2],
    pub delta: [[String; 2]; 2],
    pub s: Vec<[String; 2]>,
}

pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub s: Vec<G1Affine>,
}

struct PreparedProof {
    /// Rescaled pairs (r^i * A_i, B_i)
    ab_pairs: Vec<(G1Affine, G2Affine)>,
    /// (-sum_i r^i * P, Q)
    rP: (G1Affine, G2Affine),
    /// (-PI, h)
    pi: (G1Affine, G2Affine),
    /// (- sum_i r^i C_i, D)
    zc: (G1Affine, G2Affine),
}

pub fn batch_verify(
    ctx: &mut Context<Fr>,
    vk: &VerificationKey,
    proofs: &Vec<Proof>,
) {
    todo!();
}
