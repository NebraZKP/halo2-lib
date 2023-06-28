use halo2_base::halo2_proofs::halo2curves::bn256::{
    Bn256, Fr, G1Affine, G2Affine,
};
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

// todo: implement trait Serialize for VerificationKey
