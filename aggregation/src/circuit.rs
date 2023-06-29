use std::fs::File;

use halo2_base::halo2_proofs::halo2curves::bn256::{
    Fq, Fq2, Fr, G1Affine, G2Affine,
};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::FieldChip;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// Util functions for reading field and curve points from JSON.

fn fr_from_str(s: &String) -> Fr {
    Fr::from_str_vartime(s.as_str())
        .unwrap_or_else(|| panic!("Failed to parse Fr string: {s}"))
}

fn fq_from_str(s: &String) -> Fq {
    Fq::from_str_vartime(s.as_str())
        .unwrap_or_else(|| panic!("Failed to parse Fq string: {s}"))
}

fn g1_from_json(json: &[String; 2]) -> G1Affine {
    G1Affine {
        x: fq_from_str(&json[0]),
        y: fq_from_str(&json[1]),
    }
}

fn fq2_from_json(json: &[String; 2]) -> Fq2 {
    Fq2 {
        c0: fq_from_str(&json[0]),
        c1: fq_from_str(&json[1]),
    }
}

fn g2_from_json(json: &[[String; 2]; 2]) -> G2Affine {
    G2Affine {
        x: fq2_from_json(&json[0]),
        y: fq2_from_json(&json[1]),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonVerificationKey {
    pub alpha: [String; 2],
    pub beta: [[String; 2]; 2],
    pub gamma: [[String; 2]; 2],
    pub delta: [[String; 2]; 2],
    pub s: Vec<[String; 2]>,
}

#[derive(Debug)]
pub struct VerificationKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub s: Vec<G1Affine>,
}

impl From<&JsonVerificationKey> for VerificationKey {
    fn from(vk_json: &JsonVerificationKey) -> Self {
        VerificationKey {
            alpha: g1_from_json(&vk_json.alpha),
            beta: g2_from_json(&vk_json.beta),
            gamma: g2_from_json(&vk_json.gamma),
            delta: g2_from_json(&vk_json.delta),
            s: vk_json.s.iter().map(g1_from_json).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonProof {
    pub a: [String; 2],
    pub b: [[String; 2]; 2],
    pub c: [String; 2],
}

#[derive(Debug)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    // /// Public inputs
    // pub pi: Vec<Fr>,
}

impl From<&JsonProof> for Proof {
    fn from(json: &JsonProof) -> Self {
        Proof {
            a: g1_from_json(&json.a),
            b: g2_from_json(&json.b),
            c: g1_from_json(&json.c),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonPublicInputs(Vec<String>);

#[derive(Debug)]
pub struct PublicInputs(Vec<Fr>);

impl From<&JsonPublicInputs> for PublicInputs {
    fn from(json: &JsonPublicInputs) -> Self {
        PublicInputs(json.0.iter().map(fr_from_str).collect())
    }
}

pub fn load_json<T: DeserializeOwned + Clone>(filename: &str) -> T {
    let val: T = serde_json::from_reader(
        File::open(filename).unwrap_or_else(|e| panic!("{filename}: {e:?}")),
    )
    .unwrap_or_else(|e| panic!("{filename} JSON: {e:?}"));
    val
}

pub fn load_vk(filename: &str) -> VerificationKey {
    let vk_json: JsonVerificationKey = load_json(filename);
    VerificationKey::from(&vk_json)
}

pub fn load_proof_and_inputs(filename: &str) -> (Proof, PublicInputs) {
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct JsonProofAndInputs {
        proof: JsonProof,
        inputs: JsonPublicInputs,
    }

    let proof_pi_json: JsonProofAndInputs = load_json(filename);
    (
        Proof::from(&proof_pi_json.proof),
        PublicInputs::from(&proof_pi_json.inputs),
    )
}

// In-circuit objects

pub struct AssignedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub a: EcPoint<F, FC::FieldPoint>,
    pub b: EcPoint<F, FC::FieldPoint>,
    pub c: EcPoint<F, FC::FieldPoint>,
}

pub struct AssignedPublicInputs<F: PrimeField + ScalarField>(
    Vec<AssignedValue<F>>,
);

/// "Prepared" here means that all curve points have been accumulated and we
/// have a sequence of pairs of G1 and G2 points ready for passing to a
/// multi-Miller loop.
struct AssignedPreparedProof {
    /// Rescaled pairs (r^i * A_i, B_i)
    pub ab_pairs: Vec<(G1Affine, G2Affine)>,
    /// (-sum_i r^i * P, Q)
    pub rP: (G1Affine, G2Affine),
    /// (-PI, h)
    pub pi: (G1Affine, G2Affine),
    /// (- sum_i r^i C_i, D)
    pub zc: (G1Affine, G2Affine),
}

/// Execute the top-level batch verification by accumulating (as far as
/// possible) all proofs and public inputs, and performing a single large
/// pairing check.
pub fn batch_verify<FC: FieldChip<Fr>>(
    ctx: &mut Context<Fr>,
    fp_chip: &FC,
    vk: &VerificationKey,
    proofs: &Vec<(AssignedProof<Fr, FC>, AssignedPublicInputs<Fr>)>,
) {
    todo!()
}
