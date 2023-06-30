use std::fs::File;

use halo2_base::halo2_proofs::halo2curves::bn256::{
    multi_miller_loop, Fq, Fq2, Fr, G1Affine, G2Affine, G2Prepared, Gt, G1,
};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::CurveAffineExt;

use halo2_base::halo2_proofs::halo2curves::pairing::MillerLoopResult;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::iter::once;

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
pub struct VerificationKey<C1 = G1Affine, C2 = G2Affine>
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
{
    pub alpha: C1,
    pub beta: C2,
    pub gamma: C2,
    pub delta: C2,
    pub s: Vec<C1>,
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
pub struct Proof<C1 = G1Affine, C2 = G2Affine>
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
{
    pub a: C1,
    pub b: C2,
    pub c: C1,
}

/// "Prepared" here means that all curve points have been accumulated and we
/// have a sequence of pairs of G1 and G2 points ready for passing to a
/// multi-Miller loop.
struct PreparedProof {
    /// Rescaled pairs (r^i * A_i, B_i)
    pub ab_pairs: Vec<(G1Affine, G2Affine)>,
    /// (-sum_i r^i * P, Q)
    pub rp: (G1Affine, G2Affine),
    /// (-PI, h)
    pub pi: (G1Affine, G2Affine),
    /// (- sum_i r^i C_i, D)
    pub zc: (G1Affine, G2Affine),
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

#[derive(Clone, Debug)]
pub struct PublicInputs<F = Fr>(pub Vec<F>)
where
    F: PrimeField;

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

pub fn prepare_public_inputs(
    vk: &VerificationKey,
    inputs: &PublicInputs,
) -> G1Affine {
    let mut pi = G1::from(vk.s[0]);
    for i in 0..inputs.0.len() {
        pi = pi + (vk.s[i + 1] * inputs.0[i]);
    }
    G1Affine::from(pi)
}

pub(crate) fn check_miller_pairs(
    pairs: &Vec<(&G1Affine, &G2Prepared)>,
) -> bool {
    let miller_out = multi_miller_loop(pairs.as_slice());
    let pairing_out = miller_out.final_exponentiation();
    println!("PAIRING OUT: {pairing_out:?}");
    // Pairing check
    pairing_out == Gt::identity()
}

pub fn verify(
    vk: &VerificationKey,
    proof: &Proof,
    inputs: &PublicInputs,
) -> bool {
    assert!(vk.s.len() == inputs.0.len() + 1);

    // Multiply PIs by VK.s

    let pi = prepare_public_inputs(vk, inputs);

    // Compute the product of pairings

    // This mimics the arrangement in circuit:
    // check_miller_pairs(&vec![
    //     (&proof.a, &G2Prepared::from_affine(proof.b)),
    //     (&-vk.alpha, &G2Prepared::from_affine(vk.beta)),
    //     (&-pi, &G2Prepared::from_affine(G2Affine::generator())),
    //     (&-proof.c, &G2Prepared::from_affine(vk.delta)),
    // ])

    check_miller_pairs(&vec![
        (&proof.a, &G2Prepared::from_affine(proof.b)),
        (&-vk.alpha, &G2Prepared::from_affine(vk.beta)),
        (&-pi, &G2Prepared::from_affine(G2Affine::generator())),
        (&-proof.c, &G2Prepared::from_affine(vk.delta)),
    ])
}

pub(crate) fn batch_verify_compute_r_powers(
    r: Fr,
    num_powers: usize,
) -> Vec<Fr> {
    assert!(num_powers >= 2);
    let mut powers = Vec::<Fr>::with_capacity(num_powers);
    powers.push(Fr::from(1));
    powers.push(r);
    for i in 2..num_powers {
        powers.push(powers.last().unwrap() * r);
    }

    assert!(powers.len() == num_powers);
    powers
}

pub(crate) fn batch_verify_compute_f_j(
    s: &Vec<G1Affine>,
    inputs: &Vec<&PublicInputs>,
    r_powers: &Vec<Fr>,
    sum_r_powers: &Fr,
    j: usize,
) -> Fr {
    if j == 0 {
        return *sum_r_powers;
    }

    let mut res = inputs[0].0[j - 1];
    for i in 1..inputs.len() {
        let r_pow_i = r_powers[i];
        let input = inputs[i].0[j - 1];
        res += r_pow_i * input;
    }
    res
}

pub(crate) fn batch_verify_compute_minus_pi(
    s: &Vec<G1Affine>,
    inputs: &Vec<&PublicInputs>,
    r_powers: &Vec<Fr>,
    sum_r_powers: Fr,
) -> G1Affine {
    let num_proofs = inputs.len();
    let num_inputs = inputs[0].0.len();
    assert!(s.len() == num_inputs + 1);

    // f_j is the sum of r_i * PI_i[j] (j-th input to the i-th proof)
    //
    //   f_j = \sum_{0}^{n-1} r^i PI_{i,j}
    //
    // n = num_proofs
    //
    // Implicitly, each input set includes 1 at position 0, hence:
    //
    //   f_0 = \sum_{0}^{n-1} r^i = sum_r_powers
    //   f_j = \sum_{0}^{n-1} r^i = PI_{i,j-1}

    let mut pi =
        s[0] * batch_verify_compute_f_j(s, inputs, r_powers, &sum_r_powers, 0);
    for j in 1..num_inputs + 1 {
        let pi_i = s[j]
            * batch_verify_compute_f_j(s, inputs, r_powers, &sum_r_powers, j);

        pi = pi + pi_i;
    }

    G1Affine::from(-pi)
}

pub(crate) fn batch_verify_compute_minus_ZC(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r_powers: &Vec<Fr>,
) -> G1Affine {
    let z_C: G1 = proofs_and_inputs
        .iter()
        .zip(r_powers.iter())
        .map(|(p_i, r_power)| p_i.0.c * r_power)
        .reduce(|a, b| a + b)
        .unwrap();
    G1Affine::from(-z_C)
}

pub(crate) fn batch_verify_compute_r_i_A_i_B_i(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r_powers: &Vec<Fr>,
) -> Vec<(G1Affine, G2Affine)> {
    let A_is = proofs_and_inputs.iter().map(|p_i| p_i.0.a);
    let A_i_r_is = A_is
        .zip(r_powers.iter())
        .map(|(A, r_i)| G1Affine::from(A * r_i));

    let B_is = proofs_and_inputs.iter().map(|p_i| p_i.0.b);
    A_i_r_is.zip(B_is).collect()
}

pub(crate) fn batch_verify_compute_miller_pairs(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r: Fr,
) -> Vec<(G1Affine, G2Prepared)> {
    let num_proofs = proofs_and_inputs.len();
    assert!(num_proofs > 0);
    let num_inputs = proofs_and_inputs[0].1 .0.len();
    let r_powers: Vec<Fr> = batch_verify_compute_r_powers(r, num_proofs);
    assert!(r_powers[0] == Fr::from(1));
    assert!(r_powers[num_proofs - 1] == r_powers[1] * r_powers[num_proofs - 2]);

    let sum_r_powers: Fr =
        r_powers.iter().copied().reduce(|a, b| (a + b)).unwrap();

    // TODO: remove these once all issues are fixed.

    // Accumulated public inputs

    let minus_pi = batch_verify_compute_minus_pi(
        &vk.s,
        &proofs_and_inputs.iter().map(|p_i| p_i.1).collect(),
        &r_powers,
        sum_r_powers,
    );

    // Compute z_C

    let minus_z_C: G1Affine =
        batch_verify_compute_minus_ZC(vk, proofs_and_inputs, &r_powers);

    // Compute ( \sum_i r^i ) * P

    let minus_r_P: G1Affine = G1Affine::from(-(vk.alpha * sum_r_powers));

    // Construct (A_i * r^i, B_i)

    let r_i_A_i_B_i =
        batch_verify_compute_r_i_A_i_B_i(vk, proofs_and_inputs, &r_powers);

    // Miller pairs

    let miller_pairs = r_i_A_i_B_i
        .iter()
        .copied()
        .chain(once((minus_r_P, vk.beta)))
        .chain(once((minus_pi, G2Affine::generator())))
        .chain(once((minus_z_C, vk.delta)));
    let miller_pairs = miller_pairs.map(|(a, b)| (a, G2Prepared::from(b)));

    let miller_pairs: Vec<(G1Affine, G2Prepared)> = miller_pairs.collect();

    miller_pairs
}

pub fn batch_verify(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r: Fr,
) -> bool {
    let miller_pairs =
        batch_verify_compute_miller_pairs(vk, proofs_and_inputs, r);
    let miller_pair_refs: Vec<(&G1Affine, &G2Prepared)> = miller_pairs
        .iter()
        .map(|(a, b)| (a, b))
        .collect::<Vec<(&G1Affine, &G2Prepared)>>();
    check_miller_pairs(&miller_pair_refs)
}
