use std::fs::File;

use halo2_base::halo2_proofs::halo2curves::bn256::{
    multi_miller_loop, Fq, Fq2, Fr, G1Affine, G2Affine, G2Prepared, Gt, G1,
};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;

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

/// "Prepared" here means that all curve points have been accumulated and we
/// have a sequence of pairs of G1 and G2 points ready for passing to a
/// multi-Miller loop.
struct PreparedProof {
    /// Rescaled pairs (r^i * A_i, B_i)
    pub ab_pairs: Vec<(G1Affine, G2Affine)>,
    /// (-sum_i r^i * P, Q)
    pub rP: (G1Affine, G2Affine),
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

#[derive(Debug)]
pub struct PublicInputs(pub Vec<Fr>);

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

pub fn verify(
    vk: &VerificationKey,
    proof: &Proof,
    inputs: &PublicInputs,
) -> bool {
    assert!(vk.s.len() == inputs.0.len() + 1);

    // Multiply PIs by VK.s

    let pi = {
        let mut pi = G1::from(vk.s[0]);
        for i in 0..inputs.0.len() {
            pi = pi + (vk.s[i + 1] * inputs.0[i]);
        }
        G1Affine::from(pi)
    };

    // Compute the product of pairings

    let miller_out = multi_miller_loop(&[
        (&-proof.a, &G2Prepared::from_affine(proof.b)),
        (&vk.alpha, &G2Prepared::from_affine(vk.beta)),
        (&pi, &G2Prepared::from_affine(G2Affine::generator())),
        (&proof.c, &G2Prepared::from_affine(vk.delta)),
    ]);
    let pairing_out = miller_out.final_exponentiation();

    // Pairing check

    return pairing_out == Gt::identity();
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
    println!(" =====================");
    if j == 0 {
        return *sum_r_powers;
    }

    let mut res = inputs[0].0[j - 1];
    println!(" res = {res:?}");
    for i in 1..inputs.len() {
        println!(" i = {i:?}");
        let r_pow_i = r_powers[i];
        println!(" r_powers[i] = {r_pow_i:?}");
        let input = inputs[i].0[j - 1];
        println!(" inputs[i].0[j - 1] = {input:?}");
        // res += r_powers[i] * inputs[i].0[j - 1];
        res += r_pow_i * input;
        println!(" res = {res:?}");
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
    let expect = [
        G1Affine::from(G1::generator() * Fr::from(114)),
        G1Affine::from(G1::generator() * Fr::from(1944)),
        G1Affine::from(G1::generator() * Fr::from(3810)),
    ];
    assert!(G1Affine::from(pi) == expect[0]);
    for j in 1..num_proofs {
        println!("j={j:?}");
        let pi_i = s[j]
            * batch_verify_compute_f_j(s, inputs, r_powers, &sum_r_powers, j);
        assert!(G1Affine::from(pi_i) == expect[j]);

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

pub fn batch_verify(
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(&Proof, &PublicInputs)>,
    r: Fr,
) -> bool {
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

    // TODO: copy required because inputs to reduce closure are refrences, but
    // return a full Fr.
    let minus_r_P: G1Affine = G1Affine::from(-(vk.alpha * sum_r_powers));

    // A_i * r^i

    let A_is = proofs_and_inputs.iter().map(|p_i| p_i.0.a);
    let A_i_r_is = A_is
        .zip(r_powers.iter())
        .map(|(A, r_i)| G1Affine::from(A * r_i));

    let B_is = proofs_and_inputs.iter().map(|p_i| p_i.0.b);
    let A_B_pairs = A_i_r_is.zip(B_is);

    let A_B_pairs = A_B_pairs
        .chain(once((minus_r_P, G2Affine::generator())))
        .chain(once((minus_pi, vk.beta)))
        .chain(once((minus_z_C, vk.delta)));
    let A_B_pairs = A_B_pairs.map(|(a, b)| (a, G2Prepared::from(b)));

    // Miller

    let A_B_pairs: Vec<(G1Affine, G2Prepared)> = A_B_pairs.collect();
    let pair_refs: Vec<(&G1Affine, &G2Prepared)> = A_B_pairs
        .iter()
        .map(|(a, b)| (a, b))
        .collect::<Vec<(&G1Affine, &G2Prepared)>>();

    let miller_out = multi_miller_loop(pair_refs.as_slice());

    let pairing_out = miller_out.final_exponentiation();

    println!("PAIRING OUT: {pairing_out:?}");

    // Pairing check

    return pairing_out == Gt::identity();
}
