use super::*;
use crate::native::{
    batch_verify, batch_verify_compute_f_j, batch_verify_compute_minus_ZC,
    batch_verify_compute_minus_pi, batch_verify_compute_r_powers,
    load_proof_and_inputs, load_vk, verify, Proof, PublicInputs,
    VerificationKey,
};
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Fr, G1Affine, G2Affine, G1, G2},
};
use rand_core::OsRng;

fn encode(f: i32) -> G1Affine {
    G1Affine::from(G1::generator() * Fr::from(f as u64))
}

fn encode_g2(f: i32) -> G2Affine {
    G2Affine::from(G2::generator() * Fr::from(f as u64))
}

fn encode_fr(f: &Fr) -> G1Affine {
    G1Affine::from(G1::generator() * f)
}

fn encode_vec(fs: &Vec<i32>) -> Vec<G1Affine> {
    fs.iter().map(|a| encode(*a)).collect()
}

#[test]
fn test_groth16_verify() {
    let vk = load_vk(VK_FILE);
    let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
    let (proof2, inputs2) = load_proof_and_inputs(PROOF3_FILE);

    assert!(verify(&vk, &proof1, &inputs1));
    assert!(verify(&vk, &proof2, &inputs2));
    assert!(!verify(&vk, &proof2, &inputs1));
}

#[test]
fn test_pi_accumulation() {
    // Let:
    //     s = { [2], [3], [5] }
    //  pi_1 = {       4 ,  6  }
    //  pi_2 = {       8   10  }
    //  pi_3 = {       12  14  }
    //     r = 7
    //
    // then the accumulated PI term should be:
    //
    //   PI = PI_1 + r*PI_2
    //
    // where
    //
    //   PI_1 = [2] + 4*[3] + 6*[5] =  [44]
    //   PI_2 = [2] + 8*[3] +10*[5] =  [76]
    //   PI_3 = [2] +12*[3] +14*[5] = [108]
    //
    // so
    //
    //   PI = [44]+7*[76]+7^2*[108] = [44 + 532 + 5292] = [5868]

    let expect = -encode(5868);

    // let s: Vec<G1Affine> = [2, 3u32, 4u32].iter().map(encode).collect();
    let s: Vec<G1Affine> = encode_vec(&vec![2, 3, 5]);

    let pi_1 = PublicInputs(vec![Fr::from(4), Fr::from(6)]);
    let pi_2 = PublicInputs(vec![Fr::from(8), Fr::from(10)]);
    let pi_3 = PublicInputs(vec![Fr::from(12), Fr::from(14)]);

    let r = Fr::from(7);

    // Check r_powers

    let r_powers = batch_verify_compute_r_powers(r, 3);
    assert!(Fr::from(1) == r_powers[0]);
    assert!(Fr::from(7) == r_powers[1]);
    assert!(Fr::from(7 * 7) == r_powers[2]);

    let sum_r_powers: Fr =
        r_powers.iter().copied().reduce(|a, b| a + b).unwrap();
    assert!(Fr::from(1 + 7 + 49) == sum_r_powers);

    let inputs = vec![&pi_1, &pi_2, &pi_3];

    // Check each f_j
    //     s = { [2], [3], [5] }
    //  pi_1 = {       4 ,  6  }
    //  pi_2 = {       8   10  }
    //  pi_3 = {       12  14  }
    //     r = 7

    // f_0 = 1 + 7 + 49 = 57
    // f_1 = 4 + 8*7 + 12*49 = 648
    // f_2 = 6 + 10*7 + 14*49 = 6 + 70 + 686 = 762
    assert!(
        Fr::from(57)
            == batch_verify_compute_f_j(
                &s,
                &inputs,
                &r_powers,
                &sum_r_powers,
                0
            )
    );
    assert!(
        Fr::from(648)
            == batch_verify_compute_f_j(
                &s,
                &inputs,
                &r_powers,
                &sum_r_powers,
                1
            )
    );
    assert!(
        Fr::from(762)
            == batch_verify_compute_f_j(
                &s,
                &inputs,
                &r_powers,
                &sum_r_powers,
                2
            )
    );

    // expect = 57*[2] + 648*[3] + 762*[5]
    //        = [114]  + [1944]  + [3810]
    //        = [5868]

    let actual =
        batch_verify_compute_minus_pi(&s, &inputs, &r_powers, sum_r_powers);

    assert!(expect == actual);

    // let pi_1 = PublicInputs(encode_vec(&vec![4, 6]));
    // let pi_2 = PublicInputs(encode_vec(&vec![8, 10]));
    // let pi_3 = PublicInputs(encode_vec(&vec![12, 14]));

    // let actual = batch_verify_compute_minus_pi(
    //     &vec!{ encode( , proofs_and_inputs, r_powers, sum_r_powers)
}

#[test]
fn test_compute_ZC() {
    let vk = VerificationKey {
        alpha: encode(2),
        beta: encode_g2(3),
        gamma: encode_g2(1),
        delta: encode_g2(5),
        s: vec![encode(11)],
    };
    let proofs_and_inputs: Vec<(Proof, PublicInputs)> = vec![
        (
            Proof {
                a: encode(4),
                b: encode_g2(6),
                c: encode(8),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
        (
            Proof {
                a: encode(10),
                b: encode_g2(12),
                c: encode(14),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
        (
            Proof {
                a: encode(16),
                b: encode_g2(18),
                c: encode(20),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
    ];

    let r = Fr::from(7);
    let r_powers = batch_verify_compute_r_powers(r, 3);

    let expect = -encode(8 + 7 * 14 + 49 * 20);
    assert!(
        expect
            == batch_verify_compute_minus_ZC(
                &vk,
                &proofs_and_inputs.iter().map(|(a, b)| (a, b)).collect(),
                &r_powers
            )
    );
}

#[test]
fn test_groth16_batch_verify() {
    let vk = load_vk(VK_FILE);

    let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
    let (proof2, inputs2) = load_proof_and_inputs(PROOF2_FILE);
    let (proof3, inputs3) = load_proof_and_inputs(PROOF3_FILE);
    let r = Fr::random(OsRng);

    let result = batch_verify(
        &vk,
        &vec![
            (&proof1, &inputs1),
            (&proof2, &inputs2),
            (&proof3, &inputs3),
        ],
        r,
    );

    assert!(result);
}

#[test]
fn test_load_groth16() {
    // Load VK

    let vk = load_vk(VK_FILE);
    println!("VK is {vk:?}");

    // Load Proof and PI

    let (proof, inputs) = load_proof_and_inputs(PROOF1_FILE);
    println!("PROOF is {proof:?}");
    println!("PIs are {inputs:?}");
}
