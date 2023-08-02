use super::*;
use crate::native::{
    batch_verify, compute_f_j, compute_minus_ZC, compute_minus_pi,
    compute_r_i_A_i_B_i, compute_r_powers, load_proof_and_inputs, load_vk,
    prepare_public_inputs, verify, Proof, PublicInputs, VerificationKey,
};
use halo2_base::halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Fr, G1Affine},
};

use rand_core::OsRng;

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
    //  pi_4 = {       16  18  }
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
    //   PI_4 = [2] +16*[3] +18*[5] = [140]
    //
    // so
    //
    //   PI = [44]+7*[76]+7^2*[108]+7^3*[140] = [53888]

    let expect = -encode_g1(53888);

    let vk = VerificationKey {
        alpha: encode_g1(1),
        beta: encode_g2(1),
        delta: encode_g2(1),
        s: encode_vec(&vec![2, 3, 5]),
    };
    let s: &Vec<G1Affine> = &vk.s;

    let pi_1 = PublicInputs(vec![Fr::from(4), Fr::from(6)]);
    let pi_2 = PublicInputs(vec![Fr::from(8), Fr::from(10)]);
    let pi_3 = PublicInputs(vec![Fr::from(12), Fr::from(14)]);
    let pi_4 = PublicInputs(vec![Fr::from(16), Fr::from(18)]);
    let num_proofs = 4;

    let r = Fr::from(7);

    // Check r_powers

    let r_powers = compute_r_powers(r, num_proofs);
    assert!(Fr::from(1) == r_powers[0]);
    assert!(Fr::from(7) == r_powers[1]);
    assert!(Fr::from(7 * 7) == r_powers[2]);
    assert!(Fr::from(7 * 7 * 7) == r_powers[3]);

    let sum_r_powers: Fr =
        r_powers.iter().copied().reduce(|a, b| a + b).unwrap();
    let inputs = vec![&pi_1, &pi_2, &pi_3, &pi_4];

    // Check the individual f_j values

    // f_0 = 1 + 7 + 49 + 343 = 400
    // f_1 = 4 + 8*7 + 12*49 + 16*343 = 6136
    // f_2 = 6 + 10*7 + 14*49 + 18*343 = 6 + 70 + 686 +6147 = 6936
    assert!(Fr::from(400) == compute_f_j(&inputs, &r_powers, &sum_r_powers, 0));
    assert!(
        Fr::from(6136) == compute_f_j(&inputs, &r_powers, &sum_r_powers, 1)
    );
    assert!(
        Fr::from(6936) == compute_f_j(&inputs, &r_powers, &sum_r_powers, 2)
    );

    // Manually compute one proof at a time.

    let computed = {
        let pi_prep_1 = prepare_public_inputs(&vk, &pi_1);
        let pi_prep_2 = prepare_public_inputs(&vk, &pi_2);
        let pi_prep_3 = prepare_public_inputs(&vk, &pi_3);
        let pi_prep_4 = prepare_public_inputs(&vk, &pi_4);

        assert!(pi_prep_1 == encode_g1(2 * 1 + 3 * 4 + 5 * 6));
        assert!(pi_prep_2 == encode_g1(2 * 1 + 3 * 8 + 5 * 10));
        assert!(pi_prep_3 == encode_g1(2 * 1 + 3 * 12 + 5 * 14));
        assert!(pi_prep_4 == encode_g1(2 * 1 + 3 * 16 + 5 * 18));

        G1Affine::from(
            -(pi_prep_1
                + pi_prep_2 * r
                + pi_prep_3 * (r * r)
                + pi_prep_4 * (r * r * r)),
        )
    };

    // Run the full computation and check

    let actual = compute_minus_pi(s, &inputs, &r_powers, sum_r_powers);

    assert!(expect == actual);
    assert!(expect == computed);
}

#[test]
#[allow(non_snake_case)]
fn test_compute_ZC() {
    let proofs_and_inputs: Vec<(Proof, PublicInputs)> = vec![
        (
            Proof {
                a: encode_g1(4),
                b: encode_g2(6),
                c: encode_g1(8),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
        (
            Proof {
                a: encode_g1(10),
                b: encode_g2(12),
                c: encode_g1(14),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
        (
            Proof {
                a: encode_g1(16),
                b: encode_g2(18),
                c: encode_g1(20),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
    ];

    let r = Fr::from(7);
    let r_powers = compute_r_powers(r, 3);

    let expect = -encode_g1(8 + 7 * 14 + 49 * 20);
    assert!(
        expect
            == compute_minus_ZC(
                proofs_and_inputs
                    .iter()
                    .map(|(a, b)| (a, b))
                    .collect::<Vec<_>>()
                    .as_slice(),
                &r_powers
            )
    );
}

#[test]
#[allow(non_snake_case)]
fn test_compute_r_i_A_i_B_i() {
    let proofs_and_inputs: Vec<(Proof, PublicInputs)> = vec![
        (
            Proof {
                a: encode_g1(4),
                b: encode_g2(6),
                c: encode_g1(8),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
        (
            Proof {
                a: encode_g1(10),
                b: encode_g2(12),
                c: encode_g1(14),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
        (
            Proof {
                a: encode_g1(16),
                b: encode_g2(18),
                c: encode_g1(20),
            },
            PublicInputs(vec![Fr::from(0)]),
        ),
    ];

    let r = Fr::from(7);
    let r_powers = compute_r_powers(r, 3);

    let expect = vec![
        (encode_g1(4), encode_g2(6)),
        (encode_g1(70), encode_g2(12)),
        (encode_g1(49 * 16), encode_g2(18)),
    ];

    let r_i_A_i_B_i = compute_r_i_A_i_B_i(
        proofs_and_inputs
            .iter()
            .map(|(a, b)| (a, b))
            .collect::<Vec<_>>()
            .as_slice(),
        &r_powers,
    );

    assert!(expect == r_i_A_i_B_i);
}

#[test]
#[allow(non_snake_case)]
fn test_compute_pi_2() {
    let vk = load_vk(VK_FILE);

    let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
    let (proof2, inputs2) = load_proof_and_inputs(PROOF2_FILE);
    let (proof3, inputs3) = load_proof_and_inputs(PROOF3_FILE);

    let r = Fr::random(OsRng);

    // Perform the computation explicitly for 3 proofs

    assert!(verify(&vk, &proof1, &inputs1));
    assert!(verify(&vk, &proof2, &inputs2));
    assert!(verify(&vk, &proof3, &inputs3));

    let pi1 = prepare_public_inputs(&vk, &inputs1);
    let _pi2 = prepare_public_inputs(&vk, &inputs2);
    let pi3 = prepare_public_inputs(&vk, &inputs3);
    let num_proofs = 3;

    let _PI_computed = G1Affine::from(-(pi1 + (pi3 * r)));
    let r_powers = compute_r_powers(r, num_proofs);
    let sum_r_powers = r_powers.iter().copied().reduce(|a, b| a + b).unwrap();

    // f_is

    let inputs = vec![&inputs1, &inputs2, &inputs3];
    let f_0 = compute_f_j(&inputs, &r_powers, &sum_r_powers, 0);
    let f_1 = compute_f_j(&inputs, &r_powers, &sum_r_powers, 1);
    let f_2 = compute_f_j(&inputs, &r_powers, &sum_r_powers, 2);
    let f_3 = compute_f_j(&inputs, &r_powers, &sum_r_powers, 3);
    assert!(f_0 == sum_r_powers);
    assert!(f_1 == (inputs1.0[0] + inputs2.0[0] * r + inputs3.0[0] * r * r));
    assert!(f_2 == (inputs1.0[1] + inputs2.0[1] * r + inputs3.0[1] * r * r));
    assert!(f_3 == (inputs1.0[2] + inputs2.0[2] * r + inputs3.0[2] * r * r));

    // Manually computed

    let PI_computed = -G1Affine::from(
        vk.s[0] * f_0 + vk.s[1] * f_1 + vk.s[2] * f_2 + vk.s[3] * f_3,
    );

    // Actual computation

    let PI_actual = compute_minus_pi(
        &vk.s,
        &vec![&inputs1, &inputs2, &inputs3],
        &r_powers,
        sum_r_powers,
    );

    assert!(PI_computed == PI_actual);
}

#[test]
fn test_groth16_batch_verify() {
    let vk = load_vk(VK_FILE);

    let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
    let (proof2, _inputs2) = load_proof_and_inputs(PROOF2_FILE);
    let (proof3, inputs3) = load_proof_and_inputs(PROOF3_FILE);
    let r = Fr::random(OsRng);

    // All valid proofs

    assert!(batch_verify(
        &vk,
        &vec![
            (&proof1, &inputs1),
            // (&proof2, &inputs2),
            (&proof3, &inputs3),
        ],
        r,
    ));

    // Invalid proofs included

    assert!(!batch_verify(
        &vk,
        &vec![
            (&proof1, &inputs1),
            (&proof2, &inputs3),
            (&proof3, &inputs3),
        ],
        r,
    ));
}
