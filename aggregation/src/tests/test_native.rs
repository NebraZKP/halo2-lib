use super::*;
use crate::native::{batch_verify, load_proof_and_inputs, load_vk, verify};
use halo2_base::halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr};
use rand_core::OsRng;

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
