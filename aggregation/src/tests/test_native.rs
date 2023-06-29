use super::*;
use crate::native::{load_proof_and_inputs, load_vk, verify};

#[test]
fn test_groth16_verify() {
    let vk = load_vk(VK_FILE);
    let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
    let (proof2, inputs2) = load_proof_and_inputs(PROOF2_FILE);

    assert!(verify(&vk, &proof1, &inputs1));
    assert!(verify(&vk, &proof2, &inputs2));
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
