use super::*;
use crate::native::{load_proof_and_inputs, load_vk};

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
