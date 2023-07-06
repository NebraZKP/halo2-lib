use super::*;
use crate::{
    circuit::{AssignedProof, AssignedPublicInputs, BatchVerifier},
    native::{
        load_proof_and_inputs, load_vk, Proof, PublicInputs, VerificationKey,
    },
};
use halo2_base::{
    gates::builder::GateThreadBuilder, halo2_proofs::halo2curves::bn256::Fr,
    safe_types::RangeChip,
};
use halo2_ecc::bn254::FpChip;
use std::iter::once;

#[derive(Debug, Deserialize)]
struct TestConfig {}

fn batch_verify_circuit(
    builder: &mut GateThreadBuilder<Fr>,
    config: &BasicConfig,
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(Proof, PublicInputs)>,
) {
    let range = RangeChip::<Fr>::default(config.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, config.limb_bits, config.num_limbs);
    let batch_verifier = BatchVerifier { fp_chip: &fp_chip };

    // Assign proofs / instances as witnesses in `ctx`
    let assigned_proofs_and_inputs: Vec<(
        AssignedProof<Fr>,
        AssignedPublicInputs<Fr>,
    )> = proofs_and_inputs
        .iter()
        .map(|p_i| {
            (
                batch_verifier.assign_proof(builder.main(0), &p_i.0),
                batch_verifier
                    .assign_public_inputs(builder.main(0), p_i.1.clone()),
            )
        })
        .collect();

    // TODO: correct challenge r
    let r = builder.main(0).assign_witnesses(once(Fr::from(2)))[0];

    // Call `batch_verify`
    batch_verifier.verify(builder, vk, &assigned_proofs_and_inputs, r);
}

// TODO: enable this when test passes
// #[test]
#[allow(dead_code)]
fn test_aggregation_circuit() {
    const PATH: &str = "src/tests/configs/circuit.config";

    // Read the vk
    let vk = load_vk(VK_FILE);

    // Read the proofs
    let proofs_and_inputs: Vec<(Proof, PublicInputs)> =
        [PROOF1_FILE, PROOF2_FILE, PROOF3_FILE]
            .iter()
            .map(|e| load_proof_and_inputs(*e))
            .collect();

    let proofs_and_inputs = vec![
        proofs_and_inputs[0].clone(),
        proofs_and_inputs[1].clone(),
        proofs_and_inputs[2].clone(),
        proofs_and_inputs[0].clone(),
        proofs_and_inputs[1].clone(),
        proofs_and_inputs[2].clone(),
        proofs_and_inputs[0].clone(),
        proofs_and_inputs[1].clone(),
    ];

    run_circuit_mock_test(PATH, |builder, config, _tc: &TestConfig| {
        batch_verify_circuit(builder, config, &vk, &proofs_and_inputs)
    });
}
