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

const PATH: &str = "src/tests/configs/circuit.config";

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
    let batch_verifier = BatchVerifier::<_>::new(&fp_chip);

    // Assign proofs / instances as witnesses in `ctx`
    let assigned_proofs_and_inputs: Vec<(
        AssignedProof<Fr>,
        AssignedPublicInputs<Fr>,
    )> = proofs_and_inputs
        .iter()
        .map(|p_i| {
            (
                batch_verifier.assign_proof(builder.main(0), &p_i.0),
                batch_verifier.assign_public_inputs(builder.main(0), &p_i.1),
            )
        })
        .collect();

    // Call `BatchVerifier::verify`
    batch_verifier.verify(builder, vk, &assigned_proofs_and_inputs);
}

fn aggregation_circuit(
    builder: &mut GateThreadBuilder<Fr>,
    config: &BasicConfig,
    _test_config: &TestConfig,
) {
    // Read the vk
    let vk = load_vk(VK_FILE);

    // Read the proofs
    let proofs_and_inputs: Vec<(Proof, PublicInputs)> =
        [PROOF1_FILE, PROOF2_FILE, PROOF3_FILE]
            .iter()
            .map(|e| load_proof_and_inputs(e))
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

    batch_verify_circuit(builder, config, &vk, &proofs_and_inputs)
}

#[test]
fn test_aggregation_circuit_mock() {
    run_circuit_mock_test(PATH, aggregation_circuit);
}

#[ignore = "takes too long"]
#[test]
fn test_aggregation_circuit() {
    run_circuit_test(PATH, aggregation_circuit);
}
