use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_base::utils::fs::gen_srs;
use halo2_ecc::halo2_base::gates::builder::{
    CircuitBuilderStage, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_ecc::halo2_base::Context;
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    degree: u32,
    num_proofs: usize,
}

/// Given concrete `data` for a circuit, generates circuit's constraints in `ctx`.
fn circuit_test(ctx: &mut Context<Fr>, params: CircuitParams, data: ()) {
    todo!()
}

/// Samples concrete circuit data, returns circuit.
fn random_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    // call circuit_test
    todo!()
}

#[test]
fn test_aggregation_circuit() {
    // Read parameters from a config file
    let path = "src/tests/circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let k = params.degree;
    let kzg_params = gen_srs(k);

    // Call `random_circuit_test` to get a circuit builder
    let circuit = random_circuit(params, CircuitBuilderStage::Keygen, None);
    // Generate keys
    let vk_time = start_timer!(|| "Generating vkey");
    let vk = keygen_vk(&kzg_params, &circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "Generating pkey");
    let pk = keygen_pk(&kzg_params, vk, &circuit).unwrap();
    end_timer!(pk_time);

    // Generate proof
    // Verify proof
}