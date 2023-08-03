use crate::{
    native::{load_proof_and_inputs, load_vk, Proof, PublicInputs},
    recursion::{gen_inner_circuit_snark, InnerCircuit},
    tests::{BasicConfig, PROOF1_FILE, PROOF2_FILE, PROOF3_FILE, VK_FILE},
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::CircuitBuilderStage,
    halo2_proofs::{
        dev::MockProver,
        poly::{
            commitment::Params,
            kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
    },
    utils::fs::gen_srs,
};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_proof},
    CircuitExt, SHPLONK,
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
};

#[test]
fn inner_circuit() {
    // Read the vk
    let application_vk = load_vk(VK_FILE);

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

    let params = gen_srs(21);

    let inner_circuit = InnerCircuit::new(
        CircuitBuilderStage::Mock,
        None,
        params.k() as usize - 1,
        &application_vk,
        proofs_and_inputs,
    );
    let config = inner_circuit.inner.config(params.k(), Some(10));
    print!("Innner circuit config: {config:?}");
    let _ = MockProver::run(params.k(), &inner_circuit, vec![vec![]]).unwrap();
}

// RUST_BACKTRACE=full cargo test --package aggregation --lib -- tests::recursion::outer_circuit --exact --nocapture
#[test]
fn outer_circuit() {
    const INNER_PATH: &str = "src/tests/configs/inner_circuit.config";
    const OUTER_PATH: &str = "src/tests/configs/outer_circuit.config";
    for inner_config_str in
        BufReader::new(File::open(INNER_PATH).unwrap()).lines()
    {
        let inner_config = inner_config_str.unwrap().clone();
        for outer_config_str in
            BufReader::new(File::open(OUTER_PATH).unwrap()).lines()
        {
            single_outer_circuit(
                inner_config.clone(),
                outer_config_str.unwrap(),
            );
        }
    }
}

fn single_outer_circuit(inner_config_str: String, outer_config_str: String) {
    let inner_config: BasicConfig =
        serde_json::from_str(inner_config_str.as_ref()).unwrap();
    let outer_config: BasicConfig =
        serde_json::from_str(outer_config_str.as_ref()).unwrap();
    // Read the vk
    let application_vk = load_vk(VK_FILE);
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

    let inner_params = gen_srs(inner_config.degree);
    let outer_params = gen_srs(outer_config.degree);

    let inner_snarks = [(); 3].map(|_| {
        gen_inner_circuit_snark(
            &inner_params,
            proofs_and_inputs.clone(),
            &application_vk,
        )
    });

    // Then create aggregation circuit of these `inner_snarks`
    // TODO: Shplonk v GWC ?
    let outer_circuit = AggregationCircuit::keygen::<SHPLONK>(
        &outer_params,
        inner_snarks.clone(),
    );
    let pk_timer = start_timer!(|| "Outer Circuit Proving Key Gen");
    let pk = gen_pk(&outer_params, &outer_circuit, None);
    end_timer!(pk_timer);
    let break_points = outer_circuit.break_points();
    drop(outer_circuit);

    let outer_circuit = AggregationCircuit::prover::<SHPLONK>(
        &outer_params,
        inner_snarks,
        break_points,
    );
    // TODO: Min rows?
    let config = outer_circuit.config(outer_params.k(), Some(10));
    println!("Outer circuit config: {config:#?}");
    let instances = outer_circuit.instances();
    let outer_timer = start_timer!(|| "Outer Circuit Proving");
    let _proof = gen_proof::<_, ProverSHPLONK<_>, VerifierSHPLONK<_>>(
        &outer_params,
        &pk,
        outer_circuit,
        instances,
        None,
    );
    end_timer!(outer_timer);
}
