use crate::tests::sample_proof::{get_proof, unsafe_setup, UnsafeSrs};

use super::proof::{JsonVerificationKey, VerificationKey};
use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof,
};
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::poly::kzg::{
    commitment::{KZGCommitmentScheme, ParamsKZG},
    multiopen::{ProverSHPLONK, VerifierSHPLONK},
    strategy::SingleStrategy,
};
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
    TranscriptWriterBuffer,
};
use halo2_base::utils::fs::gen_srs;
use halo2_ecc::halo2_base::gates::builder::{
    CircuitBuilderStage, MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
};
use halo2_ecc::halo2_base::Context;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs::File;

pub mod sample_proof;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    degree: u32,
    num_proofs: usize,
}

/// Given concrete `data` for a circuit, generates circuit's constraints in `ctx`.
fn circuit_test(
    ctx: &mut Context<Fr>,
    params: CircuitParams,
    proofs: (),
    vk: (),
) {
    // Assign proofs / instances as witnesses in `ctx`

    // Call `verify_batch`
    todo!()
}

/// Samples concrete circuit data, returns circuit.
fn random_circuit(
    params: CircuitParams,
    stage: CircuitBuilderStage,
    break_points: Option<MultiPhaseThreadBreakPoints>,
) -> RangeCircuitBuilder<Fr> {
    // sample/read some Groth16 proofs somehow
    let (vk, pk) = unsafe_setup(UnsafeSrs);
    let proof = get_proof(pk, OsRng);
    // call circuit_test
    todo!()
}

#[test]
fn test_aggregation_circuit() {
    // Read parameters from a config file
    let path = "src/tests/circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path)
            .unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let rng = OsRng;
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
    let break_points = circuit.0.break_points.take();
    drop(circuit);

    // Create proof
    let proof_time = start_timer!(|| "Proving time");
    let circuit =
        random_circuit(params, CircuitBuilderStage::Prover, Some(break_points));
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&kzg_params, &pk, &[circuit], &[&[]], rng, &mut transcript)
    .unwrap();
    let proof = transcript.finalize();
    end_timer!(proof_time);
    // Verify proof
    let verify_time = start_timer!(|| "Verify time");
    let verifier_params = kzg_params.verifier_params();
    let strategy = SingleStrategy::new(&kzg_params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        verifier_params,
        pk.get_vk(),
        strategy,
        &[&[]],
        &mut transcript,
    )
    .unwrap();
    end_timer!(verify_time);
}

#[test]
fn test_load_groth16() {
    const VK_FILE: &str = "src/tests/vk.json";
    let vk: JsonVerificationKey = serde_json::from_reader(
        File::open(VK_FILE).unwrap_or_else(|e| panic!("{VK_FILE}: {e:?}")),
    )
    .unwrap_or_else(|e| panic!("{VK_FILE} JSON: {e:?}"));

    let x = Fr::from(1);
    println!("{x:?}");

    let y = Fr::from(2);
    println!("{y:?}");

    let z = Fr::from_str_vartime("20491192805390485299153009773594534940189261866228447918068658471970481763042");
    println!("{z:?}");

    // assert!(false);
}
