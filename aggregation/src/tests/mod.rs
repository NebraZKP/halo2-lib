use crate::circuit::{
    AssignedProof, AssignedPublicInputs, JsonProof, JsonPublicInputs,
    PublicInputs,
};
use crate::tests::sample_proof::{get_proof, unsafe_setup, UnsafeSrs};

use super::circuit::{JsonVerificationKey, Proof, VerificationKey};
use super::*;
use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::GateThreadBuilder;
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
use halo2_base::safe_types::RangeChip;
use halo2_base::utils::fs::gen_srs;
use halo2_ecc::bn254::FpChip;
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
    limb_bits: usize,
    num_limbs: usize,
    lookup_bits: usize,
    num_proofs: usize,
}

// /// Given concrete `data` for a circuit, generates circuit's constraints in `ctx`.
// fn circuit_test(
//     ctx: &mut Context<Fr>,
//     params: &CircuitParams,
//     proofs: (),
//     vk: &VerificationKey,
// ) {
//     let range = RangeChip::<Fr>::default(params.lookup_bits);
//     let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);

//     // Assign proofs / instances as witnesses in `ctx`

//     // Call `verify_batch`

//     todo!()
// }

// /// Samples concrete circuit data, returns circuit.
// fn random_circuit(
//     params: CircuitParams,
//     stage: CircuitBuilderStage,
//     break_points: Option<MultiPhaseThreadBreakPoints>,
// ) -> RangeCircuitBuilder<Fr> {
//     // sample/read some Groth16 proofs somehow
//     let (vk, pk) = unsafe_setup(UnsafeSrs);
//     let proof = get_proof(pk, OsRng);
//     // call circuit_test
//     todo!()
// }

fn read_vk() -> VerificationKey {
    todo!();
}

fn read_proofs() -> (Vec<Proof>, Vec<Vec<Fr>>) {
    todo!();
}

fn batch_verify_circuit(
    ctx: &mut Context<Fr>,
    params: &CircuitParams,
    break_points: Option<MultiPhaseThreadBreakPoints>,
    vk: &VerificationKey,
    proofs: &Vec<Proof>,
    public_inputs: &Vec<Vec<Fr>>,
) -> RangeCircuitBuilder<Fr> {
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);

    // Assign proofs / instances as witnesses in `ctx`
    let assigned_proofs: Vec<AssignedProof<Fr, FpChip<Fr>>> =
        proofs.iter().map(|p| todo!()).collect();
    let assigned_pi: Vec<AssignedPublicInputs<Fr>> =
        public_inputs.iter().map(|pi| todo!()).collect();

    // Call `batch_verify`
    batch_verify(ctx, &fp_chip, vk, &assigned_proofs, &assigned_pi);

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

    // Read the vk
    let inner_vk = read_vk();

    // Read the proofs
    let (inner_proofs, inner_pi) = read_proofs();

    // Construct the circuit for this inner_vk.  Generate outer keys.
    let mut builder = GateThreadBuilder::<Fr>::keygen();
    let circuit = batch_verify_circuit(
        builder.main(0),
        &params,
        None,
        &inner_vk,
        &inner_proofs,
        &inner_pi,
    );

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
    let mut builder = GateThreadBuilder::<Fr>::prover();
    let circuit = batch_verify_circuit(
        builder.main(0),
        &params,
        Some(break_points),
        &inner_vk,
        &inner_proofs,
        &inner_pi,
    );

    //Create proof
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
    const PROOF1_FILE: &str = "src/tests/proof1.json";

    // Load VK

    let vk_json: JsonVerificationKey = serde_json::from_reader(
        File::open(VK_FILE).unwrap_or_else(|e| panic!("{VK_FILE}: {e:?}")),
    )
    .unwrap_or_else(|e| panic!("{VK_FILE} JSON: {e:?}"));

    let vk = VerificationKey::from(&vk_json);
    println!("VK is {vk:?}");

    #[derive(Debug, Serialize, Deserialize)]
    struct JsonProofAndInputs {
        proof: JsonProof,
        inputs: JsonPublicInputs,
    };

    // Load Proof and PI

    let proof_pi_json: JsonProofAndInputs = serde_json::from_reader(
        File::open(PROOF1_FILE)
            .unwrap_or_else(|e| panic!("{PROOF1_FILE}: {e:?}")),
    )
    .unwrap_or_else(|e| panic!("{PROOF1_FILE} JSON: {e:?}"));

    let proof = Proof::from(&proof_pi_json.proof);
    println!("PROOF is {proof:?}");

    let public_inputs = PublicInputs::from(&proof_pi_json.inputs);
    println!("PIs are {public_inputs:?}");
}
