use super::*;
use crate::{
    circuit::{AssignedProof, AssignedPublicInputs, BatchVerifier},
    native::{
        load_proof_and_inputs, load_vk, Proof, PublicInputs, VerificationKey,
    },
};
use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::GateThreadBuilder,
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
        poly::{
            commitment::ParamsProver,
            kzg::{
                commitment::KZGCommitmentScheme,
                multiopen::{ProverSHPLONK, VerifierSHPLONK},
                strategy::SingleStrategy,
            },
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
            TranscriptWriterBuffer,
        },
    },
    safe_types::RangeChip,
    utils::fs::gen_srs,
};
use halo2_ecc::{
    bn254::FpChip, halo2_base::gates::builder::RangeCircuitBuilder,
};
use rand_core::OsRng;
use std::{fs::File, iter::once, marker::PhantomData};

fn batch_verify_circuit(
    builder: &mut GateThreadBuilder<Fr>,
    params: &CircuitParams,
    vk: &VerificationKey,
    proofs_and_inputs: &Vec<(Proof, PublicInputs)>,
) {
    let range = RangeChip::<Fr>::default(params.lookup_bits);
    let fp_chip = FpChip::<Fr>::new(&range, params.limb_bits, params.num_limbs);
    let batch_verifier = BatchVerifier {
        fp_chip: &fp_chip,
        _f: PhantomData,
    };

    // Assign proofs / instances as witnesses in `ctx`
    let assigned_proofs_and_inputs: Vec<(
        AssignedProof<Fr, FpChip<Fr>>,
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

// cargo test --package aggregation --lib --all-features -- tests::test_circuit::test_aggregation_circuit --exact --nocapture
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
    let inner_vk = load_vk(VK_FILE);

    // Read the proofs
    let inner_proofs_and_inputs: Vec<(Proof, PublicInputs)> =
        [PROOF1_FILE, PROOF2_FILE, PROOF3_FILE]
            .iter()
            .map(|e| load_proof_and_inputs(*e))
            .collect();

    // Construct the circuit for this inner_vk.  Generate outer keys.
    let mut builder = GateThreadBuilder::<Fr>::keygen();
    batch_verify_circuit(
        &mut builder,
        &params,
        &inner_vk,
        &inner_proofs_and_inputs,
    );
    builder.config(k as usize, Some(20));
    let circuit = RangeCircuitBuilder::keygen(builder);

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
    batch_verify_circuit(
        &mut builder,
        &params,
        &inner_vk,
        &inner_proofs_and_inputs,
    );
    builder.config(k as usize, Some(20));
    let circuit = RangeCircuitBuilder::prover(builder, break_points);

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
