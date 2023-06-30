use crate::circuit::scalar_powers;
use ark_std::{end_timer, start_timer};
use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::builder::RangeCircuitBuilder;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof,
};
use halo2_base::halo2_proofs::poly::{
    commitment::ParamsProver,
    kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
};
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
    TranscriptWriterBuffer,
};
use halo2_base::utils::fs::gen_srs;
use halo2_base::utils::ScalarField;
use rand_core::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

pub trait TestCircuitParameters<F: ScalarField> {
    /// Degree of KZG SRS
    fn degree(self) -> u32;

    /// Constraint generation
    fn build(self, builder: &mut GateThreadBuilder<F>);
}

pub fn test_component<'de, P>(config_path: impl AsRef<Path>)
where
    P: Copy + DeserializeOwned + TestCircuitParameters<Fr>,
{
    let params: P = serde_json::from_reader(
        File::open(config_path)
            .unwrap_or_else(|e| panic!("Path does not exist: {e:?}")),
    )
    .unwrap();
    let rng = OsRng;
    let k = params.degree();
    let kzg_params = gen_srs(k);

    // Keygen
    let mut builder = GateThreadBuilder::<Fr>::keygen();
    params.build(&mut builder);
    builder.config(k as usize, Some(20)); // why 20?
    let circuit = RangeCircuitBuilder::keygen(builder);

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
    params.build(&mut builder);
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ScalarPowerCircuit
// make generic over F
// where F: ScalarField
{
    degree: u32,
    base: u64, // cast to F
    len: usize,
    // _f: PhantomData<F>
}

impl TestCircuitParameters<Fr> for ScalarPowerCircuit {
    fn degree(self) -> u32 {
        self.degree
    }

    fn build(self, builder: &mut GateThreadBuilder<Fr>) {
        let ctx = builder.main(0);

        let base = ctx.load_witness(Fr::from(self.base));
        let result = scalar_powers(ctx, base, self.len);

        let answer = (0..self.len).map(|i| Fr::from(self.base.pow(i as u32)));

        for (result, answer) in result.iter().zip(answer) {
            let answer = ctx.load_constant(answer);
            ctx.constrain_equal(result, &answer);
        }
    }
}
// cargo test --package aggregation --lib --all-features -- tests::component::scalar_powers_test --exact --nocapture
#[test]
fn scalar_powers_test() {
    let path = "src/tests/configs/scalar_powers.config";
    test_component::<ScalarPowerCircuit>(path)
}
