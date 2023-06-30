use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::{GateThreadBuilder, RangeCircuitBuilder},
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
    utils::{fs::gen_srs, ScalarField},
};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fs::File, path::Path};

/// Interface for testing a circuit component.
pub trait TestCircuit<F: ScalarField> {
    /// Degree of KZG SRS
    fn degree(self) -> u32;

    /// Constraint generation
    fn build(self, builder: &mut GateThreadBuilder<F>);
}

/// Test a circuit from a config located at `path`.
pub fn test_component<'de, P>(path: impl AsRef<Path>)
where
    P: Copy + DeserializeOwned + TestCircuit<Fr>,
{
    let params: P = serde_json::from_reader(
        File::open(path)
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

pub mod scalar_powers {
    use super::*;
    use crate::circuit::scalar_powers;

    #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
    /// A circuit to compute powers of `base` from `0` to `len - 1`.
    pub struct ScalarPowerCircuit {
        degree: u32,
        /// To-Do: write `base` as a F element
        base: u64,
        len: usize,
    }

    impl TestCircuit<Fr> for ScalarPowerCircuit {
        fn degree(self) -> u32 {
            self.degree
        }

        fn build(self, builder: &mut GateThreadBuilder<Fr>) {
            let ctx = builder.main(0);

            let base = ctx.load_witness(Fr::from(self.base));
            let result = scalar_powers(ctx, base, self.len);

            let answer =
                (0..self.len).map(|i| Fr::from(self.base.pow(i as u32)));

            for (result, answer) in result.iter().zip(answer) {
                let answer = ctx.load_constant(answer);
                ctx.constrain_equal(result, &answer);
            }
        }
    }
    // cargo test --package aggregation --lib --all-features -- tests::component::scalar_powers::test --exact --nocapture
    #[test]
    fn test() {
        let path = "src/tests/configs/scalar_powers.config";
        test_component::<ScalarPowerCircuit>(path)
    }
}
