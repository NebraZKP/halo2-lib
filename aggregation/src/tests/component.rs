use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::{GateThreadBuilder, RangeCircuitBuilder},
    halo2_proofs::{
        dev::MockProver,
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
pub fn test_component<P>(path: impl AsRef<Path>)
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
    let computed_params = builder.config(k as usize, Some(20));
    println!("Computed config: {computed_params:?}");

    let circuit = RangeCircuitBuilder::prover(builder, break_points);
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

/// Run `MockProver` on a circuit from a config located at `path`.
/// This often gives more informative error messages.
pub fn mock_test_component<P>(path: impl AsRef<Path>)
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

    let mut builder = GateThreadBuilder::<Fr>::mock();
    params.build(&mut builder);
    builder.config(k as usize, Some(10));
    let circuit = RangeCircuitBuilder::mock(builder);

    MockProver::run(k, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
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

    // cargo test --package aggregation --lib --all-features -- tests::component::scalar_powers::mock_test --exact --nocapture
    #[test]
    fn mock_test() {
        let path = "src/tests/configs/scalar_powers.config";
        mock_test_component::<ScalarPowerCircuit>(path)
    }
}

pub mod scale_pairs {
    use halo2_base::{
        gates::RangeChip,
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::{
                bn256::{Fq, Fq2, G2Affine},
                group::Curve,
            },
        },
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::{fp::FpChip, fp2::Fp2Chip, FieldChip},
    };

    use super::*;
    use crate::circuit::scale_pairs;

    #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
    /// A circuit to compute `(scalar_i * A_i, B_i)`
    pub struct ScalePairsCircuit {
        degree: u32,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
        /// Number of pairs to scale
        len: usize,
    }

    impl TestCircuit<Fr> for ScalePairsCircuit {
        fn degree(self) -> u32 {
            self.degree
        }

        fn build(self, builder: &mut GateThreadBuilder<Fr>) {
            std::env::set_var("LOOKUP_BITS", self.lookup_bits.to_string());
            let range = RangeChip::<Fr>::default(self.lookup_bits);
            let fp_chip =
                FpChip::<_, Fq>::new(&range, self.limb_bits, self.num_limbs);
            let g1_chip = EccChip::new(&fp_chip);
            let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
            let g2_chip = EccChip::new(&fp2_chip);

            let ctx = builder.main(0);

            // Sample points and scalars
            let (a, (b, r)): (Vec<_>, (Vec<_>, Vec<_>)) = (0..self.len)
                .map(|_| {
                    (
                        G1Affine::random(OsRng),
                        (G2Affine::random(OsRng), Fr::random(OsRng)),
                    )
                })
                .unzip();

            // Assign to circuit
            let (assigned_pairs, assigned_r): (Vec<_>, Vec<_>) = a
                .iter()
                .zip(b.iter())
                .zip(r.iter())
                .map(|((a, b), r)| {
                    (
                        (
                            g1_chip.assign_point(ctx, a.clone()),
                            g2_chip.assign_point(ctx, b.clone()),
                        ),
                        ctx.load_witness(r.clone()),
                    )
                })
                .unzip();

            // Scale pairs
            let scaled_pairs = scale_pairs::<G1Affine, Fr, _>(
                &fp_chip,
                ctx,
                assigned_r,
                assigned_pairs,
            );

            // Compute answers, assign to circuit
            let assigned_answers: Vec<_> = a
                .iter()
                .zip(b.iter())
                .zip(r.iter())
                .map(|((a, b), r)| {
                    (
                        g1_chip.assign_point(ctx, G1Affine::from(a * r)),
                        g2_chip.assign_point(ctx, b.clone()),
                    )
                })
                .collect();

            // Constrain results
            let _ = scaled_pairs
                .iter()
                .zip(assigned_answers)
                .map(|((answer_a, answer_b), (computed_a, computed_b))| {
                    g1_chip.assert_equal(ctx, answer_a.clone(), computed_a);
                    g2_chip.assert_equal(ctx, answer_b.clone(), computed_b);
                })
                .collect::<Vec<_>>();
        }
    }

    // cargo test --package aggregation --lib --all-features -- tests::component::scale_pairs::test --exact --nocapture
    #[test]
    fn test() {
        let path = "src/tests/configs/scale_pairs.config";
        test_component::<ScalePairsCircuit>(path)
    }
}

pub mod fp_mul {
    use halo2_base::{
        gates::RangeChip,
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::{
                bn256::{Fq, Fq2, G2Affine},
                group::Curve,
            },
        },
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::{fp::FpChip, fp2::Fp2Chip, FieldChip},
    };

    use super::*;

    #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
    /// Circuit for a single non-native multiplication
    pub struct FpMulCircuit {
        degree: u32,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
    }

    impl TestCircuit<Fr> for FpMulCircuit {
        fn degree(self) -> u32 {
            self.degree
        }

        fn build(self, builder: &mut GateThreadBuilder<Fr>) {
            std::env::set_var("LOOKUP_BITS", self.lookup_bits.to_string());

            let ctx = builder.main(0);

            let a = Fq::random(OsRng);
            let b = Fq::random(OsRng);
            let range = RangeChip::<Fr>::default(self.lookup_bits);
            let fp_chip =
                FpChip::<_, Fq>::new(&range, self.limb_bits, self.num_limbs);
            let assign_a = fp_chip.load_private(ctx, a);
            let assign_b = fp_chip.load_private(ctx, b);
            let ab = fp_chip.mul(ctx, assign_a, assign_b);
        }
    }

    // cargo test --package aggregation --lib --all-features -- tests::component::fp_mul::test --exact --nocapture
    #[test]
    fn test() {
        let path = "src/tests/configs/fp_mul.config";
        test_component::<FpMulCircuit>(path)
    }

    // cargo test --package aggregation --lib --all-features -- tests::component::fp_mul::mock_test --exact --nocapture
    #[test]
    fn mock_test() {
        let path = "src/tests/configs/fp_mul.config";
        mock_test_component::<FpMulCircuit>(path)
    }
}
