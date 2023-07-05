use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::{GateThreadBuilder, RangeCircuitBuilder},
    halo2_proofs::{
        dev::MockProver,
        halo2curves::{
            bn256::{Bn256, Fr, G1Affine},
            group::Group,
        },
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
use halo2_ecc::fields::{FieldChip, FieldExtConstructor};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader},
    iter::once,
    path::Path,
};

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
    P: Copy + DeserializeOwned + TestCircuit<Fr> + Debug,
{
    let params_file = File::open(path)
        .unwrap_or_else(|e| panic!("Path does not exist: {e:?}"));
    let params_reader = BufReader::new(params_file);
    for line in vec![params_reader.lines().next().unwrap()] {
        println!("line: {line:?}");
        let params: P = serde_json::from_str(line.unwrap().as_str()).unwrap();
        println!("params: {params:?}");
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
        let mut transcript =
            Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
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
        let mut transcript =
            Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
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
}

/// Run `MockProver` on a circuit from a config located at `path`.
/// This often gives more informative error messages.
pub fn mock_test_component<P>(path: impl AsRef<Path>)
where
    P: Copy + DeserializeOwned + TestCircuit<Fr>,
{
    let params_file = File::open(path)
        .unwrap_or_else(|e| panic!("Path does not exist: {e:?}"));
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let params: P = serde_json::from_str(line.unwrap().as_str()).unwrap();
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
            let scaled_pairs = scale_pairs::<Fr>(
                &fp_chip,
                ctx,
                assigned_r,
                assigned_pairs,
            );

            let answer: Vec<_> = scaled_pairs
                .into_iter()
                .zip(scalars)
                .zip(pairs)
                .map(|((circuit_pair, scalar), (a, b))| {
                    let answer = ((a * scalar).to_affine(), b);
                    let g1_answer = g1_chip.assign_point(ctx, answer.0);
                    println!("Answer: {:?}", answer);
                    println!(
                        "Computed G1: {:?}",
                        (circuit_pair.0.x.value(), circuit_pair.0.y.value())
                    );
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

pub mod multi_pairing {
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::{
                bn256::{Fq, Fq2, G2Affine, Gt},
                group::ff::PrimeField,
            },
        },
        Context,
    };
    use halo2_ecc::{
        bn254::{Fp12Chip, FqPoint},
        ecc::{EcPoint, EccChip},
        fields::{fp::FpChip, fp2::Fp2Chip, vector::FieldVector, FieldChip},
    };
    use std::marker::PhantomData;

    use crate::{
        circuit::{AssignedPreparedProof, BatchVerifier},
        native::{
            batch_verify_compute_prepared_proof,
            batch_verify_get_pairing_pairs, load_proof_and_inputs, load_vk,
            pairing, PreparedProof,
        },
    };

    use super::{super::*, *};

    #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
    struct MultiPairing {
        degree: u32,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
        num_random_pairs: usize,
    }

    impl MultiPairing {
        fn build_circuit(
            self,
            builder: &mut GateThreadBuilder<Fr>,
            prepared_proof: &PreparedProof,
        ) {
            std::env::set_var("LOOKUP_BITS", self.lookup_bits.to_string());
            let mut ctx = builder.main(0);

            // Setup the chip

            let range = RangeChip::<Fr>::default(self.lookup_bits);
            let fp_chip =
                FpChip::<Fr, Fq>::new(&range, self.limb_bits, self.num_limbs);
            let batch_verifier = BatchVerifier::<G1Affine, G2Affine, _, _> {
                fp_chip: &fp_chip,
                _f: PhantomData,
            };
            let g1_chip = EccChip::new(&fp_chip);
            let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
            let g2_chip = EccChip::new(&fp2_chip);
            let fp12_chip = Fp12Chip::<Fr>::new(&fp_chip);

            // Natively compute the expected pairing result

            let expect = {
                let pairs_values =
                    batch_verify_get_pairing_pairs(&prepared_proof);
                println!("pairs_values = {pairs_values:?}");
                let pairing_out = pairing(&pairs_values);
                println!("expect pairing_out = {pairing_out:?}");

                pairing_out
            };

            // Load values into in-circuit object and execute in-circuit and
            // compare the answer

            fn assign_pair<'a>(
                ctx: &mut Context<Fr>,
                g1_chip: &EccChip<Fr, FpChip<Fr, Fq>>,
                g2_chip: &EccChip<Fr, Fp2Chip<Fr, FpChip<Fr, Fq>, Fq2>>,
                pair: &'a (G1Affine, G2Affine),
            ) -> (
                EcPoint<Fr, <FpChip<'a, Fr, Fq> as FieldChip<Fr>>::FieldPoint>,
                EcPoint<
                    Fr,
                    FieldVector<
                        <FpChip<'a, Fr, Fq> as FieldChip<Fr>>::FieldPoint,
                    >,
                >,
            ) {
                (
                    g1_chip.assign_point_unchecked(ctx, pair.0),
                    g2_chip.assign_point_unchecked(ctx, pair.1),
                )
            }

            let prepared = AssignedPreparedProof::<Fr, FpChip<_, Fq>> {
                ab_pairs: prepared_proof
                    .ab_pairs
                    .iter()
                    .map(|x| assign_pair(&mut ctx, &g1_chip, &g2_chip, x))
                    .collect(),
                rp: assign_pair(
                    &mut ctx,
                    &g1_chip,
                    &g2_chip,
                    &prepared_proof.rp,
                ),
                pi: assign_pair(
                    &mut ctx,
                    &g1_chip,
                    &g2_chip,
                    &prepared_proof.pi,
                ),
                zc: assign_pair(
                    &mut ctx,
                    &g1_chip,
                    &g2_chip,
                    &prepared_proof.zc,
                ),
            };

            // Run the multi-miller loop

            let pairing_out: FqPoint<Fr> =
                batch_verifier.multi_pairing(ctx, &prepared);

            let pairing_out_unsafe: <Fp12Chip<Fr> as FieldChip<Fr>>::UnsafeFieldPoint =
                <Fp12Chip<Fr> as FieldChip<Fr>>::UnsafeFieldPoint::from(
                    pairing_out,
                );

            // Check values
            let actual = fp12_chip.get_assigned_value(&pairing_out_unsafe);

            println!("actual = {actual:?}");

            assert!(Gt(actual) == expect);
        }
    }

    impl TestCircuit<Fr> for MultiPairing {
        fn degree(self) -> u32 {
            self.degree
        }

        fn build(self, builder: &mut GateThreadBuilder<Fr>) {
            // Load native vk and proof

            if self.num_random_pairs == 0 {
                let vk = load_vk(VK_FILE);
                let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
                let (proof2, inputs2) = load_proof_and_inputs(PROOF2_FILE);
                let (proof3, inputs3) = load_proof_and_inputs(PROOF3_FILE);
                let r = Fr::random(OsRng);
                println!("r = {r:?}");

                // Compute everything natively

                let prepared_proof = batch_verify_compute_prepared_proof(
                    &vk,
                    &vec![
                        (&proof1, &inputs1),
                        (&proof2, &inputs2),
                        (&proof3, &inputs3),
                    ],
                    r,
                );

                self.build_circuit(builder, &prepared_proof);
            } else {
                let prepared_proof = PreparedProof {
                    ab_pairs: (0..self.num_random_pairs)
                        .map(|_| {
                            (G1Affine::random(OsRng), G2Affine::random(OsRng))
                        })
                        .collect(),
                    rp: (encode(3), encode_g2(5)),
                    pi: (encode(7), encode_g2(1)),
                    zc: (encode(11), encode_g2(13)),
                };

                self.build_circuit(builder, &prepared_proof);
            }
        }
    }

    #[test]
    fn test() {
        mock_test_component::<MultiPairing>(
            "src/tests/configs/multi_pairing.config",
        );
        // test_component::<MultiPairing>("src/tests/configs/multi_miller.config");
    }
}

pub mod pairing_check {
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::{
                bn256::{Fq, Fq12, Fq2, Fq6, G2Affine, Gt},
                group::ff::PrimeField,
            },
        },
        Context,
    };
    use halo2_ecc::{
        bn254::{Fp12Chip, FqPoint},
        ecc::{EcPoint, EccChip},
        fields::{fp::FpChip, fp2::Fp2Chip, vector::FieldVector, FieldChip},
    };
    use std::marker::PhantomData;

    use crate::{
        circuit::{AssignedPreparedProof, BatchVerifier},
        native::{
            batch_verify_compute_prepared_proof,
            batch_verify_get_pairing_pairs, load_proof_and_inputs, load_vk,
            pairing, PreparedProof,
        },
    };

    use super::{super::*, *};

    #[derive(Clone, Copy, Debug, Deserialize, Serialize)]
    struct PairingCheck {
        degree: u32,
        lookup_bits: usize,
        limb_bits: usize,
        num_limbs: usize,
        num_random_pairs: usize,
    }

    impl TestCircuit<Fr> for PairingCheck {
        fn degree(self) -> u32 {
            self.degree
        }

        fn build(self, builder: &mut GateThreadBuilder<Fr>) {
            std::env::set_var("LOOKUP_BITS", self.lookup_bits.to_string());
            let mut ctx = builder.main(0);

            // Setup the chip

            let range = RangeChip::<Fr>::default(self.lookup_bits);
            let fp_chip =
                FpChip::<Fr, Fq>::new(&range, self.limb_bits, self.num_limbs);
            let batch_verifier = BatchVerifier::<G1Affine, G2Affine, _, _> {
                fp_chip: &fp_chip,
                _f: PhantomData,
            };

            // Test valid and invalid results.

            let fp12_one = Fq12::one();

            let fp12_chip = Fp12Chip::<Fr>::new(&fp_chip);
            let pairing_result = fp12_chip.load_private(ctx, fp12_one);
            batch_verifier.check_pairing_result(ctx, &pairing_result);
        }
    }

    #[test]
    fn test() {
        // let f1 = Fq::one();
        // let f0 = Fq::zero();
        // let fp12_not_ones = vec![
        //     Fq12::new([f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f1, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f1, f0, f0, f0, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f1, f0, f0, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f1, f0, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f0, f1, f0, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f0, f0, f1, f0, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f1, f0, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f1, f0, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f1, f0]),
        //     Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f1]),
        // ];

        // mock_test_component_fails(
        //     "src/tests/configs/pairing_check.config",
        //     |ctx| build_pairing_check_circuit(ctx, Fp12::zero()),
        // );

        // mock_test_component::<PairingCheck>(
        //     "src/tests/configs/pairing_check.config",
        //     |ctx| build_pairing_check_circuit(ctx, one),
        // );

        // mock_test_component::<PairingCheck>(
        //     "src/tests/configs/pairing_check.config",
        //     |ctx, params| build_pairing_check_circuit(ctx, params, one),
        // );

        // mock_test_component::<PairingCheck>(
        //     "src/tests/configs/pairing_check.config",
        //     |ctx, params| build_pairing_check_circuit(ctx, two),
        // );

        mock_test_component::<PairingCheck>(
            "src/tests/configs/pairing_check.config",
        );
    }
}
