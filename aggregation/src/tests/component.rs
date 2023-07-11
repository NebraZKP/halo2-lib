use super::{run_circuit_mock_test, run_circuit_test, BasicConfig};
use halo2_base::{
    gates::builder::GateThreadBuilder,
    halo2_proofs::halo2curves::bn256::{Fr, G1Affine},
};
use rand_core::OsRng;
use serde::Deserialize;
use std::fmt::Debug;

pub mod scalar_powers {
    use super::*;
    use crate::circuit::BatchVerifier;

    #[derive(Debug, Deserialize)]
    /// A circuit to compute powers of `base` from `0` to `len - 1`.
    pub struct ScalarPowerCircuit {
        // degree: u32,
        /// To-Do: write `base` as a F element
        base: u64,
        len: usize,
    }

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        _basic_config: &BasicConfig,
        test_config: &ScalarPowerCircuit,
    ) {
        let ctx = builder.main(0);

        let base = ctx.load_witness(Fr::from(test_config.base));
        let result = BatchVerifier::scalar_powers(ctx, base, test_config.len);

        let answer = (0..test_config.len)
            .map(|i| Fr::from(test_config.base.pow(i as u32)));

        for (result, answer) in result.iter().zip(answer) {
            let answer = ctx.load_constant(answer);
            ctx.constrain_equal(result, &answer);
        }
    }

    const PATH: &str = "src/tests/configs/scalar_powers.config";

    #[test]
    fn mock_test() {
        run_circuit_mock_test(PATH, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(PATH, build_circuit);
    }
}

pub mod scale_pairs {
    use halo2_base::{
        gates::RangeChip,
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::bn256::{Fq, Fq2, G2Affine},
        },
    };
    use halo2_ecc::{
        ecc::EccChip,
        fields::{fp::FpChip, fp2::Fp2Chip},
    };

    use super::*;
    use crate::circuit::BatchVerifier;

    #[derive(Debug, Deserialize)]
    /// A circuit to compute `(scalar_i * A_i, B_i)`
    pub struct ScalePairsCircuit {
        /// Number of pairs to scale
        len: usize,
    }

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        basic_config: &BasicConfig,
        test_config: &ScalePairsCircuit,
    ) {
        let range = RangeChip::<Fr>::default(basic_config.lookup_bits);
        let fp_chip = FpChip::<_, Fq>::new(
            &range,
            basic_config.limb_bits,
            basic_config.num_limbs,
        );
        let batch_verifier = BatchVerifier { fp_chip: &fp_chip };
        let g1_chip = EccChip::new(&fp_chip);
        let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        let ctx = builder.main(0);

        // Sample points and scalars
        let (a, (b, r)): (Vec<_>, (Vec<_>, Vec<_>)) = (0..test_config.len)
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
        let scaled_pairs =
            batch_verifier.scale_pairs(ctx, assigned_r, assigned_pairs);

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

    #[test]
    fn test_mock() {
        let path = "src/tests/configs/scale_pairs.config";
        run_circuit_mock_test(path, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        let path = "src/tests/configs/scale_pairs.config";
        run_circuit_test(path, build_circuit);
    }
}

pub mod fp_mul {
    use halo2_base::{
        gates::RangeChip,
        halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fq},
    };
    use halo2_ecc::fields::{fp::FpChip, FieldChip};

    use super::*;

    #[derive(Debug, Deserialize)]
    /// Circuit for a single non-native multiplication
    pub struct FpMulCircuit {}

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        basic_config: &BasicConfig,
        _test_config: &FpMulCircuit,
    ) {
        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        let ctx = builder.main(0);

        let a = Fq::random(OsRng);
        let b = Fq::random(OsRng);
        let range = RangeChip::<Fr>::default(basic_config.lookup_bits);
        let fp_chip = FpChip::<_, Fq>::new(
            &range,
            basic_config.limb_bits,
            basic_config.num_limbs,
        );
        let assign_a = fp_chip.load_private(ctx, a);
        let assign_b = fp_chip.load_private(ctx, b);
        let _ab = fp_chip.mul(ctx, assign_a, assign_b);
    }

    const PATH: &str = "src/tests/configs/fp_mul.config";

    #[test]
    fn mock_test() {
        run_circuit_mock_test(PATH, build_circuit);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(PATH, build_circuit);
    }
}

mod multi_pairing {
    use super::super::*;
    use crate::{
        circuit::{AssignedPreparedProof, BatchVerifier},
        native::{
            compute_prepared_proof, get_pairing_pairs, load_proof_and_inputs,
            load_vk, pairing, PreparedProof,
        },
    };
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::halo2curves::{
            bn256::{Fq, Fq2, G2Affine},
            group::ff::Field,
        },
        Context,
    };
    use halo2_ecc::{
        bn254::{Fp12Chip, FqPoint},
        ecc::{EcPoint, EccChip},
        fields::{fp::FpChip, fp2::Fp2Chip, vector::FieldVector, FieldChip},
    };

    #[derive(Debug, Deserialize)]
    struct MultiPairing {
        pub num_random_pairs: usize,
    }

    fn do_build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        basic_config: &BasicConfig,
        prepared_proof: &PreparedProof,
    ) {
        let mut ctx = builder.main(0);

        // Setup the chip

        let range = RangeChip::<Fr>::default(basic_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            basic_config.limb_bits,
            basic_config.num_limbs,
        );
        let batch_verifier = BatchVerifier { fp_chip: &fp_chip };
        let g1_chip = EccChip::new(&fp_chip);
        let fp2_chip = Fp2Chip::<Fr, FpChip<Fr, Fq>, Fq2>::new(&fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        let fp12_chip = Fp12Chip::<Fr>::new(&fp_chip);

        // Natively compute the expected pairing result

        let expect = {
            let pairs_values = get_pairing_pairs(&prepared_proof);
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
                FieldVector<<FpChip<'a, Fr, Fq> as FieldChip<Fr>>::FieldPoint>,
            >,
        ) {
            (
                g1_chip.assign_point_unchecked(ctx, pair.0),
                g2_chip.assign_point_unchecked(ctx, pair.1),
            )
        }

        let prepared = AssignedPreparedProof::<Fr> {
            ab_pairs: prepared_proof
                .ab_pairs
                .iter()
                .map(|x| assign_pair(&mut ctx, &g1_chip, &g2_chip, x))
                .collect(),
            rp: assign_pair(&mut ctx, &g1_chip, &g2_chip, &prepared_proof.rp),
            pi: assign_pair(&mut ctx, &g1_chip, &g2_chip, &prepared_proof.pi),
            zc: assign_pair(&mut ctx, &g1_chip, &g2_chip, &prepared_proof.zc),
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

        // Instead of assert!(Gt(actual) == expect);
        assert_eq!(format!("Gt({:?})", actual), format!("{expect:?}"));
    }

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        basic_config: &BasicConfig,
        config: &MultiPairing,
    ) {
        // Load native vk and proof

        if config.num_random_pairs == 0 {
            let vk = load_vk(VK_FILE);
            let (proof1, inputs1) = load_proof_and_inputs(PROOF1_FILE);
            let (proof2, inputs2) = load_proof_and_inputs(PROOF2_FILE);
            let (proof3, inputs3) = load_proof_and_inputs(PROOF3_FILE);
            let r = Fr::random(OsRng);

            // Compute everything natively

            let prepared_proof = compute_prepared_proof(
                &vk,
                &vec![
                    (&proof1, &inputs1),
                    (&proof2, &inputs2),
                    (&proof3, &inputs3),
                ],
                r,
            );

            do_build_circuit(builder, basic_config, &prepared_proof);
        } else {
            let prepared_proof = PreparedProof {
                ab_pairs: (0..config.num_random_pairs)
                    .map(|_| (G1Affine::random(OsRng), G2Affine::random(OsRng)))
                    .collect(),
                rp: (encode_g1(3), encode_g2(5)),
                pi: (encode_g1(7), encode_g2(1)),
                zc: (encode_g1(11), encode_g2(13)),
            };

            do_build_circuit(builder, basic_config, &prepared_proof);
        }
    }

    #[test]
    fn test_mock() {
        run_circuit_mock_test(
            "src/tests/configs/multi_pairing.config",
            build_circuit,
        );
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(
            "src/tests/configs/multi_pairing.config",
            build_circuit,
        );
    }
}

mod pairing_check {
    use super::*;
    use crate::{circuit::BatchVerifier, tests::run_circuit_mock_test_failure};
    use halo2_base::{
        gates::{builder::GateThreadBuilder, RangeChip},
        halo2_proofs::{
            arithmetic::Field,
            halo2curves::bn256::{Fq, Fq12},
        },
    };
    use halo2_ecc::{
        bn254::Fp12Chip,
        fields::{fp::FpChip, FieldChip, FieldExtConstructor},
    };

    #[derive(Deserialize, Debug)]
    struct PairingCheck {}

    fn build_circuit(
        builder: &mut GateThreadBuilder<Fr>,
        basic_config: &BasicConfig,
        _test_config: &PairingCheck,
        output_value: Fq12,
    ) {
        let mut ctx = builder.main(0);

        // Setup the chip

        let range = RangeChip::<Fr>::default(basic_config.lookup_bits);
        let fp_chip = FpChip::<Fr, Fq>::new(
            &range,
            basic_config.limb_bits,
            basic_config.num_limbs,
        );
        let batch_verifier = BatchVerifier { fp_chip: &fp_chip };

        // Test valid and invalid results.

        let fp12_chip = Fp12Chip::<Fr>::new(&fp_chip);
        let pairing_result = fp12_chip.load_private(&mut ctx, output_value);
        batch_verifier.check_pairing_result(&mut ctx, &pairing_result);
    }

    #[ignore = "takes too long"]
    #[test]
    fn test() {
        run_circuit_test(
            "src/tests/configs/pairing_check.config",
            |ctx, basic_config, test_config| {
                build_circuit(ctx, basic_config, test_config, Fq12::one())
            },
        );
    }

    #[test]
    fn mock_test() {
        run_circuit_mock_test(
            "src/tests/configs/pairing_check.config",
            |ctx, basic_config, test_config| {
                build_circuit(ctx, basic_config, test_config, Fq12::one())
            },
        );
    }

    #[test]
    fn mock_failure_test() {
        // Ensure that non-zero outputs from the pairing are detected by the
        // circuit.  (This case is rather trivial, but for now it exercises the
        // run_circuit_mock_test_failure function).

        let f1 = Fq::one();
        let f0 = Fq::zero();
        let fp12_not_ones = vec![
            Fq12::new([f1 + f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f1, f0, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f1, f0, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f1, f0, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f1, f0, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f1, f0, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f1, f0, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f1, f0, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f1, f0, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f1, f0]),
            Fq12::new([f1, f0, f0, f0, f0, f0, f0, f0, f0, f0, f0, f1]),
        ];

        for val in fp12_not_ones.iter() {
            run_circuit_mock_test_failure(
                "src/tests/configs/pairing_check.config",
                |ctx, basic_config, test_config| {
                    build_circuit(ctx, basic_config, test_config, *val)
                },
            );
        }
    }
}
