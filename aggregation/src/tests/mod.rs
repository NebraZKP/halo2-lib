use ark_std::{end_timer, start_timer};
use halo2_base::{
    gates::builder::{GateThreadBuilder, RangeCircuitBuilder},
    halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine, G1, G2},
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
    utils::fs::gen_srs,
};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize};
use std::{
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

// pub mod sample_proof;
mod component;
mod test_circuit;
mod test_native;

const VK_FILE: &str = "src/tests/vk.json";
const PROOF1_FILE: &str = "src/tests/proof1.json";
const PROOF2_FILE: &str = "src/tests/proof2.json";
const PROOF3_FILE: &str = "src/tests/proof3.json";

pub(crate) fn encode_g1(f: i32) -> G1Affine {
    G1Affine::from(G1::generator() * Fr::from(f as u64))
}

pub(crate) fn encode_g2(f: i32) -> G2Affine {
    G2Affine::from(G2::generator() * Fr::from(f as u64))
}

#[allow(dead_code)] // Kept for completeness and generating debug data
pub(crate) fn encode_fr(f: &Fr) -> G1Affine {
    G1Affine::from(G1::generator() * f)
}

pub(crate) fn encode_vec(fs: &Vec<i32>) -> Vec<G1Affine> {
    fs.iter().map(|a| encode_g1(*a)).collect()
}

#[derive(Deserialize, Debug)]
pub struct BasicConfig {
    pub degree: u32,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

fn parse_configs<C: DeserializeOwned + Debug>(line: &str) -> (BasicConfig, C) {
    let basic_config: BasicConfig = serde_json::from_str(line).unwrap();
    println!("basic config: {basic_config:?}");
    let test_config: C = serde_json::from_str(line).unwrap();
    println!("test config: {test_config:?}");
    (basic_config, test_config)
}

/// Test key, witness generation and proof generation of a circuit, based on
/// the configurations in `path`.  The file `path` must contain one or more
/// lines of JSON specifying a `BasicConfig`, with any extra attributes
/// required by the test-specific object type `C`.  The function
/// `build_circuit` is used to contruct a circuit using the `BasicConfig` and
/// `C` objects read from `path`.  The `build_circuit` function can optionally
/// return a type R (R = () for functions that do not return anything). The
/// returned value for each invocation (i.e. for each line in the config file)
/// is returned from this function.
fn run_circuit_test<
    C: DeserializeOwned + Debug,
    R,
    BC: Fn(&mut GateThreadBuilder<Fr>, &BasicConfig, &C) -> R,
>(
    path: impl AsRef<Path>,
    build_circuit: BC,
) -> Vec<R> {
    let mut out = Vec::<R>::new();

    let params_file = File::open(&path).unwrap_or_else(|e| {
        let path = path.as_ref().to_str().unwrap();
        panic!("Path {path} does not exist: {e:?}")
    });
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let (basic_config, test_config) =
            parse_configs(line.as_ref().unwrap().as_str());

        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        // let rng = OsRng;
        let k = basic_config.degree;
        let kzg_params = gen_srs(k);

        // Keygen
        let mut builder = GateThreadBuilder::<Fr>::keygen();

        build_circuit(&mut builder, &basic_config, &test_config);

        let computed_params = builder.config(k as usize, Some(20));
        println!("Computed config (keygen): {computed_params:?}");
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

        out.push(build_circuit(&mut builder, &basic_config, &test_config));

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
        >(&kzg_params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
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

    out
}

/// Run `MockProver` on a circuit from a config located at `path`.  Operation
/// is exactly the same as run_circuit_test, except that `MockProver` is used.
/// This often gives more informative error messages.
pub fn run_circuit_mock_test<
    C: DeserializeOwned + Debug,
    R,
    BC: Fn(&mut GateThreadBuilder<Fr>, &BasicConfig, &C) -> R,
>(
    path: impl AsRef<Path>,
    build_circuit: BC,
) -> Vec<R> {
    let mut out = Vec::<R>::new();

    let params_file = File::open(&path).unwrap_or_else(|e| {
        let path = path.as_ref().to_str().unwrap();
        panic!("Path {path} does not exist: {e:?}")
    });
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let (basic_config, test_config) =
            parse_configs(line.as_ref().unwrap().as_str());

        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        let k = basic_config.degree;

        let mut builder = GateThreadBuilder::<Fr>::mock();

        out.push(build_circuit(&mut builder, &basic_config, &test_config));

        let computed_params = builder.config(k as usize, Some(10));
        println!("Computed config (keygen): {computed_params:?}");
        let circuit = RangeCircuitBuilder::mock(builder);

        MockProver::run(k, &circuit, vec![])
            .unwrap()
            .assert_satisfied();
    }

    out
}

/// Run `MockProver` on a circuit from a config located at `path`.  Operation
/// is exactly the same as run_circuit_test, except that `MockProver` is used.
/// This often gives more informative error messages.
pub fn run_circuit_mock_test_failure<
    C: DeserializeOwned + Debug,
    BC: Fn(&mut GateThreadBuilder<Fr>, &BasicConfig, &C),
>(
    path: impl AsRef<Path>,
    build_circuit: BC,
) {
    let params_file = File::open(&path).unwrap_or_else(|e| {
        let path = path.as_ref().to_str().unwrap();
        panic!("Path {path} does not exist: {e:?}")
    });
    let params_reader = BufReader::new(params_file);
    for line in params_reader.lines() {
        let (basic_config, test_config) =
            parse_configs(line.as_ref().unwrap().as_str());

        std::env::set_var("LOOKUP_BITS", basic_config.lookup_bits.to_string());

        let k = basic_config.degree;

        let mut builder = GateThreadBuilder::<Fr>::mock();

        build_circuit(&mut builder, &basic_config, &test_config);

        builder.config(k as usize, Some(10));
        let circuit = RangeCircuitBuilder::mock(builder);

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        let res = prover.verify();
        match res {
            Ok(_) => {
                panic!("Expected circuit failure");
            }
            Err(_failures) => {
                // TODO: Determine how to allow the caller to specify a
                // specific failiure. (_failures is a vector of error codes,
                // so need to consider exactly what the caller should
                // provide).
            }
        }
    }
}
