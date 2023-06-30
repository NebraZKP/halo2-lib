use serde::Deserialize;

// pub mod sample_proof;
mod test_circuit;
mod test_native;

const VK_FILE: &str = "src/tests/vk.json";
const PROOF1_FILE: &str = "src/tests/proof1.json";
const PROOF2_FILE: &str = "src/tests/proof2.json";
const PROOF3_FILE: &str = "src/tests/proof3.json";

#[derive(Clone, Copy, Debug, Deserialize)]
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
