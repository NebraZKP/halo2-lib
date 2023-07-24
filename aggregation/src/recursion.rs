use crate::{
    circuit::BatchVerifier,
    native::{Proof, PublicInputs, VerificationKey},
};
use halo2_base::{
    gates::{
        builder::{
            CircuitBuilderStage, GateThreadBuilder,
            MultiPhaseThreadBreakPoints, RangeCircuitBuilder,
            RangeWithInstanceCircuitBuilder, RangeWithInstanceConfig,
        },
        range::RangeChip,
    },
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        halo2curves::bn256::{Bn256, Fr},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
};
use halo2_ecc::bn254::FpChip;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{gen_pk, halo2::gen_snark_gwc, CircuitExt, Snark};
use std::{fs::File, path::Path};

// Modeled on `AggregationCircuit`

// TODO:
// - Use references to proof and pis

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnerCircuitConfigParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
}

impl InnerCircuitConfigParams {
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        serde_json::from_reader(
            File::open(path).expect("Aggregation config path does not exist"),
        )
        .unwrap()
    }
}

/// Inner circuit batch verifies the application proofs.
#[derive(Clone, Debug)]
pub struct InnerCircuit {
    pub inner: RangeWithInstanceCircuitBuilder<Fr>,
    // TODO: What data does it need to carry around?
}

const BITS: usize = 88;
const LIMBS: usize = 3;

impl InnerCircuit {
    pub fn new(
        stage: CircuitBuilderStage,
        break_points: Option<MultiPhaseThreadBreakPoints>,
        lookup_bits: usize,
        vk: &VerificationKey,
        proofs_and_pis: Vec<(Proof, PublicInputs)>,
    ) -> Self {
        let mut builder = match stage {
            CircuitBuilderStage::Mock => GateThreadBuilder::mock(),
            CircuitBuilderStage::Prover => GateThreadBuilder::prover(),
            CircuitBuilderStage::Keygen => GateThreadBuilder::keygen(),
        };
        let ctx = builder.main(0);

        let range = RangeChip::<Fr>::default(lookup_bits);
        let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
        let batch_verifier = BatchVerifier::<_>::new(&fp_chip);

        // Assign the inputs
        let proofs_and_pis: Vec<_> = proofs_and_pis
            .iter()
            .map(|(proof, inputs)| {
                (
                    batch_verifier.assign_proof(ctx, proof),
                    batch_verifier.assign_public_inputs(ctx, inputs),
                )
            })
            .collect();
        // 4. Call the batch verify fn
        let vk = batch_verifier.assign_verification_key(ctx, &vk);
        batch_verifier.verify(&mut builder, &vk, &proofs_and_pis);
        // 5. Construct Self
        let circuit = match stage {
            CircuitBuilderStage::Mock => RangeCircuitBuilder::mock(builder),
            CircuitBuilderStage::Keygen => RangeCircuitBuilder::keygen(builder),
            CircuitBuilderStage::Prover => {
                RangeCircuitBuilder::prover(builder, break_points.unwrap())
            }
        };
        let inner = RangeWithInstanceCircuitBuilder::new(circuit, vec![]);
        Self { inner }
    }
}

impl Circuit<Fr> for InnerCircuit {
    type Config = RangeWithInstanceConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        RangeWithInstanceCircuitBuilder::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}

// TODO: Expose public inputs
impl CircuitExt<Fr> for InnerCircuit {
    fn num_instance(&self) -> Vec<usize> {
        vec![0]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![]]
    }
}

/// Produce a proof of the inner circuit
pub fn gen_inner_circuit_snark(
    params: &ParamsKZG<Bn256>,
    application_proofs_and_pis: Vec<(Proof, PublicInputs)>,
    application_vk: &VerificationKey,
) -> Snark {
    let inner_circuit = InnerCircuit::new(
        CircuitBuilderStage::Keygen,
        None,
        params.k() as usize - 1,
        application_vk,
        application_proofs_and_pis.clone(),
    );
    std::env::set_var("LOOKUP_BITS", (params.k() - 1).to_string());
    let config = inner_circuit
        .inner
        .circuit
        .0
        .builder
        .borrow()
        .config(params.k() as usize, Some(5)); // TODO: Min rows?
    println!("Inner circuit config: {config:?}");

    let inner_pk = gen_pk(params, &inner_circuit, None);
    let break_points = inner_circuit.inner.break_points();

    let inner_circuit = InnerCircuit::new(
        CircuitBuilderStage::Prover,
        Some(break_points),
        params.k() as usize - 1,
        application_vk,
        application_proofs_and_pis,
    );

    gen_snark_gwc(params, &inner_pk, inner_circuit, None::<&str>)
}
