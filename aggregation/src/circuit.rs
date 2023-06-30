use std::marker::PhantomData;

use halo2_base::gates::builder::GateThreadBuilder;
use halo2_base::gates::GateChip;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::{CurveAffine, CurveAffineExt};
use halo2_base::safe_types::GateInstructions;
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context, QuantumCell};
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::vector::FieldVector;
use halo2_ecc::fields::{FieldChip, Selectable};

use crate::native::{Proof, PublicInputs, VerificationKey};

// In-circuit objects

/// In-circuit Groth16 proof
pub struct AssignedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub a: EcPoint<F, FC::FieldPoint>,
    pub b: EcPoint<F, FieldVector<FC::FieldPoint>>,
    pub c: EcPoint<F, FC::FieldPoint>,
}

/// In-circuit public inputs
pub struct AssignedPublicInputs<F: PrimeField + ScalarField>(
    Vec<AssignedValue<F>>,
);

/// In-circuit equivalent of PreparedProof.
struct AssignedPreparedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub ab_pairs: Vec<(EcPoint<F, FC::FieldPoint>, EcPoint<F, FC::FieldPoint>)>,
    pub rP: (
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    ),
    pub ri: (
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    ),
    pub sc: (
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    ),
}

pub struct BatchVerifier<C1, F, FC>
where
    C1: CurveAffineExt,
    F: PrimeField + ScalarField,
    FC: FieldChip<F, FieldType = C1::Base>,
{
    pub fp_chip: FC,
    pub _f: PhantomData<(C1, F)>,
}

impl<C1, F, FC> BatchVerifier<C1, F, FC>
where
    C1: CurveAffineExt,
    F: PrimeField + ScalarField,
    FC: FieldChip<F, FieldType = C1::Base>
        + Selectable<F, <FC as FieldChip<F>>::FieldPoint>,
{
    pub fn assign_public_inputs(
        self: &Self,
        ctx: &mut Context<F>,
        inputs: &PublicInputs,
    ) -> AssignedPublicInputs<F> {
        todo!();
    }

    pub fn assign_proof(
        self: &Self,
        ctx: &mut Context<F>,
        proof: &Proof,
    ) -> AssignedProof<F, FC> {
        todo!();
    }

    fn prepare_proofs<C2>(
        self: &Self,
        builder: &mut GateThreadBuilder<F>,
        vk: &VerificationKey<C1, C2>,
        proofs: Vec<(AssignedProof<F, FC>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) -> AssignedPreparedProof<F, FC>
    where
        C2: CurveAffineExt,
    {
        let ecc_chip = EccChip::new(&self.fp_chip);

        let r_powers = scalar_powers(builder.main(0), r, proofs.len());

        // Process public inputs
        let (proofs, public_inputs): (Vec<_>, Vec<_>) =
            proofs.into_iter().unzip();
        let processed_public_inputs =
            process_public_inputs(builder.main(0), r_powers, public_inputs);
        // `fixed_base_msm_in` expects a Vec<Vec<_>> of scalars
        let processed_public_inputs: Vec<_> = processed_public_inputs
            .0
            .into_iter()
            .map(|scalar| vec![scalar])
            .collect();
        ecc_chip.fixed_base_msm_in(
            builder,
            &vk.s, // TODO: Make vk generic over field or else make this specialized to Bn base
            processed_public_inputs,
            Fr::NUM_BITS as usize, // TODO: what's this generically?
            4,                     // TODO: Just grabbed this from MSM config
            0,                     // TODO: Do we ever use a non-zero phase?
        );

        // Scale (A, B) pairs

        // Combine C points

        // Compute - r_sum * P

        // Load from vk
        todo!()
    }

    fn multi_miller(
        self: &Self,
        ctx: &mut Context<F>,
        prepared: &AssignedPreparedProof<F, FC>,
    ) -> FieldVector<FC::FieldPoint> {
        todo!()
    }

    fn final_exponentiation(
        self: &Self,
        ctx: &mut Context<F>,
        miller_out: &FieldVector<FC::FieldPoint>,
    ) -> FieldVector<FC::FieldPoint> {
        todo!();
    }

    /// Constrain final_exp_out == 1 in GT
    fn check_final_exp(
        self: &Self,
        ctx: &mut Context<F>,
        final_exp_out: &FieldVector<FC::FieldPoint>,
    ) -> FieldVector<FC::FieldPoint> {
        todo!();
    }

    /// Execute the top-level batch verification by accumulating (as far as
    /// possible) all proofs and public inputs, and performing a single large
    /// pairing check.
    pub fn verify<C2>(
        self: &Self,
        builder: &mut GateThreadBuilder<F>,
        vk: &VerificationKey<C1, C2>,
        proofs: Vec<(AssignedProof<F, FC>, AssignedPublicInputs<F>)>,
    ) where
        C2: CurveAffineExt,
    {
        let r = todo!();
        let prepared = self.prepare_proofs(builder, vk, proofs, r);
        let miller_out = self.multi_miller(builder.main(0), &prepared);
        let final_exp_out =
            self.final_exponentiation(builder.main(0), &miller_out);
        self.check_final_exp(builder.main(0), &final_exp_out);
    }
}

/// Return accumulated public inputs
fn process_public_inputs<F: ScalarField>(
    ctx: &mut Context<F>,
    powers: Vec<QuantumCell<F>>,
    public_inputs: Vec<AssignedPublicInputs<F>>,
) -> AssignedPublicInputs<F> {
    let gate = GateChip::default();
    let num_pub_in = public_inputs[0].0.len();
    let f: Vec<AssignedValue<F>> = (0..num_pub_in)
        .map(|j| {
            // Combine jth public input from each proof
            let inputs = public_inputs.iter().map(|pub_in| pub_in.0[j].into());
            gate.inner_product(ctx, powers.clone(), inputs)
        })
        .collect();
    AssignedPublicInputs(f)
}

/// Return r^0, r, ... r^{len - 1}
fn scalar_powers<F: ScalarField>(
    ctx: &mut Context<F>,
    r: AssignedValue<F>,
    len: usize,
) -> Vec<QuantumCell<F>> {
    let gate = GateChip::default();
    let mut result = Vec::with_capacity(len);
    result.push(ctx.load_constant(F::one()).into());
    result.push(r.into());
    let current = r;
    for _ in 2..len {
        let current = gate.mul(ctx, current, r);
        result.push(current.into());
    }
    debug_assert_eq!(result.len(), len);
    result
}
