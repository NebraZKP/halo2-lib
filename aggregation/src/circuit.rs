use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::vector::FieldVector;
use halo2_ecc::fields::FieldChip;

use crate::native::{Proof, PublicInputs, VerificationKey};

// In-circuit objects

// In-circuit Groth16 proof
pub struct AssignedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub a: EcPoint<F, FC::FieldPoint>,
    pub b: EcPoint<F, FieldVector<FC::FieldPoint>>,
    pub c: EcPoint<F, FC::FieldPoint>,
}

// In-circuit public inputs
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

pub struct BatchVerifier<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    fp_chip: FC,
    phantom_data: F,
}

impl<F: PrimeField + ScalarField, FC: FieldChip<F>> BatchVerifier<F, FC> {
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

    fn prepare_proofs(
        self: &Self,
        ctx: &mut Context<F>,
        vk: &VerificationKey,
        proofs: &Vec<(AssignedProof<F, FC>, AssignedPublicInputs<F>)>,
    ) -> AssignedPreparedProof<F, FC> {
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
    pub fn batch_verify(
        self: &Self,
        ctx: &mut Context<F>,
        vk: &VerificationKey,
        proofs: &Vec<(AssignedProof<F, FC>, AssignedPublicInputs<F>)>,
    ) {
        let prepared = self.prepare_proofs(ctx, vk, proofs);
        let miller_out = self.multi_miller(ctx, &prepared);
        let final_exp_out = self.final_exponentiation(ctx, &miller_out);
        self.check_final_exp(ctx, &final_exp_out);
    }
}
