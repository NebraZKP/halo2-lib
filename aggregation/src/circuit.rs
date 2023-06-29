use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::FieldExt;
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

pub fn assign_public_inputs<F: PrimeField + ScalarField>(
    ctx: &mut Context<F>,
    inputs: &PublicInputs,
) -> AssignedPublicInputs<F> {
    todo!();
}

pub fn assign_proof<F: PrimeField + ScalarField, FC: FieldChip<F>>(
    ctx: &mut Context<F>,
    proof: &Proof,
) -> AssignedProof<F, FC> {
    todo!();
}

fn prepare_proofs<FC: FieldChip<Fr>>(
    ctx: &mut Context<Fr>,
    fp_chip: &FC,
    vk: &VerificationKey,
    proofs: &Vec<(AssignedProof<Fr, FC>, AssignedPublicInputs<Fr>)>,
) -> AssignedPreparedProof<Fr, FC> {
    todo!()
}

fn run_multi_miller<FC: FieldChip<Fr>>(
    ctx: &mut Context<Fr>,
    fp_chip: &FC,
    prepared: &AssignedPreparedProof<Fr, FC>,
) -> FieldVector<FC::FieldPoint> {
    todo!()
}

fn run_final_exp<FC: FieldChip<Fr>>(
    ctx: &mut Context<Fr>,
    fp_chip: &FC,
    miller_out: &FieldVector<FC::FieldPoint>,
) -> FieldVector<FC::FieldPoint> {
    todo!();
}

/// Constrain final_exp_out == 1 in GT
fn check_final_exp<FC: FieldChip<Fr>>(
    ctx: &mut Context<Fr>,
    fp_chip: &FC,
    final_exp_out: &FieldVector<FC::FieldPoint>,
) -> FieldVector<FC::FieldPoint> {
    todo!();
}

/// Execute the top-level batch verification by accumulating (as far as
/// possible) all proofs and public inputs, and performing a single large
/// pairing check.
pub fn batch_verify<FC: FieldChip<Fr>>(
    ctx: &mut Context<Fr>,
    fp_chip: &FC,
    vk: &VerificationKey,
    proofs: &Vec<(AssignedProof<Fr, FC>, AssignedPublicInputs<Fr>)>,
) {
    let prepared: AssignedPreparedProof<Fr, FC> =
        prepare_proofs(ctx, fp_chip, vk, proofs);
    let miller_out: FieldVector<FC::FieldPoint> =
        run_multi_miller(ctx, fp_chip, &prepared);
    let final_exp_out: FieldVector<FC::FieldPoint> =
        run_final_exp(ctx, fp_chip, &miller_out);
    check_final_exp(ctx, fp_chip, &final_exp_out);
}
