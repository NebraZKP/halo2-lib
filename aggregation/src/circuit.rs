use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2_base::halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_base::utils::ScalarField;
use halo2_base::{AssignedValue, Context};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::fields::FieldChip;

use crate::native::VerificationKey;

// In-circuit objects

pub struct AssignedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub a: EcPoint<F, FC::FieldPoint>,
    pub b: EcPoint<F, FC::FieldPoint>,
    pub c: EcPoint<F, FC::FieldPoint>,
}

pub struct AssignedPublicInputs<F: PrimeField + ScalarField>(
    Vec<AssignedValue<F>>,
);

/// "Prepared" here means that all curve points have been accumulated and we
/// have a sequence of pairs of G1 and G2 points ready for passing to a
/// multi-Miller loop.
struct AssignedPreparedProof {
    /// Rescaled pairs (r^i * A_i, B_i)
    pub ab_pairs: Vec<(G1Affine, G2Affine)>,
    /// (-sum_i r^i * P, Q)
    pub rP: (G1Affine, G2Affine),
    /// (-PI, h)
    pub pi: (G1Affine, G2Affine),
    /// (- sum_i r^i C_i, D)
    pub zc: (G1Affine, G2Affine),
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
    todo!()
}
