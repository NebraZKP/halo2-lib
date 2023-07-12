use std::hash::Hash;

use halo2_base::{
    halo2_proofs::halo2curves::{group::ff::PrimeField, FieldExt},
    utils::ScalarField,
    AssignedValue, Context,
};
use halo2_ecc::fields::{fp::FpChip, FieldChip, PrimeFieldChip};
use poseidon::PoseidonChip;

// TODO: determine the correct values for these Poseidon constants.
const R_F: usize = 8;
const R_P: usize = 57;

/// Hash a ReducedFieldPoint to a scalar value.  ReducedFieldPoint must be
/// used, since it is the unique representation.  This creates a poseidon
/// sponge, absorbing each limb of the unique representation, and then
/// squeezing.
pub fn hash_fq<
    F: ScalarField + PrimeField,
    Fq: FieldExt + Hash,
    // FC: FieldChip<F> + PrimeFieldChip<F>,
>(
    ctx: &mut Context<F>,
    fp_chip: &FpChip<F, Fq>,
    fp: &<FpChip<F, Fq> as FieldChip<F>>::ReducedFieldPoint,
) -> AssignedValue<F> {
    let mut poseidon = PoseidonChip::<F, 4, 3>::new(ctx, R_F, R_P).unwrap();
    poseidon.update(fp.inner().as_ref().truncation.limbs.as_slice());
    poseidon.squeeze(ctx, fp_chip.gate()).unwrap()
}
