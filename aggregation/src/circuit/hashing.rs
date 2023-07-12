use std::hash::Hash;

use halo2_base::{
    halo2_proofs::halo2curves::{group::ff::PrimeField, FieldExt},
    utils::ScalarField,
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::{
        fp::{FpChip, Reduced},
        vector::FieldVector,
        FieldChip,
    },
};
use poseidon::PoseidonChip;

// TODO: determine the correct values for these Poseidon constants.
const R_F: usize = 8;
const R_P: usize = 57;

/// This creates a poseidon sponge, absorbing instances of InCircuitHash and
/// then squeezing.
pub struct Hasher<'a, F: ScalarField + PrimeField, Fq: FieldExt + Hash> {
    pub fp_chip: &'a FpChip<'a, F, Fq>,
    pub poseidon: PoseidonChip<F, 4, 3>,
}

impl<'a, F: ScalarField + PrimeField, Fq: FieldExt + Hash> Hasher<'a, F, Fq> {
    pub fn new(ctx: &mut Context<F>, fp_chip: &'a FpChip<'a, F, Fq>) -> Self {
        Hasher {
            fp_chip,
            poseidon: PoseidonChip::<F, 4, 3>::new(ctx, R_F, R_P).unwrap(),
        }
    }

    pub fn absorb<T: InCircuitHash<F, Fq>>(self: &mut Self, assigned: &T) {
        assigned.hash(self);
    }

    pub fn squeeze(self: &mut Self, ctx: &mut Context<F>) -> AssignedValue<F> {
        self.poseidon.squeeze(ctx, self.fp_chip.gate()).unwrap()
    }
}

/// An object which can be absorbed by a Hasher
pub trait InCircuitHash<F: ScalarField + PrimeField, Fq: FieldExt + Hash> {
    fn hash(self: &Self, hasher: &mut Hasher<F, Fq>);
}

/// Absorbe an in-circuit Fq element (FpChip::ReducedFieldPoint).  This must
/// be a Reduced<...> since that is the unique representation of the
/// underlying value.
impl<F: ScalarField + PrimeField, Fq: FieldExt + Hash> InCircuitHash<F, Fq>
    for Reduced<ProperCrtUint<F>, Fq>
{
    fn hash(self: &Self, hasher: &mut Hasher<F, Fq>) {
        hasher
            .poseidon
            .update(self.inner().as_ref().truncation.limbs.as_slice());
    }
}

/// Absorb an in-circuit element of an extention of Fq value.
impl<F: ScalarField + PrimeField, Fq: FieldExt + Hash> InCircuitHash<F, Fq>
    for FieldVector<Reduced<ProperCrtUint<F>, Fq>>
{
    fn hash(self: &Self, hasher: &mut Hasher<F, Fq>) {
        for element in self.0.iter() {
            element.hash(hasher);
        }
    }
}

/// Absorb an in-circuit EC point
impl<
        F: ScalarField + PrimeField,
        Fq: FieldExt + Hash,
        FP: InCircuitHash<F, Fq>,
    > InCircuitHash<F, Fq> for EcPoint<F, FP>
{
    fn hash(self: &Self, hasher: &mut Hasher<F, Fq>) {
        self.x.hash(hasher);
        self.y.hash(hasher);
    }
}
