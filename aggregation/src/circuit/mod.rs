mod batch_verifier;
mod hashing;
pub use batch_verifier::*;
use halo2_base::utils::ScalarField;
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::EcPoint,
    fields::{fp::Reduced, vector::FieldVector, PrimeField},
};
pub use hashing::*;

/// Conversion from a reduced (unique) represenation to a regular
/// representation.
pub trait FromReduced<R> {
    fn from_reduced(reduced: &R) -> Self;
}

impl<F: ScalarField + PrimeField, Fp: Clone>
    FromReduced<EcPoint<F, Reduced<ProperCrtUint<F>, Fp>>>
    for EcPoint<F, ProperCrtUint<F>>
{
    fn from_reduced(
        reduced: &EcPoint<F, Reduced<ProperCrtUint<F>, Fp>>,
    ) -> Self {
        EcPoint::new(reduced.x.inner().clone(), reduced.y.inner().clone())
    }
}

impl<F: ScalarField + PrimeField, Fp: Clone>
    FromReduced<EcPoint<F, FieldVector<Reduced<ProperCrtUint<F>, Fp>>>>
    for EcPoint<F, FieldVector<ProperCrtUint<F>>>
{
    fn from_reduced(
        reduced: &EcPoint<F, FieldVector<Reduced<ProperCrtUint<F>, Fp>>>,
    ) -> Self {
        EcPoint::new(
            FieldVector::<ProperCrtUint<F>>::from(&reduced.x),
            FieldVector::<ProperCrtUint<F>>::from(&reduced.y),
        )
    }
}

impl<R, T: FromReduced<R>> FromReduced<Vec<R>> for Vec<T> {
    fn from_reduced(reduced: &Vec<R>) -> Self {
        reduced.iter().map(T::from_reduced).collect()
    }
}
