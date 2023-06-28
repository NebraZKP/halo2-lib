use rand_core::OsRng;

pub(crate) struct UnsafeSrs;

///
pub(crate) struct UnsafePk;

/// Wrapper around a verifying key
pub(crate) struct UnsafeVk;

/// Wrapper around a `Groth16Proof`
pub(crate) struct UnsafeProof;

pub fn unsafe_setup(srs: UnsafeSrs) -> (UnsafeVk, UnsafePk) {
    todo!()
}

pub fn get_proof(pk: UnsafePk, rng: OsRng) -> Groth16Proof;
