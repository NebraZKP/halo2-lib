use rand_core::OsRng;

pub struct UnsafeSrs;

///
pub struct UnsafePk;

/// Wrapper around a verifying key
pub struct UnsafeVk;

/// Wrapper around a `Groth16Proof`
pub struct Groth16Proof;

pub fn unsafe_setup(srs: UnsafeSrs) -> (UnsafeVk, UnsafePk) {
    todo!()
}

pub fn get_proof(pk: UnsafePk, rng: OsRng) -> Groth16Proof {
    todo!();
}
