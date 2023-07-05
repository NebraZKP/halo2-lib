use halo2_base::halo2_proofs::halo2curves::bn256::{
    Fr, G1Affine, G2Affine, G1, G2,
};
use serde::Deserialize;

// pub mod sample_proof;
mod component;
mod test_circuit;
mod test_native;

const VK_FILE: &str = "src/tests/vk.json";
const PROOF1_FILE: &str = "src/tests/proof1.json";
const PROOF2_FILE: &str = "src/tests/proof2.json";
const PROOF3_FILE: &str = "src/tests/proof3.json";

pub(crate) fn encode(f: i32) -> G1Affine {
    G1Affine::from(G1::generator() * Fr::from(f as u64))
}

pub(crate) fn encode_g2(f: i32) -> G2Affine {
    G2Affine::from(G2::generator() * Fr::from(f as u64))
}

#[allow(dead_code)]
pub(crate) fn encode_fr(f: &Fr) -> G1Affine {
    G1Affine::from(G1::generator() * f)
}

pub(crate) fn encode_vec(fs: &Vec<i32>) -> Vec<G1Affine> {
    fs.iter().map(|a| encode(*a)).collect()
}
