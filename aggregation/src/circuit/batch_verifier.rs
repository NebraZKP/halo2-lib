use super::{FromReduced, PoseidonHasher};
use crate::native::{Proof, PublicInputs, VerificationKey};
use halo2_base::{
    gates::{builder::GateThreadBuilder, GateChip},
    halo2_proofs::halo2curves::{
        bn256::{Fq, Fq12, Fq2, G1Affine, G2Affine},
        group::ff::{Field, PrimeField},
    },
    safe_types::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    bn254::{pairing::PairingChip, Fp12Chip, FqPoint},
    ecc::{scalar_multiply, EcPoint, EccChip},
    fields::{
        fp::{FpChip, Reduced},
        vector::FieldVector,
        FieldChip,
    },
};
use poseidon::PoseidonChip;
use std::iter::once;

pub const DEFAULT_NUM_PROOFS: usize = 8;
pub const DEFAULT_NUM_PUBLIC_INPUTS: usize = 3;
pub const DEFAULT_NUM_PUBLIC_INPUTS_PLUS_ONE: usize =
    DEFAULT_NUM_PUBLIC_INPUTS + 1;

// TODO: determine the correct values for these Poseidon constants.  See
// https://github.com/openzklib/openzl/blob/main/openzl-crypto/src/poseidon/constants.rs.
const R_F: usize = 8;
const R_P: usize = 57;

/// TODO: Is it worth allowing this to be variable?
const WINDOW_BITS: usize = 4;

// In-circuit objects

pub type G1Point<'a, F> =
    EcPoint<F, <FpChip<'a, F, Fq> as FieldChip<F>>::FieldPoint>;
pub type G2Point<'a, F> =
    EcPoint<F, FieldVector<<FpChip<'a, F, Fq> as FieldChip<F>>::FieldPoint>>;

/// Assigned G1 and G2 points where we want a unique representation, e.g. for
/// proof elements, where the protocol should not introduce malleability of
/// the incoming proofs.
pub type G1InputPoint<'a, F> =
    EcPoint<F, <FpChip<'a, F, Fq> as FieldChip<F>>::ReducedFieldPoint>;
pub type G2InputPoint<'a, F> = EcPoint<
    F,
    FieldVector<<FpChip<'a, F, Fq> as FieldChip<F>>::ReducedFieldPoint>,
>;

/// In-circuit Groth16 Verification Key
pub struct AssignedVerificationKey<'a, F: PrimeField + ScalarField> {
    pub alpha: G1InputPoint<'a, F>,
    pub beta: G2InputPoint<'a, F>,
    pub gamma: G2InputPoint<'a, F>,
    pub delta: G2InputPoint<'a, F>,
    pub s: Vec<G1InputPoint<'a, F>>,
}

/// In-circuit Groth16 proof
#[derive(Clone, Debug)]
pub struct AssignedProof<'a, F: PrimeField + ScalarField> {
    pub a: G1InputPoint<'a, F>,
    pub b: G2InputPoint<'a, F>,
    pub c: G1InputPoint<'a, F>,
}

/// In-circuit public inputs
#[derive(Clone, Debug)]
pub struct AssignedPublicInputs<F: PrimeField + ScalarField>(
    pub Vec<AssignedValue<F>>,
);

/// In-circuit equivalent of PreparedProof.
// TODO: handle hard-coded values
pub(crate) struct AssignedPreparedProof<'a, F: PrimeField + ScalarField> {
    pub ab_pairs: Vec<(G1Point<'a, F>, G2Point<'a, F>)>,
    pub rp: (G1Point<'a, F>, G2Point<'a, F>),
    pub pi: (G1Point<'a, F>, G2Point<'a, F>),
    pub zc: (G1Point<'a, F>, G2Point<'a, F>),
}

pub struct BatchVerifier<
    'a,
    F,
    const NUM_PROOFS: usize = DEFAULT_NUM_PROOFS,
    const NUM_PUBLIC_INPUTS: usize = DEFAULT_NUM_PUBLIC_INPUTS,
    const NUM_PUBLIC_INPUTS_PLUS_ONE: usize = DEFAULT_NUM_PUBLIC_INPUTS_PLUS_ONE,
> where
    F: PrimeField + ScalarField,
{
    fp_chip: &'a FpChip<'a, F, Fq>,
}

impl<
        'a,
        F,
        const NUM_PROOFS: usize,
        const NUM_PUBLIC_INPUTS: usize,
        const NUM_PUBLIC_INPUTS_PLUS_ONE: usize,
    >
    BatchVerifier<
        'a,
        F,
        NUM_PROOFS,
        NUM_PUBLIC_INPUTS,
        NUM_PUBLIC_INPUTS_PLUS_ONE,
    >
where
    F: PrimeField + ScalarField,
{
    pub fn new(fp_chip: &'a FpChip<F, Fq>) -> BatchVerifier<'a, F> {
        assert!(NUM_PUBLIC_INPUTS_PLUS_ONE == NUM_PUBLIC_INPUTS + 1);
        BatchVerifier { fp_chip }
    }

    pub fn fp_chip(&self) -> &FpChip<'a, F, Fq> {
        self.fp_chip
    }

    pub fn assign_verification_key(
        &self,
        ctx: &mut Context<F>,
        vk: &VerificationKey,
    ) -> AssignedVerificationKey<F> {
        AssignedVerificationKey {
            alpha: self.assign_g1_reduced(ctx, vk.alpha),
            beta: self.assign_g2_reduced(ctx, vk.beta),
            gamma: self.assign_g2_reduced(ctx, vk.gamma),
            delta: self.assign_g2_reduced(ctx, vk.delta),
            s: vk
                .s
                .iter()
                .copied()
                .map(|s| self.assign_g1_reduced(ctx, s))
                .collect(),
        }
    }

    pub fn assign_public_inputs(
        &self,
        ctx: &mut Context<F>,
        inputs: &PublicInputs<F>,
    ) -> AssignedPublicInputs<F> {
        assert!(inputs.0.len() == NUM_PUBLIC_INPUTS);
        AssignedPublicInputs(ctx.assign_witnesses(inputs.0.iter().copied()))
    }

    pub fn assign_proof(
        &self,
        ctx: &mut Context<F>,
        proof: &Proof,
    ) -> AssignedProof<F> {
        AssignedProof {
            a: self.assign_g1_reduced(ctx, proof.a),
            b: self.assign_g2_reduced(ctx, proof.b),
            c: self.assign_g1_reduced(ctx, proof.c),
        }
    }

    pub fn compute_r(
        ctx: &mut Context<F>,
        _vk: &AssignedVerificationKey<F>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
    ) -> AssignedValue<F> {
        assert!(NUM_PUBLIC_INPUTS_PLUS_ONE == NUM_PUBLIC_INPUTS + 1);

        // TODO: Seed the poseidon state with (some hash of) the VK

        let mut poseidon = PoseidonChip::<
            F,
            NUM_PUBLIC_INPUTS_PLUS_ONE,
            NUM_PUBLIC_INPUTS,
        >::new(ctx, R_F, R_P)
        .expect("create poseidon chip");
        for pi in proofs {
            poseidon.update(pi.1 .0.as_slice());
        }

        let gate = GateChip::default();
        poseidon.squeeze(ctx, &gate).expect("squeeze")
    }

    /// Execute the top-level batch verification by accumulating (as far as
    /// possible) all proofs and public inputs, and performing a single large
    /// pairing check.  Returns the AssignedValue holding the hash of the
    /// verification key.
    pub fn verify(
        &self,
        builder: &mut GateThreadBuilder<F>,
        vk: &AssignedVerificationKey<F>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
    ) -> AssignedValue<F> {
        let r = Self::compute_r(builder.main(0), vk, proofs);
        self.verify_with_challenge(builder, vk, proofs, r)
    }

    pub(crate) fn verify_with_challenge(
        &self,
        builder: &mut GateThreadBuilder<F>,
        vk: &AssignedVerificationKey<F>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) -> AssignedValue<F> {
        assert!(proofs.len() == NUM_PROOFS);
        let vk_hash = self.compute_vk_hash(builder.main(0), vk);
        let prepared = self.prepare_proofs(builder, vk, (*proofs).clone(), r);
        let ctx = builder.main(0);
        let pairing_out = self.multi_pairing(ctx, &prepared);
        self.check_pairing_result(ctx, &pairing_out);
        vk_hash
    }

    pub(crate) fn assign_fq_reduced(
        &self,
        ctx: &mut Context<F>,
        value: Fq,
    ) -> Reduced<ProperCrtUint<F>, Fq> {
        let assigned = self.fp_chip.load_private(ctx, value);
        self.fp_chip.enforce_less_than(ctx, assigned)
    }

    pub(crate) fn assign_fq2_reduced(
        &self,
        ctx: &mut Context<F>,
        value: Fq2,
    ) -> FieldVector<Reduced<ProperCrtUint<F>, Fq>> {
        FieldVector(vec![
            self.assign_fq_reduced(ctx, value.c0),
            self.assign_fq_reduced(ctx, value.c1),
        ])
    }

    pub(crate) fn assign_g1_reduced(
        &self,
        ctx: &mut Context<F>,
        value: G1Affine,
    ) -> EcPoint<F, Reduced<ProperCrtUint<F>, Fq>> {
        EcPoint::new(
            self.assign_fq_reduced(ctx, value.x),
            self.assign_fq_reduced(ctx, value.y),
        )
    }

    pub(crate) fn assign_g2_reduced(
        &self,
        ctx: &mut Context<F>,
        value: G2Affine,
    ) -> EcPoint<F, FieldVector<Reduced<ProperCrtUint<F>, Fq>>> {
        EcPoint::new(
            self.assign_fq2_reduced(ctx, value.x),
            self.assign_fq2_reduced(ctx, value.y),
        )
    }

    pub(crate) fn compute_vk_hash(
        &self,
        ctx: &mut Context<F>,
        vk: &AssignedVerificationKey<F>,
    ) -> AssignedValue<F> {
        let mut hasher = PoseidonHasher::<F, Fq>::new(ctx, self.fp_chip);
        hasher.absorb(vk);
        hasher.squeeze(ctx)
    }

    pub(crate) fn prepare_proofs(
        &self,
        builder: &mut GateThreadBuilder<F>,
        vk: &AssignedVerificationKey<F>,
        proofs: Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) -> AssignedPreparedProof<F> {
        let gate = GateChip::default();
        let ecc_chip = EccChip::new(self.fp_chip);

        let ctx = builder.main(0);

        // Compute the powers of r, and their sum
        let r_powers = Self::scalar_powers(ctx, r, proofs.len());
        // TODO: clone() here is required by GateInstructions.  Why does it
        // need a full copy?
        let r_sum = gate.sum(ctx, r_powers.clone());

        // Process public inputs
        let (proofs, public_inputs): (Vec<_>, Vec<_>) =
            proofs.into_iter().unzip();
        let processed_public_inputs =
            Self::compute_f_js(ctx, &r_powers, &r_sum, &public_inputs);

        // `fixed_base_msm_in` expects a Vec<Vec<_>> of scalars
        let processed_public_inputs: Vec<_> = processed_public_inputs
            .into_iter()
            .map(|scalar| vec![scalar])
            .collect();

        let vk_s: Vec<EcPoint<F, ProperCrtUint<F>>> =
            Vec::<EcPoint<F, ProperCrtUint<F>>>::from_reduced(&vk.s);
        let pi = ecc_chip.variable_base_msm_in::<G1Affine>(
            builder,
            vk_s.as_slice(),
            processed_public_inputs,
            F::NUM_BITS as usize,
            WINDOW_BITS,
            0, // TODO: Do we ever use a non-zero phase?
        );
        let minus_pi = ecc_chip.negate(builder.main(0), pi);

        // Split into Vec<(A,B)>, and Vec<C>.  Also convert into the
        // non-reduced versions of the group elements.
        let (ab_pairs, c_points): (Vec<_>, Vec<_>) = proofs
            .into_iter()
            .map(|proof| {
                (
                    (
                        G1Point::<F>::from_reduced(&proof.a),
                        G2Point::<F>::from_reduced(&proof.b),
                    ),
                    G1Point::<F>::from_reduced(&proof.c),
                )
            })
            .unzip();

        // Combine C points
        let zc = ecc_chip.variable_base_msm_in::<G1Affine>(
            builder,
            &c_points,
            r_powers
                .iter()
                .map(|scalar| vec![*scalar])
                .collect::<Vec<_>>(),
            F::NUM_BITS as usize,
            WINDOW_BITS,
            0,
        );
        let minus_zc = ecc_chip.negate(builder.main(0), zc);

        // Scale (A, B) pairs
        let scaled_ab_pairs =
            self.scale_pairs(builder.main(0), r_powers, ab_pairs);

        // Compute - r_sum * P
        let ctx = builder.main(0);
        let rp = ecc_chip.scalar_mult::<G1Affine>(
            ctx,
            G1Point::<F>::from_reduced(&vk.alpha),
            vec![r_sum],
            F::NUM_BITS as usize,
            WINDOW_BITS,
        );
        let minus_rp = ecc_chip.negate(ctx, rp);
        // Load from vk
        AssignedPreparedProof {
            ab_pairs: scaled_ab_pairs,
            rp: (minus_rp, G2Point::<F>::from_reduced(&vk.beta)),
            pi: (minus_pi, G2Point::<F>::from_reduced(&vk.gamma)),
            zc: (minus_zc, G2Point::<F>::from_reduced(&vk.delta)),
        }
    }

    /// Return the `f_j` values (where f_j is the accumulation of the j-th
    /// public input for each proof).
    pub(crate) fn compute_f_js(
        ctx: &mut Context<F>,
        r_powers: &[AssignedValue<F>],
        r_sum: &AssignedValue<F>,
        public_inputs: &[AssignedPublicInputs<F>],
    ) -> Vec<AssignedValue<F>> {
        let gate = GateChip::default();
        let num_pub_in = public_inputs[0].0.len();

        // Compute the f_j values:
        // f_0 = r_sum
        // f_j = \sum_{i=0}^{N-1} r^i pi[i][j]

        let f_js: Vec<AssignedValue<F>> = once(*r_sum)
            .chain((0..num_pub_in).map(|j| {
                // Iterator over the jth public input of each proof
                let inputs =
                    public_inputs.iter().map(|pub_in| pub_in.0[j].into());
                // TODO: clone (via to_owned) here is because QuantumCell
                // doesn't implement From<&AssignedValue<F>>
                gate.inner_product(ctx, r_powers.to_owned(), inputs)
            }))
            .collect();
        assert!(f_js.len() == num_pub_in + 1);
        f_js
    }

    pub(crate) fn prepared_proof_to_pair_refs<'prep>(
        prepared: &'prep AssignedPreparedProof<'prep, F>,
    ) -> Vec<(&'prep G1Point<'prep, F>, &'prep G2Point<'prep, F>)> {
        // TODO: consider moving this to an
        //   impl From<AssignedPreparedProof> for Vec<(&EcPoint, &EcPoint)>

        let pairs: Vec<(&'prep G1Point<F>, &'prep G2Point<F>)> = prepared
            .ab_pairs
            .iter()
            .chain(once(&prepared.rp))
            .chain(once(&prepared.pi))
            .chain(once(&prepared.zc))
            .map(|(a, b)| (a, b))
            .collect();

        pairs
    }

    pub(crate) fn multi_pairing<'prep>(
        &self,
        ctx: &mut Context<F>,
        prepared: &'prep AssignedPreparedProof<'prep, F>,
    ) -> FqPoint<F> {
        // TODO: try to make this more generic.  Current problem is that
        // halo2-ecc::bn254::pairing::PairingChip insists on a
        // halo2-ecc::bn254::FpChip, which is a concrete implementation
        // (i.e. the PairingChip is not generic over types implementing the
        // FieldChip trait, say).  So we cannot pass in self.fp_chip, which is
        // a generic FieldChip.

        let pairing_chip = PairingChip::<F>::new(self.fp_chip);
        let pair_refs = Self::prepared_proof_to_pair_refs(prepared);
        let miller_out = pairing_chip.multi_miller_loop(ctx, pair_refs);
        pairing_chip.final_exp(ctx, miller_out)
    }

    /// Constrain final_exp_out == 1 in GT
    pub(crate) fn check_pairing_result(
        &self,
        ctx: &mut Context<F>,
        final_exp_out: &FqPoint<F>,
    ) {
        let fp12_chip = Fp12Chip::<F>::new(self.fp_chip);
        let fp12_one = fp12_chip.load_constant(ctx, Fq12::one());
        fp12_chip.assert_equal(ctx, final_exp_out, fp12_one);
    }

    /// Return r^0, r, ... r^{len - 1}
    pub(crate) fn scalar_powers(
        ctx: &mut Context<F>,
        r: AssignedValue<F>,
        len: usize,
    ) -> Vec<AssignedValue<F>> {
        let gate = GateChip::default();
        let mut result = Vec::with_capacity(len);
        result.push(ctx.load_constant(F::one()));
        result.push(r);
        let mut current = r;
        for _ in 2..len {
            current = gate.mul(ctx, current, r);
            result.push(current);
        }
        debug_assert_eq!(result.len(), len);
        result
    }

    /// Returns `(scalar_i * A_i, B_i)`
    pub(crate) fn scale_pairs(
        &self,
        ctx: &mut Context<F>,
        scalars: Vec<AssignedValue<F>>,
        pairs: Vec<(G1Point<F>, G2Point<F>)>,
    ) -> Vec<(G1Point<'a, F>, G2Point<'a, F>)> {
        let mut result = Vec::with_capacity(pairs.len());
        for ((g1, g2), scalar) in pairs.into_iter().zip(scalars.into_iter()) {
            result.push((
                scalar_multiply::<_, FpChip<F, Fq>, G1Affine>(
                    self.fp_chip,
                    ctx,
                    g1,
                    vec![scalar],
                    F::NUM_BITS as usize,
                    WINDOW_BITS,
                ),
                g2,
            ))
        }
        result
    }
}
