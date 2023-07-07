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
    bn254::{pairing::PairingChip, Fp12Chip, FqPoint},
    ecc::{scalar_multiply, EcPoint, EccChip},
    fields::{fp::FpChip, fp2::Fp2Chip, vector::FieldVector, FieldChip},
};
use std::iter::once;

/// TODO: Is it worth allowing this to be variable?
const WINDOW_BITS: usize = 4;

// In-circuit objects

pub type G1Point<'a, F> =
    EcPoint<F, <FpChip<'a, F, Fq> as FieldChip<F>>::FieldPoint>;
pub type G2Point<'a, F> =
    EcPoint<F, FieldVector<<FpChip<'a, F, Fq> as FieldChip<F>>::FieldPoint>>;

/// In-circuit Groth16 proof
#[derive(Clone, Debug)]
pub struct AssignedProof<'a, F: PrimeField + ScalarField> {
    pub a: G1Point<'a, F>,
    pub b: G2Point<'a, F>,
    pub c: G1Point<'a, F>,
}

/// In-circuit public inputs
#[derive(Clone, Debug)]
pub struct AssignedPublicInputs<F: PrimeField + ScalarField>(
    Vec<AssignedValue<F>>,
);

/// In-circuit equivalent of PreparedProof.
// TODO: handle hard-coded values
pub(crate) struct AssignedPreparedProof<'a, F: PrimeField + ScalarField> {
    pub ab_pairs: Vec<(G1Point<'a, F>, G2Point<'a, F>)>,
    pub rp: (G1Point<'a, F>, G2Point<'a, F>),
    pub pi: (G1Point<'a, F>, G2Point<'a, F>),
    pub zc: (G1Point<'a, F>, G2Point<'a, F>),
}

pub struct BatchVerifier<'a, F>
where
    F: PrimeField + ScalarField,
{
    pub fp_chip: &'a FpChip<'a, F, Fq>,
}

impl<'a, F> BatchVerifier<'a, F>
where
    F: PrimeField + ScalarField,
{
    pub fn assign_public_inputs(
        self: &Self,
        ctx: &mut Context<F>,
        inputs: PublicInputs<F>,
    ) -> AssignedPublicInputs<F> {
        AssignedPublicInputs(ctx.assign_witnesses(inputs.0))
    }

    pub fn assign_proof(
        self: &Self,
        ctx: &mut Context<F>,
        proof: &Proof,
    ) -> AssignedProof<F> {
        let g1_chip = EccChip::new(self.fp_chip);
        let fp2_chip = Fp2Chip::<F, FpChip<F, Fq>, Fq2>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        AssignedProof {
            a: g1_chip.assign_point(ctx, proof.a),
            b: g2_chip.assign_point(ctx, proof.b),
            c: g1_chip.assign_point(ctx, proof.c),
        }
    }

    /// Execute the top-level batch verification by accumulating (as far as
    /// possible) all proofs and public inputs, and performing a single large
    /// pairing check.
    pub fn verify(
        self: &Self,
        builder: &mut GateThreadBuilder<F>,
        vk: &VerificationKey<G1Affine, G2Affine>,
        proofs: &Vec<(AssignedProof<F>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) {
        let prepared = self.prepare_proofs(builder, vk, (*proofs).clone(), r);
        let ctx = builder.main(0);
        let pairing_out = self.multi_pairing(ctx, &prepared);
        self.check_pairing_result(ctx, &pairing_out);
    }

    pub(crate) fn prepare_proofs(
        self: &Self,
        builder: &mut GateThreadBuilder<F>,
        vk: &VerificationKey<G1Affine, G2Affine>,
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

        let pi = ecc_chip.fixed_base_msm_in(
            builder,
            &vk.s,
            processed_public_inputs,
            F::NUM_BITS as usize,
            WINDOW_BITS,
            0, // TODO: Do we ever use a non-zero phase?
        );
        let minus_pi = ecc_chip.negate(builder.main(0), pi);

        // Split into Vec<(A,B)>, and Vec<C>
        let (ab_pairs, c_points): (Vec<_>, Vec<_>) = proofs
            .into_iter()
            .map(|proof| ((proof.a, proof.b), proof.c))
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
        let rp = ecc_chip.fixed_base_scalar_mult(
            ctx,
            &vk.alpha,
            vec![r_sum],
            F::NUM_BITS as usize,
            WINDOW_BITS,
        );
        let minus_rp = ecc_chip.negate(ctx, rp);
        // Load from vk
        let fp2_chip = Fp2Chip::<F, FpChip<F, Fq>, Fq2>::new(self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        AssignedPreparedProof {
            ab_pairs: scaled_ab_pairs,
            rp: (minus_rp, g2_chip.assign_constant_point(ctx, vk.beta)),
            pi: (minus_pi, g2_chip.assign_constant_point(ctx, vk.gamma)),
            zc: (minus_zc, g2_chip.assign_constant_point(ctx, vk.delta)),
        }
    }

    /// Return the `f_j` values (where f_j is the accumulation of the j-th
    /// public input for each proof).
    pub(crate) fn compute_f_js(
        ctx: &mut Context<F>,
        r_powers: &Vec<AssignedValue<F>>,
        r_sum: &AssignedValue<F>,
        public_inputs: &Vec<AssignedPublicInputs<F>>,
    ) -> Vec<AssignedValue<F>> {
        let gate = GateChip::default();
        let num_pub_in = public_inputs[0].0.len();

        // Compute the f_j values:
        // f_0 = r_sum
        // f_j = \sum_{i=0}^{N-1} r^i pi[i][j]

        let f_js: Vec<AssignedValue<F>> = once(r_sum.clone())
            .chain((0..num_pub_in).map(|j| {
                // Iterator over the jth public input of each proof
                let inputs =
                    public_inputs.iter().map(|pub_in| pub_in.0[j].into());
                // TODO: clone here is because QuantumCell doesn't implement
                // From<&AssignedValue<F>>
                gate.inner_product(ctx, r_powers.clone(), inputs)
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
        self: &Self,
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
        self: &Self,
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
        result.push(ctx.load_constant(F::one()).into());
        result.push(r.into());
        let mut current = r.clone();
        for _ in 2..len {
            current = gate.mul(ctx, current, r);
            result.push(current);
        }
        debug_assert_eq!(result.len(), len);
        result
    }

    /// Returns `(scalar_i * A_i, B_i)`
    pub(crate) fn scale_pairs(
        self: &Self,
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
