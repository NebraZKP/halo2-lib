use halo2_base::{
    gates::{builder::GateThreadBuilder, GateChip},
    halo2_proofs::halo2curves::{group::ff::PrimeField, CurveAffineExt},
    safe_types::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
};
use halo2_ecc::{
    ecc::{scalar_multiply, EcPoint, EccChip},
    fields::{
        fp2::Fp2Chip, vector::FieldVector, FieldChip, FieldExtConstructor,
        PrimeFieldChip, Selectable,
    },
};
use std::{hash::Hash, marker::PhantomData};

use crate::native::{Proof, PublicInputs, VerificationKey};

/// TODO: Is it worth allowing this to be variable?
const WINDOW_BITS: usize = 4;

// In-circuit objects

/// In-circuit Groth16 proof
pub struct AssignedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub a: EcPoint<F, FC::FieldPoint>,
    pub b: EcPoint<F, FieldVector<FC::FieldPoint>>,
    pub c: EcPoint<F, FC::FieldPoint>,
}

/// In-circuit public inputs
pub struct AssignedPublicInputs<F: PrimeField + ScalarField>(
    Vec<AssignedValue<F>>,
);

/// In-circuit equivalent of PreparedProof.
struct AssignedPreparedProof<F: PrimeField + ScalarField, FC: FieldChip<F>> {
    pub ab_pairs: Vec<(
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    )>,
    pub rp: (
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    ),
    pub pi: (
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    ),
    pub zc: (
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    ),
}

pub struct BatchVerifier<C1, C2, F, FC>
where
    C1: CurveAffineExt,
    C2: CurveAffineExt,
    F: PrimeField + ScalarField,
    FC: FieldChip<F, FieldType = C1::Base>,
{
    pub fp_chip: FC,
    pub _f: PhantomData<(C1, C2, F)>,
}

impl<C1, C2, F, FC> BatchVerifier<C1, C2, F, FC>
where
    C1: CurveAffineExt,
    C1::Base: Hash,
    C2: CurveAffineExt,
    C2::Base: FieldExtConstructor<C1::Base, 2>,
    F: PrimeField + ScalarField,
    FC: PrimeFieldChip<F, FieldType = C1::Base>
        + Selectable<F, <FC as FieldChip<F>>::FieldPoint>
        + Selectable<F, <FC as FieldChip<F>>::ReducedFieldPoint>,
    // todo: simplify these trait bounds
    FieldVector<<FC as FieldChip<F>>::UnsafeFieldPoint>:
        From<FieldVector<<FC as FieldChip<F>>::FieldPoint>>,
    FieldVector<<FC as FieldChip<F>>::FieldPoint>:
        From<FieldVector<<FC as FieldChip<F>>::ReducedFieldPoint>>,
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
        proof: &Proof<C1, C2>,
    ) -> AssignedProof<F, FC> {
        let g1_chip = EccChip::new(&self.fp_chip);
        let fp2_chip = Fp2Chip::<F, FC, C2::Base>::new(&self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);
        AssignedProof {
            a: g1_chip.assign_point(ctx, proof.a),
            b: g2_chip.assign_point(ctx, proof.b),
            c: g1_chip.assign_point(ctx, proof.c),
        }
    }

    fn prepare_proofs(
        self: &Self,
        builder: &mut GateThreadBuilder<F>,
        vk: &VerificationKey<C1, C2>,
        proofs: Vec<(AssignedProof<F, FC>, AssignedPublicInputs<F>)>,
        r: AssignedValue<F>,
    ) -> AssignedPreparedProof<F, FC>
    where
        // there must be a more concise way to express these constraints
        FieldVector<<FC as FieldChip<F>>::UnsafeFieldPoint>:
            From<FieldVector<<FC as FieldChip<F>>::FieldPoint>>,
        FieldVector<<FC as FieldChip<F>>::UnsafeFieldPoint>:
            From<FieldVector<<FC as FieldChip<F>>::FieldPoint>>,
        FieldVector<<FC as FieldChip<F>>::FieldPoint>:
            From<FieldVector<<FC as FieldChip<F>>::ReducedFieldPoint>>,
        FieldVector<<FC as FieldChip<F>>::FieldPoint>:
            From<FieldVector<<FC as FieldChip<F>>::ReducedFieldPoint>>,
    {
        let ecc_chip = EccChip::new(&self.fp_chip);

        let r_powers = scalar_powers(builder.main(0), r, proofs.len());

        // Process public inputs
        let (proofs, public_inputs): (Vec<_>, Vec<_>) =
            proofs.into_iter().unzip();
        let processed_public_inputs = process_public_inputs(
            builder.main(0),
            r_powers.clone(),
            public_inputs,
        );
        // `fixed_base_msm_in` expects a Vec<Vec<_>> of scalars
        let processed_public_inputs: Vec<_> = processed_public_inputs
            .0
            .into_iter()
            .map(|scalar| vec![scalar])
            .collect();
        let pi = ecc_chip.fixed_base_msm_in(
            builder,
            &vk.s, // TODO: Make vk generic over field or else make this specialized to Bn base
            processed_public_inputs,
            F::NUM_BITS as usize,
            WINDOW_BITS,
            0, // TODO: Do we ever use a non-zero phase?
        );
        let minus_pi = ecc_chip.negate(builder.main(0), pi);

        let (pairs, c_points): (Vec<_>, Vec<_>) = proofs
            .into_iter()
            .map(|proof| ((proof.a, proof.b), proof.c))
            .unzip();
        // Scale (A, B) pairs
        let ab_pairs = scale_pairs::<C1, _, _>(
            &self.fp_chip,
            builder.main(0),
            r_powers.clone(),
            pairs,
        );
        // Combine C points
        let zc = ecc_chip.variable_base_msm_in::<C1>(
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

        // Compute - r_sum * P
        let gate = GateChip::default();
        let ctx = builder.main(0);

        let r_sum = gate.sum(ctx, r_powers);
        let rp = ecc_chip.fixed_base_scalar_mult(
            ctx,
            &vk.alpha,
            vec![r_sum],
            F::NUM_BITS as usize,
            WINDOW_BITS,
        );
        let minus_rp = ecc_chip.negate(ctx, rp);
        // Load from vk
        let fp2_chip = Fp2Chip::<F, FC, C2::Base>::new(&self.fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        AssignedPreparedProof {
            ab_pairs,
            rp: (minus_rp, g2_chip.assign_constant_point(ctx, vk.beta)),
            pi: (minus_pi, g2_chip.assign_constant_point(ctx, vk.gamma)),
            zc: (minus_zc, g2_chip.assign_constant_point(ctx, vk.delta)),
        }
    }

    fn multi_miller(
        self: &Self,
        ctx: &mut Context<F>,
        prepared: &AssignedPreparedProof<F, FC>,
    ) -> FieldVector<FC::FieldPoint> {
        todo!()
    }

    fn final_exponentiation(
        self: &Self,
        ctx: &mut Context<F>,
        miller_out: &FieldVector<FC::FieldPoint>,
    ) -> FieldVector<FC::FieldPoint> {
        todo!();
    }

    /// Constrain final_exp_out == 1 in GT
    fn check_final_exp(
        self: &Self,
        ctx: &mut Context<F>,
        final_exp_out: &FieldVector<FC::FieldPoint>,
    ) -> FieldVector<FC::FieldPoint> {
        todo!();
    }

    /// Execute the top-level batch verification by accumulating (as far as
    /// possible) all proofs and public inputs, and performing a single large
    /// pairing check.
    pub fn verify(
        self: &Self,
        builder: &mut GateThreadBuilder<F>,
        vk: &VerificationKey<C1, C2>,
        proofs: Vec<(AssignedProof<F, FC>, AssignedPublicInputs<F>)>,
    ) {
        // Temporary until r sampling is decided
        let r = {
            let ctx = builder.main(0);
            ctx.assign_witnesses(core::iter::once(F::from(2)))[0] // TODO
        };
        let prepared = self.prepare_proofs(builder, vk, proofs, r);
        let miller_out = self.multi_miller(builder.main(0), &prepared);
        let final_exp_out =
            self.final_exponentiation(builder.main(0), &miller_out);
        self.check_final_exp(builder.main(0), &final_exp_out);
    }
}

/// Return accumulated public inputs
pub fn process_public_inputs<F: ScalarField>(
    ctx: &mut Context<F>,
    powers: Vec<AssignedValue<F>>,
    public_inputs: Vec<AssignedPublicInputs<F>>,
) -> AssignedPublicInputs<F> {
    let gate = GateChip::default();
    let num_pub_in = public_inputs[0].0.len();
    let f: Vec<AssignedValue<F>> = (0..num_pub_in)
        .map(|j| {
            // Combine jth public input from each proof
            let inputs = public_inputs.iter().map(|pub_in| pub_in.0[j].into());
            gate.inner_product(ctx, powers.clone(), inputs)
        })
        .collect();
    AssignedPublicInputs(f)
}

/// Return r^0, r, ... r^{len - 1}
pub fn scalar_powers<F: ScalarField>(
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
pub fn scale_pairs<C1, F, FC>(
    field_chip: &FC,
    ctx: &mut Context<F>,
    scalars: Vec<AssignedValue<F>>,
    pairs: Vec<(
        EcPoint<F, FC::FieldPoint>,
        EcPoint<F, FieldVector<FC::FieldPoint>>,
    )>,
) -> Vec<(
    EcPoint<F, FC::FieldPoint>,
    EcPoint<F, FieldVector<FC::FieldPoint>>,
)>
where
    C1: CurveAffineExt,
    F: PrimeField + ScalarField,
    FC: FieldChip<F, FieldType = C1::Base>
        + Selectable<F, <FC as FieldChip<F>>::FieldPoint>,
{
    let mut result = Vec::with_capacity(pairs.len());
    for ((g1, g2), scalar) in pairs.into_iter().zip(scalars.into_iter()) {
        result.push((
            scalar_multiply::<_, _, C1>(
                field_chip,
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
