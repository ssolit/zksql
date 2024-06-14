// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! Main module for the ZeroCheck protocol.
/// A ZeroCheck for `f(x)` proves that `f(x) = 0` for all `x \in {0,1}^num_vars`
/// It is derived from SumCheck.
/// use std::{fmt::Debug, marker::PhantomData};

use crate::poly_iop::{errors::PolyIOPErrors, sum_check::SumCheck, PolyIOP};
use arithmetic::eq_eval;
use ark_ff::PrimeField;
use ark_std::{end_timer, start_timer};
use std::fmt::Debug;
use transcript::IOPTranscript;

pub mod new_stuff;


#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZeroCheckSubClaim<F: PrimeField> {
    // the evaluation point
    pub point: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
    // the initial challenge r which is used to build eq(x, r)
    pub init_challenge: Vec<F>,
}

pub trait ZeroCheck<F: PrimeField>: SumCheck<F> {
    type ZeroCheckSubClaim: Clone + Debug + Default + PartialEq;
    type ZeroCheckProof: Clone + Debug + Default + PartialEq;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a ZeroCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// ZeroCheck prover/verifier.
    fn init_transcript() -> Self::Transcript;

    /// initialize the prover to argue for the sum of polynomial over
    /// {0,1}^`num_vars` is zero.
    fn prove(
        poly: &Self::VirtualPolynomial,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::ZeroCheckProof, PolyIOPErrors>;

    /// verify the claimed sum using the proof
    fn verify(
        proof: &Self::ZeroCheckProof,
        aux_info: &Self::VPAuxInfo,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::ZeroCheckSubClaim, PolyIOPErrors>;
}

impl<F: PrimeField> ZeroCheck<F> for PolyIOP<F> {
    type ZeroCheckSubClaim = ZeroCheckSubClaim<F>;
    type ZeroCheckProof = Self::SumCheckProof;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<F>::new(b"Initializing ZeroCheck transcript")
    }

    fn prove(
        poly: &Self::VirtualPolynomial,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::ZeroCheckProof, PolyIOPErrors> {
        let start = start_timer!(|| "zero check prove");

        let length = poly.aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;
        let f_hat = poly.build_f_hat(r.as_ref())?;
        let res = <Self as SumCheck<F>>::prove(&f_hat, transcript);

        end_timer!(start);
        res
    }

    fn verify(
        proof: &Self::ZeroCheckProof,
        fx_aux_info: &Self::VPAuxInfo,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::ZeroCheckSubClaim, PolyIOPErrors> {
        let start = start_timer!(|| "zero check verify");

        // check that the sum is zero
        if proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1] != F::zero() {
            return Err(PolyIOPErrors::InvalidProof(format!(
                "zero check: sum {} is not zero",
                proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1]
            )));
        }

        // generate `r` and pass it to the caller for correctness check
        let length = fx_aux_info.num_variables;
        let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;

        // hat_fx's max degree is increased by eq(x, r).degree() which is 1
        let mut hat_fx_aux_info = fx_aux_info.clone();
        hat_fx_aux_info.max_degree += 1;
        let sum_subclaim =
            <Self as SumCheck<F>>::verify(F::zero(), proof, &hat_fx_aux_info, transcript)?;

        // expected_eval = sumcheck.expect_eval/eq(v, r)
        // where v = sum_check_sub_claim.point
        let eq_x_r_eval = eq_eval(&sum_subclaim.point, &r)?;
        let expected_evaluation = sum_subclaim.expected_evaluation / eq_x_r_eval;

        end_timer!(start);
        Ok(ZeroCheckSubClaim {
            point: sum_subclaim.point,
            expected_evaluation,
            init_challenge: r,
        })
    }
}