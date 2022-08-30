//! Main module for the ZeroCheck protocol.

use std::fmt::Debug;

use crate::{errors::PolyIOPErrors, sum_check::SumCheck, PolyIOP};
use arithmetic::build_eq_x_r;
use ark_ff::PrimeField;
use ark_poly::MultilinearExtension;
use ark_std::{end_timer, start_timer};
use transcript::IOPTranscript;

/// A zero check IOP subclaim for \hat f(x) is 0, consists of the following:
///   - the SubClaim from the SumCheck
///   - the initial challenge r which is used to build eq(x, r) in ZeroCheck
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ZeroCheckSubClaim<F: PrimeField, SC: SumCheck<F>> {
    // the SubClaim from the SumCheck
    pub sum_check_sub_claim: SC::SumCheckSubClaim,
    /// the expected evaluation
    pub expected_evaluation: F,
    // the initial challenge r which is used to build eq(x, r)
    pub init_challenge: Vec<F>,
}

/// A ZeroCheck is derived from SumCheck.
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
    /// A ZeroCheck SubClaim consists of
    /// - the SubClaim from the SumCheck
    /// - the initial challenge r which is used to build eq(x, r)
    type ZeroCheckSubClaim = ZeroCheckSubClaim<F, Self>;
    /// A ZeroCheckProof is a SumCheckProof
    type ZeroCheckProof = Self::SumCheckProof;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a ZeroCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// ZeroCheck prover/verifier.
    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<F>::new(b"Initializing ZeroCheck transcript")
    }

    /// Initialize the prover to argue for the sum of polynomial f(x) over
    /// {0,1}^`num_vars` is zero.
    ///
    /// f(x) is zero if \hat f(x) := f(x) * eq(x,r) is also a zero polynomial
    /// for a random r sampled from transcript.
    ///
    /// This function will build the \hat f(x) and then invoke the sumcheck
    /// protocol to generate a proof for which the sum of \hat f(x) is zero
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

    /// Verify that the polynomial's sum is zero using the proof.
    /// Return a Self::Subclaim that consists of the
    ///
    /// - a Subclaim that the sum is zero
    /// - the initial challenge `r` that is used to build `eq(x, r)`
    ///
    /// This function will check that \hat f(x)'s sum is zero. It does not check
    /// `\hat f(x)` is build correctly. The caller needs to makes sure that
    /// `\hat f(x) = f(x) * eq(x, r)`
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
        let subclaim =
            <Self as SumCheck<F>>::verify(F::zero(), proof, &hat_fx_aux_info, transcript)?;

        // expected_eval = sumcheck.expect_eval/eq(x, r)
        // where x = sum_check_sub_claim.point
        let eq_x_r = build_eq_x_r(&r)?;
        let expected_evaluation = subclaim.expected_evaluation
            / eq_x_r.evaluate(&subclaim.point).ok_or_else(|| {
                PolyIOPErrors::InvalidParameters("evaluation dimension does not match".to_string())
            })?;

        end_timer!(start);
        Ok(ZeroCheckSubClaim {
            sum_check_sub_claim: subclaim,
            expected_evaluation,
            init_challenge: r,
        })
    }
}

#[cfg(test)]
mod test {

    use super::ZeroCheck;
    use crate::{errors::PolyIOPErrors, PolyIOP};
    use arithmetic::VirtualPolynomial;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;

    fn test_zerocheck(
        nv: usize,
        num_multiplicands_range: (usize, usize),
        num_products: usize,
    ) -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();

        {
            // good path: zero virtual poly
            let poly =
                VirtualPolynomial::rand_zero(nv, num_multiplicands_range, num_products, &mut rng)?;

            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let proof = <PolyIOP<Fr> as ZeroCheck<Fr>>::prove(&poly, &mut transcript)?;

            let poly_info = poly.aux_info.clone();
            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let subclaim =
                <PolyIOP<Fr> as ZeroCheck<Fr>>::verify(&proof, &poly_info, &mut transcript)?
                    .sum_check_sub_claim;
            assert!(
                poly.evaluate(&subclaim.point)? == subclaim.expected_evaluation,
                "wrong subclaim"
            );
        }

        {
            // bad path: random virtual poly whose sum is not zero
            let (poly, _sum) =
                VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;

            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let proof = <PolyIOP<Fr> as ZeroCheck<Fr>>::prove(&poly, &mut transcript)?;

            let poly_info = poly.aux_info.clone();
            let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
            transcript.append_message(b"testing", b"initializing transcript for testing")?;

            assert!(
                <PolyIOP<Fr> as ZeroCheck<Fr>>::verify(&proof, &poly_info, &mut transcript)
                    .is_err()
            );
        }

        Ok(())
    }

    #[test]
    fn test_trivial_polynomial() -> Result<(), PolyIOPErrors> {
        let nv = 1;
        let num_multiplicands_range = (4, 5);
        let num_products = 1;

        test_zerocheck(nv, num_multiplicands_range, num_products)
    }
    #[test]
    fn test_normal_polynomial() -> Result<(), PolyIOPErrors> {
        let nv = 5;
        let num_multiplicands_range = (4, 9);
        let num_products = 5;

        test_zerocheck(nv, num_multiplicands_range, num_products)
    }

    #[test]
    fn zero_polynomial_should_error() -> Result<(), PolyIOPErrors> {
        let nv = 0;
        let num_multiplicands_range = (4, 13);
        let num_products = 5;

        assert!(test_zerocheck(nv, num_multiplicands_range, num_products).is_err());
        Ok(())
    }
}