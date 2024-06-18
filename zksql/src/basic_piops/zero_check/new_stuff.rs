

// use crate::poly_iop::{errors::PolyIOPErrors, sum_check::new_stuff::{
//     SumCheckIOP, SumCheckIOPProof, Transcript
// }};
// use arithmetic::{VPAuxInfo, VirtualPolynomial};
// use arithmetic::eq_eval;
// use ark_ff::PrimeField;
// use ark_std::{end_timer, start_timer};
// use std::{fmt::Debug, marker::PhantomData};
// use transcript::IOPTranscript;

// pub struct ZeroCheckIOP<F: PrimeField>(PhantomData<F>);

// /// A zero check IOP subclaim for `f(x)` consists of the following:
// ///   - the initial challenge vector r which is used to build eq(x, r) in
// ///     SumCheck
// ///   - the random vector `v` to be evaluated
// ///   - the claimed evaluation of `f(v)`
// #[derive(Clone, Debug, Default, PartialEq, Eq)]
// pub struct ZeroCheckSubClaim<F: PrimeField> {
//     // the evaluation point
//     pub point: Vec<F>,
//     /// the expected evaluation
//     pub expected_evaluation: F,
//     // the initial challenge r which is used to build eq(x, r)
//     pub init_challenge: Vec<F>,
// }
// pub type ZeroCheckIOPProof<F> = SumCheckIOPProof<F>;
// pub type ZeroCheckIOPSubClaim<F> = ZeroCheckSubClaim<F>;


// impl<F: PrimeField> ZeroCheckIOP<F> {

//     pub fn init_transcript() -> IOPTranscript<F> {
//         IOPTranscript::<F>::new(b"Initializing ZeroCheck transcript")
//     }

//     pub fn prove(
//         poly: &VirtualPolynomial<F>,
//         transcript: &mut IOPTranscript<F>,
//     ) -> Result<ZeroCheckIOPProof<F>, PolyIOPErrors> {
//         let start = start_timer!(|| "zero check prove");

//         let length = poly.aux_info.num_variables;
//         let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;
//         let f_hat = poly.build_f_hat(r.as_ref())?;
//         // TODO: output a SumcheckSubclaim instead of invoking sumcheck.
//         let res = SumCheckIOP::prove(&f_hat, transcript);

//         end_timer!(start);
//         res
//     }

//     pub fn verify(
//         proof: &ZeroCheckIOPProof<F>,
//         fx_aux_info: &VPAuxInfo<F>,
//         transcript: &mut Transcript<F>,
//     ) -> Result<ZeroCheckIOPSubClaim<F>, PolyIOPErrors> {
//         let start = start_timer!(|| "zero check verify");

//         // check that the sum is zero
//         if proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1] != F::zero() {
//             return Err(PolyIOPErrors::InvalidProof(format!(
//                 "zero check: sum {} is not zero",
//                 proof.proofs[0].evaluations[0] + proof.proofs[0].evaluations[1]
//             )));
//         }

//         // generate `r` and pass it to the caller for correctness check
//         let length = fx_aux_info.num_variables;
//         let r = transcript.get_and_append_challenge_vectors(b"0check r", length)?;

//         // hat_fx's max degree is increased by eq(x, r).degree() which is 1
//         let mut hat_fx_aux_info = fx_aux_info.clone();
//         hat_fx_aux_info.max_degree += 1;
//         let sum_subclaim =
//             SumCheckIOP::<F>::verify(F::zero(), proof, &hat_fx_aux_info, transcript)?;

//         // expected_eval = sumcheck.expect_eval/eq(v, r)
//         // where v = sum_check_sub_claim.point
//         let eq_x_r_eval = eq_eval(&sum_subclaim.point, &r)?;
//         let expected_evaluation = sum_subclaim.expected_evaluation / eq_x_r_eval;

//         end_timer!(start);
//         Ok(ZeroCheckIOPSubClaim {
//             point: sum_subclaim.point, // entire random vector
//             expected_evaluation,
//             init_challenge: r,         // first eq input (vect of log(n) field elements)
//         })
//     }
// }

// #[cfg(test)]
// mod test {

//     use super::ZeroCheckIOP;
//     use crate::poly_iop::errors::PolyIOPErrors;
//     use arithmetic::VirtualPolynomial;
//     use ark_bls12_381::Fr;
//     use ark_std::test_rng;

//     fn test_zerocheck(
//         nv: usize,
//         num_multiplicands_range: (usize, usize),
//         num_products: usize,
//     ) -> Result<(), PolyIOPErrors> {
//         let mut rng = test_rng();

//         {
//             // good path: zero virtual poly
//             let poly =
//                 VirtualPolynomial::<Fr>::rand_zero(nv, num_multiplicands_range, num_products, &mut rng)?;

//             let mut transcript = ZeroCheckIOP::init_transcript();
//             transcript.append_message(b"testing", b"initializing transcript for testing")?;
//             let proof = ZeroCheckIOP::prove(&poly, &mut transcript)?;

//             let poly_info = poly.aux_info.clone();
//             let mut transcript = ZeroCheckIOP::init_transcript();
//             transcript.append_message(b"testing", b"initializing transcript for testing")?;
//             let zero_subclaim =
//                 ZeroCheckIOP::verify(&proof, &poly_info, &mut transcript)?;
//             assert!(
//                 poly.evaluate(&zero_subclaim.point)? == zero_subclaim.expected_evaluation,
//                 "wrong subclaim"
//             );
//         }

//         {
//             // bad path: random virtual poly whose sum is not zero
//             let (poly, _sum) =
//                 VirtualPolynomial::<Fr>::rand(nv, num_multiplicands_range, num_products, &mut rng)?;

//             let mut transcript = ZeroCheckIOP::init_transcript();
//             transcript.append_message(b"testing", b"initializing transcript for testing")?;
//             let proof = ZeroCheckIOP::prove(&poly, &mut transcript)?;

//             let poly_info = poly.aux_info.clone();
//             let mut transcript = ZeroCheckIOP::init_transcript();
//             transcript.append_message(b"testing", b"initializing transcript for testing")?;

//             assert!(
//                 ZeroCheckIOP::verify(&proof, &poly_info, &mut transcript)
//                     .is_err()
//             );
//         }

//         Ok(())
//     }

//     #[test]
//     fn test_trivial_polynomial() -> Result<(), PolyIOPErrors> {
//         let nv = 1;
//         let num_multiplicands_range = (4, 5);
//         let num_products = 1;

//         test_zerocheck(nv, num_multiplicands_range, num_products)
//     }
//     #[test]
//     fn test_normal_polynomial() -> Result<(), PolyIOPErrors> {
//         let nv = 5;
//         let num_multiplicands_range = (4, 9);
//         let num_products = 5;

//         test_zerocheck(nv, num_multiplicands_range, num_products)
//     }

//     #[test]
//     fn zero_polynomial_should_error() -> Result<(), PolyIOPErrors> {
//         let nv = 0;
//         let num_multiplicands_range = (4, 13);
//         let num_products = 5;

//         assert!(test_zerocheck(nv, num_multiplicands_range, num_products).is_err());
//         Ok(())
//     }
// }
