// // Prove a bag is strictly sorted 
// // by showing it's elements are a subset of [0, 2^n] 
// // and the product of its elements is non-zero

// use arithmetic::VPAuxInfo;
// use ark_ec::pairing::Pairing;
// use ark_ff::PrimeField;
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer};
// use std::{sync::Arc, usize};
// use subroutines::{
//     pcs::PolynomialCommitmentScheme,
//     poly_iop::{errors::PolyIOPErrors, prelude::SumCheck, PolyIOP}, PCSError,
//     ZeroCheck,
// };
// use transcript::IOPTranscript;

// use crate::zksql_poly_iop::bag_multitool::bag_subset::{BagSubsetCheckSubClaim, BagSubsetCheckProof};
// use subroutines::poly_iop::prelude::ProductCheck;

// /// A BagStrictSortCheck check subclaim consists of
// /// a bag subset subclaim
// /// a product subclaim
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagStrictSortCheckSubClaim<F: PrimeField> {
//     // the SubClaim from the ZeroCheck
//     pub bag_subset_subclaim: BagSubsetCheckSubClaim<F, ZeroCheck<F>, SumCheck<F>>,
//     pub product_subclaim: <Self as ProductCheck::<F, ZeroCheck<F>>>::ProductCheckSubClaim,
// }

// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagStrictSortCheckProof<
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
//     SC: SumCheck<E::ScalarField>,
//     ZC: ZeroCheck<E::ScalarField>,
// > {
//     pub lhs_sumcheck_proof: SC::SumCheckProof,
//     pub rhs_sumcheck_proof: SC::SumCheckProof,
//     pub v: E::ScalarField,
//     pub fhat_zero_check_proof: ZC::ZeroCheckProof,
//     pub ghat_zero_check_proof: ZC::ZeroCheckProof,
//     pub fhat_comm: PCS::Commitment,
//     pub ghat_comm: PCS::Commitment,
// }