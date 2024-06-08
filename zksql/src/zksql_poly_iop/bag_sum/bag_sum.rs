// use arithmetic::VPAuxInfo;
// use ark_ec::pairing::Pairing;
// use ark_ff::PrimeField;
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer, Zero};
// use std::{fmt::Debug, marker::PhantomData, sync::Arc};
// use subroutines::{
//     pcs::PolynomialCommitmentScheme,
//     poly_iop::{
//         errors::PolyIOPErrors,
//         prelude::{IOPProof, ZeroCheckIOPSubClaim, SumCheckIOPSubClaim},
//     },
//     PCSError,
// };
// use transcript::IOPTranscript;

// use crate::zksql_poly_iop::bag_multitool::bag_multitool::{BagMultiToolIOP, BagMultiToolIOPProof};

// pub struct BagSumIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);


// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagSumIOPProof<
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
// > {
//     pub lhs_sumcheck_proof: IOPProof<E::ScalarField>,
//     pub rhs_sumcheck_proof: IOPProof<E::ScalarField>,
//     pub v: E::ScalarField,
//     pub fhat_zero_check_proof: IOPProof<E::ScalarField>,
//     pub ghat_zero_check_proof: IOPProof<E::ScalarField>,
//     pub fhat_comm: PCS::Commitment,
//     pub ghat_comm: PCS::Commitment,
// }

// /// A BagSumCheck check subclaim consists of
// /// two sumcheck subclaims, and the value v they should both equal
// /// the random challenge gamma
// /// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagSumIOPSubClaim<F: PrimeField> {
//     pub lhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
//     pub rhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
//     pub v: F,
//     pub gamma: F,
//     pub fhat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
//     pub ghat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
// }



// // takes in two fx vectors
// // makes a consolidated fx