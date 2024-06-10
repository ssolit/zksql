// use arithmetic::{VPAuxInfo, VirtualPolynomial};
// use ark_ec::pairing::Pairing;
// use ark_ff::{batch_inversion, Field, PrimeField};
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer, Zero};
// use std::{fmt::Debug, marker::PhantomData, ops::Neg, simd::SupportedLaneCount, sync::Arc};
// use subroutines::{
//     pcs::PolynomialCommitmentScheme,
//     poly_iop::{
//         errors::PolyIOPErrors,
//         prelude::{SumCheckIOP, SumCheckIOPSubClaim, ZeroCheckIOP, ZeroCheckIOPProof, ZeroCheckIOPSubClaim, ProductCheckIOP, ProductCheckIOPProof, ProductCheckIOPSubClaim},
//     },
//     IOPProof,
// };
// use transcript::IOPTranscript;

// use crate::zksql_poly_iop::bag_multitool::{
//     bag_subset::{BagSubsetIOP, BagSubsetIOPProof, BagSubsetIOPSubClaim},
//     bag_eq::{BagEqIOP, BagEqIOPProof, BagEqIOPSubClaim},
// };

// pub struct BagSuppIOPIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// #[derive(Clone, Debug, PartialEq)]
// pub struct BagSuppIOPIOPProof<
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
// > {
//     pub supp_subset_proof: BagSubsetIOPProof<E, PCS>,               // check supp is subset of orig
//     pub bag_inclusion_proof: ProductCheckIOPProof<E, PCS>,          // check multiplicities aren't zero
//     // skip equality check b/c we construct supp as already sorted
//     pub sort_subset_proof: ProductCheckIOPProof<E, PCS>,            // check p_hat has no zeros
//     pub p_hat_construction_proof: ProductCheckIOPProof<E, PCS>,     // check p_hat is constructed correctly
    
    
// }

// // /// A BagSuppIOPCheck check subclaim consists of
// // /// a bag subset subclaim
// // /// a product subclaim
// // #[derive(Clone, Debug, Default, PartialEq)]
// // pub struct BagSuppIOPIOPSubClaim<F: PrimeField> {
// //     pub bag_eq_subclaim: BagEqIOPSubClaim<F>,
// //     pub bag_subset_subclaim: BagSubsetIOPSubClaim<F>,
// //     // pub product_subclaim: ProductCheckIOPSubClaim<F>,
// // }

// impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSuppIOP<E, PCS> 
// where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>
// {
//     pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
//         IOPTranscript::<E::ScalarField>::new(b"Initializing BagSuppIOP transcript")
//     }

//     pub fn prove(
//         pcs_param: &PCS::ProverParam,
//         bag: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         supp: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_bag: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         num_nulls: usize,
//         range_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_range: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<
//         (
//             BagSuppIOPProof<E, PCS>,
//         ),
//         PolyIOPErrors,
//     > {
//         let start = start_timer!(|| "bagStrictSort prove");
//         let mut transcript = Self::init_transcript();

//         // show supp is a subset of bag
//         // let supp_one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(supp.num_vars, vec![E::ScalarField::one(); 2_usize.pow(supp.num_vars as u32)]));
//         let null_offset = E::ScalarField::from(num_nulls as u64); // TODO: FIX THIS IS PROBABLY WRONG
//         let (bag_subset_proof,) = BagSubsetIOP::<E, PCS>::prove(
//             pcs_param,
//             &supp.clone(),
//             &bag.clone(),
//             &m_bag.clone(),
//             null_offset,
//             &mut transcript,
//         )?;

//         // show supp include all elements of bag by showing m_bag has no zeros
//         let m_bag_evals = m_bag.evaluations.clone();
//         batch_inversion(&mut m_bag_evals);
//         let m_bag_inverse = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//             m_bag.num_vars,
//             m_bag_evals,
//         ));
//         let m_bag_inverse_comm = PCS::commit(pcs_param, &m_bag_inverse)?;
//         let m_bag_one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(m_bag.num_vars, vec![E::ScalarField::one(); 2_usize.pow(m_bag.num_vars as u32)]));
//         let (ProductCheckIOPProof,_, _ ) = ProductCheckIOP::<E, PCS>::prove(
//             pcs_param,
//             &[m_bag.clone(), m_bag_inverse.clone()],
//             &[m_bag_one_poly.clone()],
//             &mut transcript,
//         )?;

//         // show supp is sorted by calling bag_sort

//             // // show supp is sorted by showing supp(i+1) - supp(i) is non-negative
//             // // create p_hat = p(i+1) - p(i)
//             // let mut supp_hat_evals = vec![E::ScalarField::zero(); supp.evaluations.len()];
//             // for (i, window) in supp.evaluations.windows(2).enumerate() {
//             //     supp_hat_evals[i + 1] = window[1] - window[0];
//             // }
//             // supp_hat_evals[0] = E::ScalarField::one(); // set first value to 1 since we need a non-zero are there are only num_elems - 1 differences to check. TODO double check this

//             // let supp_hat = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//             //     supp.num_vars,
//             //     supp_hat_evals,
//             // ));

//             // #[cfg(debug_assertions)]
//             // {
//             //     println!("bag_sort debug sort assertion starting");
//             //     for i in 0..supp_hat_evals.len() {
//             //         assert!(supp_hat_evals[i] <= *range_poly.evaluations.last().unwrap());
//             //     }
//             //     println!("bag_sort debug sort assertion passed");
//             // }

//             // let (sort_subset_proof,) = BagSubsetIOP::<E, PCS>::prove(
//             //     pcs_param,
//             //     supp_hat.clone(),
//             //     range_poly.clone(),
//             //     &mut transcript,
//             // )?;

//             // // TODO: check that no elements of p_hat are zero
//             // // can just check that m_range[0] = 0?
//             // // let p_hat_eval_inverses = p_hat.evaluations.clone();
//             // // batch_inversion(&mut p_hat_eval_inverses);
//             // // let p_hat_inverse = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//             // //     p_hat.num_vars,
//             // //     p_hat_eval_inverses,
//             // // ));
//             // // let p_hat_inverse_comm = PCS::commit(pcs_param, &p_hat_inverse)?;

//             // // show supp_hat is constructed correctly



//         Ok(BagStrictSortIOPProof::<E, PCS> {
//             bag_eq_proof: bag_eq_proof,
//             bag_subset_proof: bag_subset_proof,
//         });
        



//     }

//     // pub fn verification_info (
//     //     pcs_param: &PCS::ProverParam,
//     //     p: Arc<DenseMultilinearExtension<E::ScalarField>>,
//     //     sorted_p: Arc<DenseMultilinearExtension<E::ScalarField>>,
//     //     transcript: &mut IOPTranscript<E::ScalarField>,
//     // ) -> Result<
//     //     (
//     //         VPAuxInfo<E::ScalarField>
//     //     ),
//     //     PolyIOPErrors,
//     // > {
//     // }

//     // pub fn verify(
//     //     pcs_param: &PCS::ProverParam,
//     //     proof: &BagStrictSortIOPProof<E, PCS>,
//     //     aux_info: &VPAuxInfo<E::ScalarField>,
//     //     transcript: &mut IOPTranscript<E::ScalarField>,
//     // ) -> Result<BagStrictSortIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
//     //     let start = start_timer!(|| "bagStrictSort verify");

//     // }


// }