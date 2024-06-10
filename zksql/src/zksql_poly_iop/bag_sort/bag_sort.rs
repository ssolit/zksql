// // Prove a bag is strictly sorted 
// // by showing it's elements are a subset of [0, 2^n] 
// // and the product of its elements is non-zero

// use arithmetic::{VPAuxInfo, VirtualPolynomial};
// use ark_ec::pairing::Pairing;
// use ark_ff::{Field, PrimeField, batch_inversion};
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer, Zero};
// use std::{fmt::Debug, marker::PhantomData, ops::Neg, sync::Arc};
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

// pub struct BagStrictSortIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// #[derive(Clone, Debug, PartialEq)]
// pub struct BagStrictSortIOPProof<
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
// > {
//     // pub bag_eq_proof: BagEqIOPProof<E, PCS>,
//     pub bag_subset_proof: BagSubsetIOPProof<E, PCS>,
//     // pub product_proof: ProductCheckIOPProof<E, PCS>,
// }

// /// A BagStrictSortCheck check subclaim consists of
// /// a bag subset subclaim
// /// a product subclaim
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagStrictSortIOPSubClaim<F: PrimeField> {
//     // pub bag_eq_subclaim: BagEqIOPSubClaim<F>,
//     pub bag_subset_subclaim: BagSubsetIOPSubClaim<F>,
//     // pub product_subclaim: ProductCheckIOPSubClaim<F>,
// }

// impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagStrictSortIOP<E, PCS> 
// where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>
// {
//     pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
//         IOPTranscript::<E::ScalarField>::new(b"Initializing BagStrictSortIOP transcript")
//     }

//     pub fn prove(
//         pcs_param: &PCS::ProverParam,
//         sorted_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         range_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_range: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         num_nulls: usize,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<
//         (
//             BagStrictSortIOPProof<E, PCS>,
//         ),
//         PolyIOPErrors,
//     > {
//         let start = start_timer!(|| "bagStrictSort prove");
//         let mut transcript = Self::init_transcript();
//         let sorted_nv = sorted_poly.num_vars;

//         // create shifted permutation poly and helpers
//         // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
//         // 	    (p,q) are p is orig, q is p offset by 1 with wraparound
//         let s_evals: Vec<E::ScalarField> = (0..sorted_nv).map(|x| E::ScalarField::from(x as u64)).collect();

//         let t_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_nv);
//         t_evals.push(E::ScalarField::from((sorted_nv-1) as u64));
//         t_evals.extend((0..sorted_nv-1).map(|x| E::ScalarField::from(x as u64)));

//         let q_evals = Vec::<E::ScalarField>::with_capacity(sorted_nv);
//         q_evals.push(*sorted_poly.evaluations.last().unwrap());
//         q_evals.extend(sorted_poly.evaluations);
//         q_evals.pop();


//         let s = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, s_evals));
//         let t = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, t_evals));
//         let q = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals));
        
//         // get a verifier challenge gamma, and do a prescribed permutation check
//         // by checking s+gamma*p and t+gamma*q is some permutation of each other

//         transcript.append(b"s", &s);


        
//         //  get verifier challenge gamma,  do multiset equality check s+gamma*p and t+gamma*q


//         // Multiply with selector with is 1 everywhere except at zero 
//         // Sorted_poly = [a_0, a_1, ..]
//         // Selector = [0, 1, 1, ..]
//         // do range check over  [selector * (q - p) + (1 - selector)] // this is cheaper than opening an extra commitment, is (1 - selector)


//         // TODO: figure out how to deal with nulls

//         // show sorted_poly is sorted by showing sorted_poly(i+1) - sorted_poly(i) is non-negative
//         // create p_hat = p(i+1) - p(i)
//         let mut sorted_poly_hat_evals = vec![E::ScalarField::zero(); sorted_poly.evaluations.len()];
//         for (i, window) in sorted_poly.evaluations.windows(2).enumerate() {
//             sorted_poly_hat_evals[i + 1] = window[1] - window[0];
//         }
//         sorted_poly_hat_evals[0] = E::ScalarField::one(); // set first value to 1 since we need a non-zero are there are only num_elems - 1 differences to check. TODO double check this

//         let sorted_poly_hat = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//             sorted_poly.num_vars,
//             sorted_poly_hat_evals,
//         ));

//         #[cfg(debug_assertions)]
//         {
//             println!("bag_sort debug sort assertion starting");
//             for i in 0..sorted_poly_hat_evals.len() {
//                 assert!(sorted_poly_hat_evals[i] <= *range_poly.evaluations.last().unwrap());
//             }
//             println!("bag_sort debug sort assertion passed");
//         }

//         let (sort_subset_proof,) = BagSubsetIOP::<E, PCS>::prove(
//             pcs_param,
//             sorted_poly_hat.clone(),
//             range_poly.clone(),
//             m_range.clone(),
//             // null_offset,
//             &mut transcript,
//         )?;

//         // TODO: check that no elements of p_hat are zero
//         // can just check that m_range[0] = 0?
//         // let p_hat_eval_inverses = p_hat.evaluations.clone();
//         // batch_inversion(&mut p_hat_eval_inverses);
//         // let p_hat_inverse = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//         //     p_hat.num_vars,
//         //     p_hat_eval_inverses,
//         // ));
//         // let p_hat_inverse_comm = PCS::commit(pcs_param, &p_hat_inverse)?;

//         // show sorted_poly_hat is constructed correctly



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




// // first thing: how to prove multiplicity vector contrains no zeros?
// //         - take the inverse and prove it is the one poly