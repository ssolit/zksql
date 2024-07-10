// use ark_ec::pairing::Pairing;
// use ark_ff::batch_inversion;
// use ark_poly::DenseMultilinearExtension;
// use ark_poly::MultilinearExtension;
// use ark_std::{end_timer, One, start_timer, Zero};
// use std::marker::PhantomData;

// use subroutines::pcs::PolynomialCommitmentScheme;
// use crate::{
//     tracker::prelude::*,
//     zksql_poly_iop::{
//         bag_sort::bag_sort::BagStrictSortIOP,
//         bag_multitool::bag_subset::BagSubsetIOP,
//     },
// };

// pub struct BagSuppIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSuppIOP<E, PCS> 
// where PCS: PolynomialCommitmentScheme<E> {
//     pub fn prove(
//         prover_tracker: &mut ProverTrackerRef<E, PCS>,
//         bag: &Bag<E, PCS>,
//         supp: &Bag<E, PCS>,
//         m_bag: &TrackedPoly<E, PCS>,
//         range_poly: &TrackedPoly<E, PCS>,
//         m_range:&TrackedPoly<E, PCS>,
//     ) -> Result<(), PolyIOPErrors> {
//         let start = start_timer!(|| "bagStrictSort prove");
    
//         // (BagSubsetIOP) Show supp is a subset of bag 
//         BagSubsetIOP::<E, PCS>::prove(
//             prover_tracker,
//             &supp,
//             &bag,
//             &m_bag,
//         )?;
    
//         // Show supp includes all elements of bag by showing m_bag has no zeros
//         let mut m_bag_evals = m_bag.evaluations().clone();
//         batch_inversion(&mut m_bag_evals);
//         let m_bag_inverse_mle = DenseMultilinearExtension::from_evaluations_vec(m_bag.num_vars,m_bag_evals);
//         let m_bag_inverse_poly = prover_tracker.track_and_commit_poly(m_bag_inverse_mle)?;

        
//         let (bag_inclusion_proof, _, _) = ProductCheckIOP::<E, PCS>::prove(
//             pcs_param,
//             &[m_bag.clone(), m_bag_inverse.clone()],
//             &[m_bag_one_poly.clone(), m_bag_one_poly.clone()], // for some reason fxs and gxs need to be the same length
//             &mut transcript.clone(),
//         )?;
    
//         // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
//         let (bag_sort_proof,) = BagStrictSortIOP::<E, PCS>::prove(
//             pcs_param,
//             supp.clone(),
//             range_poly.clone(),
//             m_range.clone(),
//             &mut transcript.clone(),
//         )?;
    
//         let proof = BagSuppIOPProof::<E, PCS> {
//             supp_subset_proof,
//             supp_superset_proof: bag_inclusion_proof,
//             supp_sorted_proof: bag_sort_proof,
//         };
    
//         end_timer!(start);
//         Ok(proof)
//     }

//     pub fn verify(
//         verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
//         bag: &BagComm<E, PCS>,
//         supp: &BagComm<E, PCS>,
//         m_bag: &TrackedComm<E, PCS>,
//         range_poly: &TrackedComm<E, PCS>,
//         m_range: &TrackedComm<E, PCS>,
//     ) -> Result<(), PolyIOPErrors> {
//         let start = start_timer!(|| "bagStrictSort verify");

//         if aux_info_vec.len() != 6 {
//             return Err(PolyIOPErrors::InvalidVerifier(
//                 format!(
//                     "BagSuppIOP::verify Error: aux_info_vec length is not 6, was {}",
//                     aux_info_vec.len()
//                 ),
//             ));
//         }

//         let supp_subset_subclaim = BagSubsetIOP::<E, PCS>::verify(
//             pcs_param,
//             &proof.supp_subset_proof,
//             &aux_info_vec[0],
//             &aux_info_vec[1],
//             &mut transcript.clone(),
//         )?;

//         let supp_superset_subclaim = ProductCheckIOP::<E, PCS>::verify(
//             &proof.supp_superset_proof,
//             &aux_info_vec[2],
//             &mut transcript.clone(),
//         )?;

//         let supp_sorted_subclaim = BagStrictSortIOP::<E, PCS>::verify(
//             pcs_param,
//             &proof.supp_sorted_proof,
//             &aux_info_vec[3],
//             &aux_info_vec[4],
//             &aux_info_vec[5],
//             &mut transcript.clone(),
//         )?;

//         end_timer!(start);
//         Ok(BagSuppIOPSubClaim::<E::ScalarField>{
//             supp_subset_subclaim,
//             supp_superset_subclaim,
//             supp_sorted_subclaim,
//         })

//     }


// }