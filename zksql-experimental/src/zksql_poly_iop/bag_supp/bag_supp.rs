// use arithmetic::VPAuxInfo;
// use ark_ec::pairing::Pairing;
// use ark_ff::{batch_inversion,PrimeField};
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer, Zero};
// use std::{fmt::Debug, marker::PhantomData, sync::Arc};
// use subroutines::{
//     pcs::PolynomialCommitmentScheme,
//     poly_iop::{
//         errors::PolyIOPErrors,
//         prelude::{ProductCheckIOP, ProductCheckIOPProof, ProductCheckIOPSubClaim},
//     },
// };
// use transcript::IOPTranscript;

// use crate::zksql_poly_iop::bag_multitool::bag_subset::{BagSubsetIOP, BagSubsetIOPProof, BagSubsetIOPSubClaim};
// use crate::zksql_poly_iop::bag_sort::bag_sort::{BagStrictSortIOP, BagStrictSortIOPProof, BagStrictSortIOPSubClaim};

// pub struct BagSuppIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// #[derive(Clone, Debug, PartialEq)]
// pub struct BagSuppIOPProof<
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
// > {
//     pub supp_subset_proof: BagSubsetIOPProof<E, PCS>,               // check supp is subset of orig
//     pub supp_superset_proof: ProductCheckIOPProof<E, PCS>,          // check multiplicities aren't zero
//     pub supp_sorted_proof: BagStrictSortIOPProof<E, PCS>,            // check supp is sorted
// }

// /// A BagSuppIOPCheck check subclaim consists of
// /// a bag subset subclaim
// /// a product subclaim
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagSuppIOPSubClaim<F: PrimeField> {
//     pub supp_subset_subclaim: BagSubsetIOPSubClaim<F>,  
//     pub supp_superset_subclaim: ProductCheckIOPSubClaim<F>,
//     pub supp_sorted_subclaim: BagStrictSortIOPSubClaim<F>,
// }

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
//         range_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_range: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<BagSuppIOPProof<E, PCS>, PolyIOPErrors> {
//         let start = start_timer!(|| "bagStrictSort prove");
    
//         // (BagSubsetIOP) Show supp is a subset of bag 
//         let (supp_subset_proof,) = BagSubsetIOP::<E, PCS>::prove(
//             pcs_param,
//             &supp,
//             &bag,
//             &m_bag,
//             E::ScalarField::zero(), // assuming no null offset
//             &mut transcript.clone(),
//         )?;
    
//         // (ProductCheckIOP) Show supp includes all elements of bag by showing m_bag has no zeros
//         let mut m_bag_evals = m_bag.evaluations.clone();
//         batch_inversion(&mut m_bag_evals);
//         let m_bag_inverse = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//             m_bag.num_vars,
//             m_bag_evals,
//         ));
//         let m_bag_one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(m_bag.num_vars, vec![E::ScalarField::one(); 2_usize.pow(m_bag.num_vars as u32)]));
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
    

//     pub fn verification_info (
//         pcs_param: &PCS::ProverParam,
//         bag: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         supp: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_bag: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         range_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_range: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<Vec<VPAuxInfo<E::ScalarField>>, PolyIOPErrors> {
//         let mut aux_info_vec: Vec<VPAuxInfo<E::ScalarField>> = Vec::new();
//         let subset_aux = BagSubsetIOP::<E, PCS>::verification_info(
//             pcs_param,
//             &supp,
//             &bag,
//             &m_bag,
//             E::ScalarField::zero(), // assuming no null offset
//             &mut transcript.clone(),
//         );
//         aux_info_vec.push(subset_aux.0);
//         aux_info_vec.push(subset_aux.1);
//         let superset_aux = ProductCheckIOP::<E, PCS>::verification_info(
//             pcs_param,
//             &[m_bag.clone(), m_bag.clone()],
//             &[m_bag.clone()],
//             &mut transcript.clone(),
//         );
//         aux_info_vec.push(superset_aux);
//         let sorted_aux_tup = BagStrictSortIOP::<E, PCS>::verification_info(
//             pcs_param,
//             supp.clone(),
//             range_poly.clone(),
//             m_range.clone(),
//             &mut transcript.clone(),
//         );
//         aux_info_vec.push(sorted_aux_tup.0);
//         aux_info_vec.push(sorted_aux_tup.1);
//         aux_info_vec.push(sorted_aux_tup.2);
//         Ok(aux_info_vec)

//     }

//     pub fn verify(
//         pcs_param: &PCS::ProverParam,
//         proof: &BagSuppIOPProof<E, PCS>,
//         aux_info_vec: Vec<VPAuxInfo<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<BagSuppIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
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