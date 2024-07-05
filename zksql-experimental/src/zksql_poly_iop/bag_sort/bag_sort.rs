// // Prove a bag is strictly sorted 
// // by showing it's elements are a subset of [0, 2^n] 
// // and the product of its elements is non-zero

// use arithmetic::VPAuxInfo;
// use ark_ec::pairing::Pairing;
// use ark_ff::{batch_inversion, PrimeField};
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer, Zero};
// use std::{fmt::Debug, marker::PhantomData, sync::Arc};

// use subroutines::{
//     pcs::PolynomialCommitmentScheme
// };
// use crate::{
//     utils::{
//         prover_tracker::{ProverTrackerRef, TrackedPoly}, 
//         tracker_structs::TrackerID, 
//         verifier_tracker::{TrackedComm, VerifierTrackerRef},
//         errors::PolyIOPErrors,
//     },
//     zksql_poly_iop::bag_multitool::{
//         bag_multitool::{Bag, BagComm, BagMultiToolIOP},
//         bag_presc_perm::{BagPrescPermIOP}, 
//         bag_subset::{BagSubsetIOP},
//     },
// };

// pub struct BagStrictSortIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagStrictSortIOP<E, PCS> 
// where PCS: PolynomialCommitmentScheme<E> {
//     pub fn prove(
//         prover_tracker: &mut ProverTrackerRef<E, PCS>,
//         sorted_bag: &Bag<E, PCS>,
//         range_poly: &TrackedPoly<E, PCS>,
//         m_range: &TrackedPoly<E, PCS>,
//     ) -> Result<(), PolyIOPErrors> {
//         let start = start_timer!(|| "bagStrictSort prove");
//         let sorted_poly_evals = sorted_bag.poly.evaluations();
//         let sorted_nv = sorted_bag.num_vars();
//         let sorted_len = sorted_poly_evals.len();
//         let range_nv = range_poly.num_vars;
//         let range_len = 2_usize.pow(range_nv as u32);

//         // create shifted permutation poly and helpers
//         // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
//         // 	    (p,q) are p is orig, q is p offset by 1 with wraparound
//         let mut perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_nv);
//         perm_evals.push(E::ScalarField::from((sorted_len - 1) as u64));
//         perm_evals.extend((0..(sorted_len - 1)).map(|x| E::ScalarField::from(x as u64)));

//         let mut q_evals = Vec::<E::ScalarField>::with_capacity(sorted_nv);
//         q_evals.push(*sorted_poly_evals.last().unwrap());
//         q_evals.extend_from_slice(&sorted_poly_evals[..sorted_len]);
//         q_evals.pop();

//         let perm_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, perm_evals);
//         let q_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals);
//         let one_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len]);
        
        
//         // Prove that q is a prescribed permutation of p
//         let perm_poly = prover_tracker.track_mat_poly(perm_mle)?;
//         let q_poly = prover_tracker.track_mat_poly(q_mle)?;
//         let one_poly = prover_tracker.track_mat_poly(one_mle)?;
//         let q_bag = Bag::new(q_poly, one_poly);
//         BagPrescPermIOP::<E, PCS>::prove(
//             prover_tracker,
//             &sorted_bag.clone(),
//             &q_bag.clone(),
//             &perm_poly.clone(),
//         )?;

//         // #[cfg(debug_assertions)] {
//         //     let aux_info = BagPrescPermIOP::<E, PCS>::verification_info(
//         //         pcs_param,
//         //         &sorted_bag.clone(),
//         //         &q.clone(),
//         //         &perm.clone(),
//         //         &mut transcript.clone(),
//         //     );

//         //     let verify_result = BagPrescPermIOP::<E, PCS>::verify(
//         //         pcs_param,
//         //         &presc_perm_proof,
//         //         &aux_info,
//         //         &mut transcript.clone(),
//         //     );
//         //     match verify_result {
//         //         Ok(_) => (),
//         //         Err(e) => println!("BagStrictSortIOP::prove failed: {}", e),
//         //     }
//         // }

//         // TODO: Next step is selector stuff. see below or textEdit
//         // Multiply with selector with is 1 everywhere except at zero 
//         // sorted_bag = [a_0, a_1, ..]
//         // Selector = [0, 1, 1, ..]
//         // do range check over  [selector * (q - p) + (1 - selector)] // this is cheaper than opening an extra commitment, is (1 - selector)
//         let mut selector_evals = vec![E::ScalarField::one(); sorted_len];
//         selector_evals[0] = E::ScalarField::zero();
//         let diff_evals = (0..sorted_len).map(
//             |i| selector_evals[i] * (sorted_poly_evals[i] - q_evals[i]) + one_mle[i] - selector_evals[i]
//         ).collect::<Vec<_>>();
//         let selector_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, selector_evals);
//         let diff_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_evals);

//         let selector = prover_tracker.track_mat_poly(selector_mle)?;
//         let diff_poly = prover_tracker.track_mat_poly(diff_mle)?;
//         let diff_sel_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len]); 
//         let diff_sel = prover_tracker.track_mat_poly(diff_sel_mle)?;
//         let diff_bag = Bag::new(diff_poly.clone(), diff_sel);

//         // DIFF_SEL IS WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//         println!("\n\nRemember Diff Sel is wrong, needs to account for multiple zeros !!!!!!!!");
//         println!("diff_evals: {:?}", diff_evals);
//         println!("\n\n");

//         let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![E::ScalarField::one(); range_len]);
//         let range_sel = prover_tracker.track_mat_poly(range_sel_mle)?;
//         let range_bag = Bag::new(range_poly.clone(), range_sel);
//         BagSubsetIOP::<E, PCS>::prove(
//             prover_tracker,
//             &diff_bag.clone(),
//             &range_bag.clone(),
//             &m_range.clone(),
//         )?;

//         // show diff_evals are all non-zero
//         // (ProductCheckIOP) Show supp includes all elements of bag by showing m_bag has no zeros
//         let mut diff_eval_inverses = diff_evals.clone();
//         batch_inversion(&mut diff_eval_inverses);
//         println!("diff_evals: {:?}", diff_evals);
//         println!("diff_eval_inverses: {:?}", diff_eval_inverses);
//         let diff_inverse_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
//             diff_bag.num_vars(),
//             diff_eval_inverses,
//         ));
//         // WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//         // TODO: get this to error successfully since I shouldn't be using 2poly
//         println!("\n\nRemember 2 poly is hardcoded here, so it should be failing");
//         println!("diff_evals: {:?}", diff_evals);
//         println!("\n\n");
//         let two_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(diff_bag.num_vars, vec![E::ScalarField::from(3 as u64); diff_bag.poly.evaluations.len()]));
//         let (no_dups_product_proof, _, _) = ProductCheckIOP::<E, PCS>::prove(
//             pcs_param,
//             &[diff_poly, diff_inverse_poly],
//             &[two_poly.clone(), one_poly.clone()], // for some reason fxs and gxs need to be the same length
//             &mut transcript.clone(),
//         )?;

//         // #[cfg(debug_assertions)] {
//         //     let (f_aux_info, g_aux_info) = BagSubsetIOP::<E, PCS>::verification_info(
//         //         pcs_param,
//         //     &diff_poly.clone(),
//         //     &range_poly.clone(),
//         //     &m_range.clone(),
//         //         null_offset,
//         //         &mut transcript.clone(),
//         //     );
//         //     let verify_result = BagSubsetIOP::<E, PCS>::verify(
//         //         pcs_param,
//         //         &range_proof,
//         //         &f_aux_info,
//         //         &g_aux_info,
//         //         &mut transcript.clone(),
//         //     );
//         //     match verify_result {
//         //         Ok(_) => (),
//         //         Err(e) => println!("BagStrictSortIOP::prove failed: {}", e),
//         //     }
//         // }

//         end_timer!(start);
//         Ok(())
//     }

//     pub fn verify(
//         pcs_param: &PCS::ProverParam,
//         proof: &BagStrictSortIOPProof<E, PCS>,
//         aux_info_vec: &Vec<Vec<VPAuxInfo<E::ScalarField>>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<BagStrictSortIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
//         let start = start_timer!(|| "BagStrictSortIOP verify");

//         let presc_perm_subclaim = BagPrescPermIOP::<E, PCS>::verify(
//             pcs_param,
//             &proof.presc_perm_proof,
//             &aux_info_vec[0],
//             &aux_info_vec[1],   
//             &aux_info_vec[2],
//             &aux_info_vec[3],
//             &mut transcript.clone(),
//         )?;

//         let range_subclaim = BagSubsetIOP::<E, PCS>::verify(
//             pcs_param,
//             &proof.range_proof,
//             &aux_info_vec[4],
//             &aux_info_vec[5],
//             &aux_info_vec[6],
//             &aux_info_vec[7],
//             &mut  transcript.clone(),
//         )?;

//         println!("starting no_dups_product verification");
//         let no_dups_product_subclaim = ProductCheckIOP::<E, PCS>::verify(
//             &proof.no_dups_product_proof,
//             &aux_info_vec[8][0],
//             &mut transcript.clone(),
//         )?;
//         println!("no_dups_product verification successful");

//         end_timer!(start);
//         Ok(BagStrictSortIOPSubClaim::<E::ScalarField>{
//             presc_perm_subclaim: presc_perm_subclaim,
//             range_subclaim: range_subclaim,
//             no_dups_product_subclaim: no_dups_product_subclaim,
//         })
//     }
// }