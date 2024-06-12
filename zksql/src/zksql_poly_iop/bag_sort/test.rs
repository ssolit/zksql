// #[cfg(test)]
// mod test {
//     use ark_ec::pairing::Pairing;
//     use ark_poly::DenseMultilinearExtension;
    
    
//     use std::sync::Arc;
//     use std::collections::HashSet;
//     use subroutines::{
//         pcs::PolynomialCommitmentScheme,
//         poly_iop::errors::PolyIOPErrors,
//         MultilinearKzgPCS
//     };
//     use transcript::IOPTranscript;

//     use ark_bls12_381::{Bls12_381, Fr};
//     use ark_std::test_rng;
//     use ark_std::rand::Rng;

//     use crate::zksql_poly_iop::bag_sort::bag_sort::BagStrictSortIOP;


//     fn test_bag_strict_sort() -> Result<(), PolyIOPErrors> {
//         // testing params
//         let nv = 4;
//         let num_range_pow = 10;
//         let mut rng = test_rng();

//         // PCS params
//         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, num_range_pow)?;
//         let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(num_range_pow))?;

//         // create a strictly sorted poly
//         let mut set = HashSet::new();
//         while set.len() < 2_usize.pow(nv as u32) {
//             let num = rng.gen_range(1..1000);
//             set.insert(num);
//         }
//         let mut sorted_poly_nums: Vec<i32> = set.into_iter().collect();
//         sorted_poly_nums.sort();
//         let sorted_poly_evals = sorted_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect();
//         let sorted_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, sorted_poly_evals));

//         // create the range poly and its multiplicity vector
//         let range_poly_evals = (0..2_usize.pow(num_range_pow as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
//         let range_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(num_range_pow, range_poly_evals));
//         let mut m_range_nums = vec![0; 2_usize.pow(num_range_pow as u32)];
//         let diff_nums = (1..2_usize.pow(nv as u32)).map(
//             |i| sorted_poly_nums[i] - sorted_poly_nums[i - 1]
//         ).collect::<Vec<_>>();
//         for i in 0..diff_nums.len() {
//             m_range_nums[diff_nums[i] as usize] += 1;
//         }
//         m_range_nums[1] += 1; // add one because the first number in diff_evals is set to 1
//         let m_range_evals = m_range_nums.iter().map(|x| Fr::from(*x as u64)).collect();
//         let m_range = Arc::new(DenseMultilinearExtension::from_evaluations_vec(num_range_pow, m_range_evals));


//         // initialize transcript 
//         let mut transcript = BagStrictSortIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
//         transcript.append_message(b"testing", b"initializing transcript for testing")?;

//         // test good path
//         test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, sorted_poly.clone(), range_poly.clone(), m_range.clone(), &mut transcript)?;
//         println!("BagStrictSortIOP good path test passed");

//         // test bad path 1: sorted poly is not strictly sorted
//         let mut bad_sorted_poly_nums_1 = sorted_poly_nums.clone();
//         bad_sorted_poly_nums_1[0] = sorted_poly_nums[1];
//         bad_sorted_poly_nums_1[1] = sorted_poly_nums[0];
//         let bad_sorted_poly_1_evals = bad_sorted_poly_nums_1.iter().map(|x| Fr::from(*x as u64)).collect();
//         let bad_sorted_poly_1 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, bad_sorted_poly_1_evals));
//         let bad_result1 = test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, bad_sorted_poly_1, range_poly.clone(), m_range.clone(), &mut transcript);
//         assert!(bad_result1.is_err());
//         println!("BagStrictSortIOP bad path 1 test passed");

//         // test bad path 2: sorted poly has a duplicate
//         let mut bad_sorted_poly_nums_2 = sorted_poly_nums.clone();
//         bad_sorted_poly_nums_2[1] = sorted_poly_nums[0];
//         let bad_sorted_poly_2_evals = bad_sorted_poly_nums_2.iter().map(|x| Fr::from(*x as u64)).collect();
//         let bad_sorted_poly_2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, bad_sorted_poly_2_evals));
//         let bad_result2 = test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, bad_sorted_poly_2, range_poly.clone(), m_range.clone(), &mut transcript);
//         assert!(bad_result2.is_err());
//         println!("BagStrictSortIOP bad path 2 test passed");


//         Ok(())

//     }

//     fn test_bag_strict_sort_helper<E: Pairing, PCS>(
//         pcs_param: &PCS::ProverParam,
//         sorted_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         range_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_range: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<(), PolyIOPErrors>
//     where
//         E: Pairing,
//         PCS: PolynomialCommitmentScheme<
//             E,
//             Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
//         >,
//     {
//         let (proof,) = BagStrictSortIOP::<E, PCS>::prove(pcs_param, sorted_poly.clone(), range_poly.clone(), m_range.clone(), &mut transcript.clone())?;
//         let (presc_perm_aux_info, range_aux_info_1, range_aux_info_2) = BagStrictSortIOP::<E, PCS>::verification_info(pcs_param, sorted_poly, range_poly, m_range, &mut transcript.clone());
//         BagStrictSortIOP::<E, PCS>::verify(pcs_param, &proof, &presc_perm_aux_info, &range_aux_info_1, &range_aux_info_2, &mut transcript.clone())?;
//         Ok(())
//     }

//     #[test]
//     fn bag_strict_sort_test() {
//         let res = test_bag_strict_sort();
//         res.unwrap();
//     }
// }