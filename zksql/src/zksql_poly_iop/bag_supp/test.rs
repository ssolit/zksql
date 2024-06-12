
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
//     use ark_std::{Zero, One, test_rng};
//     use ark_std::rand::Rng;

//     use crate::zksql_poly_iop::bag_supp::bag_supp::BagSuppIOP;
    

//     fn test_bag_supp() -> Result<(), PolyIOPErrors> {
//         // testing params
//         let orig_nv = 4;
//         let supp_nv = orig_nv - 1;
//         let num_range_pow = 10;
//         let mut rng = test_rng();

//         // PCS params
//         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, num_range_pow)?;
//         let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(num_range_pow))?;

//         // create a poly with duplicates and its supp
//         let mut set = HashSet::new();
//         while set.len() < 2_usize.pow(supp_nv as u32) {
//             let num = rng.gen_range(1..1000);
//             set.insert(num);
//         }
//         let mut supp_nums: Vec<i32> = set.into_iter().collect();
//         supp_nums.sort();
//         let supp_evals = supp_nums.iter().map(|x| Fr::from(*x as u64)).collect();
//         let supp = Arc::new(DenseMultilinearExtension::from_evaluations_vec(supp_nv, supp_evals));

//         let mut orig_poly_nums = supp_nums.clone();
//         orig_poly_nums.append(&mut supp_nums.clone());
//         let orig_poly_evals = orig_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect();
//         let orig_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(orig_nv, orig_poly_evals));

//         let mut m_bag_evals = vec![Fr::one(); 2_usize.pow(supp_nv as u32)];
//         m_bag_evals.append(&mut vec![Fr::zero(); 2_usize.pow(supp_nv as u32)]);
//         let m_bag = Arc::new(DenseMultilinearExtension::from_evaluations_vec(orig_nv, m_bag_evals));

//         // create the range poly and its multiplicity vector
//         let range_poly_evals = (0..2_usize.pow(num_range_pow as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
//         let range_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(num_range_pow, range_poly_evals));

//         let mut m_range_nums = vec![0; 2_usize.pow(num_range_pow as u32)];
//         let diff_nums = (1..2_usize.pow(supp_nv as u32)).map(
//             |i| supp_nums[i] - supp_nums[i - 1]
//         ).collect::<Vec<_>>();
//         for i in 0..diff_nums.len() {
//             m_range_nums[diff_nums[i] as usize] += 1;
//         }
//         m_range_nums[1] += 1; // add one because the first number in diff_evals is set to 1
//         let m_range_evals = m_range_nums.iter().map(|x| Fr::from(*x as u64)).collect();
//         let m_range = Arc::new(DenseMultilinearExtension::from_evaluations_vec(num_range_pow, m_range_evals));


//         // initialize transcript 
//         let mut transcript = BagSuppIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
//         transcript.append_message(b"testing", b"initializing transcript for testing")?;

//         // test good path
//         test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, orig_poly.clone(), supp.clone(), m_bag.clone(), range_poly.clone(), m_range.clone(), &mut transcript)?;
//         println!("BagSuppIOP good path test passed");

//         // test bad path 1: supp is not strictly sorted
//         let mut bad_supp_nums_1 = supp_nums.clone();
//         bad_supp_nums_1[0] = supp_nums[1];
//         bad_supp_nums_1[1] = supp_nums[0];
//         let bad_supp_1_evals = bad_supp_nums_1.iter().map(|x| Fr::from(*x as u64)).collect();
//         let bad_supp_1 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(supp_nv, bad_supp_1_evals));
//         let bad_result1 = test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, orig_poly.clone(), bad_supp_1.clone(), m_bag.clone(), range_poly.clone(), m_range.clone(), &mut transcript);
//         assert!(bad_result1.is_err());
//         println!("BagSuppIOP bad path 1 test passed");

//         // test bad path 2: supp has an element not in orig
//         let mut bad_supp_nums_2 = supp_nums.clone();
//         bad_supp_nums_2[0] = 1023;
//         let bad_supp_2_evals = bad_supp_nums_2.iter().map(|x| Fr::from(*x as u64)).collect();
//         let bad_supp_2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(supp_nv, bad_supp_2_evals));
//         let bad_result2 = test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, orig_poly.clone(), bad_supp_2.clone(), m_bag.clone(), range_poly.clone(), m_range.clone(), &mut transcript);
//         assert!(bad_result2.is_err());
//         println!("BagSuppIOP bad path 2 test passed");

//         // test bad path 3: supp is missing an element in orig
//         let mut bad_supp_nums_3 = supp_nums.clone();
//         bad_supp_nums_3[0] = bad_supp_nums_3[1];
//         let mut m_range_nums = m_range_nums.clone();
//         let diff_nums = (1..2_usize.pow(supp_nv as u32)).map(
//             |i| supp_nums[i] - supp_nums[i - 1]
//         ).collect::<Vec<_>>();
//         for i in 0..diff_nums.len() {
//             m_range_nums[diff_nums[i] as usize] += 1;
//         }
//         m_range_nums[1] += 1; // add one because the first number in diff_evals is set to 1
//         let m_range_evals = m_range_nums.iter().map(|x| Fr::from(*x as u64)).collect();
//         let m_range = Arc::new(DenseMultilinearExtension::from_evaluations_vec(num_range_pow, m_range_evals));
//         let bad_result3 = test_bag_supp_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, orig_poly.clone(), supp.clone(), m_bag.clone(), range_poly.clone(), m_range.clone(), &mut transcript);
//         assert!(bad_result3.is_err());
//         println!("BagSuppIOP bad path 3 test passed");

//         Ok(())

//     }

//     fn test_bag_supp_helper<E: Pairing, PCS>(
//         pcs_param: &PCS::ProverParam,
//         bag: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         supp: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         m_bag: Arc<DenseMultilinearExtension<E::ScalarField>>,
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
//         let proof = BagSuppIOP::<E, PCS>::prove(pcs_param, bag.clone(), supp.clone(), m_bag.clone(), range_poly.clone(), m_range.clone(), &mut transcript.clone())?;
//         let aux_info_vec = BagSuppIOP::<E, PCS>::verification_info(pcs_param, bag, supp, m_bag, range_poly, m_range, &mut transcript.clone())?;
//         BagSuppIOP::<E, PCS>::verify(pcs_param, &proof, aux_info_vec, &mut transcript.clone())?;
//         Ok(())
//     }

//     #[test]
//     fn bag_supp_test() {
//         let res = test_bag_supp();
//         res.unwrap();
//     }
// }