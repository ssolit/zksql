#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    
    use std::collections::HashSet;
    use subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::{One, Zero, rand::Rng};

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::bag_sort::bag_sort::BagStrictSortIOP,
    };


    fn test_bag_strict_sort() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 4;
        let num_range_pow = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, num_range_pow)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create a strictly sorted poly
        let mut set = HashSet::new();
        while set.len() < 2_usize.pow(nv as u32) {
            let num = rng.gen_range(1..1000);
            set.insert(num);
        }
        let mut sorted_poly_nums: Vec<i32> = set.into_iter().collect();
        sorted_poly_nums.sort();
        let sorted_poly_evals = sorted_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let sorted_bag_poly = DenseMultilinearExtension::from_evaluations_vec(nv, sorted_poly_evals);
        let one_poly = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]);
        let sorted_bag_sel = one_poly.clone();

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(num_range_pow as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_poly = DenseMultilinearExtension::from_evaluations_vec(num_range_pow, range_poly_evals);
        let mut m_range_nums = vec![0; 2_usize.pow(num_range_pow as u32)];
        let diff_nums = (1..2_usize.pow(nv as u32)).map(
            |i| sorted_poly_nums[i] - sorted_poly_nums[i - 1]
        ).collect::<Vec<_>>();
        for i in 0..diff_nums.len() {
            m_range_nums[diff_nums[i] as usize] += 1;
        }
        let m_range_evals = m_range_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let m_range = DenseMultilinearExtension::from_evaluations_vec(num_range_pow, m_range_evals);

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // test good path 1
        test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &sorted_bag_poly, &sorted_bag_sel, &range_poly.clone(), &m_range.clone())?;
        println!("BagStrictSortIOP good path 1 test passed");

        // test good path 2: sel is non-trivial
        // The first two elements are both 0, but only the second element is included by the selector
        let mut sorted_poly_nums_2 = sorted_poly_nums.clone();
        sorted_poly_nums_2[0] = 0;
        sorted_poly_nums_2[1] = 0;
        sorted_poly_nums_2[2] = 0;
        let sorted_poly_evals_2 = sorted_poly_nums_2.iter().map(|x| Fr::from(*x as u64)).collect();
        let sorted_poly_2 = DenseMultilinearExtension::from_evaluations_vec(nv, sorted_poly_evals_2);
        let mut sel_2_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        sel_2_evals[0] = Fr::zero(); 
        sel_2_evals[1] = Fr::zero(); 
        let sel_2 = DenseMultilinearExtension::from_evaluations_vec(nv, sel_2_evals);
        let mut m_range_nums_2 = vec![0; 2_usize.pow(num_range_pow as u32)];
        let diff_nums_2 = (1..2_usize.pow(nv as u32)).map(
            |i| sorted_poly_nums_2[i] - sorted_poly_nums_2[i - 1]
        ).collect::<Vec<_>>();
        for i in 0..diff_nums_2.len() {
            m_range_nums_2[diff_nums_2[i] as usize] += 1;
        }
        let m_range_evals_2 = m_range_nums_2.iter().map(|x| Fr::from(*x as u64)).collect();
        let m_range_2 = DenseMultilinearExtension::from_evaluations_vec(num_range_pow, m_range_evals_2);
        test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &sorted_poly_2, &sel_2, &range_poly.clone(), &m_range_2.clone())?;
        println!("BagStrictSortIOP good path 2 test passed");

        // test bad path 1: sorted poly is not strictly sorted
        let mut bad_sorted_poly_nums_1 = sorted_poly_nums.clone();
        bad_sorted_poly_nums_1[0] = sorted_poly_nums[1];
        bad_sorted_poly_nums_1[1] = sorted_poly_nums[0];
        let bad_sorted_poly_1_evals = bad_sorted_poly_nums_1.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad_sorted_poly_1 = DenseMultilinearExtension::from_evaluations_vec(nv, bad_sorted_poly_1_evals);
        let bad_result1: Result<(), PolyIOPErrors> = test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &bad_sorted_poly_1, &sorted_bag_sel, &range_poly.clone(), &m_range.clone());
        assert!(bad_result1.is_err());
        println!("BagStrictSortIOP bad path 1 test passed");

        // test bad path 2: sorted poly has a duplicate
        let mut bad_sorted_poly_nums_2 = sorted_poly_nums.clone();
        bad_sorted_poly_nums_2[1] = sorted_poly_nums[0];
        let bad_sorted_poly_2_evals = bad_sorted_poly_nums_2.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad_sorted_poly_2 = DenseMultilinearExtension::from_evaluations_vec(nv, bad_sorted_poly_2_evals);
        let mut bad2_m_range_nums = vec![0; 2_usize.pow(num_range_pow as u32)];
        let bad2_diff_nums = (1..2_usize.pow(nv as u32)).map(
            |i| bad_sorted_poly_nums_2[i] - bad_sorted_poly_nums_2[i - 1]
        ).collect::<Vec<_>>();
        for i in 0..bad2_diff_nums.len() {
            bad2_m_range_nums[bad2_diff_nums[i] as usize] += 1;
        }
        let bad2_m_range_evals = bad2_m_range_nums.iter().map(|x| Fr::from(*x as u64)).collect();
        let bad2_m_range = DenseMultilinearExtension::from_evaluations_vec(num_range_pow, bad2_m_range_evals);
        let bad_result2 = test_bag_strict_sort_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker.deep_copy(), &mut verifier_tracker.deep_copy(), &bad_sorted_poly_2, &sorted_bag_sel, &range_poly.clone(), &bad2_m_range.clone());
        assert!(bad_result2.is_err());
        println!("BagStrictSortIOP bad path 2 test passed");

        Ok(())

    }

    fn test_bag_strict_sort_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        sorted_bag_poly: &DenseMultilinearExtension<E::ScalarField>,
        sorted_bag_sel: &DenseMultilinearExtension<E::ScalarField>,
        range_mle: &DenseMultilinearExtension<E::ScalarField>,
        m_range: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
       // Set up prover_tracker and prove
       let sorted_bag = Bag::new(prover_tracker.track_and_commit_poly(sorted_bag_poly.clone())?, prover_tracker.track_and_commit_poly(sorted_bag_sel.clone())?);
       let range_poly = prover_tracker.track_and_commit_poly(range_mle.clone())?;
       let m_range = prover_tracker.track_and_commit_poly(m_range.clone())?;


       BagStrictSortIOP::<E, PCS>::prove(
           prover_tracker,
           &sorted_bag,
           &range_poly,
           &m_range,
       )?;
       let proof = prover_tracker.compile_proof();
       
       // set up verifier tracker, create subclaims, and verify IOPProofs
       verifier_tracker.set_compiled_proof(proof);
       let sorted_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(sorted_bag.poly.id), verifier_tracker.transfer_prover_comm(sorted_bag.selector.id));
       let range_comm = verifier_tracker.transfer_prover_comm(range_poly.id);
       let m_range_comm = verifier_tracker.transfer_prover_comm(m_range.id);
       BagStrictSortIOP::<E, PCS>::verify(verifier_tracker, &sorted_bag_comm, &range_comm, &m_range_comm)?;
       verifier_tracker.verify_claims()?;

       // check that the ProverTracker and VerifierTracker are in the same state
       let p_tracker = prover_tracker.clone_underlying_tracker();
       let v_tracker = verifier_tracker.clone_underlying_tracker();
       assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
       assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
       assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
       Ok(())
    }

    #[test]
    fn bag_strict_sort_test() {
        let res = test_bag_strict_sort();
        res.unwrap();
    }
}