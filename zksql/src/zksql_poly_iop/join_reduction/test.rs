#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;

    use subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::join_reduction::{
            join_reduction::JoinReductionIOP,
            utils::calc_join_reduction_lr_sel_advice,
            utils::calc_join_reduction_mid_inclusion_advice,
        },
    };

    fn test_join_reduction() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let range_nums = (0..2_usize.pow(range_nv as u32)).collect::<Vec<usize>>();
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // Test good path 1: one-to-one join 
        print!("JoinReductionIOP good path 1 test: ");
        println!();
        let nv = 3;
        let poly_a_nums =   vec![0, 0, 0, 1, 2, 3, 4, 5];
        let a_sel_nums =    vec![0, 0, 1, 1, 1, 1, 1, 1];
        let poly_b_nums =   vec![4, 5, 6, 7, 8, 0, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 0, 0, 0];
        let poly_a_evals = poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let a_sel_evals = a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_b_evals = poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let b_sel_evals = b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(nv, poly_a_evals);
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, a_sel_evals);
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(nv, poly_b_evals);
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(nv, b_sel_evals);
        let (l_sel_mle, r_sel_mle) = calc_join_reduction_lr_sel_advice::<Bls12_381>(&poly_a_mle, &a_sel_mle, &poly_b_mle, &b_sel_mle);
        let (mid_a_inclusion_m_mle, mid_b_inclusion_m_mle) = calc_join_reduction_mid_inclusion_advice::<Bls12_381>(&poly_a_mle, &poly_b_mle, &l_sel_mle, &r_sel_mle);

        test_join_reduction_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &poly_a_mle, 
            &a_sel_mle,
            &poly_b_mle,
            &b_sel_mle, 
            &l_sel_mle, 
            &r_sel_mle, 
            &mid_a_inclusion_m_mle, 
            &mid_b_inclusion_m_mle,
            &range_mle.clone(),
        )?;
        println!("passed");

        Ok(())

    }

    fn test_join_reduction_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_a_sel: &DenseMultilinearExtension<E::ScalarField>,
        bag_b_poly: &DenseMultilinearExtension<E::ScalarField>,
        bag_b_sel: &DenseMultilinearExtension<E::ScalarField>,
        l_sel: &DenseMultilinearExtension<E::ScalarField>,
        r_sel: &DenseMultilinearExtension<E::ScalarField>,
        mid_a_inclusion_m: &DenseMultilinearExtension<E::ScalarField>,
        mid_b_inclusion_m: &DenseMultilinearExtension<E::ScalarField>,
        range_poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        let bag_a = Bag::new(prover_tracker.track_and_commit_poly(bag_a_poly.clone())?, prover_tracker.track_and_commit_poly(bag_a_sel.clone())?); 
        let bag_b = Bag::new(prover_tracker.track_and_commit_poly(bag_b_poly.clone())?, prover_tracker.track_and_commit_poly(bag_b_sel.clone())?); 
        let l_sel = prover_tracker.track_and_commit_poly(l_sel.clone())?;
        let r_sel = prover_tracker.track_and_commit_poly(r_sel.clone())?;
        let mid_a_inclusion_m = prover_tracker.track_and_commit_poly(mid_a_inclusion_m.clone())?;
        let mid_b_inclusion_m = prover_tracker.track_and_commit_poly(mid_b_inclusion_m.clone())?;
        let range_bag = Bag::new(prover_tracker.track_and_commit_poly(range_poly.clone())?, prover_tracker.track_and_commit_poly(range_poly.clone())?);

        JoinReductionIOP::<E, PCS>::prove(
            prover_tracker,
            &bag_a, 
            &bag_b, 
            &l_sel, 
            &r_sel, 
            &mid_a_inclusion_m, 
            &mid_b_inclusion_m,
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let bag_a_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_a.poly.id), verifier_tracker.transfer_prover_comm(bag_a.selector.id), bag_a.num_vars()); 
        let bag_b_comm = BagComm::new(verifier_tracker.transfer_prover_comm(bag_b.poly.id), verifier_tracker.transfer_prover_comm(bag_b.selector.id), bag_b.num_vars()); 
        let l_sel_comm = verifier_tracker.transfer_prover_comm(l_sel.id);
        let r_sel_comm = verifier_tracker.transfer_prover_comm(r_sel.id);
        let mid_a_inclusion_m_comm = verifier_tracker.transfer_prover_comm(mid_a_inclusion_m.id);
        let mid_b_inclusion_m_comm = verifier_tracker.transfer_prover_comm(mid_b_inclusion_m.id);
        let range_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(range_bag.poly.id), verifier_tracker.transfer_prover_comm(range_bag.selector.id), range_bag.num_vars());

        JoinReductionIOP::<E, PCS>::verify(
            verifier_tracker,
            &bag_a_comm,
            &bag_b_comm,
            &l_sel_comm,
            &r_sel_comm,
            &mid_a_inclusion_m_comm,
            &mid_b_inclusion_m_comm,
            &range_bag_comm,
        )?;
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
    fn join_reduction_test() {
        let res = test_join_reduction();
        res.unwrap();
    }
}