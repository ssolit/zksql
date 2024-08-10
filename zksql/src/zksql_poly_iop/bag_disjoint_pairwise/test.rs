#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;

    use subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::One;
    use ark_std::test_rng;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::bag_disjoint::{
            bag_disjoint::BagDisjointIOP,
            utils::calc_bag_disjoint_advice,
        },
    };
    use crate::zksql_poly_iop::bag_disjoint_pairwise::bag_disjoint_pairwise::BagDisjointPairwiseIOP;

    fn test_bag_disjoint_pairwise() -> Result<(), PolyIOPErrors> {
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

        // Test good path 1: three bags are disjoint, different sizes
        print!("BagDisjointPairwiseIOP good path 1 test: ");
        let poly_a_nv = 4;
        let poly_b_nv = 3;
        let poly_c_nv = 2;
        let poly_a_nums = (0..16).collect::<Vec<usize>>();
        let poly_b_nums = (16..24).collect::<Vec<usize>>();
        let poly_c_nums = (24..28).collect::<Vec<usize>>();
        let poly_a_sel_evals = vec![Fr::one(); 2_usize.pow(poly_a_nv as u32)];
        let poly_b_sel_evals = vec![Fr::one(); 2_usize.pow(poly_b_nv as u32)];
        let poly_c_sel_evals = vec![Fr::one(); 2_usize.pow(poly_c_nv as u32)];

        let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_c_mle = DenseMultilinearExtension::from_evaluations_vec(poly_c_nv, poly_c_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let poly_a_sel = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv, poly_a_sel_evals);
        let poly_b_sel = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv, poly_b_sel_evals);
        let poly_c_sel = DenseMultilinearExtension::from_evaluations_vec(poly_c_nv, poly_c_sel_evals);

        let bag_mles = vec![(poly_a_mle, poly_a_sel), (poly_b_mle, poly_b_sel), (poly_c_mle, poly_c_sel)];
        test_bag_disjoint_pairwise_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(
            &mut prover_tracker, 
            &mut verifier_tracker, 
            &bag_mles, 
            &range_mle.clone(),
        )?;
        println!("passed");

        Ok(())
    }

    fn test_bag_disjoint_pairwise_helper<E: Pairing, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_mles: &[(DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>)],
        range_mle: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors> 
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>, 
    {
        let mut bags = Vec::<Bag<E, PCS>>::new();
        for (poly, sel) in bag_mles.iter() {
            let poly = prover_tracker.track_and_commit_poly(poly.clone())?;
            let sel = prover_tracker.track_and_commit_poly(sel.clone())?;
            let bag = Bag::new(poly, sel);
            bags.push(bag);
        }
        let range_bag = Bag::new(prover_tracker.track_and_commit_poly(range_mle.clone())?, prover_tracker.track_and_commit_poly(range_mle.clone())?);

        BagDisjointPairwiseIOP::<E, PCS>::prove(
            prover_tracker,
            &bags,
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        // set up verifier tracker, create subclaims, and verify IOPProofs
        verifier_tracker.set_compiled_proof(proof);
        let bags_comm = bags.iter().map(|bag| BagComm::new(verifier_tracker.transfer_prover_comm(bag.poly.id), verifier_tracker.transfer_prover_comm(bag.selector.id), bag.num_vars())).collect::<Vec<BagComm<E, PCS>>>();
        let range_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(range_bag.poly.id), verifier_tracker.transfer_prover_comm(range_bag.selector.id), range_bag.num_vars());
        BagDisjointPairwiseIOP::<E, PCS>::verify(
            verifier_tracker,
            &bags_comm,
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
    fn bag_disjoint_pairwise_with_advice_test() {
        let res = test_bag_disjoint_pairwise();
        res.unwrap();
    }


}