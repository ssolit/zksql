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
    use ark_std::One;

    use crate::{
        tracker::prelude::*,
        zksql_poly_iop::group_by::group_by::{AggregationTypes, GroupByIOP, GroupByInstruction, GroupByInstructionWithProvingAdvice, GroupByInstructionWithVerifyingAdvice},
        
    };

    fn test_group_by_count() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        
        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(range_nv as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_poly_evals);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![Fr::one(); 2_usize.pow(range_nv as u32)]);

        // Test the count aggregation
        let pre_nv = 3; 
        let pre_group_nums = vec![1, 1, 1, 2, 2, 3, 0, 0];
        let pre_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let pre_agg_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let support_col_nums = vec![0, 0, 0, 0, 0, 1, 2, 3]; // recall these need to be ordered for the support IOP gadget to pass
        let support_sel_nums = vec![0, 0, 0, 0, 0, 1, 1, 1];
        let support_mult_nums = vec![0, 0, 0, 0, 0, 3, 2, 1];
        let agg_nums = support_mult_nums.clone(); // for count its the same as support_mult_nums, this is actually a dummy var

        let pre_group_vals = pre_group_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_group_sel_vals = pre_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_agg_vals = pre_agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_col_vals = support_col_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_sel_vals = support_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_mult_vals = support_mult_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let agg_vals = agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        let pre_group_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_vals.clone());
        let pre_group_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_sel_vals.clone());
        let pre_agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_agg_vals.clone());
        let support_col_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_col_vals.clone());
        let support_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_sel_vals.clone());
        let support_mult_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_mult_vals.clone());
        let agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, agg_vals.clone());

        let pre_group_poly = prover_tracker.track_and_commit_poly(pre_group_mle.clone())?;
        let pre_group_sel_poly = prover_tracker.track_and_commit_poly(pre_group_sel_mle.clone())?;
        let pre_agg_poly = prover_tracker.track_and_commit_poly(pre_agg_mle.clone())?;
        let support_col_poly = prover_tracker.track_and_commit_poly(support_col_mle.clone())?;
        let support_sel_poly = prover_tracker.track_and_commit_poly(support_sel_mle.clone())?;
        let support_mult_poly = prover_tracker.track_and_commit_poly(support_mult_mle.clone())?;
        let agg_poly = prover_tracker.track_and_commit_poly(agg_mle.clone())?;
        
        let table = Table::new(vec![pre_group_poly.clone(), pre_agg_poly.clone()], pre_group_sel_poly.clone());
        let range_poly = prover_tracker.track_and_commit_poly(range_mle.clone())?;
        let range_sel_poly = prover_tracker.track_and_commit_poly(range_sel_mle.clone())?;
        let range_bag = Bag::new(range_poly.clone(), range_sel_poly.clone());

        let grouping_cols = vec![0];
        let proving_agg_instr = vec![(0, AggregationTypes::Count, agg_poly.clone())];

        GroupByIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::prove_with_advice(
            &mut prover_tracker,
            &table,
            &GroupByInstructionWithProvingAdvice {
                grouping_cols: grouping_cols.clone(),
                support_cols: vec![support_col_poly],
                support_sel: support_sel_poly,
                support_multiplicity: support_mult_poly,
                agg_instr: proving_agg_instr,
            },
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        verifier_tracker.set_compiled_proof(proof);
        let pre_group_comm_id = verifier_tracker.get_next_id();
        let pre_group_comm = verifier_tracker.transfer_prover_comm(pre_group_comm_id);
        let pre_group_sel_comm_id = verifier_tracker.get_next_id();
        let pre_group_sel_comm = verifier_tracker.transfer_prover_comm(pre_group_sel_comm_id);
        let pre_agg_comm_id = verifier_tracker.get_next_id();
        let pre_agg_comm = verifier_tracker.transfer_prover_comm(pre_agg_comm_id);
        let support_col_comm_id = verifier_tracker.get_next_id();
        let support_col_comm = verifier_tracker.transfer_prover_comm(support_col_comm_id);
        let support_sel_comm_id = verifier_tracker.get_next_id();
        let support_sel_comm = verifier_tracker.transfer_prover_comm(support_sel_comm_id);
        let support_mult_comm_id = verifier_tracker.get_next_id();
        let support_mult_comm = verifier_tracker.transfer_prover_comm(support_mult_comm_id);
        let agg_comm_id = verifier_tracker.get_next_id();
        let agg_comm = verifier_tracker.transfer_prover_comm(agg_comm_id);
        let table_comm = TableComm::new(vec![pre_group_comm, pre_agg_comm], pre_group_sel_comm.clone(), table.num_vars());
        let range_comm_id = verifier_tracker.get_next_id();
        let range_comm = verifier_tracker.transfer_prover_comm(range_comm_id);
        let range_sel_comm_id = verifier_tracker.get_next_id();
        let range_sel_comm = verifier_tracker.transfer_prover_comm(range_sel_comm_id);
        let range_bag_comm = BagComm::new(range_comm, range_sel_comm, range_nv);
        let verifier_agg_instr = vec![(0, AggregationTypes::Count, agg_comm.clone())];
        
        GroupByIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::verify_with_advice(
            &mut verifier_tracker,
            &table_comm,
            &GroupByInstructionWithVerifyingAdvice {
                grouping_cols,
                support_cols: vec![support_col_comm],
                support_sel: support_sel_comm,
                support_multiplicity: support_mult_comm,
                agg_instr: verifier_agg_instr,
            },
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

    fn test_group_by_sum() -> Result<(), PolyIOPErrors> {
        // testing params
        let range_nv = 10;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        
        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

        // create the range poly and its multiplicity vector
        let range_poly_evals = (0..2_usize.pow(range_nv as u32)).map(|x| Fr::from(x as u64)).collect(); // numbers are between 0 and 2^10 by construction
        let range_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, range_poly_evals);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![Fr::one(); 2_usize.pow(range_nv as u32)]);

        // Test the count aggregation
        let pre_nv = 3; 
        let pre_group_nums = vec![1, 1, 1, 2, 2, 3, 0, 0];
        let pre_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
        let pre_agg_nums = vec![11, 12, 13, 14, 15, 16, 0, 0];
        let support_col_nums = vec![0, 0, 0, 0, 0, 1, 2, 3]; // recall these need to be ordered for the support IOP gadget to pass
        let support_sel_nums = vec![0, 0, 0, 0, 0, 1, 1, 1];
        let support_mult_nums = vec![0, 0, 0, 0, 0, 3, 2, 1];
        let agg_nums = vec![0, 0, 0, 0, 0, 36, 29, 16];

        let pre_group_vals = pre_group_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_group_sel_vals = pre_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let pre_agg_vals = pre_agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_col_vals = support_col_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_sel_vals = support_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let support_mult_vals = support_mult_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let agg_vals = agg_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        let pre_group_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_vals.clone());
        let pre_group_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_group_sel_vals.clone());
        let pre_agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, pre_agg_vals.clone());
        let support_col_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_col_vals.clone());
        let support_sel_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_sel_vals.clone());
        let support_mult_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, support_mult_vals.clone());
        let agg_mle = DenseMultilinearExtension::from_evaluations_vec(pre_nv, agg_vals.clone());

        let pre_group_poly = prover_tracker.track_and_commit_poly(pre_group_mle.clone())?;
        let pre_group_sel_poly = prover_tracker.track_and_commit_poly(pre_group_sel_mle.clone())?;
        let pre_agg_poly = prover_tracker.track_and_commit_poly(pre_agg_mle.clone())?;
        let support_col_poly = prover_tracker.track_and_commit_poly(support_col_mle.clone())?;
        let support_sel_poly = prover_tracker.track_and_commit_poly(support_sel_mle.clone())?;
        let support_mult_poly = prover_tracker.track_and_commit_poly(support_mult_mle.clone())?;
        let agg_poly = prover_tracker.track_and_commit_poly(agg_mle.clone())?;
        
        let table = Table::new(vec![pre_group_poly.clone(), pre_agg_poly.clone()], pre_group_sel_poly.clone());
        let range_poly = prover_tracker.track_and_commit_poly(range_mle.clone())?;
        let range_sel_poly = prover_tracker.track_and_commit_poly(range_sel_mle.clone())?;
        let range_bag = Bag::new(range_poly.clone(), range_sel_poly.clone());

        let grouping_cols = vec![0];
        let proving_agg_instr = vec![(1, AggregationTypes::Sum, agg_poly.clone())];

        GroupByIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::prove_with_advice(
            &mut prover_tracker,
            &table,
            &GroupByInstructionWithProvingAdvice {
                grouping_cols: grouping_cols.clone(),
                support_cols: vec![support_col_poly],
                support_sel: support_sel_poly,
                support_multiplicity: support_mult_poly,
                agg_instr: proving_agg_instr,
            },
            &range_bag,
        )?;
        let proof = prover_tracker.compile_proof()?;

        verifier_tracker.set_compiled_proof(proof);
        let pre_group_comm_id = verifier_tracker.get_next_id();
        let pre_group_comm = verifier_tracker.transfer_prover_comm(pre_group_comm_id);
        let pre_group_sel_comm_id = verifier_tracker.get_next_id();
        let pre_group_sel_comm = verifier_tracker.transfer_prover_comm(pre_group_sel_comm_id);
        let pre_agg_comm_id = verifier_tracker.get_next_id();
        let pre_agg_comm = verifier_tracker.transfer_prover_comm(pre_agg_comm_id);
        let support_col_comm_id = verifier_tracker.get_next_id();
        let support_col_comm = verifier_tracker.transfer_prover_comm(support_col_comm_id);
        let support_sel_comm_id = verifier_tracker.get_next_id();
        let support_sel_comm = verifier_tracker.transfer_prover_comm(support_sel_comm_id);
        let support_mult_comm_id = verifier_tracker.get_next_id();
        let support_mult_comm = verifier_tracker.transfer_prover_comm(support_mult_comm_id);
        let agg_comm_id = verifier_tracker.get_next_id();
        let agg_comm = verifier_tracker.transfer_prover_comm(agg_comm_id);
        let table_comm = TableComm::new(vec![pre_group_comm, pre_agg_comm], pre_group_sel_comm.clone(), table.num_vars());
        let range_comm_id = verifier_tracker.get_next_id();
        let range_comm = verifier_tracker.transfer_prover_comm(range_comm_id);
        let range_sel_comm_id = verifier_tracker.get_next_id();
        let range_sel_comm = verifier_tracker.transfer_prover_comm(range_sel_comm_id);
        let range_bag_comm = BagComm::new(range_comm.clone(), range_sel_comm.clone(), range_nv);
        let verifier_agg_instr = vec![(1, AggregationTypes::Sum, agg_comm.clone())];
        
        GroupByIOP::<Bls12_381, MultilinearKzgPCS<Bls12_381>>::verify_with_advice(
            &mut verifier_tracker,
            &table_comm,
            &GroupByInstructionWithVerifyingAdvice {
                grouping_cols,
                support_cols: vec![support_col_comm],
                support_sel: support_sel_comm,
                support_multiplicity: support_mult_comm,
                agg_instr: verifier_agg_instr,
            },
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
    fn final_group_by_count_test() {
        let res = test_group_by_count();
        res.unwrap();
    }

    #[test]
    fn final_group_by_sum_test() {
        let res = test_group_by_sum();
        res.unwrap();
    }
}