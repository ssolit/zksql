#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::{Zero, One};
    use subroutines::{
        pcs::PolynomialCommitmentScheme,
        MultilinearKzgPCS
    };

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::rand::prelude::SliceRandom;

    use crate::{
        utils::{
            bag::{Bag, BagComm},
            prover_tracker::{ProverTracker, ProverTrackerRef, TrackedPoly},
            verifier_tracker::{TrackedComm, VerifierTracker, VerifierTrackerRef},
            errors::PolyIOPErrors,
        }, 
        zksql_poly_iop::bag_multitool::{
            bag_multitool::BagMultiToolIOP,
            bag_eq::BagEqIOP,
            bag_subset::BagSubsetIOP,
            bag_sum::BagSumIOP,
            bag_presc_perm::BagPrescPermIOP,
        },
    };

    // Sets up randomized inputs for testing BagMultiToolCheck
    fn test_bag_multitool() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 4;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init f, mf, and a permutation vec, and build g, mg based off of it
        let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let mf = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let f_evals: Vec<Fr> = f.evaluations.clone();
        let mf_evals: Vec<Fr> = mf.evaluations.clone();
        let mut permute_vec: Vec<usize> = (0..f_evals.len()).collect();
        permute_vec.shuffle(&mut rng);
        let g_evals: Vec<Fr> = permute_vec.iter().map(|&i| f_evals[i]).collect();
        let mg_evals: Vec<Fr> = permute_vec.iter().map(|&i| mf_evals[i]).collect();
        let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
        let mg = DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone());

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_tracker(ProverTracker::new(pcs_prover_param));
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param));

        // Good Path 1: they are a correct permutation, selector is all ones
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); f_evals.len()]);
        let f_sel = one_mle.clone();
        let g_sel = one_mle.clone();
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[g.clone()], &[g_sel.clone()], &[mg.clone()])?;
        println!("Good path 1 passed");

        // // Good Path 2: selector includes zeros
        let f2_evals = f_evals.clone();
        let mut f2_sel_evals = vec![Fr::one(); f_evals.len()];
        f2_sel_evals[permute_vec[0]] = Fr::zero();
        let g2_evals = g_evals.clone();
        let mut g2_sel_evals = vec![Fr::one(); g_evals.len()];
        g2_sel_evals[0] = Fr::zero();

        let f2 = DenseMultilinearExtension::from_evaluations_vec(nv, f2_evals.clone());
        let f2_sel =DenseMultilinearExtension::from_evaluations_vec(nv, f2_sel_evals.clone());
        let g2 =DenseMultilinearExtension::from_evaluations_vec(nv, g2_evals.clone());
        let g2_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g2_sel_evals.clone());
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f2.clone()], &[f2_sel.clone()], &[mf.clone()],&[g2.clone()], &[g2_sel.clone()], &[mg.clone()])?;
        println!("Good path 2 passed");


        // Good Path 3: f is split into two polynomials
        let half_one_poly = DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f_evals.len()/2]);
        let f3a_evals = f_evals.clone()[..f_evals.len()/2].to_vec();
        let f3b_evals = f_evals.clone()[f_evals.len()/2..].to_vec();
        let mf3a_evals = mf_evals.clone()[..mf_evals.len()/2].to_vec();
        let mf3b_evals = mf_evals.clone()[mf_evals.len()/2..].to_vec();
        let f3a = DenseMultilinearExtension::from_evaluations_vec(nv-1, f3a_evals.clone());
        let mf3a = DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3a_evals.clone());
        let f3b = DenseMultilinearExtension::from_evaluations_vec(nv-1, f3b_evals.clone());
        let mf3b = DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3b_evals.clone());
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f3a, f3b], &[half_one_poly.clone(), half_one_poly.clone()], &[mf3a.clone(), mf3b.clone()], &[g.clone()], &[g_sel.clone()], &[mg.clone()])?;
        println!("good path 3 passed");

        // good paths passed. Now check bad paths
        let h = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let h_sel = one_mle.clone();
        let mh = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();

        // incorrect multiplicities
        let bad_result1 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f.clone()], &[f_sel.clone()], &[mf.clone()],&[h], &[h_sel],  &[mf.clone()]);
        assert!(bad_result1.is_err());
        // incorrect polynomials
        let bad_result2 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[f.clone()], &[f_sel.clone()],&[mh]);
        assert!(bad_result2.is_err());
        // incorrect selectors
        let bad_result3 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[g2.clone()], &[g2_sel.clone()],  &[mg.clone()]);
        assert!(bad_result3.is_err());
        println!("bad paths passed");

        // // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagMultiToolCheck
        fn test_bag_multitool_helper<E: Pairing, PCS> (
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        fs: &[DenseMultilinearExtension<E::ScalarField>],
        f_sels:&[DenseMultilinearExtension<E::ScalarField>],
        mfs: &[DenseMultilinearExtension<E::ScalarField>],
        gs: &[DenseMultilinearExtension<E::ScalarField>],
        g_sels: &[DenseMultilinearExtension<E::ScalarField>],
        mgs: &[DenseMultilinearExtension<E::ScalarField>],
    ) -> Result<(), PolyIOPErrors>  where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,{
        // Set up prover_tracker and prove
        let f_polys_vec: Vec<TrackedPoly<E, PCS>> = fs.iter().map(|p| prover_tracker.track_mat_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let f_sel_polys_vec: Vec<TrackedPoly<E, PCS>> = f_sels.iter().map(|p| prover_tracker.track_mat_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let mf_polys_vec: Vec<TrackedPoly<E, PCS>> = mfs.iter().map(|p| prover_tracker.track_mat_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let g_polys_vec: Vec<TrackedPoly<E, PCS>> = gs.iter().map(|p| prover_tracker.track_mat_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let g_sel_polys_vec: Vec<TrackedPoly<E, PCS>> = g_sels.iter().map(|p| prover_tracker.track_mat_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;
        let mg_polys_vec: Vec<TrackedPoly<E, PCS>> = mgs.iter().map(|p| prover_tracker.track_mat_poly(p.clone())).collect::<Result<Vec<_>, _>>()?;

        let f_bags_vec: Vec<Bag<E, PCS>> = f_polys_vec.iter()
            .zip(f_sel_polys_vec.iter())
            .map(|(f, f_sel)| Bag::new(f.clone(), f_sel.clone()))
            .collect();
        let f_bags: &[Bag<E, PCS>] = &f_bags_vec;

        let g_bags_vec: Vec<Bag<E, PCS>> = g_polys_vec.iter()
            .zip(g_sel_polys_vec.iter())
            .map(|(g, g_sel)| Bag::new(g.clone(), g_sel.clone()))
            .collect();
        let g_bags: &[Bag<E, PCS>] = &g_bags_vec;

        BagMultiToolIOP::<E, PCS>::prove(
            prover_tracker,
            f_bags,
            g_bags,
            &mf_polys_vec,
            &mg_polys_vec
        )?;
        let proof = prover_tracker.compile_proof();
        
        // set up verifier tracker and create subclaims
        verifier_tracker.set_compiled_proof(proof);

        let f_comms_vec: Vec<TrackedComm<E, PCS>> = f_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<E, PCS>>>();
        let f_sel_comms_vec: Vec<TrackedComm<E, PCS>> = f_sel_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<E, PCS>>>();
        let mf_comms_vec: Vec<TrackedComm<E, PCS>> = mf_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<E, PCS>>>();
        let g_comms_vec: Vec<TrackedComm<E, PCS>> = g_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<E, PCS>>>();
        let g_sel_comms_vec: Vec<TrackedComm<E, PCS>> = g_sel_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<E, PCS>>>();
        let mg_comms_vec: Vec<TrackedComm<E, PCS>> = mg_polys_vec.iter().map(|p| verifier_tracker.transfer_prover_comm(p.id)).collect::<Vec<TrackedComm<E, PCS>>>();

        let f_bags_vec: Vec<BagComm<E, PCS>> = f_comms_vec.iter()
            .zip(f_sel_comms_vec.iter())
            .map(|(f, f_sel)| BagComm::new(f.clone(), f_sel.clone()))
            .collect();
        let f_bags: &[BagComm<E, PCS>] = &f_bags_vec;

        let g_bags_vec: Vec<BagComm<E, PCS>> = g_comms_vec.iter()
            .zip(g_sel_comms_vec.iter())
            .map(|(g, g_sel)| BagComm::new(g.clone(), g_sel.clone()))
            .collect();
        let g_bags: &[BagComm<E, PCS>] = &g_bags_vec;
        BagMultiToolIOP::<E, PCS>::verify(verifier_tracker, f_bags, g_bags, &mf_comms_vec, &mg_comms_vec)?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        
        Ok(())
    }

    // Sets up randomized inputs for testing BagEqCheck
    fn test_bageq() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init f, mf, and a permutation vec, and build g, mg based off of it
        let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let one_poly = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]);
        let f_sel = one_poly.clone();
        let g_sel = one_poly.clone();
        
        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_tracker(ProverTracker::new(pcs_prover_param));
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param));

        // Good Path 
        test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(),  &g.clone(), &g_sel.clone())?;
        println!("Good path passed");

        // Bad path
        let mut h_evals = f.evaluations.clone();
        h_evals[0] = h_evals[0] + Fr::one();
        let h = DenseMultilinearExtension::from_evaluations_vec(f.num_vars, h_evals);
        let h_sel = one_poly.clone();

        let bad_result1 = test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(), &h.clone(), &h_sel.clone());
        assert!(bad_result1.is_err());
        println!("Bad path passed");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagEqCheck
    fn test_bageq_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f: &DenseMultilinearExtension<E::ScalarField>,
        f_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        // Set up prover_tracker and prove
        let f_bag = Bag::new(prover_tracker.track_mat_poly(f.clone())?, prover_tracker.track_mat_poly(f_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_mat_poly(g.clone())?, prover_tracker.track_mat_poly(g_sel.clone())?);


        BagEqIOP::<E, PCS>::prove(
            prover_tracker,
            &f_bag,
            &g_bag,
        )?;
        let proof = prover_tracker.compile_proof();
        
        // set up verifier tracker and create subclaims
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id));
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id));
        BagEqIOP::<E, PCS>::verify(verifier_tracker, &f_bag_comm, &g_bag_comm)?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        
        Ok(())
    }

    // Sets up randomized inputs for testing BagSubsetIOP
    fn test_bagsubset() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init g, build f and mg off of it. Test sets it to something like
        // g = [a, b, c, d, ...], f = [a, a, 0, d], mg = [2, 0, 0, 1, ...]
        let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let g_sel_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        let g_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone());
        
        
        let mut f_evals = g.evaluations.clone();
        f_evals[1] = f_evals[0];
        let mut f_sel_evals = vec![Fr::one(); f_evals.len()];
        f_sel_evals[2] = Fr::zero();
        let f = DenseMultilinearExtension::from_evaluations_vec(nv, f_evals.clone());
        let f_sel = DenseMultilinearExtension::from_evaluations_vec(nv, f_sel_evals.clone());
        
        
        let mut mg_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        mg_evals[0] = Fr::from(2u64);
        mg_evals[1] = Fr::zero();
        mg_evals[2] = Fr::zero();
        let mg = DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone());

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_tracker(ProverTracker::new(pcs_prover_param));
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param));

        // Good path 1: described above
        test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(),  &g.clone(), &g_sel.clone(), &mg.clone())?;
        println!("test_bagsubset_helper good path 1 passed");

        // Good path 2: f and g are different sized
        let f_small_evals = [g.evaluations[0], g.evaluations[1]].to_vec();
        let f_small = DenseMultilinearExtension::from_evaluations_vec(1, f_small_evals.clone());
        let f_small_sel = DenseMultilinearExtension::from_evaluations_vec(1, vec![Fr::one(); 2_usize.pow(1 as u32)]);
        let mut mg_small_evals = vec![Fr::zero(); mg_evals.len()];
        mg_small_evals[0] = Fr::one();
        mg_small_evals[1] = Fr::one();
        let mg_small = DenseMultilinearExtension::from_evaluations_vec(nv, mg_small_evals.clone());
        test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f_small.clone(), &f_small_sel.clone(),  &g.clone(), &g_sel.clone(), &mg_small.clone())?;
        println!("test_bagsubset_helper good path 2 passed");

        // bad path
        mg_evals[0] = Fr::one();
        let bad_mg = DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone());
        let bad_result1 = test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(), &g.clone(), &g_sel.clone(), &bad_mg.clone());
        assert!(bad_result1.is_err());

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagSubsetIOP
    fn test_bagsubset_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f: &DenseMultilinearExtension<E::ScalarField>,
        f_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
        mg: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        // Set up prover_tracker and prove
        let f_bag = Bag::new(prover_tracker.track_mat_poly(f.clone())?, prover_tracker.track_mat_poly(f_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_mat_poly(g.clone())?, prover_tracker.track_mat_poly(g_sel.clone())?);
        let mg = prover_tracker.track_mat_poly(mg.clone())?;

        BagSubsetIOP::<E, PCS>::prove(
            prover_tracker,
            &f_bag,
            &g_bag,
            &mg,
        )?;
        let proof = prover_tracker.compile_proof();
        
        // set up verifier tracker and create subclaims
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id));
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id));
        let mg_comm = verifier_tracker.transfer_prover_comm(mg.id);
        BagSubsetIOP::<E, PCS>::verify(
        verifier_tracker, 
        &f_bag_comm, 
        &g_bag_comm,
        &mg_comm,
    )?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        
        Ok(())
    }

    // Sets up randomized inputs for testing BagSumIOP
    fn test_bagsum() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init a permutation vec, and build stuff off of it
        let gen = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let gen_evals: Vec<Fr> = gen.evaluations.clone();

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_tracker(ProverTracker::new(pcs_prover_param));
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param));

        // good path 1, f0 and f1 are the same size
        let one_poly = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]);
        let f0_evals = gen_evals.clone()[..gen_evals.len()/2].to_vec();
        let f1_evals = gen_evals.clone()[gen_evals.len()/2 ..].to_vec();
        let half_one_poly = DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f0_evals.len()]);
        let g_evals = gen_evals.clone();
        let f0 = DenseMultilinearExtension::from_evaluations_vec(nv-1, f0_evals.clone());
        let f0_sel = half_one_poly.clone();
        let f1 = DenseMultilinearExtension::from_evaluations_vec(nv-1, f1_evals.clone());
        let f1_sel = half_one_poly.clone();
        let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
        let g_sel = one_poly.clone();

        test_bagsum_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f0.clone(), &f0_sel.clone(), &f1.clone(), &f1_sel.clone(), &g.clone(), &g_sel.clone())?;
        println!("test_bagsum good path 1 passed\n");

        // good path 2, f0 and f1 are different sized
        let f0_evals = gen_evals.clone()[..gen_evals.len()/2].to_vec();
        let f0_sel_evals = vec![Fr::one(); f0_evals.len()];
        let f1_evals = gen_evals.clone()[gen_evals.len()/2 .. (gen_evals.len() * 3/4)].to_vec();
        let f1_sel_evals = vec![Fr::one(); f1_evals.len()];

        let mut g_evals = gen_evals.clone();
        for i in (gen_evals.len() * 3/4)..gen_evals.len() {
            g_evals[i] = Fr::zero();
        }
        let mut g_sel_evals = vec![Fr::one(); g_evals.len()];
        for i in (gen_evals.len() * 3/4) .. gen_evals.len() {
            g_sel_evals[i] = Fr::zero();
        }

        let f0 = DenseMultilinearExtension::from_evaluations_vec(nv-1, f0_evals.clone());
        let f0_sel = DenseMultilinearExtension::from_evaluations_vec(nv-1, f0_sel_evals.clone());
        let f1 = DenseMultilinearExtension::from_evaluations_vec(nv-2, f1_evals.clone());
        let f1_sel = DenseMultilinearExtension::from_evaluations_vec(nv-2, f1_sel_evals.clone());
        let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
        let g_sel = DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone());

        test_bagsum_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f0.clone(), &f0_sel.clone(), &f1.clone(), &f1_sel.clone(), &g.clone(), &g_sel.clone())?;
        println!("test_bagsum good path 2 passed\n");

        // bad path
        let mut bad_f0_evals = f0_evals.clone();
        bad_f0_evals[0] = Fr::one();
        bad_f0_evals[1] = Fr::one();
        let bad_f0 = DenseMultilinearExtension::from_evaluations_vec(nv-1, bad_f0_evals.clone());
        let bad_f0_sel = DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f0_evals.len()]);
        let bad_result1 = test_bagsum_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &bad_f0.clone(), &bad_f0_sel.clone(), &f1.clone(), &f1_sel.clone(), &g.clone(), &g_sel.clone());
        assert!(bad_result1.is_err());

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagSumIOP
    fn test_bagsum_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f0: &DenseMultilinearExtension<E::ScalarField>,
        f0_sel: &DenseMultilinearExtension<E::ScalarField>,
        f1: &DenseMultilinearExtension<E::ScalarField>,
        f1_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        // Set up prover_tracker and prove
        let f0_bag = Bag::new(prover_tracker.track_mat_poly(f0.clone())?, prover_tracker.track_mat_poly(f0_sel.clone())?);
        let f1_bag = Bag::new(prover_tracker.track_mat_poly(f1.clone())?, prover_tracker.track_mat_poly(f1_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_mat_poly(g.clone())?, prover_tracker.track_mat_poly(g_sel.clone())?);

        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            &f0_bag,
            &f1_bag,
            &g_bag,
        )?;
        let proof = prover_tracker.compile_proof();

        // set up verifier tracker and create subclaims
        verifier_tracker.set_compiled_proof(proof);
        let f0_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f0_bag.poly.id), verifier_tracker.transfer_prover_comm(f0_bag.selector.id));
        let f1_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f1_bag.poly.id), verifier_tracker.transfer_prover_comm(f1_bag.selector.id));
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id));
        BagSumIOP::<E, PCS>::verify(verifier_tracker, &f0_bag_comm, &f1_bag_comm, &g_bag_comm)?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        
        Ok(())
    }

    // Sets up randomized inputs for testing BagPrescPermIOP
    fn test_bag_presc_perm() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // Create Trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_tracker(ProverTracker::new(pcs_prover_param));
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param));

        // randomly init f, and a permuation vec, and build g off of it
        let one_poly = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]);
        let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let f_evals: Vec<Fr> = f.evaluations.clone();
        let mut permute_vec: Vec<usize> = (0..f_evals.len()).collect();
        permute_vec.shuffle(&mut rng);
        let perm_evals: Vec<Fr> = permute_vec.iter().map(|x| Fr::from(*x as u64)).collect();
        let perm = DenseMultilinearExtension::from_evaluations_vec(nv, perm_evals.clone());
        let g_evals: Vec<Fr> = permute_vec.iter().map(|&i| f_evals[i]).collect();
        let g = DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone());
        let f_sel = one_poly.clone();
        let g_sel = one_poly.clone();

        // good path
        test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(), &g.clone(), &g_sel.clone(), &perm.clone())?;
        println!("test_presc_perm good path 1 passed\n");

        // bad path 1 - different elements
        let mut bad_f_evals = f_evals.clone();
        bad_f_evals[0] = Fr::one();
        bad_f_evals[1] = Fr::one();
        let bad_f = DenseMultilinearExtension::from_evaluations_vec(nv, bad_f_evals.clone());
        let bad_f_sel = one_poly.clone();
        let bad_result1 = test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &bad_f.clone(), &bad_f_sel.clone(), &g.clone(), &g_sel.clone(), &perm.clone());
        assert!(bad_result1.is_err());
        println!("test_presc_perm bad path 1 passed\n");

        // bad path 2 - f and g are a different permutation than perm
        let mut bad_perm_evals = perm_evals.clone();
        let old_0_eval = perm_evals[0];
        bad_perm_evals[0] = bad_perm_evals[1];
        bad_perm_evals[1] = old_0_eval;
        let bad_perm = DenseMultilinearExtension::from_evaluations_vec(nv, bad_perm_evals.clone());
        let bad_result2 = test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &f.clone(), &f_sel.clone(), &g.clone(), &g_sel.clone(), &bad_perm.clone());
        assert!(bad_result2.is_err());
        println!("test_presc_perm bad path 2 passed\n");

        // exit successfully 
        Ok(())
    }

        // Given inputs, calls and verifies BagPrescPermIOP
    fn test_bag_presc_perm_helper<E, PCS>(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        f: &DenseMultilinearExtension<E::ScalarField>,
        f_sel: &DenseMultilinearExtension<E::ScalarField>,
        g: &DenseMultilinearExtension<E::ScalarField>,
        g_sel: &DenseMultilinearExtension<E::ScalarField>,
        perm: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    {
        // Set up prover_tracker and prove
        let f_bag = Bag::new(prover_tracker.track_mat_poly(f.clone())?, prover_tracker.track_mat_poly(f_sel.clone())?);
        let g_bag = Bag::new(prover_tracker.track_mat_poly(g.clone())?, prover_tracker.track_mat_poly(g_sel.clone())?);
        let perm = prover_tracker.track_mat_poly(perm.clone())?;
        
        BagPrescPermIOP::<E, PCS>::prove(
            prover_tracker,
            &f_bag,
            &g_bag,
            &perm,
        )?;
        let proof = prover_tracker.compile_proof();

        // set up verifier tracker and create subclaims
        verifier_tracker.set_compiled_proof(proof);
        let f_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(f_bag.poly.id), verifier_tracker.transfer_prover_comm(f_bag.selector.id));
        let g_bag_comm = BagComm::new(verifier_tracker.transfer_prover_comm(g_bag.poly.id), verifier_tracker.transfer_prover_comm(g_bag.selector.id));
        let perm_comm = verifier_tracker.transfer_prover_comm(perm.id);
        BagPrescPermIOP::<E, PCS>::verify(verifier_tracker, &f_bag_comm, &g_bag_comm, &perm_comm)?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);
        assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
        assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);
        
        Ok(())
        
    }


    // test callers
    #[test]
    fn bag_multitool_test() {
        let res = test_bag_multitool();
        res.unwrap();
    }

    #[test]
    fn bageq_test() {
        let res = test_bageq();
        res.unwrap();
    }

    #[test]
    fn bagsubset_test() {
        let res = test_bagsubset();
        res.unwrap();
    }

    #[test]
    fn bagsum_test() {
        let res = test_bagsum();
        res.unwrap();
    }

    #[test]
    fn bag_presc_perm_test() {
        let res = test_bag_presc_perm();
        res.unwrap();
    }
}