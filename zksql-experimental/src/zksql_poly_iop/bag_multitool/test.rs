#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::{Zero, One};
    use std::{sync::Arc, vec};
    use subroutines::{
        pcs::{self, PolynomialCommitmentScheme},
        poly_iop::errors::PolyIOPErrors,
        MultilinearKzgPCS
    };
    use transcript::IOPTranscript;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::rand::prelude::SliceRandom;

    use crate::{
        utils::{
            prover_tracker::{self, CompiledZKSQLProof, ProverTracker, ProverTrackerRef, TrackedPoly},
            verifier_tracker::{self, TrackedComm, VerifierTracker, VerifierTrackerRef},
        }, 
        zksql_poly_iop::bag_multitool::bag_multitool::{ArcMLE, Bag, BagComm, BagMultiToolIOP}};

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

        // Create Trackers and add polys to them
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_tracker(ProverTracker::new(pcs_prover_param));
        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param));
        // let f_poly = prover_tracker.track_mat_poly(f)?;
        // let mf_poly = prover_tracker.track_mat_poly(mf)?;
        // let g_poly = prover_tracker.track_mat_poly(g)?;
        // let mg_poly = prover_tracker.track_mat_poly(mg)?;

        // Good Path 1: they are a correct permutation, selector is all ones
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); f_evals.len()]);
        let f_sel = one_mle.clone();
        let g_sel = one_mle.clone();
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&mut prover_tracker, &mut verifier_tracker, &[f.clone()], &[f_sel.clone()], &[mf.clone()], &[g.clone()], &[g_sel.clone()], &[mg.clone()])?;
        println!("Good path 1 passed");

        // // Good Path 2: selector includes zeros
        // let f2_evals = f_evals.clone();
        // let mut f2_sel_evals = vec![Fr::one(); f_evals.len()];
        // f2_sel_evals[permute_vec[0]] = Fr::zero();
        // let g2_evals = g_evals.clone();
        // let mut g2_sel_evals = vec![Fr::one(); g_evals.len()];
        // g2_sel_evals[0] = Fr::zero();

        // let f2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, f2_evals.clone()));
        // let f2_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, f2_sel_evals.clone()));
        // let g2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g2_evals.clone()));
        // let g2_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g2_sel_evals.clone()));
        // let f2_bag = Bag::new(f2, f2_sel);
        // let g2_bag = Bag::new(g2, g2_sel);
        // test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f2_bag.clone()], &[g2_bag.clone()], &[mf.clone()], &[mg.clone()],  &mut transcript)?;
        // println!("Good path 2 passed");


        // // Good Path 3: f is split into two polynomials
        // let half_one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f_evals.len()/2]));
        // let f3a_evals = f_evals.clone()[..f_evals.len()/2].to_vec();
        // let f3b_evals = f_evals.clone()[f_evals.len()/2..].to_vec();
        // let mf3a_evals = mf_evals.clone()[..mf_evals.len()/2].to_vec();
        // let mf3b_evals = mf_evals.clone()[mf_evals.len()/2..].to_vec();
        // let f3a = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f3a_evals.clone()));
        // let mf3a = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3a_evals.clone()));
        // let f3b = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f3b_evals.clone()));
        // let mf3b = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3b_evals.clone()));
        // let f3a_bag = Bag::new(f3a.clone(), half_one_poly.clone());
        // let f3b_bag = Bag::new(f3b.clone(), half_one_poly.clone());
        // test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f_bag.clone(), f3a_bag, f3b_bag], &[g_bag.clone(), g_bag.clone()], &[mf.clone(), mf3a.clone(), mf3b.clone(), ], &[mg.clone(), mg.clone()], &mut transcript)?;
        // println!("good path 3 passed");

        // // good paths passed. Now check bad paths
        // let h = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        // let h_bag = Bag::new(h.clone(), one_poly.clone());
        // let mh = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();

        // // incorrect multiplicities
        // let bad_result1 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f_bag.clone()], &[h_bag], &[mf.clone()], &[mf.clone()], &mut transcript);
        // assert!(bad_result1.is_err());
        // // incorrect polynomials
        // let bad_result2 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f_bag.clone()], &[f_bag.clone()], &[mf.clone()], &[mh], &mut transcript);
        // assert!(bad_result2.is_err());
        // // incorrect selectors
        // let bad_result3 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f_bag.clone()], &[g2_bag.clone()], &[mf.clone()], &[mg.clone()], &mut transcript);
        // assert!(bad_result3.is_err());
        // println!("bad paths passed");

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
        println!("finished transfering comms");

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
        // assert_eq!(p_tracker.transcript, v_tracker.transcript);
        Ok(())
    }

//     // Sets up randomized inputs for testing BagEqCheck
//     fn test_bageq() -> Result<(), PolyIOPErrors> {
//         // testing params
//         let nv = 8;
//         let mut rng = test_rng();

//         // PCS params
//         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
//         let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

//         // randomly init f, mf, and a permutation vec, and build g, mg based off of it
//         let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
//         let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
//         let one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]));
//         let f_bag = Bag::new(f, one_poly.clone());
//         let g_bag = Bag::new(g, one_poly.clone());
        
//         // initialize transcript 
//         let mut transcript = BagEqIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
//         transcript.append_message(b"testing", b"initializing transcript for testing")?;

//         // call the helper to run the proofand verify now that everything is set up 
//         test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f_bag.clone(), &g_bag.clone(), &mut transcript)?;
//         println!("Good path passed");

//         // Bad path
//         let mut h_evals = f_bag.poly.evaluations.clone();
//         h_evals[0] = h_evals[0] + Fr::one();
//         let h_poly = DenseMultilinearExtension::from_evaluations_vec(f_bag.num_vars, h_evals);
//         let h = Arc::new(h_poly);
//         let h_bag = Bag::new(h, one_poly.clone());

//         let bad_result1 = test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f_bag.clone(), &h_bag, &mut transcript);
//         assert!(bad_result1.is_err());
//         println!("Bad path passed");

//         // exit successfully 
//         Ok(())
//     }

//      // Given inputs, calls and verifies BagEqCheck
//     fn test_bageq_helper<E, PCS>(
//         pcs_param: &PCS::ProverParam,
//         fx: &Bag<E>,
//         gx: &Bag<E>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<(), PolyIOPErrors>
//     where
//         E: Pairing,
//         PCS: PolynomialCommitmentScheme<
//             E,
//             Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
//         >,
//     {
//         let (proof,) = BagEqIOP::<E, PCS>::prove(pcs_param, fx, gx, &mut transcript.clone())?;
//         let (f_sc_info, f_zc_info, g_sc_info, g_zc_info) = BagEqIOP::<E, PCS>::verification_info(pcs_param, fx, gx, &mut transcript.clone());
//         BagEqIOP::verify(pcs_param,&proof, &f_sc_info, &f_zc_info, &g_sc_info, &g_zc_info, &mut transcript.clone())?;
//         Ok(())
//     }

//     // Sets up randomized inputs for testing BagSubsetIOP
//     fn test_bagsubset() -> Result<(), PolyIOPErrors> {
//         // testing params
//         let nv = 8;
//         let mut rng = test_rng();

//         // PCS params
//         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
//         let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

//         // randomly init g, build f and mg off of it. Test sets it to something like
//         // g = [a, b, c, d, ...], f = [a, a, 0, d], mg = [2, 0, 0, 1, ...]
//         let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
//         let g_sel_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
//         let g_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone()));
//         let g_bag = Bag::new(g, g_sel);
        
//         let mut f_evals = g_bag.poly.evaluations.clone();
//         f_evals[1] = f_evals[0];
//         let mut f_sel_evals = vec![Fr::one(); f_evals.len()];
//         f_sel_evals[2] = Fr::zero();
//         let f = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, f_evals.clone()));
//         let f_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, f_sel_evals.clone()));
//         let f_bag = Bag::new(f, f_sel);
        
//         let mut mg_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
//         mg_evals[0] = Fr::from(2u64);
//         mg_evals[1] = Fr::zero();
//         mg_evals[2] = Fr::zero();
//         let mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone()));

//         // initialize transcript 
//         let mut transcript = BagEqIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
//         transcript.append_message(b"testing", b"initializing transcript for testing")?;

//         // Good path 1: described above
//         test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f_bag.clone(), &g_bag.clone(), &mg.clone(), &mut transcript)?;
//         println!("test_bagsubset_helper good path 1 passed");

//         // Good path 2: f and g are different sized
//         let f_small_evals = [g_bag.poly.evaluations[0], g_bag.poly.evaluations[1]].to_vec();
//         let f_small = Arc::new(DenseMultilinearExtension::from_evaluations_vec(1, f_small_evals.clone()));
//         let f_small_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(1, vec![Fr::one(); 2_usize.pow(1 as u32)]));
//         let f_small_bag = Bag::new(f_small.clone(), f_small_sel);
//         let mut mg_small_evals = vec![Fr::zero(); mg_evals.len()];
//         mg_small_evals[0] = Fr::one();
//         mg_small_evals[1] = Fr::one();
//         let mg_small = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_small_evals.clone()));
//         test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f_small_bag.clone(), &g_bag.clone(), &mg_small.clone(), &mut transcript)?;
//         println!("test_bagsubset_helper good path 2 passed");

//         // bad path
//         mg_evals[0] = Fr::one();
//         let bad_mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone()));
//         let bad_result1 = test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f_bag.clone(), &g_bag.clone(), &bad_mg.clone(), &mut transcript);
//         assert!(bad_result1.is_err());

//         // exit successfully 
//         Ok(())
//     }

//      // Given inputs, calls and verifies BagSubsetIOP
//     fn test_bagsubset_helper<E, PCS>(
//         pcs_param: &PCS::ProverParam,
//         fx: &Bag<E>,
//         gx: &Bag<E>,
//         mg: &ArcMLE<E>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<(), PolyIOPErrors>
//     where
//         E: Pairing,
//         PCS: PolynomialCommitmentScheme<
//             E,
//             Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
//         >,
//     {
//         let (proof,) = BagSubsetIOP::<E, PCS>::prove(pcs_param, fx, gx, mg, &mut transcript.clone())?;
//         let (f_sc_info, f_zc_info, g_sc_info, g_zc_info) = BagSubsetIOP::<E, PCS>::verification_info(pcs_param, fx, gx, mg, &mut transcript.clone());
//         BagSubsetIOP::<E, PCS>::verify(pcs_param,&proof, &f_sc_info, &f_zc_info, &g_sc_info, &g_zc_info, &mut transcript.clone())?;
//         Ok(())
//     }

//     // Sets up randomized inputs for testing BagSumIOP
//     fn test_bagsum() -> Result<(), PolyIOPErrors> {
//         // testing params
//         let nv = 8;
//         let mut rng = test_rng();

//         // PCS params
//         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
//         let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

//         // initialize transcript 
//         let mut transcript = BagEqIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
//         transcript.append_message(b"testing", b"initializing transcript for testing")?;


//         // randomly init f, mf, and a permutation vec, and build fa, fb, g, mg based off of it
//         let gen = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
//         let gen_evals: Vec<Fr> = gen.evaluations.clone();

//         // good path 1, f0 and f1 are the same size
//         let f0_evals = gen_evals.clone()[..gen_evals.len()/2].to_vec();
//         let f1_evals = gen_evals.clone()[gen_evals.len()/2 ..].to_vec();
//         let half_one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f0_evals.len()]));
//         let g_evals = gen_evals.clone();
//         let f0 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f0_evals.clone()));
//         let f1 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f1_evals.clone()));
//         let g = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone()));
//         let one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]));
//         let f0_bag = Bag::new(f0, half_one_poly.clone());
//         let f1_bag = Bag::new(f1, half_one_poly.clone());
//         let g_bag = Bag::new(g, one_poly.clone());

//         test_bagsum_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, f0_bag.clone(), f1_bag.clone(), g_bag.clone(),  &mut transcript)?;
//         println!("test_bagsum good path 1 passed\n");

//         // good path 2, f0 and f1 are different sized
//         let f0_evals = gen_evals.clone()[..gen_evals.len()/2].to_vec();
//         let f0_sel_evals = vec![Fr::one(); f0_evals.len()];
//         let f1_evals = gen_evals.clone()[gen_evals.len()/2 .. (gen_evals.len() * 3/4)].to_vec();
//         let f1_sel_evals = vec![Fr::one(); f1_evals.len()];

//         let mut g_evals = gen_evals.clone();
//         for i in (gen_evals.len() * 3/4)..gen_evals.len() {
//             g_evals[i] = Fr::zero();
//         }
//         let mut g_sel_evals = vec![Fr::one(); g_evals.len()];
//         for i in (gen_evals.len() * 3/4) .. gen_evals.len() {
//             g_sel_evals[i] = Fr::zero();
//         }

//         let f0 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f0_evals.clone()));
//         let f0_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f0_sel_evals.clone()));
//         let f0_bag = Bag::new(f0, f0_sel);
//         let f1 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-2, f1_evals.clone()));
//         let f1_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-2, f1_sel_evals.clone()));
//         let f1_bag = Bag::new(f1, f1_sel);
//         let g = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone()));
//         let g_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_sel_evals.clone()));
//         let g_bag = Bag::new(g, g_sel);


//         // test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f0.clone(), f1.clone()], &[g.clone()], &[get_one_m(f0.num_vars), get_one_m(f1.num_vars)], &[get_one_m(g.num_vars)], null_offset, &mut transcript.clone())?;
//         // println!("test_bagsum bag_multitool subtest passed\n");

//         test_bagsum_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, f0_bag.clone(), f1_bag.clone(), g_bag.clone(),  &mut transcript)?;
//         println!("test_bagsum good path 2 passed\n");

//         // bad path
//         let mut bad_f0_evals = f0_evals.clone();
//         bad_f0_evals[0] = Fr::one();
//         bad_f0_evals[1] = Fr::one();
//         let bad_f0 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, bad_f0_evals.clone()));
//         let bad_f0_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, vec![Fr::one(); f0_evals.len()]));
//         let bad_f0_bag = Bag::new(bad_f0, bad_f0_sel);
//         let bad_result1 = test_bagsum_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, bad_f0_bag.clone(), f1_bag.clone(), g_bag.clone(),  &mut transcript);
//         assert!(bad_result1.is_err());

//         // exit successfully 
//         Ok(())
//     }

//      // Given inputs, calls and verifies BagSumIOP
//     fn test_bagsum_helper<E, PCS>(
//         pcs_param: &PCS::ProverParam,
//         fx0: Bag<E>,
//         fx1:  Bag<E>,
//         gx:  Bag<E>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<(), PolyIOPErrors>
//     where
//         E: Pairing,
//         PCS: PolynomialCommitmentScheme<
//             E,
//             Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
//         >,
//     {
//         let (proof,) = BagSumIOP::<E, PCS>::prove(pcs_param, fx0.clone(), fx1.clone(), gx.clone(), &mut transcript.clone())?;
//         let (f_sc_info, f_zc_info, g_sc_info, g_zc_info) = BagSumIOP::<E, PCS>::verification_info(pcs_param, fx0.clone(), fx1.clone(), gx.clone(), &mut transcript.clone());
//         BagSumIOP::<E, PCS>::verify(pcs_param,&proof, &f_sc_info, &f_zc_info, &g_sc_info, &g_zc_info, &mut transcript.clone())?;
//         Ok(())
//     }

//     // Sets up randomized inputs for testing BagPrescPermIOP
//     fn test_bag_presc_perm() -> Result<(), PolyIOPErrors> {
//         // testing params
//         let nv = 8;
//         let mut rng = test_rng();

//         // PCS params
//         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
//         let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

//         // initialize transcript 
//         let mut transcript = BagEqIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
//         transcript.append_message(b"testing", b"initializing transcript for testing")?;

//         // randomly init f, and a permuation vec, and build g off of it
//         let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
//         let f_evals: Vec<Fr> = f.evaluations.clone();
//         let mut permute_vec: Vec<usize> = (0..f_evals.len()).collect();
//         permute_vec.shuffle(&mut rng);
//         let perm_evals: Vec<Fr> = permute_vec.iter().map(|x| Fr::from(*x as u64)).collect();
//         let perm = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, perm_evals.clone()));
//         let g_evals: Vec<Fr> = permute_vec.iter().map(|&i| f_evals[i]).collect();
//         let g = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone()));
//         let one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![Fr::one(); 2_usize.pow(nv as u32)]));
//         let f_bag = Bag::new(f, one_poly.clone());
//         let g_bag = Bag::new(g, one_poly.clone());

//         // good path
//         test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, f_bag.clone(), g_bag.clone(), perm.clone(), &mut transcript)?;
//         println!("test_presc_perm good path 1 passed\n");

//         // bad path 1 - different elements
//         let mut bad_f_evals = f_evals.clone();
//         bad_f_evals[0] = Fr::one();
//         bad_f_evals[1] = Fr::one();
//         let bad_f = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, bad_f_evals.clone()));
//         let bad_f_bag = Bag::new(bad_f, one_poly.clone());
//         let bad_result1 = test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, bad_f_bag.clone(), g_bag.clone(), perm.clone(), &mut transcript);
//         assert!(bad_result1.is_err());
//         println!("test_presc_perm bad path 1 passed\n");

//         // bad path 2 - f and g are a different permutation than perm
//         let mut bad_perm_evals = perm_evals.clone();
//         let old_0_eval = perm_evals[0];
//         bad_perm_evals[0] = bad_perm_evals[1];
//         bad_perm_evals[1] = old_0_eval;
//         let bad_perm = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, bad_perm_evals.clone()));
//         let bad_result2 = test_bag_presc_perm_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, f_bag.clone(), g_bag.clone(), bad_perm.clone(), &mut transcript);
//         assert!(bad_result2.is_err());
//         println!("test_presc_perm bad path 2 passed\n");

//         // exit successfully 
//         Ok(())
//     }

//      // Given inputs, calls and verifies BagPrescPermIOP
//     fn test_bag_presc_perm_helper<E, PCS>(
//         pcs_param: &PCS::ProverParam,
//         fx: Bag<E>,
//         gx: Bag<E>,
//         perm: Arc<DenseMultilinearExtension<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<(), PolyIOPErrors>
//     where
//         E: Pairing,
//         PCS: PolynomialCommitmentScheme<
//             E,
//             Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
//         >,
//     {
//         let (proof,) = BagPrescPermIOP::<E, PCS>::prove(pcs_param, &fx.clone(), &gx.clone(), &perm.clone(), &mut transcript.clone())?;
//         let (f_sc_info, f_zc_info, g_sc_info, g_zc_info) = BagEqIOP::<E, PCS>::verification_info(pcs_param, &fx.clone(), &gx.clone(), &mut transcript.clone());
//         BagPrescPermIOP::<E, PCS>::verify(pcs_param, &proof, &f_sc_info, &f_zc_info, &g_sc_info, &g_zc_info, &mut transcript.clone())?;
//         Ok(())
//     }


    // test callers
    #[test]
    fn bag_multitool_test() {
        let res = test_bag_multitool();
        res.unwrap();
    }

//     #[test]
//     fn bageq_test() {
//         let res = test_bageq();
//         res.unwrap();
//     }

//     #[test]
//     fn bagsubset_test() {
//         let res = test_bagsubset();
//         res.unwrap();
//     }

//     #[test]
//     fn bagsum_test() {
//         let res = test_bagsum();
//         res.unwrap();
//     }

//     #[test]
//     fn bag_presc_perm_test() {
//         let res = test_bag_presc_perm();
//         res.unwrap();
//     }
}