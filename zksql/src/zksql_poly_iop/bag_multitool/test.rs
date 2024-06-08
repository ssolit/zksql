


#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::{Zero, One};
    use std::sync::Arc;
    use subroutines::{
        pcs::PolynomialCommitmentScheme,
        poly_iop::errors::PolyIOPErrors,
        MultilinearKzgPCS
    };
    use transcript::IOPTranscript;

    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;
    use ark_std::rand::prelude::SliceRandom;

    use crate::zksql_poly_iop::bag_multitool::{
        bag_multitool::BagMultiToolIOP,
        bag_eq::BagEqIOP,
        bag_subset::BagSubsetIOP,
    };

    // Sets up randomized inputs for testing BagMultiToolCheck
    fn test_bag_multitool() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 4;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init f, mf, and a permutation vec, and build g, mg based off of it
        let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let mf = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let f_evals: Vec<Fr> = f.evaluations.clone();
        let mf_evals: Vec<Fr> = mf.evaluations.clone();
        let mut permute_vec: Vec<usize> = (0..f_evals.len()).collect();
        permute_vec.shuffle(&mut rng);
        let g_evals: Vec<Fr> = permute_vec.iter().map(|&i| f_evals[i]).collect();
        let mg_evals: Vec<Fr> = permute_vec.iter().map(|&i| mf_evals[i]).collect();
        let g = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_evals.clone()));
        let mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone()));

        // initialize transcript 
        let mut transcript = BagMultiToolIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // Good Path 1: they are a correct permutation
        let null_offset = Fr::zero();
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &[mf.clone()], &[mg.clone()], null_offset, &mut transcript)?;
    //    println!("Good path passed\n");

        // Good Path 2: null_offset is one
        let null_offset = Fr::one();
        let mut f2_evals = f_evals.clone();
        let mut mf2_evals = mf_evals.clone();
        let g2_evals = g_evals.clone();
        let mut mg2_evals = mg_evals.clone();

        f2_evals[permute_vec[0]] = Fr::zero();
        mf2_evals[permute_vec[0]] = Fr::one();
        mg2_evals[0] = Fr::zero();

        let f2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, f2_evals.clone()));
        let mf2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mf2_evals.clone()));
        let g2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g2_evals.clone()));
        let mg2 = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg2_evals.clone()));
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f2.clone()], &[g2.clone()], &[mf2.clone()], &[mg2.clone()], null_offset, &mut transcript)?;
        // println!("good path 2 passed\n");

        // Good Path 3: f is split into two polynomials
        let f3a_evals = f_evals.clone()[..f_evals.len()/2].to_vec();
        let f3b_evals = f_evals.clone()[f_evals.len()/2..].to_vec();
        let mf3a_evals = mf_evals.clone()[..mf_evals.len()/2].to_vec();
        let mf3b_evals = mf_evals.clone()[mf_evals.len()/2..].to_vec();
        let f3a = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f3a_evals.clone()));
        let mf3a = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3a_evals.clone()));
        let f3b = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, f3b_evals.clone()));
        let mf3b = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv-1, mf3b_evals.clone()));
        let null_offset = Fr::zero();
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone(), f3a.clone(), f3b.clone()], &[g.clone(), g.clone()], &[mf.clone(), mf3a.clone(), mf3b.clone(), ], &[mg.clone(), mg.clone()], null_offset, &mut transcript)?;
        // println!("good path 3 passed\n");

        // good paths passed. Now check bad paths
        let h = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let mh = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();

        // incorrect multiplicities
        let bad_result1 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[h], &[mf.clone()], &[mf.clone()], null_offset, &mut transcript);
        assert!(bad_result1.is_err());
        // incorrect polynomials
        let bad_result2 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[f.clone()], &[mf.clone()], &[mh], null_offset, &mut transcript);
        assert!(bad_result2.is_err());
        // incorrect null_offset
        let bad_result3 = test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &[mf.clone()], &[mg.clone()], null_offset + Fr::one(), &mut transcript);
        assert!(bad_result3.is_err());

        // exit successfully 
        Ok(())
    }

    // Given inputs, calls and verifies BagMultiToolCheck
    fn test_bag_multitool_helper<E: Pairing, PCS> (
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mfxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mgxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>  where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
    >,{
        let (proof, ) = BagMultiToolIOP::<E, PCS>::prove(pcs_param, fxs, gxs, mfxs, mgxs, null_offset, &mut transcript.clone())?;
        let (f_aux_info, g_aux_info) = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, fxs, gxs, mfxs, mgxs, null_offset, &mut transcript.clone());
        BagMultiToolIOP::<E, PCS>::verify(&proof, &f_aux_info, &g_aux_info, &mut transcript.clone())?;
        Ok(())
    }

    // Sets up randomized inputs for testing BagEqCheck
    fn test_bageq() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init f, mf, and a permutation vec, and build g, mg based off of it
        let f = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        
        // initialize transcript 
        let mut transcript = BagEqIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // call the helper to run the proofand verify now that everything is set up 
        test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f.clone(), &g.clone(), &mut transcript)?;
        println!("test_bageq_helper good path passed");

        // good path passed. Now check bad path
        let mut h_evals = f.evaluations.clone();
        h_evals[0] = h_evals[0] + Fr::one();
        let h_poly = DenseMultilinearExtension::from_evaluations_vec(f.num_vars, h_evals);
        let h = Arc::new(h_poly);

        let bad_result1 = test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f.clone(), &h, &mut transcript);
        assert!(bad_result1.is_err());

        // exit successfully 
        Ok(())
    }

     // Given inputs, calls and verifies BagEqCheck
    fn test_bageq_helper<E, PCS>(
        pcs_param: &PCS::ProverParam,
        fx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
        E: Pairing,
        PCS: PolynomialCommitmentScheme<
            E,
            Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        >,
    {
        let (proof,) = BagEqIOP::<E, PCS>::prove(pcs_param, fx.clone(), gx.clone(), &mut transcript.clone())?;
        let aux_info = BagEqIOP::<E, PCS>::verification_info(pcs_param, fx, gx, &mut transcript.clone());
        BagEqIOP::<E, PCS>::verify(pcs_param, &proof, &aux_info, &mut transcript.clone())?;
        Ok(())
    }

    // Sets up randomized inputs for testing BagEqCheck
    fn test_bagsubset() -> Result<(), PolyIOPErrors> {
        // testing params
        let nv = 8;
        let mut rng = test_rng();

        // PCS params
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

        // randomly init g, build f and mg off of it. Test sets it to something like
        // g = [a, b, c, d, ...], f = [a, a, 0, d], mg = [2, 0, 0, 1, ...]
        let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
        
        let mut f_evals = g.evaluations.clone();
        f_evals[1] = f_evals[0];
        f_evals[2] = Fr::zero();
        let f = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, f_evals.clone()));
        let null_offset = Fr::one(); // set to 1 b/c f_evals[2] = Fr::zero(), and no other nulls are set
        
        let mut mg_evals = vec![Fr::one(); 2_usize.pow(nv as u32)];
        mg_evals[0] = Fr::from(2u64);
        mg_evals[1] = Fr::zero();
        mg_evals[2] = Fr::zero();
        let mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone()));

        // initialize transcript 
        let mut transcript = BagEqIOP::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // call the helper to run the proofand verify now that everything is set up 
        test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f.clone(), &g.clone(), &mg.clone(), null_offset, &mut transcript)?;
        println!("test_bagsubset_helper good path passed");

        // good path passed. Now check bad path
        mg_evals[0] = Fr::one();
        let bad_mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone()));
        let bad_result1 = test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &f.clone(), &g.clone(), &bad_mg.clone(), null_offset, &mut transcript);
        assert!(bad_result1.is_err());

        // exit successfully 
        Ok(())
    }

     // Given inputs, calls and verifies BagEqCheck
    fn test_bagsubset_helper<E, PCS>(
        pcs_param: &PCS::ProverParam,
        fx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        mg: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
        E: Pairing,
        PCS: PolynomialCommitmentScheme<
            E,
            Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        >,
    {
        let (proof,) = BagSubsetIOP::<E, PCS>::prove(pcs_param, fx, gx, mg, null_offset, &mut transcript.clone())?;
        let aux_info = BagSubsetIOP::<E, PCS>::verification_info(pcs_param, fx, gx, mg, null_offset, &mut transcript.clone());
        BagSubsetIOP::<E, PCS>::verify(pcs_param, &proof, &aux_info, &mut transcript.clone())?;
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
}