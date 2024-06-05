


#[cfg(test)]
mod test {
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseMultilinearExtension;
    use ark_std::{Zero, One};
    use std::sync::Arc;
    use subroutines::{
        pcs::PolynomialCommitmentScheme,
        poly_iop::{errors::PolyIOPErrors, PolyIOP},
        MultilinearKzgPCS
    };
    use transcript::IOPTranscript;

    use ark_bls12_381::{Fr, Bls12_381};
    use ark_std::test_rng;
    use ark_std::rand::prelude::SliceRandom;

    use crate::zksql_poly_iop::bag_multitool::{
        bag_multitool::BagMultiToolCheck,
        bag_eq::BagEqCheck,
        bag_subset::BagSubsetCheck,
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
        let mut transcript = <PolyIOP<Fr> as BagMultiToolCheck<Bls12_381, MultilinearKzgPCS::<Bls12_381>>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // call the helper to run the proofand verify now that everything is set up 
        // TODO: dont assume null_offset is zero
        let null_offset = Fr::zero();
        test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &[mf.clone()], &[mg.clone()], null_offset, &mut transcript)?;
        println!("test_bag_multitool good path passed");

        // good path passed. Now check bad path
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
        let (proof, ) = <PolyIOP<E::ScalarField> as BagMultiToolCheck<E, PCS>>::prove(pcs_param, fxs, gxs, mfxs, mgxs, null_offset, &mut transcript.clone())?;
        let aux_info = <PolyIOP<E::ScalarField> as BagMultiToolCheck<E, PCS>>::verification_info(pcs_param, fxs, gxs, mfxs, mgxs, null_offset, &mut transcript.clone());
        <PolyIOP<E::ScalarField> as BagMultiToolCheck<E, PCS>>::verify(&proof, &aux_info, transcript)?;
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
        let mut transcript = <PolyIOP<Fr> as BagEqCheck<Bls12_381, MultilinearKzgPCS::<Bls12_381>>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // call the helper to run the proofand verify now that everything is set up 
        test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &mut transcript)?;
        println!("test_bageq_helper good path passed");

        // good path passed. Now check bad path
        let mut h_evals = f.evaluations.clone();
        h_evals[0] = h_evals[0] + Fr::one();
        let h_poly = DenseMultilinearExtension::from_evaluations_vec(f.num_vars, h_evals);
        let h = Arc::new(h_poly);

        let bad_result1 = test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[h], &mut transcript);
        assert!(bad_result1.is_err());

        // exit successfully 
        Ok(())
    }

     // Given inputs, calls and verifies BagEqCheck
    fn test_bageq_helper<E, PCS>(
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(), PolyIOPErrors>
    where
        E: Pairing,
        PCS: PolynomialCommitmentScheme<
            E,
            Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
        >,
    {
        let (proof,) = <PolyIOP<E::ScalarField> as BagEqCheck<E, PCS>>::prove(pcs_param, fxs, gxs, &mut transcript.clone())?;
        let aux_info = <PolyIOP<E::ScalarField> as BagEqCheck<E, PCS>>::verification_info(pcs_param, fxs, gxs, &mut transcript.clone());
        <PolyIOP::<E::ScalarField> as BagEqCheck::<E, PCS>>::verify(pcs_param, &proof, &aux_info, &mut transcript.clone())?;
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
        let mut transcript = <PolyIOP<Fr> as BagEqCheck<Bls12_381, MultilinearKzgPCS::<Bls12_381>>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;

        // call the helper to run the proofand verify now that everything is set up 
        test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &[mg.clone()], null_offset, &mut transcript)?;
        println!("test_bagsubset_helper good path passed");

        // good path passed. Now check bad path
        mg_evals[0] = Fr::one();
        let bad_mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals.clone()));
        let bad_result1 = test_bagsubset_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &[bad_mg.clone()], null_offset, &mut transcript);
        assert!(bad_result1.is_err());

        // exit successfully 
        Ok(())
    }

     // Given inputs, calls and verifies BagEqCheck
    fn test_bagsubset_helper<E, PCS>(
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mg: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
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
        let (proof,) = <PolyIOP<E::ScalarField> as BagSubsetCheck<E, PCS>>::prove(pcs_param, fxs, gxs, mg, null_offset, &mut transcript.clone())?;
        let aux_info = <PolyIOP<E::ScalarField> as BagSubsetCheck<E, PCS>>::verification_info(pcs_param, fxs, gxs, mg, null_offset, &mut transcript.clone());
        <PolyIOP::<E::ScalarField> as BagSubsetCheck::<E, PCS>>::verify(pcs_param, &proof, &aux_info, &mut transcript.clone())?;
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