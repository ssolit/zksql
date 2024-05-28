use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{errors::PolyIOPErrors, prelude::SumCheck, PolyIOP},
};
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer};
use std::sync::Arc;
use std::ops::Neg;
use transcript::IOPTranscript;
use ark_ff::PrimeField;
use subroutines::ZeroCheck;
use arithmetic::{merge_polynomials, VPAuxInfo, VirtualPolynomial};
use ark_std::{Zero, One};



pub trait LogupCheck<E, PCS>: ZeroCheck<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    type LogupCheckSubClaim;
    type LogupCheckProof;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a LogupCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// LogupCheck prover/verifier.
    fn init_transcript() -> Self::Transcript;

    /// Proves that two lists of n-variate multilinear polynomials `(f1, f2,
    /// ..., fk)` and `(g1, ..., gk)` with corresponding multiplicity vectors 
    /// (m_{f1}, ..., m_{fk}) and (m_{g1}, ..., m_{gk}) satisfy:
    /// 
    ///   \Sum_{j=1}^{2^n} \frac{m_{fi}[j]}{X-fi[j]}
    ///     = \Sum_{j=1}^{2^n} \frac{m_{gi}[j]}{X-gi[j]}
    /// for each (fi, gi, mfi, mgi)
    ///
    /// Inputs:
    /// - fxs: the list of LHS polynomials
    /// - gxs: the list of RHS polynomials
    /// - mf: the list of LHS multiplicities 
    /// - mg: the list of RHS multiplicitieds
    /// - transcript: the IOP transcript
    /// - pk: PCS committing key
    ///
    /// Outputs
    /// - the logup proof
    /// - the LHS logup polynomial (used for testing)
    /// - the RHS logup polynomial (used for testing)
    ///
    /// Cost: TODO
    #[allow(clippy::type_complexity)]
    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        mf: &[Self::MultilinearExtension],
        mg: &[Self::MultilinearExtension],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::LogupCheckProof,
            VirtualPolynomial<<E as Pairing>::ScalarField>,
            VirtualPolynomial<<E as Pairing>::ScalarField>,
        ),
        PolyIOPErrors,
    >;

    /// Verify that two lists of n-variate multilinear polynomials `(f1, f2,
    /// ..., fk)` and `(g1, ..., gk)` with corresponding multiplicity vectors 
    /// (m_{f1}, ..., m_{fk}) and (m_{g1}, ..., m_{gk}) satisfy:
    /// 
    ///   \Sum_{j=1}^{2^n} \frac{m_{fi}[j]}{X-fi[j]}
    ///     = \Sum_{j=1}^{2^n} \frac{m_{gi}[j]}{X-gi[j]}
    /// for each (fi, gi, mfi, mgi)
    fn verify(
        proof: &Self::LogupCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::LogupCheckSubClaim, PolyIOPErrors>;
}


/// A logup check subclaim consists of
/// - A zero check IOP subclaim for the virtual polynomial
/// - The random challenge `alpha`
/// - A final query for `prod(1, ..., 1, 0) = 1`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogupCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>, SC: SumCheck<F>> {
    // the SubClaim from the ZeroCheck
    pub lhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub rhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub v: F,
    pub gamma: F,
    pub fhat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
    pub ghat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogupCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    SC: SumCheck<E::ScalarField>,
    ZC: ZeroCheck<E::ScalarField>,

> {
    pub lhs_sumcheck_proof: SC::SumCheckProof,
    pub rhs_sumcheck_proof: SC::SumCheckProof,
    pub v: E::ScalarField,
    pub fhat_zero_check_proof: ZC::ZeroCheckProof,
    pub ghat_zero_check_proof: ZC::ZeroCheckProof,
    // pub fxs_comm: PCS::Commitment,
    // pub gxs_comm: PCS::Commitment,
    pub mf_comm: PCS::Commitment,
    pub mg_comm: PCS::Commitment,
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}


impl<E, PCS> LogupCheck<E, PCS> for PolyIOP<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type LogupCheckSubClaim = LogupCheckSubClaim<E::ScalarField, Self, Self>;
    type LogupCheckProof = LogupCheckProof<E, PCS, Self, Self>;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<E::ScalarField>::new(b"Initializing LogupCheck transcript")
    }

    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        mfxs: &[Self::MultilinearExtension],
        mgxs: &[Self::MultilinearExtension],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::LogupCheckProof,
            VirtualPolynomial<<E as Pairing>::ScalarField>,
            VirtualPolynomial<<E as Pairing>::ScalarField>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "prod_check prove");

        // check input shape is correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != gxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and mf have different number of polynomials".to_string(),
            ));
        }
        if fxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and mf have different number of polynomials".to_string(),
            ));
        }
        for poly in fxs.iter().chain(gxs.iter()).chain(mfxs.iter()).chain(mgxs.iter()) {
            if poly.num_vars != fxs[0].num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "vectors in fxs, gxs, mf, mg, have different number of variables".to_string(),
                ));
            }
        }
        let nv = fxs[0].num_vars;

        // // iterate over vector elems and prove
        // for i in 0..fxs.len() {
        let f: Self::MultilinearExtension = fxs[0].clone();
        let g: Self::MultilinearExtension = gxs[0].clone();
        let mf: Self::MultilinearExtension  = mfxs[0].clone();
        let mg: Self::MultilinearExtension = mgxs[0].clone();

        // initalize the transcript and get a random challenge gamma
        let mf_comm = PCS::commit(pcs_param, &mf)?;
        let mg_comm = PCS::commit(pcs_param, &mg)?;
        transcript.append_serializable_element(b"mf(x)", &mf_comm)?;
        transcript.append_serializable_element(b"mg(x)", &mg_comm)?;
        let gamma = transcript.get_and_append_challenge(b"gamma")?;

        // calculate and commit to fhat(x) = (gamma + f(x))^{-1}, as well as ghat
        let mut f_evals = f.evaluations.clone();
        let mut f_minus_gamma: Vec<<E as Pairing>::ScalarField> = f_evals.iter_mut().map(|x| *x - gamma).collect();
        let fhat_evals = f_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(fhat_evals);
        let fhat = Arc::new(DenseMultilinearExtension::from_evaluations_slice(nv, fhat_evals));

        let mut g_evals = g.evaluations.clone();
        let mut g_minus_gamma: Vec<<E as Pairing>::ScalarField> = g_evals.iter_mut().map(|x| *x - gamma).collect();
        let ghat_evals = g_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(ghat_evals);
        let ghat = Arc::new(DenseMultilinearExtension::from_evaluations_slice(nv, ghat_evals));

        let fhat_comm = PCS::commit(pcs_param, &fhat)?; 
        let ghat_comm = PCS::commit(pcs_param, &ghat)?;

        transcript.append_serializable_element(b"fhat(x)", &fhat_comm)?;
        transcript.append_serializable_element(b"ghat(x)", &ghat_comm)?;
        // note: this is the state transcript should be cloned into everything

        // make virtual polynomials lhs = fhat * mf, rhs = ghat * mg
        let mut lhs = VirtualPolynomial::new(nv);
        let mut rhs = VirtualPolynomial::new(nv);
        lhs.add_mle_list([fhat.clone(), mf.clone()], E::ScalarField::one())?; // cloning Arc ptr b/c need fhat again below
        rhs.add_mle_list([ghat.clone(), mg.clone()], E::ScalarField::one())?;
        
        // calculate the sum values
        let mf_evals = &mf.evaluations;
        let mg_evals = &mg.evaluations;
        let mut s1 = E::ScalarField::zero();
        let mut s2 = E::ScalarField::zero();
        for i in 0..2_usize.pow(nv as u32) {
            s1 += fhat[i] * mf_evals[i];
            s2 += ghat[i] * mg_evals[i];
        }
        assert_eq!(s1, s2, "LogupCheck prove err: LHS and RHS have different sums");
        println!("s1 and s2 are equal. Good!");
        let v = s1;
        
        // prove the sumcheck claim SUM(h) = 0
        let mut transcript_copy = transcript.clone();
        let lhs_sumcheck_proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&lhs, &mut transcript_copy.clone())?;
        let rhs_sumcheck_proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&rhs, &mut transcript_copy.clone())?;
        
        // debug: make sure the sumcheck claim verifies
        #[cfg(debug_assertions)]
        {
            println!("LogupChec::prove Verifying sumchecks pass");
            // let mut transcript = <PolyIOP<E::ScalarField> as LogupCheck<E, PCS>>::init_transcript();
            // transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let aux_info = &lhs.aux_info.clone();
            let lhs_sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
                v,
                &lhs_sumcheck_proof,
                aux_info,
                &mut transcript_copy.clone(),
            )?;
            // let mut transcript = <PolyIOP<E::ScalarField> as LogupCheck<E, PCS>>::init_transcript();
            // transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let aux_info = &rhs.aux_info.clone();
            let rhs_sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
                v,
                &rhs_sumcheck_proof,
                aux_info,
                &mut transcript_copy.clone(),
            )?;
            println!("prove debug sumchecks passing!\n")
        }

        

        // prove fhat(x), ghat(x) is created correctly, i.e. ZeroCheck [(f(x)-gamma) * fhat(x)  - 1]
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let gamma_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![gamma.clone(); 2_usize.pow(nv as u32)]));
        
        let mut fhat_check_poly = VirtualPolynomial::new_from_mle(&f, E::ScalarField::one());
        fhat_check_poly.add_mle_list([gamma_const_poly.clone()], E::ScalarField::one().neg())?;
        fhat_check_poly.mul_by_mle(fhat, E::ScalarField::one())?;
        fhat_check_poly.add_mle_list([one_const_poly.clone()], E::ScalarField::one().neg())?;

        let mut ghat_check_poly = VirtualPolynomial::new_from_mle(&g, E::ScalarField::one());
        ghat_check_poly.add_mle_list([gamma_const_poly], E::ScalarField::one().neg())?;
        ghat_check_poly.mul_by_mle(ghat, E::ScalarField::one())?;
        ghat_check_poly.add_mle_list([one_const_poly], E::ScalarField::one().neg())?;
        
        let fhat_zero_check_proof = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(&fhat_check_poly, transcript)?;
        let ghat_zero_check_proof = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(&ghat_check_poly, transcript)?;

        Ok((
            LogupCheckProof {
                lhs_sumcheck_proof,
                rhs_sumcheck_proof,
                v,
                fhat_zero_check_proof,
                ghat_zero_check_proof,
                mf_comm,
                mg_comm,
                fhat_comm,
                ghat_comm,
            },
            fhat_check_poly,
            ghat_check_poly,
        ))
    }

    fn verify(
        proof: &Self::LogupCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::LogupCheckSubClaim, PolyIOPErrors> {
        let start = start_timer!(|| "logup_check verify");

        // update transcript and generate challenge
        transcript.append_serializable_element(b"mf(x)", &proof.mf_comm)?;
        transcript.append_serializable_element(b"mg(x)", &proof.mg_comm)?;
        let gamma = transcript.get_and_append_challenge(b"gamma")?;
        let v = proof.v;

        // invoke the respective IOP proofs for sumcheck, zerocheck fhat, zerocheck ghat
        let lhs_sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
            E::ScalarField::zero(),
            &proof.lhs_sumcheck_proof,
            aux_info,
            transcript,
        )?;

        let rhs_sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
            E::ScalarField::zero(),
            &proof.rhs_sumcheck_proof,
            aux_info,
            transcript,
        )?;

        let fhat_zerocheck_subclaim = <Self as ZeroCheck<E::ScalarField>>::verify(
            &proof.fhat_zero_check_proof,
            aux_info,
            transcript,
        )?;

        let ghat_zerocheck_subclaim = <Self as ZeroCheck<E::ScalarField>>::verify(
            &proof.ghat_zero_check_proof,
            aux_info,
            transcript,
        )?;

        Ok(LogupCheckSubClaim{
            lhs_sumcheck_subclaim, 
            rhs_sumcheck_subclaim,
            v,
            gamma,
            fhat_zerocheck_subclaim,
            ghat_zerocheck_subclaim,
        })


    }
}

fn test_bag_multitool() -> Result<(), PolyIOPErrors> {
    use ark_bls12_381::{Fr, Bls12_381};
    use subroutines::{
        pcs::{prelude::MultilinearKzgPCS, PolynomialCommitmentScheme},
        poly_iop::{errors::PolyIOPErrors, PolyIOP},
    };
    use ark_std::{test_rng};
    use ark_std::rand::prelude::SliceRandom;

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

    // println!("test_bag_multitool");
    // // println!("g_nv: {}", g.aux_info.clone().nv);
    // println!("permute vec: {:?}\n", permute_vec);
    // println!("f_evals: {:?}\n", f_evals);
    // println!("g_evals: {:?}\n", g_evals);
    // println!("mf_evals: {:?}\n", mf_evals);
    // println!("mg_evals: {:?}\n", mg_evals);
    // println!();

    // initialize transcript 
    let mut transcript = <PolyIOP<Fr> as LogupCheck<Bls12_381, MultilinearKzgPCS::<Bls12_381>>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;

    // call the helper to run the proofand verify now that everything is set up 
    test_bag_multitool_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f], &[g], &[mf], &[mg], &mut transcript)?;

    // exit successfully 
    Ok(())
}

fn test_bag_multitool_helper<E: Pairing, PCS> (
    pcs_param: &PCS::ProverParam,
    fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    mfxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    mgxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<(), PolyIOPErrors>  where
E: Pairing,
PCS: PolynomialCommitmentScheme<
    E,
    Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
>,{
    let (proof,  fhat_check_poly,ghat_check_poly) = <PolyIOP<E::ScalarField> as LogupCheck<E, PCS>>::prove(pcs_param, fxs, gxs, mfxs, mgxs, transcript)?;
    println!("test_bag_multitool_helper: proof created successfully");
    println!();
    let aux_info = fhat_check_poly.aux_info.clone();
    <PolyIOP<E::ScalarField> as LogupCheck<E, PCS>>::verify(&proof, &aux_info, transcript)?;

    Ok(())
}

#[test]
fn bag_multitool_test1() {
    let res = test_bag_multitool();
    res.unwrap();
}