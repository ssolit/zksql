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
use arithmetic::{VPAuxInfo, VirtualPolynomial};
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
    pub sumcheck_subclaim: SC::SumCheckSubClaim,
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
    pub sumcheck_proof: SC::SumCheckProof,
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


        // make virtual polynomials h = fhat * mf - ghat * mg
        let mut h = VirtualPolynomial::new(nv);
        h.add_mle_list([fhat.clone(), mf], E::ScalarField::one())?; // cloning Arc ptr b/c need fhat again below
        h.add_mle_list([ghat.clone(), mg], E::ScalarField::one())?;
        
        // prove the sumcheck claim SUM(h) = 0
        let sumcheck_proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&h, transcript)?;

        // debug: make sure the sumcheck claim verifies

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
                sumcheck_proof,
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

        // invoke the respective IOP proofs for sumcheck, zerocheck fhat, zerocheck ghat
        let sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
            E::ScalarField::zero(),
            &proof.sumcheck_proof,
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
            sumcheck_subclaim, 
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
    let g_evals = permute_vec.iter().map(|&i| f_evals[i]).collect();
    let mg_evals = permute_vec.iter().map(|&i| mf_evals[i]).collect();
    let g = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, g_evals));
    let mg = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, mg_evals));

    println!("test_bag_multitool");
    // println!("g_nv: {}", g.aux_info.clone().nv);
    println!();

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
    let aux_info = fhat_check_poly.aux_info.clone();
    <PolyIOP<E::ScalarField> as LogupCheck<E, PCS>>::verify(&proof, &aux_info, transcript)?;

    Ok(())
}

#[test]
fn bag_multitool_test1() {
    let res = test_bag_multitool();
    res.unwrap();
}