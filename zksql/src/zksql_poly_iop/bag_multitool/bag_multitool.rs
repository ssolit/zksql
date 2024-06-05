use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::ops::Neg;
use std::sync::Arc;
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{errors::PolyIOPErrors, prelude::SumCheck, PolyIOP},
    ZeroCheck,
};
use transcript::IOPTranscript;


pub trait BagMultiToolCheck<E, PCS>: ZeroCheck<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    type BagMultiToolCheckSubClaim;
    type BagMultiToolCheckProof;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a BagMultiToolCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// BagMultiToolCheck prover/verifier.
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
    /// - pcs_param: params for adding poly_comm to proof
    /// - fxs: the list of LHS polynomials
    /// - gxs: the list of RHS polynomials
    /// - mf: the list of LHS multiplicities 
    /// - mg: the list of RHS multiplicitieds
    /// - null_offset: # of additional null elements in f compared to g
    /// - transcript: the IOP transcript
    ///
    /// Outputs
    /// - the BagMultiTool proof
    #[allow(clippy::type_complexity)]
    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        mf: &[Self::MultilinearExtension],
        mg: &[Self::MultilinearExtension],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::BagMultiToolCheckProof,
        ),
        PolyIOPErrors,
    >;

    /// Based on the proving inputs, get the aux_info the verifier needs for verificiation
    /// This is determined by the shape of polynomials constructed for the final checks in prove()
    fn verification_info(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        mfxs: &[Self::MultilinearExtension],
        mgxs: &[Self::MultilinearExtension],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField>;

    /// Verify that two lists of n-variate multilinear polynomials `(f1, f2,
    /// ..., fk)` and `(g1, ..., gk)` with corresponding multiplicity vectors 
    /// (m_{f1}, ..., m_{fk}) and (m_{g1}, ..., m_{gk}) satisfy:
    /// 
    ///   \Sum_{j=1}^{2^n} \frac{m_{fi}[j]}{X-fi[j]}
    ///     = \Sum_{j=1}^{2^n} \frac{m_{gi}[j]}{X-gi[j]}
    /// for each (fi, gi, mfi, mgi)
    fn verify(
        proof: &Self::BagMultiToolCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::BagMultiToolCheckSubClaim, PolyIOPErrors>;
}


/// A BagMultiToolCheck subclaim consists of
/// - A zero check IOP subclaim for the virtual polynomial
/// - The random challenge `alpha`
/// - A final query for `prod(1, ..., 1, 0) = 1`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagMultiToolCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>, SC: SumCheck<F>> {
    // the SubClaim from the ZeroCheck
    pub null_offset: F,
    pub gamma: F,
    pub lhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub rhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub lhs_v: F,
    pub rhs_v: F,
    pub fhat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
    pub ghat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagMultiToolCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    SC: SumCheck<E::ScalarField>,
    ZC: ZeroCheck<E::ScalarField>,

> {
    pub null_offset: E::ScalarField,
    pub lhs_sumcheck_proof: SC::SumCheckProof,
    pub rhs_sumcheck_proof: SC::SumCheckProof,
    pub lhs_v: E::ScalarField,
    pub rhs_v: E::ScalarField,
    pub fhat_zero_check_proof: ZC::ZeroCheckProof,
    pub ghat_zero_check_proof: ZC::ZeroCheckProof,
    pub mf_comm: PCS::Commitment,
    pub mg_comm: PCS::Commitment,
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}


impl<E, PCS> BagMultiToolCheck<E, PCS> for PolyIOP<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type BagMultiToolCheckSubClaim = BagMultiToolCheckSubClaim<E::ScalarField, Self, Self>;
    type BagMultiToolCheckProof = BagMultiToolCheckProof<E, PCS, Self, Self>;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagMultiToolCheck transcript")
    }

    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        mfxs: &[Self::MultilinearExtension],
        mgxs: &[Self::MultilinearExtension],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::BagMultiToolCheckProof,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "BagMultiTool_check prove");

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

        // // iterate over vector elems and prove:
        // TODO: actually iterate or make inputs not be lists
        let f: Self::MultilinearExtension = fxs[0].clone();
        let g: Self::MultilinearExtension = gxs[0].clone();
        let mf: Self::MultilinearExtension  = mfxs[0].clone();
        let mg: Self::MultilinearExtension = mgxs[0].clone();

        // initalize the transcript and get a random challenge gamma
        let mf_comm = PCS::commit(pcs_param, &mf)?;
        let mg_comm = PCS::commit(pcs_param, &mg)?;
        transcript.append_serializable_element(b"mf(x)", &mf_comm)?;
        transcript.append_serializable_element(b"mg(x)", &mg_comm)?;
        transcript.append_serializable_element(b"null_offset", &null_offset)?;
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
        // transcript must be in same state at start of proving and verification or verification will fail

        // make virtual polynomials lhs = fhat * mf, rhs = ghat * mg
        let mut lhs = VirtualPolynomial::new(nv);
        let mut rhs = VirtualPolynomial::new(nv);
        lhs.add_mle_list([fhat.clone(), mf.clone()], E::ScalarField::one())?; // cloning Arc ptr b/c need fhat again below
        rhs.add_mle_list([ghat.clone(), mg.clone()], E::ScalarField::one())?;
       
        
        // calculate the sum values
        let mf_evals = &mf.evaluations;
        let mg_evals = &mg.evaluations;
        let gamma_inverse = gamma.inverse().unwrap();
        
        // let mut debug_s1 = E::ScalarField::zero();
        // let mut debug_s2 = E::ScalarField::zero();
        // for i in 0..4 {
        //     debug_s1 += fhat[i] * mf_evals[i];
        //     debug_s2 += ghat[i] * mg_evals[i];
        //     println!("debug_s1: {:?}", debug_s1);
        //     println!("debug_s2: {:?}\n", debug_s2);
        // }
        
        
        let mut s1 = E::ScalarField::zero();
        let mut s2 = E::ScalarField::zero();
        for i in 0..2_usize.pow(nv as u32) {
            s1 += fhat[i] * mf_evals[i];
            s2 += ghat[i] * mg_evals[i];
        }
        if s1 + (gamma_inverse * null_offset) != s2 {
            return Err(PolyIOPErrors::InvalidParameters("BagMultiToolCheck prove err: LHS and RHS have different sums".to_string()));
        }
        let lhs_v = s1;
        let rhs_v = s2;
        
        // prove the sumcheck claim SUM(h) = 0
        let transcript_copy = transcript.clone();
        let lhs_sumcheck_proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&lhs, &mut transcript_copy.clone())?;
        let rhs_sumcheck_proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&rhs, &mut transcript_copy.clone())?;
        
        // debug: make sure the sumcheck claim verifies
        #[cfg(debug_assertions)]
        {
            println!("BagMultiToolCheck::prove Verifying sumchecks pass");
            // let mut transcript = <PolyIOP<E::ScalarField> as BagMultiToolCheck<E, PCS>>::init_transcript();
            // transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let aux_info = &lhs.aux_info.clone();
            let _ = <Self as SumCheck<E::ScalarField>>::verify(
                lhs_v,
                &lhs_sumcheck_proof,
                aux_info,
                &mut transcript_copy.clone(),
            )?;
            // let mut transcript = <PolyIOP<E::ScalarField> as BagMultiToolCheck<E, PCS>>::init_transcript();
            // transcript.append_message(b"testing", b"initializing transcript for testing")?;
            let aux_info = &rhs.aux_info.clone();
            let _ = <Self as SumCheck<E::ScalarField>>::verify(
                rhs_v,
                &rhs_sumcheck_proof,
                aux_info,
                &mut transcript_copy.clone(),
            )?;
            println!("BagMultiToolCheck::prove debug sumchecks passing!\n");

            let f_virt = VirtualPolynomial::new_from_mle(&f.clone(), E::ScalarField::one());
            println!("f aux_info: {:?}", f_virt.aux_info);
            println!("rhs aux_info: {:?}", rhs.clone().aux_info);
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
        
        let fhat_zero_check_proof = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(&fhat_check_poly, &mut transcript.clone())?;
        let ghat_zero_check_proof = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(&ghat_check_poly, &mut transcript.clone())?;

        #[cfg(debug_assertions)]
        {
            println!("BagMultiToolCheck::prove Verifying zerochecks pass");
            let aux_info = &fhat_check_poly.aux_info.clone();
            let _ = <Self as ZeroCheck<E::ScalarField>>::verify(
                &fhat_zero_check_proof,
                aux_info,
                &mut transcript.clone(),
            )?;

            let aux_info = &ghat_check_poly.aux_info.clone();
            let _ = <Self as ZeroCheck<E::ScalarField>>::verify(
                &ghat_zero_check_proof,
                aux_info,
                &mut transcript.clone(),
            )?;
            println!("BagMultiToolCheck::prove debug zerochecks passing!\n")
        }

        end_timer!(start);
        Ok((
            BagMultiToolCheckProof {
                null_offset,
                lhs_sumcheck_proof,
                rhs_sumcheck_proof,
                lhs_v,
                rhs_v,
                fhat_zero_check_proof,
                ghat_zero_check_proof,
                mf_comm,
                mg_comm,
                fhat_comm,
                ghat_comm,
            },
        ))
    }

    fn verification_info(
        _: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        _: &[Self::MultilinearExtension],
        _: &[Self::MultilinearExtension],
        _: &[Self::MultilinearExtension],
        _: E::ScalarField,
        _: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField> {
        let f_virt = VirtualPolynomial::new_from_mle(&fxs[0], E::ScalarField::one());
        let mut aux_info = f_virt.aux_info;
        aux_info.max_degree = aux_info.max_degree + 1; // comes from f_hat having a multiplication in prove()
        return aux_info
    }

    fn verify(
        proof: &Self::BagMultiToolCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::BagMultiToolCheckSubClaim, PolyIOPErrors> {
        let start = start_timer!(|| "BagMultiToolCheck verify");

        // update transcript and generate challenge
        transcript.append_serializable_element(b"mf(x)", &proof.mf_comm)?;
        transcript.append_serializable_element(b"mg(x)", &proof.mg_comm)?;
        transcript.append_serializable_element(b"null_offset", &proof.null_offset)?;
        let gamma = transcript.get_and_append_challenge(b"gamma")?;
        transcript.append_serializable_element(b"fhat(x)", &proof.fhat_comm)?;
        transcript.append_serializable_element(b"ghat(x)", &proof.ghat_comm)?;
        let lhs_v = proof.lhs_v;
        let rhs_v = proof.rhs_v;

        // check that the claimed sum values are equal
        let gamma_inverse = gamma.inverse().unwrap();
        let null_offset = proof.null_offset;
        if lhs_v + (gamma_inverse * null_offset) != rhs_v {
            return Err(PolyIOPErrors::InvalidVerifier("LHS and RHS have different sums".to_string()));
        }

        // invoke the respective IOP proofs for sumcheck, zerocheck fhat, zerocheck ghat
        let lhs_sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
            lhs_v,
            &proof.lhs_sumcheck_proof,
            aux_info,
            &mut transcript.clone(),
        )?;

        let rhs_sumcheck_subclaim = <Self as SumCheck<E::ScalarField>>::verify(
            rhs_v,
            &proof.rhs_sumcheck_proof,
            aux_info,
            &mut transcript.clone(),
        )?;

        let fhat_zerocheck_subclaim = <Self as ZeroCheck<E::ScalarField>>::verify(
            &proof.fhat_zero_check_proof,
            aux_info,
            &mut transcript.clone(),
        )?;
        let ghat_zerocheck_subclaim = <Self as ZeroCheck<E::ScalarField>>::verify(
            &proof.ghat_zero_check_proof,
            aux_info,
            &mut transcript.clone(),
        )?;

        end_timer!(start);
        Ok(BagMultiToolCheckSubClaim{
            null_offset,
            gamma,
            lhs_sumcheck_subclaim, 
            rhs_sumcheck_subclaim,
            lhs_v,
            rhs_v,
            fhat_zerocheck_subclaim,
            ghat_zerocheck_subclaim,
        })


    }
}

