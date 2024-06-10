use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::Debug, marker::PhantomData, ops::Neg, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        prelude::{SumCheckIOP, SumCheckIOPSubClaim, ZeroCheckIOP, ZeroCheckIOPSubClaim},
    },
    IOPProof,
};
use transcript::IOPTranscript;



pub struct BagMultiToolIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagMultiToolIOPProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,

> {
    pub null_offset: E::ScalarField,
    pub mf_comms: Vec<PCS::Commitment>,
    pub mg_comms: Vec<PCS::Commitment>,
    pub fhat_comms: Vec<PCS::Commitment>,
    pub ghat_comms: Vec<PCS::Commitment>,
    pub lhs_vs: Vec<E::ScalarField>,
    pub rhs_vs: Vec<E::ScalarField>,
    pub lhs_sumcheck_proofs: Vec<IOPProof<E::ScalarField>>,
    pub rhs_sumcheck_proofs: Vec<IOPProof<E::ScalarField>>,
    pub fhat_zerocheck_proofs: Vec<IOPProof<E::ScalarField>>,
    pub ghat_zerocheck_proofs: Vec<IOPProof<E::ScalarField>>,
}

/// A BagMultiToolCheck subclaim consists of
/// - A zero check IOP subclaim for the virtual polynomial
/// - The random challenge `alpha`
/// - A final query for `prod(1, ..., 1, 0) = 1`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagMultiToolIOPSubClaim<F: PrimeField> {
    pub lhs_sumcheck_subclaims: Vec<SumCheckIOPSubClaim<F>>,
    pub rhs_sumcheck_subclaims: Vec<SumCheckIOPSubClaim<F>>,
    pub fhat_zerocheck_subclaims: Vec<ZeroCheckIOPSubClaim<F>>,
    pub ghat_zerocheck_subclaims: Vec<ZeroCheckIOPSubClaim<F>>,
}


impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagMultiToolIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>
{
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagMultiToolCheck transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mfxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mgxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagMultiToolIOPProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "BagMultiTool_check prove");

        // check input shapes are correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and mf have different number of polynomials".to_string(),
            ));
        }
        for i in 0..fxs.len() {
            if fxs[i].num_vars != mfxs[i].num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "fxs[i] and mfxs[i] have different number of polynomials".to_string(),
                ));
            }
        }

        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
       
        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and mf have different number of polynomials".to_string(),
            ));
        }
        for i in 0..gxs.len() {
            if gxs[i].num_vars != mgxs[i].num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "gxs[i] and mgxs[i] have different number of polynomials".to_string(),
                ));
            }
        }

        // initialize output vectors
        let mut mf_comms = Vec::<PCS::Commitment>::new();
        let mut mg_comms = Vec::<PCS::Commitment>::new();
        let mut fhat_comms = Vec::<PCS::Commitment>::new();
        let mut ghat_comms = Vec::<PCS::Commitment>::new();
        let mut lhs_vs = Vec::<E::ScalarField>::new();
        let mut rhs_vs = Vec::<E::ScalarField>::new();
        let mut lhs_sumcheck_proofs = Vec::<IOPProof<E::ScalarField>>::new();
        let mut rhs_sumcheck_proofs = Vec::<IOPProof<E::ScalarField>>::new();
        let mut fhat_zerocheck_proofs = Vec::<IOPProof<E::ScalarField>>::new();
        let mut ghat_zerocheck_proofs = Vec::<IOPProof<E::ScalarField>>::new();


        // initialize transcript 
        // let mut transcript = Self::init_transcript();
        for i in 0..mfxs.len() {
            let mf_comm = PCS::commit(pcs_param, &mfxs[i])?;
            transcript.append_serializable_element(b"mf", &mf_comm)?;
            mf_comms.push(mf_comm);
        }
        for i in 0..mgxs.len() {
            let mg_comm = PCS::commit(pcs_param, &mgxs[i])?;
            transcript.append_serializable_element(b"mg", &mg_comm)?;
            mg_comms.push(mg_comm);
        }
        transcript.append_serializable_element(b"null_offset", &null_offset)?;
        let gamma = transcript.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and prove:
        for i in 0..fxs.len() {
            let (phat_comm, v, challenge_poly_sumcheck_proof, phat_zero_check_proof) = Self::prove_one_multiplicity_sum(pcs_param, fxs[i].clone(), mfxs[i].clone(), gamma, transcript)?;
            fhat_comms.push(phat_comm);
            lhs_vs.push(v);
            lhs_sumcheck_proofs.push(challenge_poly_sumcheck_proof);
            fhat_zerocheck_proofs.push(phat_zero_check_proof);
        }   

        for i in 0..gxs.len() {
            let (phat_comm, v, challenge_poly_sumcheck_proof, phat_zero_check_proof) = Self::prove_one_multiplicity_sum(pcs_param, gxs[i].clone(), mgxs[i].clone(), gamma, transcript)?;
            ghat_comms.push(phat_comm);
            rhs_vs.push(v);
            rhs_sumcheck_proofs.push(challenge_poly_sumcheck_proof);
            ghat_zerocheck_proofs.push(phat_zero_check_proof);
        } 

        end_timer!(start);
        Ok((
            BagMultiToolIOPProof::<E, PCS> {
                null_offset,
                mf_comms,
                mg_comms,
                fhat_comms,
                ghat_comms,
                lhs_vs,
                rhs_vs,
                lhs_sumcheck_proofs,
                rhs_sumcheck_proofs,
                fhat_zerocheck_proofs,
                ghat_zerocheck_proofs,
            },
        ))
    }

    fn prove_one_multiplicity_sum(
        pcs_param: &PCS::ProverParam,
        p: Arc<DenseMultilinearExtension<E::ScalarField>>,
        m: Arc<DenseMultilinearExtension<E::ScalarField>>,
        gamma: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            PCS::Commitment,
            E::ScalarField,
            IOPProof<E::ScalarField>,
            IOPProof<E::ScalarField>,
        ),
        PolyIOPErrors,
    > {
        let nv = p.num_vars;
        
        let mut p_evals = p.evaluations.clone();
        let mut p_minus_gamma: Vec<<E as Pairing>::ScalarField> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat = Arc::new(DenseMultilinearExtension::from_evaluations_slice(nv, phat_evals));
        let phat_comm = PCS::commit(pcs_param, &phat)?; 
        transcript.append_serializable_element(b"phat(x)", &phat_comm)?;
        
        let mut challenge_poly = VirtualPolynomial::new(nv);
        challenge_poly.add_mle_list([phat.clone(), m.clone()], E::ScalarField::one())?; // cloning Arc ptr b/c need fhat again below
        
        let m_evals = &m.evaluations;
        let mut v = E::ScalarField::zero();
        for i in 0..2_usize.pow(nv as u32) {
            v += phat[i] * m_evals[i];
        }
        let challenge_poly_sumcheck_proof = SumCheckIOP::<E::ScalarField>::prove(&challenge_poly, &mut transcript.clone())?;

        // prove phat(x) is created correctly, i.e. ZeroCheck [(p(x)-gamma) * phat(x)  - 1]
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let gamma_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![gamma.clone(); 2_usize.pow(nv as u32)]));

        let mut phat_check_poly = VirtualPolynomial::new_from_mle(&p, E::ScalarField::one());
        phat_check_poly.add_mle_list([gamma_const_poly.clone()], E::ScalarField::one().neg())?;
        phat_check_poly.mul_by_mle(phat, E::ScalarField::one())?;
        phat_check_poly.add_mle_list([one_const_poly.clone()], E::ScalarField::one().neg())?;

        let phat_zero_check_proof = ZeroCheckIOP::<E::ScalarField>::prove(&phat_check_poly, &mut transcript.clone())?;

        return Ok((phat_comm, v, challenge_poly_sumcheck_proof, phat_zero_check_proof))

    }

    pub fn verification_info(
        _: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        _: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        _: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        _: E::ScalarField,
        _: &mut IOPTranscript<E::ScalarField>,
    ) -> (Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>) {
        let mut f_aux_info = Vec::new();
        let mut g_aux_info = Vec::new();
        for fx in fxs.iter() {
            let virt = VirtualPolynomial::new_from_mle(&fx, E::ScalarField::one());
            let mut aux_info = virt.aux_info.clone();
            aux_info.max_degree = aux_info.max_degree + 1; // comes from f_hat having a multiplication in prove()
            f_aux_info.push(aux_info);
        }
        for gx in gxs.iter() {
            let virt = VirtualPolynomial::new_from_mle(&gx, E::ScalarField::one());
            let mut aux_info = virt.aux_info.clone();
            aux_info.max_degree = aux_info.max_degree + 1; // comes from g_hat having a multiplication in prove()
            g_aux_info.push(aux_info);
        }
        return (f_aux_info, g_aux_info)
    }

    pub fn verify(
        proof: &BagMultiToolIOPProof<E, PCS>,
        f_aux_info: &Vec<VPAuxInfo<E::ScalarField>>,
        g_aux_info: &Vec<VPAuxInfo<E::ScalarField>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagMultiToolIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
        let start = start_timer!(|| "BagMultiToolCheck verify");


        // initialize transcript 
        for i in 0..proof.mf_comms.len() {
            let mf_comm = proof.mf_comms[i].clone();
            transcript.append_serializable_element(b"mf", &mf_comm)?;
        }
        for i in 0..proof.mg_comms.len() {
            let mg_comm = proof.mg_comms[i].clone();
            transcript.append_serializable_element(b"mg", &mg_comm)?;
        }
        transcript.append_serializable_element(b"null_offset", &proof.null_offset)?;
        let gamma = transcript.get_and_append_challenge(b"gamma")?;

        // check that the values of claimed sums are equal with factoring in null_offset
        let gamma_inverse = gamma.inverse().unwrap();
        let null_offset = proof.null_offset;
        let lhs_v: E::ScalarField = proof.lhs_vs.iter().sum();
        let rhs_v: E::ScalarField = proof.rhs_vs.iter().sum();

        if lhs_v + (gamma_inverse * null_offset) != rhs_v {
            let mut err_msg = "LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            err_msg.push_str(&format!(" null_offset: {}", null_offset));
            err_msg.push_str(&format!(" gamma_inverse: {}", gamma_inverse));
            return Err(PolyIOPErrors::InvalidVerifier(err_msg));
        }

        // create the subclaims for each sumcheck and zerocheck
        let mut lhs_sumcheck_subclaims = Vec::<SumCheckIOPSubClaim<E::ScalarField>>::new();
        let mut rhs_sumcheck_subclaims = Vec::<SumCheckIOPSubClaim<E::ScalarField>>::new();
        let mut fhat_zerocheck_subclaims = Vec::<ZeroCheckIOPSubClaim<E::ScalarField>>::new();
        let mut ghat_zerocheck_subclaims = Vec::<ZeroCheckIOPSubClaim<E::ScalarField>>::new();

        for i in 0..proof.lhs_sumcheck_proofs.len() {
            transcript.append_serializable_element(b"phat(x)", &proof.fhat_comms[i])?;
            
            let lhs_sumcheck_subclaim = SumCheckIOP::<E::ScalarField>::verify(
                proof.lhs_vs[i],
                &proof.lhs_sumcheck_proofs[i],
                &f_aux_info[i],
                &mut transcript.clone(),
            )?;
            lhs_sumcheck_subclaims.push(lhs_sumcheck_subclaim);

            let fhat_zerocheck_subclaim = ZeroCheckIOP::<E::ScalarField>::verify(
                &proof.fhat_zerocheck_proofs[i],
                &  f_aux_info[i],
                &mut transcript.clone(),
            )?;
            fhat_zerocheck_subclaims.push(fhat_zerocheck_subclaim);
        }
        for i in 0..proof.rhs_sumcheck_proofs.len() {
            transcript.append_serializable_element(b"phat(x)", &proof.ghat_comms[i])?;
            let rhs_sumcheck_subclaim = SumCheckIOP::<E::ScalarField>::verify(
                proof.rhs_vs[i],
                &proof.rhs_sumcheck_proofs[i],
                &g_aux_info[i],
                &mut transcript.clone(),
            )?;
            rhs_sumcheck_subclaims.push(rhs_sumcheck_subclaim);

            let ghat_zerocheck_subclaim = ZeroCheckIOP::<E::ScalarField>::verify(
                &proof.ghat_zerocheck_proofs[i],
                &g_aux_info[i],
                &mut transcript.clone(),
            )?;
            ghat_zerocheck_subclaims.push(ghat_zerocheck_subclaim);
        }

        end_timer!(start);
        Ok(BagMultiToolIOPSubClaim::<E::ScalarField>{
            lhs_sumcheck_subclaims, 
            rhs_sumcheck_subclaims,
            fhat_zerocheck_subclaims,
            ghat_zerocheck_subclaims,
        })
    }
}