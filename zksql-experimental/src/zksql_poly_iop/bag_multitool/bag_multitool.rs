// use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::{Debug}, marker::PhantomData, ops::Neg, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        // prelude::{SumCheckIOP, SumCheckIOPSubClaim, ZeroCheckIOP, ZeroCheckIOPSubClaim},
    },
    IOPProof,
};
use transcript::IOPTranscript;

use crate::utils::tracker::{IOPClaimTracker, PolyID, TrackerRef};


pub type ArcMLE<E> = Arc<DenseMultilinearExtension<<E as Pairing>::ScalarField>>;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bag<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly: PolyID,
    pub selector: PolyID,
    pub tracker: TrackerRef<E, PCS>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> Bag<E, PCS> {
    pub fn new(poly: PolyID, selector: PolyID, tracker: TrackerRef<E, PCS>) -> Self {
        Self {
            poly,
            selector,
            tracker,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagComm<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly_comm: PCS::Commitment,
    pub selector_comm: PCS::Commitment,
}


pub struct BagMultiToolIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagMultiToolIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = ArcMLE<E>>
{
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagMultiToolCheck transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Bag<E>],
        gxs: &[Bag<E>],
        mfxs: &[ArcLPoly<E>],
        mgxs: &[ArcLPoly<E>],
        transcript: &mut IOPTranscript<E::ScalarField>,
        claim_tracker: &mut IOPClaimTracker<E, PCS>,
    ) -> Result<(),PolyIOPErrors> {


        // fn prover(tracker: &mut IOPClaimTracker<E, PCS>) -> Proof {
        //     // generate a polynomial p in previous steps 
        //     let (id, cm) = tracker.add_mat_comm(p); // This guy will update the internal HashMap (materialized_polys and materialized_cms)
        //     let challenge = tracker.challenge();
        //     let evaluation = tracker.evaluate(id, challenge); // This will update the internal HashMap `(id, point) -> evaluation`
        //     tracker.compile_proof() // Return a Proof, and internally invokes PCS::open
        // }



        let start = start_timer!(|| "BagMultiTool_check prove");

        // check input shapes are correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultiToolIOP Error: fxs is empty".to_string()));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultiToolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }

        for i in 0..fxs.len() {
            if fxs[i].poly.num_vars() != mfxs[i].num_vars() {
                return Err(PolyIOPErrors::InvalidParameters(
                    "BagMultiToolIOP Error: fxs[i] and mfxs[i] have different number of polynomials".to_string(),
                ));
            }
        }

        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultiToolIOP Error: fxs is empty".to_string()));
        }
       
        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultiToolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }
        for i in 0..gxs.len() {
            if gxs[i].num_vars != mgxs[i].num_vars() {
                return Err(PolyIOPErrors::InvalidParameters(
                    "BagMultiToolIOP Error: gxs[i] and mgxs[i] have different number of polynomials".to_string(),
                ));
            }
        }


        // initialize transcript 
        // let mut transcript = Self::init_transcript();
        // for i in 0..mfxs.len() {
        //     let mf_comm = PCS::commit(pcs_param, &mfxs[i])?;
        //     transcript.append_serializable_element(b"mf", &mf_comm)?;
        //     // mf_comms.push(mf_comm);
        // }
        // for i in 0..mgxs.len() {
        //     let mg_comm = PCS::commit(pcs_param, &mgxs[i])?;
        //     transcript.append_serializable_element(b"mg", &mg_comm)?;
        //     // mg_comms.push(mg_comm);
        // }
        let gamma = transcript.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and generate subclaims:
        for i in 0..fxs.len() {
            Self::generate_subclaims(pcs_param, fxs[i].clone(), mfxs[i].clone(), gamma, transcript, claim_tracker)?;
        }   

        for i in 0..gxs.len() {
            Self::generate_subclaims(pcs_param, gxs[i].clone(), mgxs[i].clone(), gamma, transcript, claim_tracker)?;
        } 

        end_timer!(start);
        Ok(())
    }

    fn generate_subclaims(
        pcs_param: &PCS::ProverParam,
        bag: Bag<E>,
        m: ArcLPoly<E>,
        gamma: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
        claim_tracker: &mut IOPClaimTracker<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let nv = bag.num_vars;
        
        // construct phat = 1/(bag.p(x) - gamma), i.e. the denominator of the sum
        let p = bag.poly;
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<<E as Pairing>::ScalarField> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = Arc::new(DenseMultilinearExtension::from_evaluations_slice(nv, phat_evals));
        let phat_comm = PCS::commit(pcs_param, &phat_mle)?; 
        transcript.append_serializable_element(b"phat(x)", &phat_comm)?;

        // calculate what the final sum should be
        let m_evals = &m.evaluations();
        let selector_evals = &bag.selector.evaluations();
        let mut v = E::ScalarField::zero();
        for i in 0..2_usize.pow(nv as u32) {
            v += phat_mle[i] * m_evals[i] * selector_evals[i];
        }
        
        // construct the full challenge polynomial by taking phat and multiplying by the selector and multiplicities
        let phat_label_prefix = "bag_multitool_phat".to_string();
        let phat = Arc::new(LabeledPolynomial::new_with_label_prefix(phat_label_prefix, phat_mle));
        let sumcheck_challenge_poly_prefix = "bag_multitool_sumcheck_challenge_poly".to_string();
        let mut sumcheck_challenge_poly = LabeledVirtualPolynomial::new(nv);
        sumcheck_challenge_poly.label = LabeledPolynomial::<E::ScalarField>::generate_new_label_with_prefix(sumcheck_challenge_poly_prefix);
        sumcheck_challenge_poly.add_mle_list([phat.clone(), m.clone(), bag.selector], E::ScalarField::one())?;

        type MLE<F> = DenseMultilinearExtension<F>;
       
        // Create Zerocheck claim for procing phat(x) is created correctly, 
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x)  - 1]
        let one_const_mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let one_const_label_prefix = format!("one_const_{}_", nv);
        let one_const_poly = Arc::new(LabeledPolynomial::new_with_label_prefix(one_const_label_prefix, one_const_mle));
        let gamma_const_mle = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![gamma.clone(); 2_usize.pow(nv as u32)]));
        let gamma_const_label_prefix = format!("gamma_const_{}_", gamma);
        let gamma_const_poly = Arc::new(LabeledPolynomial::new_with_label_prefix(gamma_const_label_prefix, gamma_const_mle));

        let phat_check_prefix = "bag_multitool_phat_check_".to_string();
        let mut phat_check_poly = LabeledVirtualPolynomial::new_with_label_prefix(phat_check_prefix, p.num_vars());
        phat_check_poly.add_mle_list([p], E::ScalarField::one())?;
        phat_check_poly.add_mle_list([gamma_const_poly.clone()], E::ScalarField::one().neg())?;
        phat_check_poly.mul_by_mle(phat, E::ScalarField::one())?;
        phat_check_poly.add_mle_list([one_const_poly.clone()], E::ScalarField::one().neg())?;

        // add the delayed prover claims to the tracker
        claim_tracker.add_sumcheck_claim_from_virtual_poly(sumcheck_challenge_poly, v);
        claim_tracker.add_zerocheck_claim_from_virtual_poly(phat_check_poly);

        return Ok(())

    }

    // pub fn verification_info(
    //     _: &PCS::ProverParam,
    //     fxs: &[Bag<E>],
    //     gxs: &[Bag<E>],
    //     _: &[ArcLPoly<E>],
    //     _: &[ArcLPoly<E>],
    //     _: &mut IOPTranscript<E::ScalarField>,
    // ) -> (Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>) {
    //     let mut f_sc_info = Vec::new();
    //     let mut f_zc_info = Vec::new();
    //     let mut g_sc_info = Vec::new();
    //     let mut g_zc_info = Vec::new();

    //     for fx in fxs.iter() {
    //         f_sc_info.push(
    //             VPAuxInfo{
    //                 max_degree: 3, // comes from prove() creating phat with 2 multiplications
    //                 num_variables: fx.num_vars,
    //                 phantom: PhantomData::default(),
    //             }
    //         );
    //         f_zc_info.push(
    //             VPAuxInfo{
    //                 max_degree: 2, 
    //                 num_variables: fx.num_vars,
    //                 phantom: PhantomData::default(),
    //             }
    //         )
    //     }
    //     for gx in gxs.iter() {
    //         g_sc_info.push(
    //             VPAuxInfo{
    //                 max_degree: 3, // comes from prove() creating phat with 2 multiplications
    //                 num_variables: gx.num_vars,
    //                 phantom: PhantomData::default(),
    //             }
    //         );
    //         g_zc_info.push(
    //             VPAuxInfo{
    //                 max_degree: 2, 
    //                 num_variables: gx.num_vars,
    //                 phantom: PhantomData::default(),
    //             }
    //         )
    //     }
    //     return (f_sc_info, f_zc_info, g_sc_info, g_zc_info)
    // }

    // pub fn verify(
    //     proof: &BagMultiToolIOPProof<E, PCS>,
    //     f_sc_info: &Vec<VPAuxInfo<E::ScalarField>>,
    //     f_zc_info: &Vec<VPAuxInfo<E::ScalarField>>,
    //     g_sc_info: &Vec<VPAuxInfo<E::ScalarField>>,
    //     g_zc_info: &Vec<VPAuxInfo<E::ScalarField>>,
    //     transcript: &mut IOPTranscript<E::ScalarField>,
    // ) -> Result<BagMultiToolIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
    //     let start = start_timer!(|| "BagMultiToolCheck verify");


    //     // initialize transcript 
    //     for i in 0..proof.mf_comms.len() {
    //         let mf_comm = proof.mf_comms[i].clone();
    //         transcript.append_serializable_element(b"mf", &mf_comm)?;
    //     }
    //     for i in 0..proof.mg_comms.len() {
    //         let mg_comm = proof.mg_comms[i].clone();
    //         transcript.append_serializable_element(b"mg", &mg_comm)?;
    //     }
    //     let gamma = transcript.get_and_append_challenge(b"gamma")?;

    //     // check that the values of claimed sums are equal with factoring in null_offset
    //     let gamma_inverse = gamma.inverse().unwrap();
    //     let lhs_v: E::ScalarField = proof.lhs_vs.iter().sum();
    //     let rhs_v: E::ScalarField = proof.rhs_vs.iter().sum();

    //     if lhs_v != rhs_v {
    //         let mut err_msg = "BagMutltiTool Verify Error: LHS and RHS have different sums".to_string();
    //         err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
    //         err_msg.push_str(&format!(" gamma_inverse: {}", gamma_inverse));
    //         return Err(PolyIOPErrors::InvalidVerifier(err_msg));
    //     }

    //     // create the subclaims for each sumcheck and zerocheck
    //     let mut lhs_sumcheck_subclaims = Vec::<SumCheckIOPSubClaim<E::ScalarField>>::new();
    //     let mut rhs_sumcheck_subclaims = Vec::<SumCheckIOPSubClaim<E::ScalarField>>::new();
    //     let mut fhat_zerocheck_subclaims = Vec::<ZeroCheckIOPSubClaim<E::ScalarField>>::new();
    //     let mut ghat_zerocheck_subclaims = Vec::<ZeroCheckIOPSubClaim<E::ScalarField>>::new();

    //     // println!("BagMutltiTool Verify: starting lhs subchecks");
    //     for i in 0..proof.lhs_sumcheck_proofs.len() {
    //         transcript.append_serializable_element(b"phat(x)", &proof.fhat_comms[i])?;
            
    //         let lhs_sumcheck_subclaim = SumCheckIOP::<E::ScalarField>::verify(
    //             proof.lhs_vs[i],
    //             &proof.lhs_sumcheck_proofs[i],
    //             &f_sc_info[i],
    //             &mut transcript.clone(),
    //         )?;
    //         lhs_sumcheck_subclaims.push(lhs_sumcheck_subclaim);

    //         let fhat_zerocheck_subclaim = ZeroCheckIOP::<E::ScalarField>::verify(
    //             &proof.fhat_zerocheck_proofs[i],
    //             &f_zc_info[i],
    //             &mut transcript.clone(),
    //         )?;
    //         fhat_zerocheck_subclaims.push(fhat_zerocheck_subclaim);
    //     }
    //     // println!("BagMutltiTool Verify: starting rhs subchecks");
    //     for i in 0..proof.rhs_sumcheck_proofs.len() {
    //         transcript.append_serializable_element(b"phat(x)", &proof.ghat_comms[i])?;
    //         let rhs_sumcheck_subclaim = SumCheckIOP::<E::ScalarField>::verify(
    //             proof.rhs_vs[i],
    //             &proof.rhs_sumcheck_proofs[i],
    //             &g_sc_info[i],
    //             &mut transcript.clone(),
    //         )?;
    //         rhs_sumcheck_subclaims.push(rhs_sumcheck_subclaim);

    //         let ghat_zerocheck_subclaim = ZeroCheckIOP::<E::ScalarField>::verify(
    //             &proof.ghat_zerocheck_proofs[i],
    //             &g_zc_info[i],
    //             &mut transcript.clone(),
    //         )?;
    //         ghat_zerocheck_subclaims.push(ghat_zerocheck_subclaim);
    //     }

    //     end_timer!(start);
    //     Ok(BagMultiToolIOPSubClaim::<E::ScalarField>{
    //         lhs_sumcheck_subclaims, 
    //         rhs_sumcheck_subclaims,
    //         fhat_zerocheck_subclaims,
    //         ghat_zerocheck_subclaims,
    //     })
    // }
}