use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        prelude::{IOPProof, ZeroCheckIOPSubClaim, SumCheckIOPSubClaim},
    },
    PCSError,
};
use transcript::IOPTranscript;

use crate::zksql_poly_iop::bag_multitool::bag_multitool::{BagMultiToolIOP, BagMultiToolIOPProof};

pub struct BagSumIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);


#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagSumIOPProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    pub null_offset: E::ScalarField,
    pub fhat0_comm: PCS::Commitment,
    pub fhat1_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
    pub lhs0_v: E::ScalarField,
    pub lhs1_v: E::ScalarField,
    pub rhs_v: E::ScalarField,
    pub lhs0_sumcheck_proof: IOPProof<E::ScalarField>,
    pub lhs1_sumcheck_proof: IOPProof<E::ScalarField>,
    pub rhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub fhat0_zerocheck_proof: IOPProof<E::ScalarField>,
    pub fhat1_zerocheck_proof: IOPProof<E::ScalarField>,
    pub ghat_zerocheck_proof: IOPProof<E::ScalarField>,
}

/// A BagSumCheck check subclaim consists of
/// two sumcheck subclaims, and the value v they should both equal
/// the random challenge gamma
/// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagSumIOPSubClaim<F: PrimeField> {
    pub null_offset: F,
    pub lhs0_v: F,
    pub lhs1_v: F,
    pub rhs_v: F,
    pub lhs0_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub lhs1_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub rhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub fhat0_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
    pub fhat1_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
    pub ghat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
}



impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSumIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>
{
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagSumIOP transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        fx0: Arc<DenseMultilinearExtension<E::ScalarField>>,
        fx1: Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: Arc<DenseMultilinearExtension<E::ScalarField>>,
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagSumIOPProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "bagsumCheck prove");

        // initialize multiplicity vectors
        let f0_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(fx0.num_vars, vec![E::ScalarField::one(); 2_usize.pow(fx0.num_vars as u32)]));
        let f1_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(fx1.num_vars, vec![E::ScalarField::one(); 2_usize.pow(fx1.num_vars as u32)]));
        let g_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(gx.num_vars, vec![E::ScalarField::one(); 2_usize.pow(gx.num_vars as u32)]));
        let mf = vec![f0_one_const_poly, f1_one_const_poly];
        let mg = vec![g_one_const_poly];

        // use bag_multitool
        let (bag_multitool_proof,) = BagMultiToolIOP::<E, PCS>::prove(pcs_param, &[fx0, fx1], &[gx], &mf.clone(), &mg.clone(), E::ScalarField::zero(),transcript)?;
        let bag_sum_iop_proof =  BagSumIOPProof::<E, PCS>{
            null_offset,
            fhat0_comm: bag_multitool_proof.fhat_comms[0].clone(),
            fhat1_comm: bag_multitool_proof.fhat_comms[1].clone(),
            ghat_comm: bag_multitool_proof.ghat_comms[0].clone(),
            lhs0_v:  bag_multitool_proof.lhs_vs[0],
            lhs1_v:  bag_multitool_proof.lhs_vs[1],
            rhs_v:  bag_multitool_proof.rhs_vs[0],
            lhs0_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proofs[0].clone(),
            lhs1_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proofs[1].clone(),
            rhs_sumcheck_proof: bag_multitool_proof.rhs_sumcheck_proofs[0].clone(),
            fhat0_zerocheck_proof: bag_multitool_proof.fhat_zerocheck_proofs[0].clone(),
            fhat1_zerocheck_proof: bag_multitool_proof.fhat_zerocheck_proofs[1].clone(),
            ghat_zerocheck_proof: bag_multitool_proof.ghat_zerocheck_proofs[0].clone(),
        };

        end_timer!(start);
        Ok((bag_sum_iop_proof,))
    }

    pub fn verification_info(
        pcs_param: &PCS::ProverParam,
        fx0: Arc<DenseMultilinearExtension<E::ScalarField>>,
        fx1: Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: Arc<DenseMultilinearExtension<E::ScalarField>>,
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            VPAuxInfo<E::ScalarField>, 
            VPAuxInfo<E::ScalarField>,
            VPAuxInfo<E::ScalarField>
        ),
        PolyIOPErrors,
    > {
        let fx0_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(fx0.num_vars, vec![E::ScalarField::one(); 2_usize.pow(fx0.num_vars as u32)]));
        let fx1_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(fx1.num_vars, vec![E::ScalarField::one(); 2_usize.pow(fx1.num_vars as u32)]));
        let g_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(gx.num_vars, vec![E::ScalarField::one(); 2_usize.pow(gx.num_vars as u32)]));

        let fxs = vec![fx0, fx1];
        let gxs = vec![gx];
        let mfs = vec![fx0_one_const_poly, fx1_one_const_poly];
        let mgs = vec![g_one_const_poly];
        let (f_aux_info, g_aux_info) = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, &fxs, &gxs, &mfs, &mgs, null_offset, transcript);
        return Ok((f_aux_info[0].clone(), f_aux_info[1].clone(), g_aux_info[0].clone()))
    }

    pub fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &BagSumIOPProof<E, PCS>,
        fx1_aux_info: &VPAuxInfo<E::ScalarField>,
        fx2_aux_info: &VPAuxInfo<E::ScalarField>,
        gx_aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagSumIOPSubClaim<E::ScalarField>, PolyIOPErrors> {


        println!("proof.lhs0_v: {}", proof.lhs0_v);
        println!("proof.lhs1_v: {}", proof.lhs1_v);
        println!("proof.rhs_v: {}", proof.rhs_v);
        println!("proof.null_offset: {}", proof.null_offset);


        let start = start_timer!(|| "bagsumCheck verify");
        let bag_multitool_proof = Self::bagsum_proof_to_bagmulti_proof(pcs_param,proof, fx1_aux_info.num_variables, fx2_aux_info.num_variables, gx_aux_info.num_variables)?;
        let bag_multitool_subclaim = BagMultiToolIOP::verify(&bag_multitool_proof, &vec![fx1_aux_info.clone(), fx2_aux_info.clone()], &vec![gx_aux_info.clone()], transcript)?;
 
         end_timer!(start);
         Ok(BagSumIOPSubClaim{
            null_offset: bag_multitool_subclaim.null_offset,
            lhs0_v: bag_multitool_subclaim.lhs_vs[0],
            lhs1_v: bag_multitool_subclaim.lhs_vs[1],
            rhs_v: bag_multitool_subclaim.rhs_vs[0],
            lhs0_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaims[0].clone(),
            lhs1_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaims[1].clone(),
            rhs_sumcheck_subclaim: bag_multitool_subclaim.rhs_sumcheck_subclaims[0].clone(),
            fhat0_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaims[0].clone(),
            fhat1_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaims[1].clone(),
            ghat_zerocheck_subclaim: bag_multitool_subclaim.ghat_zerocheck_subclaims[0].clone(),
        })
    }

    fn bagsum_proof_to_bagmulti_proof(pcs_param: &PCS::ProverParam, bagsum_proof: &BagSumIOPProof<E, PCS>, f0nv: usize, f1nv: usize, gnv: usize) -> Result<BagMultiToolIOPProof<E, PCS>, PCSError> {
        // get the commitments for the multiplicity polynomials
        let fx0_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(f0nv, vec![E::ScalarField::one(); 2_usize.pow(f0nv as u32)]));
        let fx1_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(f1nv, vec![E::ScalarField::one(); 2_usize.pow(f1nv as u32)]));
        let g_one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(gnv, vec![E::ScalarField::one(); 2_usize.pow(gnv as u32)]));
        
        let mf_comm0 = PCS::commit(pcs_param, &fx0_one_const_poly)?;
        let mf_comm1 = PCS::commit(pcs_param, &fx1_one_const_poly)?;
        let mg_comm = PCS::commit(pcs_param, &g_one_const_poly)?;

        let mf_comms = vec![mf_comm0.clone(), mf_comm1.clone()];
        let mg_comms  = vec![mg_comm.clone()];

        let bag_multitool_proof: BagMultiToolIOPProof::<E, PCS> = BagMultiToolIOPProof{
            null_offset: bagsum_proof.null_offset,
            lhs_sumcheck_proofs: vec![bagsum_proof.lhs0_sumcheck_proof.clone(), bagsum_proof.lhs1_sumcheck_proof.clone()],
            rhs_sumcheck_proofs: vec![bagsum_proof.rhs_sumcheck_proof.clone()],
            lhs_vs:  vec![bagsum_proof.lhs0_v, bagsum_proof.lhs1_v],
            rhs_vs:  vec![bagsum_proof.rhs_v],
            fhat_zerocheck_proofs: vec![bagsum_proof.fhat0_zerocheck_proof.clone(), bagsum_proof.fhat1_zerocheck_proof.clone()],
            ghat_zerocheck_proofs: vec![bagsum_proof.ghat_zerocheck_proof.clone()],
            mf_comms: mf_comms.clone(),
            mg_comms: mg_comms.clone(),
            fhat_comms: vec![bagsum_proof.fhat0_comm.clone(), bagsum_proof.fhat1_comm.clone()],
            ghat_comms: vec![bagsum_proof.ghat_comm.clone()],
        };

        return Ok(bag_multitool_proof)
    }

}