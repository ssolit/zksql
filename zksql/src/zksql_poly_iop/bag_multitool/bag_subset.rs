use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer};
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

use super::bag_multitool::{BagMultiToolIOP, BagMultiToolIOPProof};

pub struct BagSubsetIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagSubsetIOPProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    pub null_offset: E::ScalarField,
    pub lhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub rhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub lhs_v: E::ScalarField,
    pub rhs_v: E::ScalarField,
    pub fhat_zerocheck_proof: IOPProof<E::ScalarField>,
    pub ghat_zerocheck_proof: IOPProof<E::ScalarField>,
    pub mg_comm: PCS::Commitment,
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}

/// A BagSubsetCheck check subclaim consists of
/// two sumcheck subclaims, and the value v they should both equal
/// the random challenge gamma
/// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagSubsetIOPSubClaim<F: PrimeField> {
    // pub null_offset: F,
    // pub gamma: F,
    pub lhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub rhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    // pub lhs_v: F,
    // pub rhs_v: F,
    pub fhat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
    pub ghat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
}


impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSubsetIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>> {
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagSubsetCheck transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        fx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        mg: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagSubsetIOPProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "BagSubsetCheck prove");

        if fx.num_vars != gx.num_vars {
            return Err(PolyIOPErrors::InvalidParameters(
                "fx and gx have different number of variables".to_string(),
            ));
        }
        let nv = fx.num_vars;

        // initialize multiplicity vector
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mf = one_const_poly.clone();

        // call the bag_multitool prover
        let (bag_multitool_proof,) = BagMultiToolIOP::<E, PCS>::prove(pcs_param, &[fx.clone()], &[gx.clone()], &[mf], &[mg.clone()], null_offset, transcript)?;    
        
        // reshape the bag_multitool proof into a bag_subset proof
        let bag_subset_check_proof =  BagSubsetIOPProof::<E, PCS>{
            null_offset: bag_multitool_proof.null_offset,
            lhs_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proofs[0].clone(),
            rhs_sumcheck_proof: bag_multitool_proof.rhs_sumcheck_proofs[0].clone(),
            lhs_v:  bag_multitool_proof.lhs_vs[0],
            rhs_v:  bag_multitool_proof.rhs_vs[0],
            fhat_zerocheck_proof: bag_multitool_proof.fhat_zerocheck_proofs[0].clone(),
            ghat_zerocheck_proof: bag_multitool_proof.ghat_zerocheck_proofs[0].clone(),
            mg_comm: bag_multitool_proof.mg_comms[0].clone(),
            fhat_comm: bag_multitool_proof.fhat_comms[0].clone(),
            ghat_comm: bag_multitool_proof.ghat_comms[0].clone(),
        };

        end_timer!(start);
        Ok((bag_subset_check_proof,))
    }

    pub fn verification_info (
        pcs_param: &PCS::ProverParam,
        fx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        mg: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField> {
        let nv = fx.num_vars;
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mf = vec![one_const_poly.clone()];
        let (f_aux_info, _) = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, &[fx.clone()], &[gx.clone()], &mf, &[mg.clone()], null_offset, transcript);
        return f_aux_info[0].clone()
    }

    pub fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &BagSubsetIOPProof<E, PCS>,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagSubsetIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
        let start = start_timer!(|| "BagSubsetCheck verify");
        let nv = aux_info.num_variables;

        let bag_multitool_proof = Self::bagsubset_proof_to_bagmulti_proof(pcs_param, nv, proof)?;
        let bag_multitool_subclaim = BagMultiToolIOP::verify(&bag_multitool_proof, &vec![aux_info.clone()], &vec![aux_info.clone()], transcript)?;
 
         end_timer!(start);
         Ok(BagSubsetIOPSubClaim{
            // null_offset: bag_multitool_subclaim.null_offset,
            lhs_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaims[0].clone(),
            rhs_sumcheck_subclaim: bag_multitool_subclaim.rhs_sumcheck_subclaims[0].clone(),
            // lhs_v: bag_multitool_subclaim.lhs_vs[0],
            // rhs_v: bag_multitool_subclaim.rhs_vs[0],
            // gamma: bag_multitool_subclaim.gamma,
            fhat_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaims[0].clone(),
            ghat_zerocheck_subclaim: bag_multitool_subclaim.ghat_zerocheck_subclaims[0].clone(),
        })
    }

    fn bagsubset_proof_to_bagmulti_proof(pcs_param: &PCS::ProverParam, nv: usize, bagsubset_proof: &BagSubsetIOPProof<E, PCS>) -> Result<BagMultiToolIOPProof::<E, PCS>, PCSError> {
        // initialize multiplicity vector of all ones
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mf_comm = PCS::commit(pcs_param, &one_const_poly)?; 
        
        // reformat proof to a BagMultiToolCheck proof
        let bag_multitool_proof: BagMultiToolIOPProof::<E, PCS> = BagMultiToolIOPProof{
            null_offset: bagsubset_proof.null_offset,
            lhs_sumcheck_proofs: vec![bagsubset_proof.lhs_sumcheck_proof.clone()],
            rhs_sumcheck_proofs: vec![bagsubset_proof.rhs_sumcheck_proof.clone()],
            lhs_vs:  vec![bagsubset_proof.lhs_v],
            rhs_vs:  vec![bagsubset_proof.rhs_v],
            fhat_zerocheck_proofs: vec![bagsubset_proof.fhat_zerocheck_proof.clone()],
            ghat_zerocheck_proofs: vec![bagsubset_proof.ghat_zerocheck_proof.clone()],
            mf_comms: vec![mf_comm.clone()],
            mg_comms: vec![bagsubset_proof.mg_comm.clone()],
            fhat_comms: vec![bagsubset_proof.fhat_comm.clone()],
            ghat_comms: vec![bagsubset_proof.ghat_comm.clone()],
        };

        return Ok(bag_multitool_proof)
    }
}