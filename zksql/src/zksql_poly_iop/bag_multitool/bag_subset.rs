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
pub struct BagSubsetCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    pub null_offset: E::ScalarField,
    pub lhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub rhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub lhs_v: E::ScalarField,
    pub rhs_v: E::ScalarField,
    pub fhat_zero_check_proof: IOPProof<E::ScalarField>,
    pub ghat_zero_check_proof: IOPProof<E::ScalarField>,
    pub mg_comm: PCS::Commitment,
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}

/// A BagSubsetCheck check subclaim consists of
/// two sumcheck subclaims, and the value v they should both equal
/// the random challenge gamma
/// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagSubsetCheckSubClaim<F: PrimeField> {
    pub null_offset: F,
    pub gamma: F,
    pub lhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub rhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub lhs_v: F,
    pub rhs_v: F,
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
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mg: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagSubsetCheckProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "BagSubsetCheck prove");
        // check input shape is correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != gxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        if fxs.len() != mg.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        for poly in fxs.iter().chain(gxs.iter()).chain(mg.iter()) {
            if poly.num_vars != fxs[0].num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "vectors in fxs, gxs, have different number of variables".to_string(),
                ));
            }
        }
        let nv = fxs[0].num_vars;

        // initialize multiplicity vector
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mf = vec![one_const_poly.clone()];

        // call the bag_multitool prover
        let (bag_multitool_proof,) = BagMultiToolIOP::<E, PCS>::prove(pcs_param, fxs, gxs, &mf, mg, null_offset, transcript)?;
        
        // reshape the bag_multitool proof into a bag_subset proof
        let bag_subset_check_proof =  BagSubsetCheckProof::<E, PCS>{
            null_offset: bag_multitool_proof.null_offset,
            lhs_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proof,
            rhs_sumcheck_proof: bag_multitool_proof.rhs_sumcheck_proof,
            lhs_v:  bag_multitool_proof.lhs_v,
            rhs_v:  bag_multitool_proof.rhs_v,
            fhat_zero_check_proof: bag_multitool_proof.fhat_zero_check_proof,
            ghat_zero_check_proof: bag_multitool_proof.ghat_zero_check_proof,
            mg_comm: bag_multitool_proof.mg_comm,
            fhat_comm: bag_multitool_proof.fhat_comm,
            ghat_comm: bag_multitool_proof.ghat_comm,
        };

        end_timer!(start);
        Ok((bag_subset_check_proof,))
    }

    pub fn verification_info (
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        mg: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        null_offset: E::ScalarField,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField> {
        let nv = fxs[0].num_vars;
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mf = vec![one_const_poly.clone()];
        let aux_info = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, fxs, gxs, &mf, mg, null_offset, transcript);
        return aux_info
    }

    pub fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &BagSubsetCheckProof<E, PCS>,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagSubsetCheckSubClaim<E::ScalarField>, PolyIOPErrors> {
        let start = start_timer!(|| "BagSubsetCheck verify");
        let nv = aux_info.num_variables;

        let bag_multitool_proof = Self::bagsubset_proof_to_bagmulti_proof(pcs_param, nv, proof)?;
        let bag_multitool_subclaim = BagMultiToolIOP::verify(&bag_multitool_proof, aux_info, transcript)?;
 
         end_timer!(start);
         Ok(BagSubsetCheckSubClaim{
            null_offset: bag_multitool_subclaim.null_offset,
            lhs_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaim, 
            rhs_sumcheck_subclaim: bag_multitool_subclaim.rhs_sumcheck_subclaim,
            lhs_v: bag_multitool_subclaim.lhs_v,
            rhs_v: bag_multitool_subclaim.rhs_v,
            gamma: bag_multitool_subclaim.gamma,
            fhat_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaim,
            ghat_zerocheck_subclaim: bag_multitool_subclaim.ghat_zerocheck_subclaim,
        })
    }

    fn bagsubset_proof_to_bagmulti_proof(pcs_param: &PCS::ProverParam, nv: usize, bagsubset_proof: &BagSubsetCheckProof<E, PCS>) -> Result<BagMultiToolIOPProof::<E, PCS>, PCSError> {
        // initialize multiplicity vector of all ones
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mf_comm = PCS::commit(pcs_param, &one_const_poly)?; 
        
        // reformat proof to a BagMultiToolCheck proof
        let bag_multitool_proof: BagMultiToolIOPProof::<E, PCS> = BagMultiToolIOPProof{
            null_offset: bagsubset_proof.null_offset,
            lhs_sumcheck_proof: bagsubset_proof.lhs_sumcheck_proof.clone(),
            rhs_sumcheck_proof: bagsubset_proof.rhs_sumcheck_proof.clone(),
            lhs_v:  bagsubset_proof.lhs_v,
            rhs_v:  bagsubset_proof.rhs_v,
            fhat_zero_check_proof: bagsubset_proof.fhat_zero_check_proof.clone(),
            ghat_zero_check_proof: bagsubset_proof.ghat_zero_check_proof.clone(),
            mf_comm: mf_comm.clone(),
            mg_comm: bagsubset_proof.mg_comm.clone(),
            fhat_comm: bagsubset_proof.fhat_comm.clone(),
            ghat_comm: bagsubset_proof.ghat_comm.clone(),
        };

        return Ok(bag_multitool_proof)
    }
}