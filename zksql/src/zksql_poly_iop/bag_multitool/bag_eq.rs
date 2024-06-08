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

use super::bag_multitool::{BagMultiToolIOP, BagMultiToolIOPProof};

pub struct BagEqIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagEqCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    pub lhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub rhs_sumcheck_proof: IOPProof<E::ScalarField>,
    pub v: E::ScalarField,
    pub fhat_zero_check_proof: IOPProof<E::ScalarField>,
    pub ghat_zero_check_proof: IOPProof<E::ScalarField>,
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}

/// A BagEqCheck check subclaim consists of
/// two sumcheck subclaims, and the value v they should both equal
/// the random challenge gamma
/// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagEqCheckSubClaim<F: PrimeField> {
    pub lhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub rhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
    pub v: F,
    pub gamma: F,
    pub fhat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
    pub ghat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagEqIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>> {
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagEqCheck transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagEqCheckProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "BagEqCheck prove");
        // check input shape is correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != gxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        for poly in fxs.iter().chain(gxs.iter()) {
            if poly.num_vars != fxs[0].num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "vectors in fxs, gxs, have different number of variables".to_string(),
                ));
            }
        }
        let nv = fxs[0].num_vars;

        // initialize multiplicity vector
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mx = vec![one_const_poly.clone()];

        // call the bag_multitool prover
        // the null_offset is set to zero here because we assume it is an exact permutation without extra nulls
        let (bag_multitool_proof,) = BagMultiToolIOP::<E, PCS>::prove(pcs_param, fxs, gxs, &mx.clone(), &mx.clone(), E::ScalarField::zero(),transcript)?;
        let bag_eq_check_proof =  BagEqCheckProof::<E, PCS>{
            lhs_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proof,
            rhs_sumcheck_proof: bag_multitool_proof.rhs_sumcheck_proof,
            v:  bag_multitool_proof.lhs_v,
            fhat_zero_check_proof: bag_multitool_proof.fhat_zero_check_proof,
            ghat_zero_check_proof: bag_multitool_proof.ghat_zero_check_proof,
            fhat_comm: bag_multitool_proof.fhat_comm,
            ghat_comm: bag_multitool_proof.ghat_comm,
        };

        end_timer!(start);
        Ok((bag_eq_check_proof,))
    }

    pub fn verification_info (
        pcs_param: &PCS::ProverParam,
        fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField> {
        let nv = fxs[0].num_vars;
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mx = vec![one_const_poly.clone()];
        let aux_info = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, fxs, gxs, &mx.clone(), &mx.clone(), E::ScalarField::zero(), transcript);
        return aux_info
    }

    pub fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &BagEqCheckProof<E, PCS>,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagEqCheckSubClaim<E::ScalarField>, PolyIOPErrors> {
        let start = start_timer!(|| "BagEqCheck verify");
        let nv = aux_info.num_variables;

        let bag_multitool_proof = Self::bageq_proof_to_bagmulti_proof(pcs_param, nv, proof)?;
        let bag_multitool_subclaim = BagMultiToolIOP::verify(&bag_multitool_proof, aux_info, transcript)?;
 
         end_timer!(start);
         Ok(BagEqCheckSubClaim{
            lhs_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaim, 
            rhs_sumcheck_subclaim: bag_multitool_subclaim.rhs_sumcheck_subclaim,
            v: bag_multitool_subclaim.lhs_v,
            gamma: bag_multitool_subclaim.gamma,
            fhat_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaim,
            ghat_zerocheck_subclaim: bag_multitool_subclaim.ghat_zerocheck_subclaim,
        })
    }

    fn bageq_proof_to_bagmulti_proof(pcs_param: &PCS::ProverParam, nv: usize, bageq_proof: &BagEqCheckProof<E, PCS>) -> Result<BagMultiToolIOPProof::<E, PCS>, PCSError> {
        // initialize multiplicity vector of all ones
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        // let mx = vec![one_const_poly.clone(); 2_usize.pow(nv as u32)];
        let m_comm = PCS::commit(pcs_param, &one_const_poly)?; 
        
        // reformat proof to a BagMultiToolCheck proof
        let bag_multitool_proof: BagMultiToolIOPProof::<E, PCS> = BagMultiToolIOPProof{
            null_offset: E::ScalarField::zero(),
            lhs_sumcheck_proof: bageq_proof.lhs_sumcheck_proof.clone(),
            rhs_sumcheck_proof: bageq_proof.rhs_sumcheck_proof.clone(),
            lhs_v:  bageq_proof.v,
            rhs_v:  bageq_proof.v,
            fhat_zero_check_proof: bageq_proof.fhat_zero_check_proof.clone(),
            ghat_zero_check_proof: bageq_proof.ghat_zero_check_proof.clone(),
            mf_comm: m_comm.clone(),
            mg_comm: m_comm.clone(),
            fhat_comm: bageq_proof.fhat_comm.clone(),
            ghat_comm: bageq_proof.ghat_comm.clone(),
        };

        return Ok(bag_multitool_proof)
    }
}