use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{errors::PolyIOPErrors, prelude::SumCheck, PolyIOP}, PCSError,
};
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer};
use std::{sync::Arc, usize};
use std::ops::Neg;
use transcript::IOPTranscript;
use ark_ff::PrimeField;
use subroutines::ZeroCheck;
use arithmetic::{merge_polynomials, VPAuxInfo, VirtualPolynomial};
use ark_std::{Zero, One};

use crate::zksql_poly_iop::bag_multitool::LogupCheck;

use super::bag_multitool::LogupCheckProof;


pub trait BagEqCheck<E, PCS>: LogupCheck<E, PCS>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    type BagEqCheckSubClaim;
    type BagEqCheckProof;

    /// Initialize the system with a transcript
    ///
    /// This function is optional -- in the case where a BagEqCheck is
    /// an building block for a more complex protocol, the transcript
    /// may be initialized by this complex protocol, and passed to the
    /// BagEqCheck prover/verifier.
    fn init_transcript() -> Self::Transcript;

    /// Proves that two lists of n-variate multilinear polynomials `(f1, f2,
    /// ..., fk)` and `(g1, ..., gk)` are element-wise permutations of each other
    /// By invoking the LogupCheck with multiplicities set to 1 for all numbers
    /// 
    /// Inputs:
    /// - fxs: the list of LHS polynomials
    /// - gxs: the list of RHS polynomials
    /// - transcript: the IOP transcript
    /// - pk: PCS committing key
    ///
    ///   /// Outputs
    /// - the BagEqCheck proof
    /// - other? TODO
    ///
    /// Cost: TODO
    /// #[allow(clippy::type_complexity)]
    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::BagEqCheckProof,
        ),
        PolyIOPErrors,
    >;

    /// Verify that two lists of n-variate multilinear polynomials `(f1, f2,
    /// ..., fk)` and `(g1, ..., gk)` element-wise satisfy:
    /// 
    ///   \Sum_{j=1}^{2^n} \frac{1}{X-fi[j]}
    ///     = \Sum_{j=1}^{2^n} \frac{1}{X-gi[j]}
    fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &Self::BagEqCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::BagEqCheckSubClaim, PolyIOPErrors>;

    fn bageq_proof_to_bagmulti_proof(
        pcs_param: &PCS::ProverParam,
        nv: usize,
        bageq_proof: &Self::BagEqCheckProof
    ) -> Result<<Self as LogupCheck<E, PCS>>::LogupCheckProof, PCSError>;
}

/// A BagEqCheck check subclaim consists of
/// TODO
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagEqCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>, SC: SumCheck<F>> {
    // the SubClaim from the ZeroCheck
    pub lhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub rhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub v: F,
    pub gamma: F,
    pub fhat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
    pub ghat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagEqCheckProof<
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
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}

impl<E, PCS> BagEqCheck<E, PCS> for PolyIOP<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type BagEqCheckSubClaim = BagEqCheckSubClaim<E::ScalarField, Self, Self>;
    type BagEqCheckProof = BagEqCheckProof<E, PCS, Self, Self>;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagEqCheck transcript")
    }

    fn prove(
        pcs_param: &PCS::ProverParam,
        fxs: &[Self::MultilinearExtension],
        gxs: &[Self::MultilinearExtension],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            Self::BagEqCheckProof,
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
        let mx = vec![one_const_poly.clone(); 2_usize.pow(nv as u32)];

        // call the bag_multitool prover
        let (bag_multitool_proof, _, _) = <Self as LogupCheck<E, PCS>>::prove(pcs_param, fxs, gxs, &mx.clone(), &mx.clone(), transcript)?;
        let bag_eq_check_proof =  Self::BagEqCheckProof{
            lhs_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proof,
            rhs_sumcheck_proof: bag_multitool_proof.rhs_sumcheck_proof,
            v:  bag_multitool_proof.v,
            fhat_zero_check_proof: bag_multitool_proof.fhat_zero_check_proof,
            ghat_zero_check_proof: bag_multitool_proof.ghat_zero_check_proof,
            fhat_comm: bag_multitool_proof.fhat_comm,
            ghat_comm: bag_multitool_proof.ghat_comm,
        };

        end_timer!(start);
        Ok((bag_eq_check_proof,))
        // return bag_eq_check_proof;
    }

    fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &Self::BagEqCheckProof,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut Self::Transcript,
    ) -> Result<Self::BagEqCheckSubClaim, PolyIOPErrors> {
        let start = start_timer!(|| "logup_check verify");
        let nv = aux_info.num_variables;

        let bag_multitool_proof = Self::bageq_proof_to_bagmulti_proof(pcs_param, nv, proof)?;
        let bag_multitool_subclaim = <Self as LogupCheck<E, PCS>>::verify(&bag_multitool_proof, aux_info, transcript)?;
 
         end_timer!(start);
         Ok(BagEqCheckSubClaim{
            lhs_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaim, 
            rhs_sumcheck_subclaim: bag_multitool_subclaim.rhs_sumcheck_subclaim,
            v: bag_multitool_subclaim.v,
            gamma: bag_multitool_subclaim.gamma,
            fhat_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaim,
            ghat_zerocheck_subclaim: bag_multitool_subclaim.ghat_zerocheck_subclaim,
        })
    }

    fn bageq_proof_to_bagmulti_proof(pcs_param: &PCS::ProverParam, nv: usize, bageq_proof: &Self::BagEqCheckProof) -> Result<<Self as LogupCheck<E, PCS>>::LogupCheckProof, PCSError> {
        // initialize multiplicity vector of all ones
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        // let mx = vec![one_const_poly.clone(); 2_usize.pow(nv as u32)];
        let m_comm = PCS::commit(pcs_param, &one_const_poly)?; 
        
        // reformat proof to a logupcheck proof
        let bag_multitool_proof: <Self as LogupCheck<E, PCS>>::LogupCheckProof = LogupCheckProof{
            lhs_sumcheck_proof: bageq_proof.lhs_sumcheck_proof.clone(),
            rhs_sumcheck_proof: bageq_proof.rhs_sumcheck_proof.clone(),
            v:  bageq_proof.v,
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
    let g = arithmetic::random_permutation_mles(nv, 1, &mut rng)[0].clone();
    
    // initialize transcript 
    let mut transcript = <PolyIOP<Fr> as BagEqCheck<Bls12_381, MultilinearKzgPCS::<Bls12_381>>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;

    // call the helper to run the proofand verify now that everything is set up 
    test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[g.clone()], &mut transcript)?;
    println!("test_bageq_helper good path passed");

    // good path passed. Now check bad path
    let h = VirtualPolynomial::new(nv);
    h.add_mle_list([f, g], Fr::one())?;

    let bad_result1 = test_bageq_helper::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>(&pcs_param, &[f.clone()], &[h], &mut transcript);
    assert!(bad_result1.is_err());

    // exit successfully 
    Ok(())
}

fn test_bageq_helper<E: Pairing, PCS> (
    pcs_param: &PCS::ProverParam,
    fxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    gxs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    transcript: &mut IOPTranscript<E::ScalarField>,
) -> Result<(), PolyIOPErrors>  where
E: Pairing,
PCS: PolynomialCommitmentScheme<
    E,
    Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
>,{
    let (proof,) = <PolyIOP<E::ScalarField> as BagEqCheck<E, PCS>>::prove(pcs_param, fxs, gxs, &mut transcript.clone())?;
    println!("test_bageq_helper: proof created successfully\n");
    let aux_info = fhat_check_poly.aux_info.clone();
    <PolyIOP<E::ScalarField> as BagEqCheck<E, PCS>>::verify(pcs_param, &proof, &aux_info, transcript)?;

    Ok(())
}