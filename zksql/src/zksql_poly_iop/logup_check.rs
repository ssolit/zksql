use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{errors::PolyIOPErrors, prelude::SumCheck, PolyIOP},
};
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer};
use std::sync::Arc;
use transcript::IOPTranscript;
use ark_ff::PrimeField;
use subroutines::ZeroCheck;
use arithmetic::VPAuxInfo;


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
            Self::MultilinearExtension,
            Self::MultilinearExtension,
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
pub struct LogupCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>> {
    // the SubClaim from the ZeroCheck
    pub zero_check_sub_claim: ZC::ZeroCheckSubClaim,
    // final query which consists of
    // - the vector `(1, ..., 1, 0)` (needs to be reversed because Arkwork's MLE uses big-endian
    //   format for points)
    // The expected final query evaluation is 1
    pub final_query: (Vec<F>, F),
    pub alpha: F,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LogupCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    ZC: ZeroCheck<E::ScalarField>,
> {
    pub zero_check_proof: ZC::ZeroCheckProof,
    pub fxs_comm: PCS::Commitment,
    pub gxs_comm: PCS::Commitment,
    pub mf_comm: PCS::Commitment,
    pub gx_comm: PCS::Commitment,
}


impl<E, PCS> LogupCheck<E, PCS> for PolyIOP<E::ScalarField>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>,
{
    type LogupCheckSubClaim = LogupCheckSubClaim<E::ScalarField, Self>;
    type LogupCheckProof = LogupCheckProof<E, PCS, Self>;

    fn init_transcript() -> Self::Transcript {
        IOPTranscript::<E::ScalarField>::new(b"Initializing LogupCheck transcript")
    }

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
            Self::MultilinearExtension,
            Self::MultilinearExtension,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "prod_check prove");

        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("fxs is empty".to_string()));
        }
        if fxs.len() != gxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and gxs have different number of polynomials".to_string(),
            ));
        }
        if fxs.len() != mf.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and mf have different number of polynomials".to_string(),
            ));
        }
        if fxs.len() != mg.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "fxs and mf have different number of polynomials".to_string(),
            ));
        }

        for poly in fxs.iter().chain(gxs.iter()).chain(mf.iter()).chain(mg.iter()) {
            if poly.num_vars != fxs[0].num_vars {
                return Err(PolyIOPErrors::InvalidParameters(
                    "vectors in fxs, gxs, mf, mg, have different number of variables".to_string(),
                ));
            }
        }

        // define virtual sum polynomials
        



        // generate challenge
        let frac_comm = PCS::commit(pcs_param, &frac_poly)?;
        let prod_x_comm = PCS::commit(pcs_param, &prod_x)?;
        transcript.append_serializable_element(b"frac(x)", &frac_comm)?;
        transcript.append_serializable_element(b"prod(x)", &prod_x_comm)?;
        let alpha = transcript.get_and_append_challenge(b"alpha")?;

        // build the zero-check proof
        let (zero_check_proof, _) =
            prove_zero_check(fxs, gxs, &frac_poly, &prod_x, &alpha, transcript)?;

        end_timer!(start);

        Ok((
            LogupCheckProof {
                zero_check_proof,
                prod_x_comm,
                frac_comm,
            },
            prod_x,
            frac_poly,
        ))
    }
}

use ark_ff::Field;
use std::marker::PhantomData;
fn make_id_poly<F: PrimeField>(num_vars: usize) {
    // let aux_info = VPAuxInfo::<F>{max_degree: 1, num_variables: num_vars, phantom: PhantomData::default()};
    
    // create a vec of evals corestponding to the identity fn over the boolean hypercube
    let one = F::one();
    let mut curr_val = F::one();
    let mut evaluations: Vec<F> = Vec::new();
    for i in 0..(2_usize.pow(num_vars as u32)) {
        evaluations.push(curr_val);
        curr_val = curr_val + one;
    }

    // create the mle
    let mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);

    // return the mle (TODO)

}