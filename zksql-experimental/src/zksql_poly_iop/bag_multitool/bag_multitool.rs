// use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use derivative::Derivative;
use std::{fmt::{Debug}, marker::PhantomData, ops::Neg, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        // prelude::{SumCheckIOP, SumCheckIOPSubClaim, ZeroCheckIOP, ZeroCheckIOPSubClaim},
    },
    IOPProof,
};

use crate::utils::{
    prover_tracker::{ProverTracker, ProverTrackerRef, TrackedPoly}, tracker_structs::{TrackerID, TrackerSumcheckClaim, TrackerZerocheckClaim}, verifier_tracker::{TrackedComm, VerifierTracker, VerifierTrackerRef}
};


pub type ArcMLE<E> = Arc<DenseMultilinearExtension<<E as Pairing>::ScalarField>>;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct Bag<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly: TrackedPoly<E, PCS>,
    pub selector: TrackedPoly<E, PCS>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> Bag<E, PCS> {
    pub fn new(poly: TrackedPoly<E, PCS>, selector: TrackedPoly<E, PCS>, tracker: ProverTrackerRef<E, PCS>) -> Self {
        #[cfg(debug_assertions)]
        {
            assert_eq!(poly.num_vars, selector.num_vars);
            assert!(poly.same_tracker(&selector));
        }
        Self {
            poly,
            selector,
        }
    }

    pub fn num_vars(&self) -> usize {
        self.poly.num_vars()
    }

    pub fn tracker_ref(&self) -> ProverTrackerRef<E, PCS> {
        ProverTrackerRef::new(self.poly.tracker.clone())
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct BagComm<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly: TrackedComm<E, PCS>,
    pub selector: TrackedComm<E, PCS>,
}


pub struct BagMultiToolIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagMultiToolIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E>
{

    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fxs: &[Bag<E, PCS>],
        gxs: &[Bag<E, PCS>],
        mfxs: &[TrackedPoly<E, PCS>],
        mgxs: &[TrackedPoly<E, PCS>],
    ) -> Result<(),PolyIOPErrors> {
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
            if gxs[i].num_vars() != mgxs[i].num_vars() {
                return Err(PolyIOPErrors::InvalidParameters(
                    "BagMultiToolIOP Error: gxs[i] and mgxs[i] have different number of polynomials".to_string(),
                ));
            }
        }

        // assumption is that the tracker is already initialized and the polynomials are already tracked
        // so the commitments have already been added to the tracker transcript
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and generate subclaims:
        for i in 0..fxs.len() {
            Self::prove_generate_subclaims(tracker, fxs[i].clone(), mfxs[i].clone(), gamma)?;
        }   

        for i in 0..gxs.len() {
            Self::prove_generate_subclaims(tracker, gxs[i].clone(), mgxs[i].clone(), gamma)?;
        } 

        Ok(())
    }

    fn prove_generate_subclaims(
        tracker: &mut ProverTrackerRef<E, PCS>,
        bag: Bag<E, PCS>,
        m: TrackedPoly<E, PCS>,
        gamma: E::ScalarField,
    ) -> Result<(), PolyIOPErrors> {
        let nv = bag.num_vars();
        
        // construct phat = 1/(bag.p(x) - gamma), i.e. the denominator of the sum
        let p = bag.poly;
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<<E as Pairing>::ScalarField> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = DenseMultilinearExtension::from_evaluations_slice(nv, phat_evals);

        // calculate what the final sum should be
        let m_evals = &m.evaluations();
        let selector_evals = &bag.selector.evaluations();
        let mut v = E::ScalarField::zero();
        for i in 0..2_usize.pow(nv as u32) {
            v += phat_mle[i] * m_evals[i] * selector_evals[i];
        }
        
        // construct the full challenge polynomial by taking phat and multiplying by the selector and multiplicities
        let phat = tracker.track_mat_poly(phat_mle)?;
        let sumcheck_challenge_poly = phat.mul(&m).mul(&bag.selector);
       
        // Create Zerocheck claim for procing phat(x) is created correctly, 
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x)  - 1]
        let one_const_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]);
        let one_const_poly = tracker.track_mat_poly(one_const_mle)?;
        let gamma_const_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![gamma.clone(); 2_usize.pow(nv as u32)]);
        let gamma_const_poly = tracker.track_mat_poly(gamma_const_mle)?;
        let phat_check_poly = p.sub(&gamma_const_poly).mul(&phat).sub(&one_const_poly);
       
        
        // add the delayed prover claims to the tracker
        tracker.add_sumcheck_claim(sumcheck_challenge_poly.id, v);
        tracker.add_zerocheck_claim(phat_check_poly.id);

        return Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fxs: &[BagComm<E, PCS>],
        gxs: &[BagComm<E, PCS>],
        mfxs: &[TrackedComm<E, PCS>],
        mgxs: &[TrackedComm<E, PCS>],
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagMultiToolCheck verify");

        // check input shapes are correct
        if fxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultiToolIOP Error: fxs is empty".to_string()));
        }
        if fxs.len() != mfxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultiToolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }
        if gxs.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters("BagMultiToolIOP Error: fxs is empty".to_string()));
        }
       
        if gxs.len() != mgxs.len() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagMultiToolIOP Error: fxs and mf have different number of polynomials".to_string(),
            ));
        }

        // create challenges and commitments in same fashion as prover
        // assumption is that proof inputs are already added to the tracker 
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // iterate over vector elements and generate subclaims:
        let lhs_v: E::ScalarField = E::ScalarField::zero();
        let rhs_v: E::ScalarField = E::ScalarField::zero();
        for i in 0..fxs.len() {
            let sum_claim_v = Self::verify_generate_subclaims(tracker, fxs[i].clone(), mfxs[i].clone(), gamma)?;
            lhs_v += sum_claim_v;
        }   

        for i in 0..gxs.len() {
            let sum_claim_v = Self::verify_generate_subclaims(tracker, gxs[i].clone(), mgxs[i].clone(), gamma)?;
            rhs_v += sum_claim_v;
        } 

        // check that the values of claimed sums are equal
        if lhs_v != rhs_v {
            let mut err_msg = "BagMutltiTool Verify Error: LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(PolyIOPErrors::InvalidVerifier(err_msg));
        }

        Ok(())
    }

    fn verify_generate_subclaims(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: BagComm<E, PCS>,
        m: TrackedComm<E, PCS>,
        gamma: E::ScalarField,
    ) -> Result<(E::ScalarField), PolyIOPErrors> {
        let p = bag.poly;
        // get phat mat comm from proof and add it to the tracker
        let phat_id: TrackerID = tracker.get_next_id();
        let phat_mat_comm = tracker.get_prover_comm(phat_id)?;
        let phat_closure = tracker.get_prover_closure(phat_id)?;
        let phat = tracker.track_mat_comm(phat_mat_comm, phat_closure);
        
        // make the virtual comms as prover does
        let sumcheck_challenge_comm = phat.mul(&m).mul(&bag.selector);

        let one_closure = |tracker_id: TrackerID, scalar: E::ScalarField| -> E::ScalarField {E::ScalarField::one()};
        let one_comm = tracker.track_mat_comm(Option::None, one_closure);
        let gamma_closure = |tracker_id: TrackerID, scalar: E::ScalarField| -> E::ScalarField {gamma};
        let gamma_comm = tracker.track_mat_comm(Option::None, gamma_closure);
        let phat_check_poly = p.sub(&gamma_comm).mul(&phat).sub(&one_comm);
       
        // add the delayed prover claims to the tracker
        let sum_claim_v = tracker.get_prover_claimed_eval(sumcheck_challenge_comm.id)?;
        tracker.add_sumcheck_claim(sumcheck_challenge_comm.id, sum_claim_v);
        tracker.add_zerocheck_claim(phat_check_poly.id);

        return Ok((sum_claim_v))
    }
}