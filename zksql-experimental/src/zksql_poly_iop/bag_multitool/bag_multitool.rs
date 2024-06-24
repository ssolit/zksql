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
use transcript::IOPTranscript;

use crate::utils::{
    tracker_structs::{TrackerID, TrackerSumcheckClaim, TrackerZerocheckClaim},
    prover_tracker::{ProverTracker, ProverTrackerRef, TrackedPoly},
    verifier_tracker::{VerifierTracker, VerifierTrackerRef},
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

// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagComm<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
//     pub poly_comm: PCS::Commitment,
//     pub selector_comm: PCS::Commitment,
// }


pub struct BagMultiToolIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagMultiToolIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = ArcMLE<E>>
{

    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fxs: &[Bag<E, PCS>],
        gxs: &[Bag<E, PCS>],
        mfxs: &[TrackedPoly<E, PCS>],
        mgxs: &[TrackedPoly<E, PCS>],
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
            Self::generate_subclaims(tracker, fxs[i].clone(), mfxs[i].clone(), gamma)?;
        }   

        for i in 0..gxs.len() {
            Self::generate_subclaims(tracker, gxs[i].clone(), mgxs[i].clone(), gamma)?;
        } 

        end_timer!(start);
        Ok(())
    }

    fn generate_subclaims(
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

        // assumption is that proof inputs are already added to the tracker 
        // create challenges and commitments in same fashion as prover
        // 1. pick gamma
        // 2. add phat_comm
        // 3. add sumcheck_challenge-comm
        // 4. add one_comm
        // 5. add gamma_comm
        // 6 add phat_check_comm
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        let phat_mat_comm: PCS::Commitment = proof.comms[tracker.get_next_id()].unwrap();
        let phat = tracker.track_mat_comm(phat_mat_comm, |id, x| tracker.eval_maps[id].clone()(id, x));

        let sumcheck_challenge_comm = phat.mul(&m).mul(&bag.selector);

        let one_closure = |tracker_id: TrackerID, scalar: E::ScalarField| -> E::ScalarField {E::ScalarField::one()};
        let one_comm = tracker.track_mat_comm(Option::None, one_closure);
        
        let gamma_closure = |tracker_id: TrackerID, scalar: E::ScalarField| -> E::ScalarField {gamma};
        let gamma_comm = tracker.track_mat_comm(Option::None, gamma_closure);
        


        // check that the values of claimed sums are equal
        let lhs_v: E::ScalarField = proof.lhs_vs.iter().sum();
        let rhs_v: E::ScalarField = proof.rhs_vs.iter().sum();

        if lhs_v != rhs_v {
            let mut err_msg = "BagMutltiTool Verify Error: LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(PolyIOPErrors::InvalidVerifier(err_msg));
        }

        // create the subclaims for each sumcheck and zerocheck
        let mut lhs_sumcheck_subclaims = Vec::<TrackerSumcheckClaim<E::ScalarField>>::new();
        let mut rhs_sumcheck_subclaims = Vec::<TrackerSumcheckClaim<E::ScalarField>>::new();
        let mut fhat_zerocheck_subclaims = Vec::<TrackerZerocheckClaim<E::ScalarField>>::new();
        let mut ghat_zerocheck_subclaims = Vec::<TrackerZerocheckClaim<E::ScalarField>>::new();

        // println!("BagMutltiTool Verify: starting lhs subchecks");
        for i in 0..proof.lhs_sumcheck_proofs.len() {
            tracker.append_serializable_element(b"phat(x)", &proof.fhat_comms[i])?;
            
            let lhs_sumcheck_subclaim = SumCheckIOP::<E::ScalarField>::verify(
                proof.lhs_vs[i],
                &proof.lhs_sumcheck_proofs[i],
                &f_sc_info[i],
                &mut tracker.clone(),
            )?;
            lhs_sumcheck_subclaims.push(lhs_sumcheck_subclaim);

            let fhat_zerocheck_subclaim = ZeroCheckIOP::<E::ScalarField>::verify(
                &proof.fhat_zerocheck_proofs[i],
                &f_zc_info[i],
                &mut tracker.clone(),
            )?;
            fhat_zerocheck_subclaims.push(fhat_zerocheck_subclaim);
        }
        // println!("BagMutltiTool Verify: starting rhs subchecks");
        for i in 0..proof.rhs_sumcheck_proofs.len() {
            tracker.append_serializable_element(b"phat(x)", &proof.ghat_comms[i])?;
            let rhs_sumcheck_subclaim = SumCheckIOP::<E::ScalarField>::verify(
                proof.rhs_vs[i],
                &proof.rhs_sumcheck_proofs[i],
                &g_sc_info[i],
                &mut tracker.clone(),
            )?;
            rhs_sumcheck_subclaims.push(rhs_sumcheck_subclaim);

            let ghat_zerocheck_subclaim = ZeroCheckIOP::<E::ScalarField>::verify(
                &proof.ghat_zerocheck_proofs[i],
                &g_zc_info[i],
                &mut tracker.clone(),
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