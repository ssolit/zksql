use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use subroutines::{
    pcs::PolynomialCommitmentScheme
};
use crate::utils::{
    prover_tracker::{ProverTrackerRef, TrackedPoly}, 
    tracker_structs::TrackerID, 
    verifier_tracker::{TrackedComm, VerifierTrackerRef},
    errors::PolyIOPErrors,
};
use super::{
    bag_multitool::{Bag, BagComm, BagMultiToolIOP},
    bag_eq::BagEqIOP,
};

pub struct BagPrescPermIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagPrescPermIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fx: &Bag<E, PCS>,
        gx: &Bag<E, PCS>,
        perm: &TrackedPoly<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagPrescPermCheck prove");
        // check input shape is correct
        if fx.num_vars() != gx.num_vars() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagPrescPermIOP Error: fx and gx have different number of variables".to_string(),
            ));
        }
        if fx.num_vars() != perm.num_vars {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagPrescPermIOP Error:fx and perm have different number of variables".to_string(),
            ));
        }
        let nv = fx.num_vars();

        // create one_mle  and shifted permutation poly
        // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
        // 	    (p,q) are p is orig, q is p offset by 1 with wraparound
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]);
        let ordered_evals: Vec<E::ScalarField> = (0..2_usize.pow(nv as u32)).map(|x| E::ScalarField::from(x as u64)).collect();
        let ordered_mle = DenseMultilinearExtension::from_evaluations_vec(nv, ordered_evals);
       

        // get a verifier challenge gamma
        let gamma = tracker.get_and_append_challenge(b"gamma")?;

        // calculate f_hat = s+gamma*p and g_hat = t+gamma*q, and prove these were created correctly
        let fx_evals = fx.poly.evaluations();
        let gx_evals = gx.poly.evaluations();
        let perm_evals = perm.evaluations();
        let fhat_evals = (0..2_usize.pow(fx.num_vars() as u32)).map(|i| ordered_mle[i] + gamma * fx_evals[i]).collect::<Vec<_>>();
        let ghat_evals = (0..2_usize.pow(gx.num_vars() as u32)).map(|i| perm_evals[i] + gamma * gx_evals[i]).collect::<Vec<_>>();
        let fhat_mle = DenseMultilinearExtension::from_evaluations_vec(fx.num_vars(), fhat_evals);
        let ghat_mle = DenseMultilinearExtension::from_evaluations_vec(gx.num_vars(), ghat_evals);

        // set up polynomials in the tracker
        let one_poly = tracker.track_mat_poly(one_mle)?;
        let fhat = tracker.track_mat_poly(fhat_mle)?;
        let ghat = tracker.track_mat_poly(ghat_mle)?;
        let fhat_bag = Bag::new(fhat, one_poly.clone());
        let ghat_bag = Bag::new(ghat, one_poly.clone());
       
        


        // TODO: prove these were created correctly
        // Might happen on verifier side instead?
        // let fhat_zero_check_proof = ZeroCheckIOP::<E::ScalarField>::prove(&fhat, &mut transcript)?;



        // prove f_hat, g_hat are bag_eq
        BagEqIOP::<E, PCS>::prove(tracker, &fhat_bag, &ghat_bag)?;
        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fx: &BagComm<E, PCS>,
        gx: &BagComm<E, PCS>,
        perm: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagPrescPermCheck verify");

        // set up polynomials in the tracker in same style as prover 
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        let fhat_id = tracker.get_next_id();
        let fhat_comm = tracker.transfer_prover_comm(fhat_id);
        let ghat_id = tracker.get_next_id();
        let ghat_comm = tracker.transfer_prover_comm(ghat_id);
        let fhat_comm_bag = BagComm::new(fhat_comm, one_comm.clone());
        let ghat_comm_bag = BagComm::new(ghat_comm, one_comm);
        
        BagEqIOP::<E, PCS>::verify(tracker, &fhat_comm_bag, &ghat_comm_bag)?;

         end_timer!(start);
         Ok(())
    }
}