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
    errors::PolyIOPErrors, prover_tracker::{self, ProverTrackerRef, TrackedPoly}, tracker_structs::TrackerID, verifier_tracker::{TrackedComm, VerifierTrackerRef}
};
use transcript::IOPTranscript;

use super::bag_multitool::{Bag, BagComm, BagMultiToolIOP};

pub struct BagSubsetIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSubsetIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fx: &Bag<E, PCS>,
        gx: &Bag<E, PCS>,
        mg: &TrackedPoly<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagSubsetIOP prove");
        let nv = fx.num_vars();

        // initialize multiplicity vector
        let one_const_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]);
        let mf = tracker.track_mat_poly(one_const_mle)?;

        // call the bag_multitool prover
        BagMultiToolIOP::<E, PCS>::prove(tracker, &[fx.clone()], &[gx.clone()], &[mf.clone()], &[mg.clone()])?;    
        
        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fx: &BagComm<E, PCS>,
        gx: &BagComm<E, PCS>,
        mg: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagSubsetCheck verify");

        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        BagMultiToolIOP::verify(tracker, &[fx.clone()], &[gx.clone()], &[one_comm.clone()], &[mg.clone()])?;
 
         end_timer!(start);
         Ok(())
    }
}