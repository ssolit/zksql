use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use std::collections::HashMap;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_multitool::bag_sum::BagSumIOP,
        bag_supp::bag_supp::BagSuppIOP,
    },
};
use ark_std::Zero;
use ark_std::One;

pub struct SetDisjointIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetDisjointIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

       

        Ok(())
    }
}