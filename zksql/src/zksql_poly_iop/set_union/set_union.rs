use ark_ec::pairing::Pairing;
use ark_ff::batch_inversion;
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use rayon::range;
use rayon::range_inclusive;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::zksql_poly_iop::bag_multitool::bag_sum::BagSumIOP;
use crate::zksql_poly_iop::bag_no_zeros::BagNoZerosIOP;
use crate::zksql_poly_iop::bag_supp::bag_supp::BagSuppIOP;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_sort::bag_sort::BagStrictSortIOP,
        bag_multitool::bag_multitool::BagMultiToolIOP,
    },
};

pub struct SetUnionIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetUnionIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        sum_bag: &Bag<E, PCS>,
        union_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;

        

        BagSuppIOP::<E, PCS>::prove(
            prover_tracker,
            union_bag,
            sum_bag,
        )?;
        
    
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        sum_bag: &Bag<E, PCS>,
        union_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        

        Ok(())

    }
}