use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_multitool::{bag_multitool::BagMultiToolIOP, bag_subset::BagSubsetIOP, bag_sum::BagSumIOP}, bag_no_zeros::BagNoZerosIOP, set_disjoint::set_disjoint::SetDisjointIOP, set_union::set_union::SetUnionIOP
    },
};

pub struct JoinIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> JoinIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        bag_l: &Bag<E, PCS>,
        bag_mid_a: &Bag<E, PCS>,
        bag_mid_b: &Bag<E, PCS>,
        bag_r: &Bag<E, PCS>,
        mid_a_mult: &TrackedPoly<E, PCS>,
        mid_b_mult: &TrackedPoly<E, PCS>,
        join_res_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>
    ) -> Result<(), PolyIOPErrors> {

        // prove L \mutlisetsum mid_a = A
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_l,
            bag_mid_a,
            bag_a,
        )?;

        // prove mid_b \mutlisetsum R = B
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_mid_b,
            bag_r,
            bag_b,
        )?;

        // Prove L and R are disjoint
        SetDisjointIOP::<E, PCS>::prove(
            prover_tracker,
            bag_l,
            bag_r,
            range_bag,
        )?;

        // prove mid_a and mid_b have the same support
        BagSubsetIOP::<E, PCS>::prove(
            prover_tracker,
            bag_mid_a,
            bag_mid_b,
            mid_b_mult
        )?;
       BagSubsetIOP::<E, PCS>::prove(
            prover_tracker,
            bag_mid_b,
            bag_mid_a,
            mid_a_mult
        )?;

        // prove the join result is the join product of mid_a and mid_b
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        bag_l: &BagComm<E, PCS>,
        bag_mid_a: &BagComm<E, PCS>,
        bag_mid_b: &BagComm<E, PCS>,
        bag_r: &BagComm<E, PCS>,
        mid_a_mult: &TrackedComm<E, PCS>,
        mid_b_mult: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify L \mutlisetsum mid_a = A
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker, 
            bag_l, 
            bag_mid_a,
            bag_a,
        )?;

        // verify mid_b \mutlisetsum R = B
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker, 
            bag_mid_b,
            bag_r, 
            bag_b,
        )?;

        // verify L and R are disjoint
        SetDisjointIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_l,
            bag_r,
            range_bag,
        )?;

        // verify mid_a and mid_b have the same support
        BagSubsetIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_mid_a,
            bag_mid_b,
            mid_b_mult
        )?;
        BagSubsetIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_mid_b,
            bag_mid_a,
            mid_a_mult
        )?;

        Ok(())
    }
}