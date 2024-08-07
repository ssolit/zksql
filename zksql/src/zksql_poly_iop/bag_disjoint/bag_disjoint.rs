use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use std::cmp::max;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_inclusion::bag_inclusion::BagInclusionIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
        // bag_disjoint::utils::calc_bag_disjoint_advice,
        bag_disjoint_pairwise::bag_disjoint_pairwise::BagDisjointPairwiseIOP,
    },
};


pub struct BagDisjointIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagDisjointIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>, 
        bag_a: &Bag<E, PCS>, 
        bag_b: &Bag<E, PCS>, 
        range_bag: &Bag<E, PCS>
    ) -> Result<(), PolyIOPErrors> {
        BagDisjointPairwiseIOP::<E, PCS>::prove(
            prover_tracker,
            &[bag_a.clone(), bag_b.clone()],
            range_bag,
        )?;

        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        bag_c: &Bag<E, PCS>,
        m_a: &TrackedPoly<E, PCS>,
        m_b: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        BagDisjointPairwiseIOP::<E, PCS>::prove_with_advice(
            prover_tracker, 
            &[bag_a.clone(), bag_b.clone()],
            bag_c,
            &[m_a.clone(), m_b.clone()],
            range_bag
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        BagDisjointPairwiseIOP::<E, PCS>::verify(
            verifier_tracker,
            &[bag_a.clone(), bag_b.clone()],
            range_bag,
        )?;

        Ok(())
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        bag_c: &BagComm<E, PCS>,
        m_a: &TrackedComm<E, PCS>,
        m_b: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        
        BagDisjointPairwiseIOP::<E, PCS>::verify_with_advice(
            verifier_tracker, 
            &[bag_a.clone(), bag_b.clone()],
            bag_c,
            &[m_a.clone(), m_b.clone()],
            range_bag
        )?;
        
        Ok(())
    }
}