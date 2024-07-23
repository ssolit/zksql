use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_multitool::bag_inclusion::BagInclusionIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
    },
};


pub struct BagDisjointIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagDisjointIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        bag_c: &Bag<E, PCS>,
        m_a: &TrackedPoly<E, PCS>,
        m_b: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // Prove bag_c is strictly sorted
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            bag_c,
            range_bag,
        )?;


        // Prove the multiplicity vectors use disjoint indices
        let m_mul = m_a.mul_poly(&m_b);
        prover_tracker.add_zerocheck_claim(m_mul.id);

        // prove bag_a is included in bag_c
        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            bag_a,
            bag_c,
            m_a,
        )?;

        // prove bag_b is included in bag_c
        BagInclusionIOP::<E, PCS>::prove(
            prover_tracker,
            bag_b,
            bag_c,
            m_b,
        )?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        bag_c: &BagComm<E, PCS>,
        m_a: &TrackedComm<E, PCS>,
        m_b: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify bag_c is strictly sorted
        BagStrictSortIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_c,
            range_bag,
        )?; 

        // verify the multiplicity vectors use disjoint indices
        let m_mul = m_a.mul_comms(&m_b);
        verifier_tracker.add_zerocheck_claim(m_mul.id);

        // verify bag_a is included in bag_c
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_a,
            bag_c,
            m_a,
        )?;

        // verify bag_b is included in bag_c
        BagInclusionIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_b,
            bag_c,
            m_b,
        )?;

        Ok(())
    }
}