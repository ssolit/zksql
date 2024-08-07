use ark_ec::pairing::Pairing;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_inclusion::bag_inclusion::BagInclusionIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
        bag_disjoint_pairwise::utils::{calc_bag_disjoint_pairwise_advice, calc_bag_disjoint_pairwise_sum_nv_from_comms},
    },
};


pub struct BagDisjointPairwiseIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagDisjointPairwiseIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>, 
        bags: &[Bag<E, PCS>],
        range_bag: &Bag<E, PCS>
    ) -> Result<(), PolyIOPErrors> {
        // calculate needed advice (the sum and multiplicities) and set up the prover tracker
        let ((sum_mle, sum_sel_mle), multiplicity_mles) = calc_bag_disjoint_pairwise_advice(bags)?;
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let sum = Bag::new(sum_poly.clone(), sum_sel_poly.clone());
        let mut multiplicities = Vec::<TrackedPoly<E, PCS>>::with_capacity(bags.len());
        for mult_mle in multiplicity_mles {
            multiplicities.push(prover_tracker.track_and_commit_poly(mult_mle)?);
        }

        // continue to main proving logic
        Self::prove_with_advice(
            prover_tracker,
            bags,
            &sum,
            &multiplicities,
            &range_bag,
        )?;

        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bags: &[Bag<E, PCS>],
        sum: &Bag<E, PCS>,
        multiplicities: &[TrackedPoly<E, PCS>],
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // Prove bag_c is strictly sorted
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            sum,
            range_bag,
        )?;

        // for each pair of bags, prove the multiplicity vectors use disjoint indices
        for i in 0..multiplicities.len() {
            for j in (i+1)..multiplicities.len() {
                let m_mul = multiplicities[i].mul_poly(&multiplicities[j]);
                prover_tracker.add_zerocheck_claim(m_mul.id);
            }
        }

        // prove each bag is included in the sum
        for i in 0..multiplicities.len() {
            BagInclusionIOP::<E, PCS>::prove_with_advice(
                prover_tracker,
                &bags[i],
                sum,
                &multiplicities[i],
            )?;
        }

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bags: &[BagComm<E, PCS>],
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let bag_sum_nv = calc_bag_disjoint_pairwise_sum_nv_from_comms(bags);
        // get ids for advice polynomials and transfer them to the verifier
        let sum_poly_id = verifier_tracker.get_next_id();
        let sum_poly = verifier_tracker.transfer_prover_comm(sum_poly_id);
        let sum_sel_poly_id = verifier_tracker.get_next_id();
        let sum_sel_poly = verifier_tracker.transfer_prover_comm(sum_sel_poly_id);
        let sum = BagComm::new(sum_poly, sum_sel_poly, bag_sum_nv);
        let mut multiplicities = Vec::<TrackedComm<E, PCS>>::with_capacity(bags.len());
        for _ in 0..bags.len() {
            let mult_poly_id = verifier_tracker.get_next_id();
            let mult_poly = verifier_tracker.transfer_prover_comm(mult_poly_id);
            multiplicities.push(mult_poly);
        }
        
        // continue to main verifying logic
        Self::verify_with_advice(
            verifier_tracker,
            bags,
            &sum,
            &multiplicities,
            range_bag,
        )?;

        Ok(())
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bags: &[BagComm<E, PCS>],
        sum: &BagComm<E, PCS>,
        multiplicities: &[TrackedComm<E, PCS>],
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify sum is strictly sorted
        BagStrictSortIOP::<E, PCS>::verify(
            verifier_tracker,
            sum,
            range_bag,
        )?; 

         // for each pair of bags, verify the multiplicity vectors use disjoint indices
         for i in 0..multiplicities.len() {
            for j in (i+1)..multiplicities.len() {
                let m_mul = multiplicities[i].mul_comms(&multiplicities[j]);
                verifier_tracker.add_zerocheck_claim(m_mul.id);
            }
        }

        // prove each bag is included in the sum
        for i in 0..multiplicities.len() {
            BagInclusionIOP::<E, PCS>::verify_with_advice(
                verifier_tracker,
                &bags[i],
                sum,
                &multiplicities[i],
            )?;
        }

        Ok(())
    }
}