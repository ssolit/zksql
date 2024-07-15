use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::marker::PhantomData;
use std::collections::HashMap;
use std::cmp::max;

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

pub struct SetUnionIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> SetUnionIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag_a: &Bag<E, PCS>,
        bag_b: &Bag<E, PCS>,
        union_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // calculate bag_sum = bag_a + bag_b
        let bag_sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
        let bag_sum_len = 2_usize.pow(bag_sum_nv as u32);
        let mut sum_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
        let mut sum_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
        sum_evals.extend(bag_a.poly.evaluations().iter());
        sum_evals.extend(bag_b.poly.evaluations().iter());
        sum_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_evals.len()]);
        sum_sel_evals.extend(bag_a.selector.evaluations().iter());
        sum_sel_evals.extend(bag_b.selector.evaluations().iter());
        sum_sel_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_sel_evals.len()]);

        // calculate the multiplicity vector for union_bag vs sum_bag
        let mut m_counts = HashMap::<E::ScalarField, usize>::new();
        for i in 0..bag_sum_len {
            // if the selector is zero, skip counting this element
            let sel = sum_sel_evals[i];
            if sel.is_zero() {
                continue;
            }
            // increment the count for this element
            let eval = sum_evals[i];
            if m_counts.contains_key(&eval) {
                m_counts.insert(eval, m_counts.get(&eval).unwrap() + 1);
            } else {
                m_counts.insert(eval, 1);
            }
        }
        let m_supp_nums = union_bag.poly.evaluations().iter().map(
            |x| m_counts.get(&x).unwrap().clone() as u64
        ).collect::<Vec<u64>>();
        let mut m_supp_evals = m_supp_nums.iter().map(
            |x| E::ScalarField::from(*x)
        ).collect::<Vec<E::ScalarField>>();

        // add [ 1 - union_sel] so m_supp doesn't have zeros
        // to make the supp check pass
        let union_sel_evals = union_bag.selector.evaluations();
        for i in 0..m_supp_evals.len() {
            m_supp_evals[i] += E::ScalarField::one() - union_sel_evals[i];
        }

        // create the mles from the evaluation vectors
        let sum_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_evals);
        let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_sel_evals);
        let m_supp_mle = DenseMultilinearExtension::from_evaluations_vec(union_bag.num_vars(), m_supp_evals);

        // prove a + b = sum_bag
        let sum_poly = prover_tracker.track_and_commit_poly(sum_mle)?;
        let sum_sel_poly = prover_tracker.track_and_commit_poly(sum_sel_mle)?;
        let sum_bag = &Bag::new(sum_poly, sum_sel_poly);
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;
 
        // prove union bag is the supp of sum bag
        let m_supp = prover_tracker.track_and_commit_poly(m_supp_mle)?;
        BagSuppIOP::<E, PCS>::prove(
            prover_tracker,
            sum_bag,
            union_bag,
            &m_supp,
            range_bag,
        )?;
        
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag_a: &BagComm<E, PCS>,
        bag_b: &BagComm<E, PCS>,
        union_bag: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // verify a + b = sum_bag
        let sum_nv = max(bag_a.num_vars(), bag_b.num_vars()) + 1;
        let sum_comm_id = verifier_tracker.get_next_id();
        let sum_comm = verifier_tracker.transfer_prover_comm(sum_comm_id);
        let sum_sel_comm_id = verifier_tracker.get_next_id();
        let sum_sel_comm = verifier_tracker.transfer_prover_comm(sum_sel_comm_id);
        let sum_bag = &BagComm::new(sum_comm, sum_sel_comm, sum_nv);
        BagSumIOP::<E, PCS>::verify(
            verifier_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;

        // prove union bag is the supp of sum bag
        let m_supp_id = verifier_tracker.get_next_id();
        let m_supp = verifier_tracker.transfer_prover_comm(m_supp_id);
        BagSuppIOP::<E, PCS>::verify(
            verifier_tracker,
            sum_bag,
            union_bag,
            &m_supp,
            range_bag,
        )?;

        Ok(())
    }
}