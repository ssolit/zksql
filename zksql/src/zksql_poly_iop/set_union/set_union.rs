use ark_ec::pairing::Pairing;
use ark_ff::batch_inversion;
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::marker::PhantomData;
use std::collections::HashMap;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::zksql_poly_iop::bag_multitool::bag_sum;
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

        // prove a + b = sum_bag
        BagSumIOP::<E, PCS>::prove(
            prover_tracker,
            bag_a,
            bag_b, 
            sum_bag,
        )?;

        // prove union bag is the supp of sum bag
        let mut m_counts = HashMap::<E::ScalarField, usize>::new();
        let sum_evals = sum_bag.poly.evaluations();
        for i in 0..sum_bag.poly.evaluations().len() {
            let eval = sum_evals[i];
            if m_counts.contains_key(&eval) {
                m_counts.insert(eval, m_counts.get(&eval).unwrap() + 1);
            } else {
                m_counts.insert(eval, 1);
            }
        }
        let m_supp_evals = union_bag.poly.evaluations().iter().map(
            |x| E::ScalarField::from(m_counts.get(&x).unwrap().clone() as u64)
        ).collect::<Vec<E::ScalarField>>();
        let m_supp_mle = DenseMultilinearExtension::from_evaluations_vec(union_bag.num_vars(), m_supp_evals);

        BagSuppIOP::<E, PCS>::prove(
            prover_tracker,
            union_bag,
            sum_bag,
            &m_supp_mle,
            range_bag,
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