use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::collections::HashMap;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_supp::utils::calc_bag_supp_advice,
        bag_supp::bag_supp::BagSuppIOP,
    },
};

pub struct GroupByCountIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> GroupByCountIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        pre_grouping_col_bag: &Bag<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let (support_mle, support_sel_mle, multiplicity_mle) = calc_bag_supp_advice(&pre_grouping_col_bag)?;
        let supp_poly = prover_tracker.track_and_commit_poly(support_mle)?;
        let supp_sel_poly = prover_tracker.track_and_commit_poly(support_sel_mle)?;
        let grouped_col_bag = Bag::new(supp_poly.clone(), supp_sel_poly.clone());
        let counts_poly = prover_tracker.track_and_commit_poly(multiplicity_mle)?;
        
        GroupByCountIOP::<E, PCS>::prove_with_advice(
            prover_tracker, 
            &pre_grouping_col_bag, 
            &grouped_col_bag, 
            &counts_poly,
            range_bag,
        )?;
        
        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        pre_grouping_col_bag: &Bag<E, PCS>,
        grouped_col_bag: &Bag<E, PCS>,
        counts_poly: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // prove the grouping bag is a the support of the pre-grouping bag
        // as part of this proof, it shows that counts_poly is the relevent multiplicity vector for proving 
        // the grouping bag is a subset of the support of the pre-grouping bag
        BagSuppIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            &pre_grouping_col_bag.clone(),
            &grouped_col_bag.clone(),
            &counts_poly.clone(),
            &range_bag.clone(),
        )?;

        todo!()
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        pre_grouping_col_bag: &BagComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        todo!()
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        pre_grouping_col_bag: &BagComm<E, PCS>,
        grouped_col_bag: &BagComm<E, PCS>,
        counts_poly: &TrackedComm<E, PCS>,
        range_bag: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        todo!()
    }
}