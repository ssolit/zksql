use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::One;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_multitool::bag_subset::BagSubsetIOP,
        bag_no_zeros::BagNoZerosIOP,
        bag_sort::bag_sort::BagStrictSortIOP,
    },
};

pub struct BagSuppIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSuppIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag: &Bag<E, PCS>,
        supp: &Bag<E, PCS>,
        common_mset_supp_m: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
    
        // How supp is a subset of bag
        BagSubsetIOP::<E, PCS>::prove(
            prover_tracker,
            &bag.clone(),
            &supp.clone(),
            &common_mset_supp_m.clone(),
        )?;
    
        // Show supp includes at least one copy of every element in bag
        // by showing the multiplicity poly has no zeros
        // Note: can resuse the supp.selector as the supp_m.selector
        let supp_no_dups_checker = Bag::new(common_mset_supp_m.clone(), supp.selector.clone());
        BagNoZerosIOP::<E, PCS>::prove(
            prover_tracker,
            &supp_no_dups_checker,
        )?;
    
        // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            supp,
            range_bag,
        )?;
    
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: &BagComm<E, PCS>,
        supp: &BagComm<E, PCS>,
        common_mset_supp_m: &TrackedComm<E, PCS>,
        range_bag_comm: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // Use BagMultitool PIOP to show bag and supp share a Common Multiset
        BagSubsetIOP::<E, PCS>::verify(
            verifier_tracker,
            &bag.clone(),
            &supp.clone(),
            &common_mset_supp_m.clone(),
        )?;
    
        // bag and supp are subsets of each other by showing multiplicity polys have no zeros
        let supp_no_dups_checker = BagComm::new(common_mset_supp_m.clone(), supp.selector.clone(), supp.num_vars());
        BagNoZerosIOP::<E, PCS>::verify(
            verifier_tracker,
            &supp_no_dups_checker,
        )?;
    
        // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
        BagStrictSortIOP::<E, PCS>::verify(
            verifier_tracker,
            supp,
            range_bag_comm,
        )?;

        Ok(())

    }
}