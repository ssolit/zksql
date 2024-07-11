use ark_ec::pairing::Pairing;
use ark_ff::batch_inversion;
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::zksql_poly_iop::bag_no_zeros::BagNoZerosIOP;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_sort::bag_sort::BagStrictSortIOP,
        bag_multitool::bag_multitool::BagMultiToolIOP,
    },
};

pub struct BagSuppIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSuppIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        bag: &Bag<E, PCS>,
        common_mset_bag_m: &TrackedPoly<E, PCS>,
        supp: &Bag<E, PCS>,
        common_mset_supp_m: &TrackedPoly<E, PCS>,
        range_bag: &Bag<E, PCS>,
        supp_range_m: &TrackedPoly<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
    
        // Use BagMultitool PIOP to show bag and supp share a Common Multiset
        BagMultiToolIOP::<E, PCS>::prove(
            prover_tracker,
            &[bag.clone()],
            &[supp.clone()],
            &[common_mset_bag_m.clone()],
            &[common_mset_supp_m.clone()],
        )?;
    
        // bag and supp are subsets of each other by showing multiplicity polys have no zeros
        let bag_one_mle = DenseMultilinearExtension::from_evaluations_vec(common_mset_bag_m.num_vars(), vec![E::ScalarField::one(); 2_usize.pow(common_mset_bag_m.num_vars() as u32)]);
        let bag_one_poly = prover_tracker.track_mat_poly(bag_one_mle);
        let bag_no_dups_checker = Bag::new(common_mset_bag_m.clone(), bag_one_poly.clone());
        BagNoZerosIOP::<E, PCS>::prove(
            prover_tracker,
            &bag_no_dups_checker,
        )?;
        let supp_one_mle = DenseMultilinearExtension::from_evaluations_vec(common_mset_supp_m.num_vars(), vec![E::ScalarField::one(); 2_usize.pow(common_mset_supp_m.num_vars() as u32)]);
        let supp_one_poly = prover_tracker.track_mat_poly(supp_one_mle);
        let supp_no_dups_checker = Bag::new(common_mset_supp_m.clone(), supp_one_poly.clone());
        BagNoZerosIOP::<E, PCS>::prove(
            prover_tracker,
            &supp_no_dups_checker,
        )?;
    
        // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
        BagStrictSortIOP::<E, PCS>::prove(
            prover_tracker,
            supp,
            range_bag,
            supp_range_m,
        )?;
    
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        bag: &BagComm<E, PCS>,
        common_mset_bag_m: &TrackedComm<E, PCS>,
        supp: &BagComm<E, PCS>,
        common_mset_supp_m: &TrackedComm<E, PCS>,
        range_bag_comm: &BagComm<E, PCS>,
        supp_range_m: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // Use BagMultitool PIOP to show bag and supp share a Common Multiset
        BagMultiToolIOP::<E, PCS>::verify(
            verifier_tracker,
            &[bag.clone()],
            &[supp.clone()],
            &[common_mset_bag_m.clone()],
            &[common_mset_supp_m.clone()],
        )?;
    
        // bag and supp are subsets of each other by showing multiplicity polys have no zeros
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let bag_one_comm = verifier_tracker.track_virtual_comm(Box::new(one_closure));
        let bag_no_dups_checker = BagComm::new(common_mset_bag_m.clone(), bag_one_comm.clone(), bag.num_vars());
        BagNoZerosIOP::<E, PCS>::verify(
            verifier_tracker,
            &bag_no_dups_checker,
        )?;
        let supp_one_comm = verifier_tracker.track_virtual_comm(Box::new(one_closure));
        let supp_no_dups_checker = BagComm::new(common_mset_supp_m.clone(), supp_one_comm.clone(), supp.num_vars());
        BagNoZerosIOP::<E, PCS>::verify(
            verifier_tracker,
            &supp_no_dups_checker,
        )?;
    
        // (BagStrictSortIOP) Show supp is sorted by calling bag_sort
        BagStrictSortIOP::<E, PCS>::verify(
            verifier_tracker,
            supp,
            range_bag_comm,
            supp_range_m,
        )?;

        Ok(())

    }


}