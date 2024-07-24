use ark_ec::pairing::Pairing;
use std::collections::HashMap;
use std::collections::HashSet;
use std::vec;
use std::cmp::max;
use ark_std::{Zero, One};
use ark_poly::DenseMultilinearExtension;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        util::prelude::multiplicity_count,
    },
};

pub fn calc_join_reduction_advice<E, PCS>(
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(), PolyIOPErrors> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
   // get the multiplicity counts for bag_a and bag_b
   let a_mults_map = multiplicity_count(bag_a);
   let b_mults_map = multiplicity_count(bag_b);

   // setup vars
   let a_evals = bag_a.poly.evaluations();
   let b_evals = bag_b.poly.evaluations();
   let a_len = a_evals.len();
   let b_len = b_evals.len();
   let mut l_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_a.selector.evaluations().len());
   let mut r_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_b.selector.evaluations().len());

   // create the selector for L
   for i in 0..a_len {
       let a_val = a_evals[i];
       let b_mult = b_mults_map.get(&a_val);
       if b_mult.is_none() {
           // case where a_val not in bag_b, so it belongs in L
           l_sel_evals.push(E::ScalarField::one());
       } else {
           // case where a_val in bag_b, so doesn't belong in L
           l_sel_evals.push(E::ScalarField::zero());
       }
   }
   // create the selector for R
   for i in 0..b_len {
       let b_val = b_evals[i];
       let a_mult = a_mults_map.get(&b_val);
       if a_mult.is_none() {
           // case where b_val not in bag_a, so it belongs in R
           r_sel_evals.push(E::ScalarField::one());
       } else {
           // case where b_val in bag_a, so doesn't belong in R
           r_sel_evals.push(E::ScalarField::zero());
       }
   }

   // figure out the multiplicity vectors for the subset checks
   

   Ok(())
   
}