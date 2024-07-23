use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use std::cmp::max;
use ark_std::{Zero, One};
use subroutines::pcs::PolynomialCommitmentScheme;
use ark_poly::DenseMultilinearExtension;

use crate::{
    tracker::prelude::*,
};

pub fn calc_bag_supp_advice<E, PCS>(
    bag: &Bag<E, PCS>
) -> Result<(DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>), PolyIOPErrors>  // (supp, m)
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let bag_nv = bag.num_vars();
    let bag_len = 2_usize.pow(bag_nv as u32);
    let bag_poly_evals = bag.poly.evaluations();
    let bag_sel_evals = bag.selector.evaluations();

    // sort ascending with bag_sel = 0 at the front
    let mut indices: Vec<usize> = (0..bag_len).collect();
    indices.sort_by(|&i, &j| (bag_sel_evals[i], bag_poly_evals[i]).cmp(&(bag_sel_evals[j], bag_poly_evals[j])));

    // calculate the SUPP(bag_a) and the corresponding multiplicity vector
    let mut supp_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut supp_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut multiplicities = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut i = 0;


    // get the values of elements actually in the bag and their multiplicities
    // push all the zero elements for bag_sel = 0, replacing poly values with zero
    while i < indices.len() && bag_sel_evals[indices[i]] == E::ScalarField::zero() {
        supp_evals.push(E::ScalarField::zero());
        supp_sel_evals.push(E::ScalarField::zero());
        multiplicities.push(E::ScalarField::zero());
        i += 1;
    }
    // push elements with multiplicities
    while i < indices.len() {
       let val = bag_poly_evals[indices[i]];
       let mut mult: u64 = 0;
       while i < indices.len() && bag_poly_evals[indices[i]] == val {
           mult += 1;
           i += 1;
       }
       supp_evals.push(val);
       supp_sel_evals.push(E::ScalarField::one());
       multiplicities.push(E::ScalarField::from(mult));
    }

    // create the mles from the evaluation vectors
    let supp_mle = DenseMultilinearExtension::from_evaluations_vec(bag_nv, supp_evals);
    let supp_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_nv, supp_sel_evals);
    let multiplicity_mle = DenseMultilinearExtension::from_evaluations_vec(bag_nv, multiplicities);

    Ok((supp_mle, supp_sel_mle, multiplicity_mle))
}