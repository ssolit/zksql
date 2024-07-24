use ark_ec::pairing::Pairing;
use ark_std::Zero;
use ark_poly::DenseMultilinearExtension;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        util::prelude::bag_multiplicity_count,
    },
};



pub fn calc_bag_inclusion_advice<E, PCS> (
    big_bag: &Bag<E, PCS>,
    sub_bag: &Bag<E, PCS>,
) -> DenseMultilinearExtension<E::ScalarField> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let big_bag_nv = big_bag.num_vars();
    let big_bag_evals = big_bag.poly.evaluations();
    let big_bag_len = big_bag_evals.len();
    let mut sub_bag_mults_map = bag_multiplicity_count(sub_bag);
    let mut big_bag_mult_evals = Vec::<E::ScalarField>::with_capacity(big_bag_len);

    for i in 0..big_bag_len {
        let val = big_bag_evals[i];
        let sub_bag_mult = sub_bag_mults_map.get(&val);
        if sub_bag_mult.is_none() {
            // val is not in sub_bag, so zero out the multiplicity
            big_bag_mult_evals.push(E::ScalarField::zero());
        } else {
            // val is in sub_bag, use the multiplcity
            big_bag_mult_evals.push(E::ScalarField::from(*sub_bag_mult.unwrap()));
            // update the sub_bag_mults_map to zero, so if val occurs in bag_bag multiple times we don't double count
            sub_bag_mults_map.insert(val, 0);
        }
    }

    let big_bag_mult_mle = DenseMultilinearExtension::from_evaluations_vec(big_bag_nv, big_bag_mult_evals);

    big_bag_mult_mle
}