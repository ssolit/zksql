use std::collections::HashMap;
use ark_ec::pairing::Pairing;
use ark_std::Zero;
use crate::tracker::prelude::Bag;
use subroutines::PolynomialCommitmentScheme;

// Returns a map from the unique evaluations of bag to their multiplicities
// does not include values where the selector is zero
pub fn multiplicity_count<E, PCS>(
    bag: &Bag<E, PCS>,
) -> HashMap<E::ScalarField, u64>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut mults_map = HashMap::<E::ScalarField, u64>::new();
    for i in 0..bag.poly.evaluations().len() {
        if bag.selector.evaluations()[i] == E::ScalarField::zero() {
            continue;
        }
        let val = bag.poly.evaluations()[i];
        let get_res = mults_map.get(&val);
        if get_res.is_none() {
            mults_map.insert(val, 1);
        } else {
            let mult = get_res.unwrap() + 1;
            mults_map.insert(val, mult);
        }
    }
    mults_map
}