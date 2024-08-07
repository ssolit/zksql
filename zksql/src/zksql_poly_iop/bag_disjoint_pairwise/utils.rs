use ark_ec::pairing::Pairing;
use std::collections::HashSet;
use std::vec;
use ark_std::{Zero, One, log2};
use std::collections::HashMap;
use ark_poly::DenseMultilinearExtension;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;
use crate::zksql_poly_iop::util::prelude::bag_multiplicity_count;


// calculate the nv needed for the sum polynomial for bag_disjoint_pairwise
pub fn calc_bag_disjoint_pairwise_sum_nv_from_bags<E, PCS>(
    bags: &[Bag<E, PCS>],
) -> usize
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut size = 0;
    for bag in bags {
        size += 2_usize.pow(bag.num_vars() as u32);
    }

    let nv = log2(size) as usize; // returns the ceiling of the base-2 log

    nv
}

pub fn calc_bag_disjoint_pairwise_sum_nv_from_comms<E, PCS>(
    bags: &[BagComm<E, PCS>],
) -> usize
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut size = 0;
    for bag in bags {
        size += 2_usize.pow(bag.num_vars() as u32);
    }

    let nv = log2(size) as usize; // returns the ceiling of the base-2 log

    nv
}

/// Inputs: [bags], which the prover wishes to prove are disjoint
/// Outputs: sum, [multiplicities] which the prover will use as advice to prove the bags are disjoint
pub fn calc_bag_disjoint_pairwise_advice<E, PCS>(
    bags: &[Bag<E, PCS>],
) -> Result<((DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>), Vec<DenseMultilinearExtension<E::ScalarField>>), PolyIOPErrors>  // (sum, sum_sel, [multiplicities])
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // set up sum result vectors
    let bag_sum_nv = calc_bag_disjoint_pairwise_sum_nv_from_bags(bags);
    let bag_sum_len = 2_usize.pow(bag_sum_nv as u32);
    let mut sum_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut sum_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);

    // count the mutliplicities of elements in each input bag
    let mut mult_maps = Vec::<HashMap<E::ScalarField, u64>>::with_capacity(bags.len());
    for bag in bags {
        mult_maps.push(bag_multiplicity_count(bag));
    }

    // calculate sum, the sorted Supp of the Multisetsum of the input bags
    let mut sum_evals_map = HashSet::<E::ScalarField>::new();
    for i in 0..bags.len() {
        for val in mult_maps[i].keys() {
            sum_evals_map.insert(val.clone());
        }
    }
    let mut unique_vals: Vec<E::ScalarField> = sum_evals_map.into_iter().collect();
    unique_vals.sort();
    sum_sel_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
    sum_sel_evals.extend(vec![E::ScalarField::one(); unique_vals.len()]);
    sum_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
    sum_evals.extend(unique_vals.clone());

    // calculate multiplicity vectors for the input bags relative to sum
    let mut mults_evals_vec = Vec::<Vec<E::ScalarField>>::with_capacity(bags.len());
    for i in 0..bags.len() {
        let mult_map = &mult_maps[i];
        let mut mults_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
        mults_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - unique_vals.len()]);
        for i in 0..unique_vals.len() {
            let val = unique_vals[i];
            let mult = E::ScalarField::from(*mult_map.get(&val).unwrap_or(&0));
            mults_evals.push(mult);
        }
        mults_evals_vec.push(mults_evals);
    }

    // create the mles from the evaluation vectors
    let sum_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_evals);
    let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_sel_evals);
    let mults_mles = mults_evals_vec.into_iter().map(|mults_evals| DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, mults_evals)).collect();

    Ok(((sum_mle, sum_sel_mle), mults_mles))
}