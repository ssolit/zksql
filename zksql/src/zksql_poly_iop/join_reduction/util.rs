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
        bag_supp::utils::calc_bag_supp_advice,
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
    let (l_bag, m_bag, r_bag) = bag_lmr_split(bag_a, bag_b)?;
    Ok(())
}