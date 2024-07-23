use ark_ec::pairing::Pairing;
use std::{marker::PhantomData, vec};
use std::cmp::max;
use ark_std::Zero;
use ark_poly::DenseMultilinearExtension;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_supp::utils::calc_bag_supp_advice,
    },
};

/// Inputs: bag_a, bag_b, which the prover wishes to prove are disjoint
/// Outputs: bag_c, m_a, m_b, which the prover will use as advice to prove bag_a and bag_b are disjoint
pub fn calc_bag_disjoint_advice<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>), PolyIOPErrors>  // (sum, sum_sel, m_a, m_b)
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // calculate the SUPP(bag_a) and the corresponding multiplicity vector
    let (supp_a_poly, supp_a_selector, m_a) = calc_bag_supp_advice::<E, PCS>(bag_a)?;
    // calculate the SUPP(bag_b) and the corresponding multiplicity vector
    let (supp_b_poly, supp_b_selector, m_b) = calc_bag_supp_advice::<E, PCS>(bag_b)?;

    // create the sum of supp_a and supp_b, and the corresponding multiplicity vector
    let bag_sum_nv = max(supp_a_poly.num_vars, supp_b_poly.num_vars) + 1;
    let bag_sum_len = 2_usize.pow(bag_sum_nv as u32);
    let mut sum_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut sum_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut sum_a_mults = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    let mut sum_b_mults = Vec::<E::ScalarField>::with_capacity(bag_sum_len);
    sum_evals.extend(supp_a_poly.evaluations.iter());
    sum_evals.extend(supp_b_poly.evaluations.iter());
    sum_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_evals.len()]);
    sum_sel_evals.extend(supp_a_selector.evaluations.iter());
    sum_sel_evals.extend(supp_b_selector.evaluations.iter());
    sum_sel_evals.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_sel_evals.len()]);
    sum_a_mults.extend(m_a.evaluations.iter());
    sum_a_mults.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_a_mults.len()]);
    sum_b_mults.extend(vec![E::ScalarField::zero(); m_a.evaluations.len()]);
    sum_b_mults.extend(m_b.evaluations.iter());
    sum_b_mults.extend(vec![E::ScalarField::zero(); bag_sum_len - sum_b_mults.len()]);

    // sort
    let mut indices: Vec<usize> = (0..bag_sum_len).collect();
    indices.sort_by(|&i, &j| (sum_evals[i], sum_sel_evals[i]).cmp(&(sum_evals[j], sum_sel_evals[j])));
    let sum_evals: Vec<E::ScalarField> = indices.iter().map(|&i| sum_evals[i]).collect();
    let sum_sel_evals: Vec<E::ScalarField> = indices.iter().map(|&i| sum_sel_evals[i]).collect();
    let sum_a_mults: Vec<E::ScalarField> = indices.iter().map(|&i| sum_a_mults[i]).collect();
    let sum_b_mults: Vec<E::ScalarField> = indices.iter().map(|&i| sum_b_mults[i]).collect();

    // create the mles from the evaluation vectors
    let sum_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_evals);
    let sum_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_sel_evals);
    let sum_a_mult_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_a_mults);
    let sum_b_mult_mle = DenseMultilinearExtension::from_evaluations_vec(bag_sum_nv, sum_b_mults);

    Ok((sum_mle, sum_sel_mle, sum_a_mult_mle, sum_b_mult_mle))
}