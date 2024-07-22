
use ark_ec::pairing::Pairing;
use subroutines::PolynomialCommitmentScheme;
use crate::tracker::prelude::ProverTrackerRef;
use crate::tracker::prelude::Bag;
use crate::tracker::prelude::TrackedPoly;
use crate::tracker::prelude::PolyIOPErrors;
use ark_std::Zero;
use ark_std::One;
use ark_poly::DenseMultilinearExtension;
use std::cmp::max;

pub fn bag_lmr_split<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>, TrackedPoly<E, PCS>, TrackedPoly<E, PCS>, TrackedPoly<E, PCS>, TrackedPoly<E, PCS>,), PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // set up the eval vectors
    let a_nv = bag_a.num_vars();
    let a_len = 2_usize.pow(a_nv as u32);
    let b_nv = bag_b.num_vars();
    let b_len = 2_usize.pow(b_nv as u32);
    let left_nv = a_nv;
    let left_len = a_len;
    let mid_nv = max(a_nv, b_nv);
    let mid_len = max(a_len, b_len);
    let right_nv = b_nv;
    let right_len = b_len;
    let mut l_evals = Vec::<E::ScalarField>::with_capacity(left_len);
    let mut l_mul_evals = Vec::<E::ScalarField>::with_capacity(left_len);
    let mut m_evals = Vec::<E::ScalarField>::with_capacity(mid_len);
    let mut m_amul_evals = Vec::<E::ScalarField>::with_capacity(mid_len);
    let mut m_bmul_evals = Vec::<E::ScalarField>::with_capacity(mid_len);
    let mut r_evals = Vec::<E::ScalarField>::with_capacity(right_len);
    let mut r_mul_evals =  Vec::<E::ScalarField>::with_capacity(right_len);

    // get the sorted elements of bag_a and bag_b
    let mut sorted_a_evals = Vec::<E::ScalarField>::with_capacity(left_len);
    let a_evals = bag_a.poly.evaluations();
    let a_sel_evals = bag_a.selector.evaluations();
    for i in 0..left_len {
        if !a_sel_evals[i].is_zero() {
            sorted_a_evals.push(a_evals[i]);
        }
    }
    sorted_a_evals.sort();
    let mut sorted_b_evals = Vec::<E::ScalarField>::with_capacity(right_len);
    let b_evals = bag_b.poly.evaluations();
    let b_sel_evals = bag_b.selector.evaluations();
    for i in 0..right_len {
        if !b_sel_evals[i].is_zero() {
            sorted_b_evals.push(b_evals[i]);
        }
    }
    sorted_b_evals.sort();

    // itereate through the sorted elements of bag_a and bag_b
    // and create the intermediate bags
    let mut a_index = 0;
    let mut b_index = 0;
    while a_index < sorted_a_evals.len() && b_index < sorted_b_evals.len() {
        if a_evals[a_index] < b_evals[b_index] {
            let mut mul_counter: u64 = 0;
            let val = a_evals[a_index];
            while a_evals[a_index] == val {
                mul_counter += 1;
                a_index += 1;
            }
            l_evals.push(a_evals[a_index]);
            l_mul_evals.push(E::ScalarField::from(mul_counter));
        } else if a_evals[a_index] > b_evals[b_index] {
            let mut mul_counter: u64 = 0;
            let val = b_evals[b_index];
            while b_evals[b_index] == val {
                mul_counter += 1;
                b_index += 1;
            }
            r_evals.push(b_evals[b_index]);
            r_mul_evals.push(E::ScalarField::from(mul_counter));
        } else {
            let match_eval = a_evals[a_index];
            let mut a_mul_counter: u64 = 0;
            let mut b_mul_counter: u64 = 0;
            while a_index < sorted_a_evals.len() && a_evals[a_index] == match_eval {
                a_mul_counter += 1;
                a_index += 1;
            }
            while b_index < sorted_b_evals.len() && b_evals[b_index] == match_eval {
                b_mul_counter += 1;
                b_index += 1;
            }
            m_evals.push(match_eval);
            m_amul_evals.push(E::ScalarField::from(a_mul_counter));
            m_bmul_evals.push(E::ScalarField::from(b_mul_counter));
        }
    }
    for i in a_index..a_len {
        if !a_sel_evals[i].is_zero() {
            let mut mul_counter: u64 = 0;
            let val = a_evals[a_index];
            while a_evals[a_index] == val {
                mul_counter += 1;
                a_index += 1;
            }
            l_evals.push(a_evals[a_index]);
            l_mul_evals.push(E::ScalarField::from(mul_counter));
        }
    }
    for i in b_index..b_len {
        if !b_sel_evals[i].is_zero() {
            let mut mul_counter: u64 = 0;
            let val = b_evals[b_index];
            while b_evals[b_index] == val {
                mul_counter += 1;
                b_index += 1;
            }
            r_evals.push(b_evals[b_index]);
            r_mul_evals.push(E::ScalarField::from(mul_counter));
        }
    }

    // create selectors for the intermediate bags and extend things to the correct length
    let mut l_sel_evals = vec![E::ScalarField::one(); l_evals.len()];
    l_evals.extend(vec![E::ScalarField::zero(); left_len - l_evals.len()]);
    l_sel_evals.extend(vec![E::ScalarField::zero(); left_len - l_sel_evals.len()]);
    l_mul_evals.extend(vec![E::ScalarField::zero(); left_len - l_mul_evals.len()]);
    let mut m_sel_evals = vec![E::ScalarField::one(); m_evals.len()];
    m_evals.extend(vec![E::ScalarField::zero(); mid_len - m_evals.len()]);
    m_sel_evals.extend(vec![E::ScalarField::zero(); mid_len - m_sel_evals.len()]);
    m_amul_evals.extend(vec![E::ScalarField::zero(); mid_len - m_amul_evals.len()]);
    m_bmul_evals.extend(vec![E::ScalarField::zero(); mid_len - m_bmul_evals.len()]);
    let mut r_sel_evals = vec![E::ScalarField::one(); r_evals.len()];
    r_evals.extend(vec![E::ScalarField::zero(); right_len - r_evals.len()]);
    r_sel_evals.extend(vec![E::ScalarField::zero(); right_len - r_sel_evals.len()]);
    r_mul_evals.extend(vec![E::ScalarField::zero(); right_len - r_mul_evals.len()]);

    // create the intermediate bags
    let l_mle = DenseMultilinearExtension::from_evaluations_vec(left_nv, l_evals);
    let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(left_nv, l_sel_evals);
    let l_mul_mle = DenseMultilinearExtension::from_evaluations_vec(left_nv, l_mul_evals);
    let m_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_evals);
    let m_sel_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_sel_evals);
    let m_amul_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_amul_evals);
    let m_bmul_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_bmul_evals);
    let r_mle = DenseMultilinearExtension::from_evaluations_vec(right_nv, r_evals);
    let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(right_nv, r_sel_evals);
    let r_mul_mle = DenseMultilinearExtension::from_evaluations_vec(right_nv, r_mul_evals);

    let l_bag = Bag::new(prover_tracker.track_and_commit_poly(l_mle)?, prover_tracker.track_and_commit_poly(l_sel_mle)?);
    let m_bag = Bag::new(prover_tracker.track_and_commit_poly(m_mle)?, prover_tracker.track_and_commit_poly(m_sel_mle)?);
    let r_bag = Bag::new(prover_tracker.track_and_commit_poly(r_mle)?, prover_tracker.track_and_commit_poly(r_sel_mle)?);
    let l_mul = prover_tracker.track_and_commit_poly(l_mul_mle)?;
    let ma_mul = prover_tracker.track_and_commit_poly(m_amul_mle)?;
    let mb_mul = prover_tracker.track_and_commit_poly(m_bmul_mle)?;
    let r_mul = prover_tracker.track_and_commit_poly(r_mul_mle)?;

    Ok((l_bag, m_bag, r_bag, l_mul, ma_mul, mb_mul, r_mul))
}