pub fn bag_lmr_split<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>), PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // set up the eval vectors
    let a_nv = bag_a.num_vars();
    let a_len = 2_usize.pow(a_nv as u32);
    let b_nv = bag_b.num_vars();
    let b_len = 2_usize.pow(b_nv as u32);
    let l_nv = a_nv;
    let l_len = a_len;
    let m_nv = max(a_nv, b_nv);
    let m_len = max(a_len, b_len);
    let r_nv = b_nv;
    let r_len = b_len;
    let mut l_evals = Vec::with_capacity(l_len);
    let mut m_evals = Vec::with_capacity(m_len);
    let mut r_evals = Vec::with_capacity(r_len);

    // get the sorted elements of bag_a and bag_b
    let mut sorted_a_evals = Vec::with_capacity(l_len);
    let a_evals = bag_a.poly.evaluations();
    let a_sel_evals = bag_a.selector.evaluations();
    for i in 0..l_len {
        if !a_sel_evals[i].is_zero() {
            sorted_a_evals.push(a_evals[i]);
        }
    }
    sorted_a_evals.sort();
    let mut sorted_b_evals = Vec::with_capacity(r_len);
    let b_evals = bag_b.poly.evaluations();
    let b_sel_evals = bag_b.selector.evaluations();
    for i in 0..r_len {
        if !b_sel_evals[i].is_zero() {
            sorted_b_evals.push(b_evals[i]);
        }
    }
    sorted_b_evals.sort();

    // itereate through the sorted elements of bag_a and bag_b
    // and create the intermediate bags
    let mut a_counter = 0;
    let mut b_counter = 0;
    while a_counter < sorted_a_evals.len() && b_counter < sorted_b_evals.len() {
        if a_evals[a_counter] < b_evals[b_counter] {
            l_evals.push(a_evals[a_counter]);
            a_counter += 1;
        } else if a_evals[a_counter] > b_evals[b_counter] {
            r_evals.push(b_evals[b_counter]);
            b_counter += 1;
        } else {
            let match_eval = a_evals[a_counter];
            while a_counter < sorted_a_evals.len() && a_evals[a_counter] == match_eval {
                ma_evals.push(a_evals[a_counter]);
                a_counter += 1;
            }
            while b_counter < sorted_b_evals.len() && b_evals[b_counter] == match_eval {
                mb_evals.push(b_evals[b_counter]);
                b_counter += 1;
            }
        }
    }
    for i in a_counter..a_len {
        if !a_sel_evals[i].is_zero() {
            l_evals.push(a_evals[i]);
        }
    }
    for i in b_counter..b_len {
        if !b_sel_evals[i].is_zero() {
            r_evals.push(b_evals[i]);
        }
    }

    // create selectors for the intermediate bags and extend things to the correct length
    let mut l_sel_evals = vec![E::ScalarField::one(); l_evals.len()];
    l_evals.extend(vec![E::ScalarField::zero(); l_len - l_evals.len()]);
    l_sel_evals.extend(vec![E::ScalarField::zero(); l_len - l_sel_evals.len()]);
    let mut ma_sel_evals = vec![E::ScalarField::one(); ma_evals.len()];
    ma_evals.extend(vec![E::ScalarField::zero(); ma_len - ma_evals.len()]);
    ma_sel_evals.extend(vec![E::ScalarField::zero(); ma_len - ma_sel_evals.len()]);
    let mut mb_sel_evals = vec![E::ScalarField::one(); mb_evals.len()];
    mb_evals.extend(vec![E::ScalarField::zero(); mb_len - mb_evals.len()]);
    mb_sel_evals.extend(vec![E::ScalarField::zero(); mb_len - mb_sel_evals.len()]);
    let mut r_sel_evals = vec![E::ScalarField::one(); r_evals.len()];
    r_evals.extend(vec![E::ScalarField::zero(); r_len - r_evals.len()]);
    r_sel_evals.extend(vec![E::ScalarField::zero(); r_len - r_sel_evals.len()]);

    // create the intermediate bags
    let l_mle = DenseMultilinearExtension::from_evaluations_vec(l_nv, l_evals);
    let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(l_nv, l_sel_evals);
    let ma_mle = DenseMultilinearExtension::from_evaluations_vec(ma_nv, ma_evals);
    let ma_sel_mle = DenseMultilinearExtension::from_evaluations_vec(ma_nv, ma_sel_evals);
    let mb_mle = DenseMultilinearExtension::from_evaluations_vec(mb_nv, mb_evals);
    let mb_sel_mle = DenseMultilinearExtension::from_evaluations_vec(mb_nv, mb_sel_evals);
    let r_mle = DenseMultilinearExtension::from_evaluations_vec(r_nv, r_evals);
    let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(r_nv, r_sel_evals);
    let l_bag = Bag::new(prover_tracker.track_and_commit_poly(l_mle)?, prover_tracker.track_and_commit_poly(l_sel_mle)?);
    let ma_bag = Bag::new(prover_tracker.track_and_commit_poly(ma_mle)?, prover_tracker.track_and_commit_poly(ma_sel_mle)?);
    let mb_bag = Bag::new(prover_tracker.track_and_commit_poly(mb_mle)?, prover_tracker.track_and_commit_poly(mb_sel_mle)?);
    let r_bag = Bag::new(prover_tracker.track_and_commit_poly(r_mle)?, prover_tracker.track_and_commit_poly(r_sel_mle)?);

    Ok((l_bag, ma_bag, mb_bag, r_bag))
}