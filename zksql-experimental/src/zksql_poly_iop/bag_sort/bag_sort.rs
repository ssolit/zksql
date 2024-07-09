// Prove a bag is strictly sorted 
// by showing it's elements are a subset of [0, 2^n] 
// and the product of its elements is non-zero

use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::{batch_inversion, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_poly::MultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use subroutines::{
    pcs::PolynomialCommitmentScheme
};
use crate::{
    utils::{
        bag::{Bag, BagComm},
        prover_tracker::{ProverTrackerRef, TrackedPoly}, 
        tracker_structs::TrackerID, 
        verifier_tracker::{TrackedComm, VerifierTrackerRef},
        errors::PolyIOPErrors,
    },
    zksql_poly_iop::bag_multitool::{
        bag_presc_perm::{BagPrescPermIOP}, 
        bag_subset::{BagSubsetIOP},
    },
};

pub struct BagStrictSortIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagStrictSortIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        sorted_bag: &Bag<E, PCS>,
        range_poly: &TrackedPoly<E, PCS>,
        m_range: &TrackedPoly<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "bagStrictSort prove");
        // retrieve some useful values from the inputs
        let sorted_poly_evals = sorted_bag.poly.evaluations();
        let sorted_nv = sorted_bag.num_vars();
        let sorted_len = sorted_poly_evals.len();
        let range_nv = range_poly.num_vars;
        let range_len = 2_usize.pow(range_nv as u32);
        let p_poly = sorted_bag.poly.clone();

        // create shifted permutation poly for the prescribed permutation check, which shows 
        // q is correctly created based off of p. Then we can use q for calculating diffs in the range check 
        // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
        // 	    (p,q) are p is orig input, q is p offset by 1 with wraparound
        let mut shift_perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_len);
        shift_perm_evals.push(E::ScalarField::from((sorted_len - 1) as u64));
        shift_perm_evals.extend((0..(sorted_len - 1)).map(|x| E::ScalarField::from(x as u64)));

        let mut q_evals = Vec::<E::ScalarField>::with_capacity(sorted_len);
        q_evals.push(*sorted_poly_evals.last().unwrap());
        q_evals.extend_from_slice(&sorted_poly_evals[..sorted_len]);
        q_evals.pop();

        // Create a difference poly and its selector for the range check, which shows
        // the bag is sorted since the differences are in the correct range 
        //      sorted_bag = [a_0, a_1, ..] from the input
        //      selector = [0, 1, 1, ..]
        //      diff_evals = [selector * (p - q) + (1 - selector)] 
        // recall (1 - selector) = [1, 0, 0, ..], makes first element non-zero for the product check
        let mut diff_sel_evals = vec![E::ScalarField::one(); sorted_len];
        diff_sel_evals[0] = E::ScalarField::zero();
        let diff_evals = (0..sorted_len).map(
            |i| diff_sel_evals[i] * (sorted_poly_evals[i] - q_evals[i]) + (E::ScalarField::one() - diff_sel_evals[i]) // p-q here made the sign correct? depends on sort order?
        ).collect::<Vec<_>>();
        let diff_sel_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_sel_evals);

        // Get inverses of diff_evals for the product check, which shows
        // the bag is strictly sorted (rather than just sorted) since no elements are zero
        let mut diff_eval_inverses = diff_evals.clone();
        batch_inversion(&mut diff_eval_inverses);


        // Set up the tracker and prove the prescribed permutation check
        let one_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len]);
        let shift_perm_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, shift_perm_evals);
        let q_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals);
        let one_poly = prover_tracker.track_mat_poly(one_mle);
        let shift_perm_poly = prover_tracker.track_mat_poly(shift_perm_mle); // note: is a precomputed poly
        let q_poly = prover_tracker.track_and_commit_poly(q_mle)?; // is also precomputed??
        let q_bag = Bag::new(q_poly.clone(), one_poly);
        BagPrescPermIOP::<E, PCS>::prove(
            prover_tracker,
            &sorted_bag.clone(),
            &q_bag.clone(),
            &shift_perm_poly.clone(),
        )?;

        // Set up the tracker and prove the range/subset check
        let diff_sel = prover_tracker.track_mat_poly(diff_sel_mle); // note: is a precomputed one-poly
            // diff_evals = [selector * (q - p) + (1 - selector)] 
        let diff_poly = diff_sel.mul_poly(&p_poly.sub_poly(&q_poly)).add_scalar(E::ScalarField::one()).sub_poly(&diff_sel);
        #[cfg(debug_assertions)] {
            assert_eq!(diff_poly.evaluations(), diff_evals);
        }
        let diff_bag = Bag::new(diff_poly.clone(), diff_sel);
        let range_sel_mle = DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![E::ScalarField::one(); range_len]);
        let range_sel = prover_tracker.track_mat_poly(range_sel_mle); // note: is a precomputedone-poly
        let range_bag = Bag::new(range_poly.clone(), range_sel);
        BagSubsetIOP::<E, PCS>::prove(
            prover_tracker,
            &diff_bag.clone(),
            &range_bag.clone(),
            &m_range.clone(),
        )?;
        

        
        // Set up the tracker and prove the product check
        // println!("diff_evals: {:?}", diff_evals);
        // println!("diff_eval_inverses: {:?}", diff_eval_inverses);
        // let diff_inverse_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
        //     diff_bag.num_vars(),
        //     diff_eval_inverses,
        // ));
        // TODO: Do product check
        
        // WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // TODO: get this to error successfully since I shouldn't be using 2poly
        // println!("\n\nRemember 2 poly is hardcoded here, so it should be failing");
        // println!("diff_evals: {:?}", diff_evals);
        // println!("\n\n");
        // let two_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(diff_bag.num_vars, vec![E::ScalarField::from(3 as u64); diff_bag.poly.evaluations.len()]));
        // let (no_dups_product_proof, _, _) = ProductCheckIOP::<E, PCS>::prove(
        //     pcs_param,
        //     &[diff_poly, diff_inverse_poly],
        //     &[two_poly.clone(), one_poly.clone()], // for some reason fxs and gxs need to be the same length
        //     &mut transcript.clone(),
        // )?;

        // #[cfg(debug_assertions)] {
        //     let (f_aux_info, g_aux_info) = BagSubsetIOP::<E, PCS>::verification_info(
        //         pcs_param,
        //     &diff_poly.clone(),
        //     &range_poly.clone(),
        //     &m_range.clone(),
        //         null_offset,
        //         &mut transcript.clone(),
        //     );
        //     let verify_result = BagSubsetIOP::<E, PCS>::verify(
        //         pcs_param,
        //         &range_proof,
        //         &f_aux_info,
        //         &g_aux_info,
        //         &mut transcript.clone(),
        //     );
        //     match verify_result {
        //         Ok(_) => (),
        //         Err(e) => println!("BagStrictSortIOP::prove failed: {}", e),
        //     }
        // }

        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
        sorted_bag_comm: &BagComm<E, PCS>,
        range_comm: &TrackedComm<E, PCS>,
        m_range_comm: &TrackedComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {

        // somehow need these values, perhaps from preprocessing?
        let sorted_nv = 4;
        let sorted_len = 16;
        let range_nv = 10;
        let range_len = 2_usize.pow(range_nv as u32);

        // set up closures specified in the IOP
        let p_comm = sorted_bag_comm.poly.clone();

        let mut shift_perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_len);
        shift_perm_evals.push(E::ScalarField::from((sorted_len - 1) as u64));
        shift_perm_evals.extend((0..(sorted_len - 1)).map(|x| E::ScalarField::from(x as u64)));
        let shift_perm_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, shift_perm_evals);
        let shift_perm_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(shift_perm_mle.evaluate(pt).unwrap())};
        
        let mut diff_sel_evals = vec![E::ScalarField::one(); sorted_len];
        diff_sel_evals[0] = E::ScalarField::zero();
        let diff_sel_mle = DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_sel_evals);
        let diff_sel_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(diff_sel_mle.evaluate(pt).unwrap())};
        
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        
        
        // set up the tracker and verify the prescribed permutation check
        let one_comm = verifier_tracker.track_virtual_comm(Box::new(one_closure));
        let shift_perm_comm = verifier_tracker.track_virtual_comm(Box::new(shift_perm_closure));
        let q_poly_id = verifier_tracker.get_next_id();
        let q_comm = verifier_tracker.transfer_prover_comm(q_poly_id);
        let q_bag = BagComm::new(q_comm.clone(), one_comm);
        BagPrescPermIOP::<E, PCS>::verify(
            verifier_tracker,
            &sorted_bag_comm.clone(),
            &q_bag.clone(),
            &shift_perm_comm.clone(),
        )?;

        // set up the tracker and verify the range check
        let diff_sel_comm = verifier_tracker.track_virtual_comm(Box::new(diff_sel_closure));
        let diff_comm = diff_sel_comm.mul_comms(&p_comm.sub_comms(&q_comm)).add_scalar(E::ScalarField::one()).sub_comms(&diff_sel_comm);
        let diff_bag = BagComm::new(diff_comm, diff_sel_comm);
        let range_sel_closure = one_closure.clone();
        let range_sel = verifier_tracker.track_virtual_comm(Box::new(range_sel_closure));
        let range_bag = BagComm::new(range_comm.clone(), range_sel);
        BagSubsetIOP::<E, PCS>::verify(
            verifier_tracker,
            &diff_bag.clone(),
            &range_bag.clone(),
            &m_range_comm.clone(),
        )?;




        

        Ok(())
    }
}