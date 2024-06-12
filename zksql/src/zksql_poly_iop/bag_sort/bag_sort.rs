// Prove a bag is strictly sorted 
// by showing it's elements are a subset of [0, 2^n] 
// and the product of its elements is non-zero

use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::{batch_inversion, PrimeField};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::errors::PolyIOPErrors,
};
use transcript::IOPTranscript;

use crate::zksql_poly_iop::bag_multitool::{
    bag_multitool::Bag, bag_presc_perm::{BagPrescPermIOP, BagPrescPermIOPProof, BagPrescPermIOPSubClaim}, bag_subset::{BagSubsetIOP, BagSubsetIOPProof, BagSubsetIOPSubClaim}
};
use subroutines::{ProductCheckIOP, ProductCheckIOPProof, ProductCheckIOPSubClaim};

pub struct BagStrictSortIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

#[derive(Clone, Debug, PartialEq)]
pub struct BagStrictSortIOPProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    pub presc_perm_proof: BagPrescPermIOPProof<E, PCS>,
    pub range_proof: BagSubsetIOPProof<E, PCS>,
    pub no_dups_product_proof: ProductCheckIOPProof<E, PCS>,
}

/// A BagStrictSortCheck check subclaim consists of
/// a bag subset subclaim
/// a product subclaim
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagStrictSortIOPSubClaim<F: PrimeField> {
    pub presc_perm_subclaim: BagPrescPermIOPSubClaim<F>,
    pub range_subclaim: BagSubsetIOPSubClaim<F>,
    pub no_dups_product_subclaim: ProductCheckIOPSubClaim<F>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagStrictSortIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>
{
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagStrictSortIOP transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        sorted_bag: &Bag<E>,
        range_poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        m_range: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagStrictSortIOPProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "bagStrictSort prove");
        let sorted_nv = sorted_bag.num_vars;
        let sorted_len = sorted_bag.poly.evaluations.len();
        let range_nv = range_poly.num_vars;
        let range_len = range_poly.evaluations.len();

        // create shifted permutation poly and helpers
        // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
        // 	    (p,q) are p is orig, q is p offset by 1 with wraparound
        let mut perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_nv);
        perm_evals.push(E::ScalarField::from((sorted_len - 1) as u64));
        perm_evals.extend((0..(sorted_len - 1)).map(|x| E::ScalarField::from(x as u64)));

        let mut q_evals = Vec::<E::ScalarField>::with_capacity(sorted_nv);
        q_evals.push(*sorted_bag.poly.evaluations.last().unwrap());
        q_evals.extend_from_slice(&sorted_bag.poly.evaluations[..sorted_len]);
        q_evals.pop();

        let perm = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, perm_evals));
        let q = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals));
        let one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len]));
        let q_bag = Bag::new(q, one_poly);

        // Prove that q is a prescribed permutation of p
        let (presc_perm_proof,) = BagPrescPermIOP::<E, PCS>::prove(
            pcs_param,
            &sorted_bag.clone(),
            &q_bag.clone(),
            &perm.clone(),
            &mut transcript.clone(),
        )?;

        // #[cfg(debug_assertions)] {
        //     let aux_info = BagPrescPermIOP::<E, PCS>::verification_info(
        //         pcs_param,
        //         &sorted_bag.clone(),
        //         &q.clone(),
        //         &perm.clone(),
        //         &mut transcript.clone(),
        //     );

        //     let verify_result = BagPrescPermIOP::<E, PCS>::verify(
        //         pcs_param,
        //         &presc_perm_proof,
        //         &aux_info,
        //         &mut transcript.clone(),
        //     );
        //     match verify_result {
        //         Ok(_) => (),
        //         Err(e) => println!("BagStrictSortIOP::prove failed: {}", e),
        //     }
        // }

        //TODO: Next step is selector stuff. see below or textEdit
        // Multiply with selector with is 1 everywhere except at zero 
        // sorted_bag = [a_0, a_1, ..]
        // Selector = [0, 1, 1, ..]
        // do range check over  [selector * (q - p) + (1 - selector)] // this is cheaper than opening an extra commitment, is (1 - selector)
        let one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len]));
        let mut selector_evals = vec![E::ScalarField::one(); sorted_len];
        selector_evals[0] = E::ScalarField::zero();
        let selector = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, selector_evals));
        
        let diff_evals = (0..sorted_len).map(
            |i| selector[i] * (sorted_bag.poly[i] - q_bag.poly[i]) + one_poly[i] - selector[i]
        ).collect::<Vec<_>>();

        let diff_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_evals));
        let diff_sel = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_len])); 
        let diff_bag = Bag::new(diff_poly.clone(), diff_sel);

        // DIFF_SEL IS WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        println!("\n\nRemember Diff Sel is wrong, needs to account for multiple zeros !!!!!!!!");
        println!("diff_evals: {:?}", diff_bag.poly.evaluations);
        println!("\n\n");

        let range_bag = Bag::new(range_poly.clone(), Arc::new(DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![E::ScalarField::one(); range_len])));
        let (range_proof,) = BagSubsetIOP::<E, PCS>::prove(
            pcs_param,
            &diff_bag.clone(),
            &range_bag.clone(),
            &m_range.clone(),
            &mut transcript.clone(),
        )?;

        // show diff_evals are all non-zero
        // (ProductCheckIOP) Show supp includes all elements of bag by showing m_bag has no zeros
        let mut diff_eval_inverses = diff_bag.poly.evaluations.clone();
        batch_inversion(&mut diff_eval_inverses);
        println!("diff_evals: {:?}", diff_bag.poly.evaluations);
        println!("diff_eval_inverses: {:?}", diff_eval_inverses);
        let diff_inverse_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            diff_bag.num_vars,
            diff_eval_inverses,
        ));
        // WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // TODO: get this to error successfully since I shouldn't be using 2poly
        println!("\n\nRemember 2 poly is hardcoded here, so it should be failing");
        println!("diff_evals: {:?}", diff_bag.poly.evaluations);
        println!("\n\n");
        let two_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(diff_bag.num_vars, vec![E::ScalarField::from(3 as u64); diff_bag.poly.evaluations.len()]));
        let (no_dups_product_proof, _, _) = ProductCheckIOP::<E, PCS>::prove(
            pcs_param,
            &[diff_poly, diff_inverse_poly],
            &[two_poly.clone(), one_poly.clone()], // for some reason fxs and gxs need to be the same length
            &mut transcript.clone(),
        )?;

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

        let proof = BagStrictSortIOPProof::<E, PCS> {
            presc_perm_proof: presc_perm_proof,
            range_proof: range_proof,
            no_dups_product_proof: no_dups_product_proof,
        };

        end_timer!(start);
        Ok((proof,))
    }

    pub fn verification_info (
        pcs_param: &PCS::ProverParam,
        sorted_bag: &Bag<E>,
        range_poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        m_range: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Vec<Vec<VPAuxInfo<E::ScalarField>>> {
        let mut aux_info_vec: Vec<Vec<VPAuxInfo<E::ScalarField>>> = Vec::new();
        let perm_dummy = sorted_bag.clone(); // just need something the right size
        let (a1, a2, a3, a4) = BagPrescPermIOP::<E, PCS>::verification_info(
            pcs_param,
        &sorted_bag.clone(),
        &perm_dummy.clone(),
            &perm_dummy.poly.clone(),
            &mut transcript.clone(),
        );
        aux_info_vec.push(a1);
        aux_info_vec.push(a2);
        aux_info_vec.push(a3);
        aux_info_vec.push(a4);

        let range_nv = range_poly.num_vars;
        let range_len = range_poly.evaluations.len();
        let range_bag = Bag::new(range_poly.clone(), Arc::new(DenseMultilinearExtension::from_evaluations_vec(range_nv, vec![E::ScalarField::one(); range_len])));
        let (a1, a2, a3, a4) = BagSubsetIOP::<E, PCS>::verification_info(
            pcs_param,
            &sorted_bag.clone(), // same size as diff_poly
            &range_bag.clone(),
            &m_range.clone(),
            &mut transcript.clone(),
        );
        aux_info_vec.push(a1);
        aux_info_vec.push(a2);
        aux_info_vec.push(a3);
        aux_info_vec.push(a4);

        let product_check_aux = ProductCheckIOP::<E, PCS>::verification_info(
            pcs_param,
            &[sorted_bag.poly.clone(), sorted_bag.poly.clone()],
            &[sorted_bag.poly.clone()],
            &mut transcript.clone(),
        );
        aux_info_vec.push(vec![product_check_aux]);

        return aux_info_vec;
    }

    pub fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &BagStrictSortIOPProof<E, PCS>,
        aux_info_vec: &Vec<Vec<VPAuxInfo<E::ScalarField>>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagStrictSortIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
        let start = start_timer!(|| "BagStrictSortIOP verify");

        let presc_perm_subclaim = BagPrescPermIOP::<E, PCS>::verify(
            pcs_param,
            &proof.presc_perm_proof,
            &aux_info_vec[0],
            &aux_info_vec[1],   
            &aux_info_vec[2],
            &aux_info_vec[3],
            &mut transcript.clone(),
        )?;

        let range_subclaim = BagSubsetIOP::<E, PCS>::verify(
            pcs_param,
            &proof.range_proof,
            &aux_info_vec[4],
            &aux_info_vec[5],
            &aux_info_vec[6],
            &aux_info_vec[7],
            &mut  transcript.clone(),
        )?;

        println!("starting no_dups_product verification");
        let no_dups_product_subclaim = ProductCheckIOP::<E, PCS>::verify(
            &proof.no_dups_product_proof,
            &aux_info_vec[8][0],
            &mut transcript.clone(),
        )?;
        println!("no_dups_product verification successful");

        end_timer!(start);
        Ok(BagStrictSortIOPSubClaim::<E::ScalarField>{
            presc_perm_subclaim: presc_perm_subclaim,
            range_subclaim: range_subclaim,
            no_dups_product_subclaim: no_dups_product_subclaim,
        })
    }
}