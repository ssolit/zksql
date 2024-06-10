// Prove a bag is strictly sorted 
// by showing it's elements are a subset of [0, 2^n] 
// and the product of its elements is non-zero

use arithmetic::{VPAuxInfo, VirtualPolynomial};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, batch_inversion};
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::Debug, marker::PhantomData, ops::Neg, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
    },
    IOPProof,
};
use transcript::IOPTranscript;

use crate::zksql_poly_iop::bag_multitool::{
    bag_subset::{BagSubsetIOP, BagSubsetIOPProof, BagSubsetIOPSubClaim},
    bag_presc_perm::{BagPrescPermIOP, BagPrescPermIOPProof, BagPrescPermIOPSubClaim},
};

pub struct BagStrictSortIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

#[derive(Clone, Debug, PartialEq)]
pub struct BagStrictSortIOPProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    pub presc_perm_proof: BagPrescPermIOPProof<E, PCS>,
    pub range_proof: BagSubsetIOPProof<E, PCS>,
}

/// A BagStrictSortCheck check subclaim consists of
/// a bag subset subclaim
/// a product subclaim
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagStrictSortIOPSubClaim<F: PrimeField> {
    pub presc_perm_subclaim: BagPrescPermIOPSubClaim<F>,
    pub range_subclaim: BagSubsetIOPSubClaim<F>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagStrictSortIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>>
{
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagStrictSortIOP transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        sorted_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
        range_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
        m_range: Arc<DenseMultilinearExtension<E::ScalarField>>,
        num_nulls: usize,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagStrictSortIOPProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "bagStrictSort prove");
        let mut transcript = Self::init_transcript();
        let sorted_nv = sorted_poly.num_vars;

        // create shifted permutation poly and helpers
        // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
        // 	    (p,q) are p is orig, q is p offset by 1 with wraparound
        let mut perm_evals: Vec<E::ScalarField>  = Vec::<E::ScalarField>::with_capacity(sorted_nv);
        perm_evals.push(E::ScalarField::from((sorted_nv-1) as u64));
        perm_evals.extend((0..sorted_nv-1).map(|x| E::ScalarField::from(x as u64)));

        let mut q_evals = Vec::<E::ScalarField>::with_capacity(sorted_nv);
        q_evals.push(*sorted_poly.evaluations.last().unwrap());
        q_evals.extend_from_slice(&sorted_poly.evaluations[..sorted_nv-1]);
        q_evals.pop();

        let perm = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, perm_evals));
        let q = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, q_evals));
        
        // Prove that q is a prescribed permutation of p
        let (presc_perm_proof,) = BagPrescPermIOP::<E, PCS>::prove(
            pcs_param,
            sorted_poly.clone(),
            q.clone(),
            perm.clone(),
            &mut transcript,
        )?;

        //TODO: Next step is selector stuff. see below or textEdit
        // Multiply with selector with is 1 everywhere except at zero 
        // Sorted_poly = [a_0, a_1, ..]
        // Selector = [0, 1, 1, ..]
        // do range check over  [selector * (q - p) + (1 - selector)] // this is cheaper than opening an extra commitment, is (1 - selector)
        let one_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, vec![E::ScalarField::one(); sorted_nv]));
        let mut selector_evals = vec![E::ScalarField::one(); sorted_nv];
        selector_evals[0] = E::ScalarField::zero();
        let selector = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, selector_evals));
        
        let diff_evals = (0..2_usize.pow(sorted_nv as u32)).map(
            |i| selector[i] * (q[i] - sorted_poly[i]) + one_poly[i] - selector[i]
        ).collect::<Vec<_>>();
        let diff_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(sorted_nv, diff_evals));
        let null_offset = E::ScalarField::zero(); // Should have no nulls in diff_poly b/c first element is always 1
        let (range_proof,) = BagSubsetIOP::<E, PCS>::prove(
            pcs_param,
            &diff_poly.clone(),
            &range_poly.clone(),
            &m_range.clone(),
            null_offset,
            &mut transcript,
        )?;

        let proof = BagStrictSortIOPProof::<E, PCS> {
            presc_perm_proof: presc_perm_proof,
            range_proof: range_proof,
        };

        end_timer!(start);
        Ok((proof,))
    }

    pub fn verification_info (
        _: &PCS::ProverParam,
        sorted_poly: Arc<DenseMultilinearExtension<E::ScalarField>>,
        _: Arc<DenseMultilinearExtension<E::ScalarField>>,
        _: Arc<DenseMultilinearExtension<E::ScalarField>>,
        _s: usize,
        _: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField>{
        return VPAuxInfo::<E::ScalarField>{
            max_degree: 1,
            num_variables: sorted_poly.num_vars,
            phantom: PhantomData::<E::ScalarField>,
        }
    }

    // pub fn verify(
    //     pcs_param: &PCS::ProverParam,
    //     proof: &BagStrictSortIOPProof<E, PCS>,
    //     aux_info: &VPAuxInfo<E::ScalarField>,
    //     transcript: &mut IOPTranscript<E::ScalarField>,
    // ) -> Result<BagStrictSortIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
    //     let start = start_timer!(|| "bagStrictSort verify");

    // }


}