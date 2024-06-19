use arithmetic::{ArithErrors, random_zero_mle_list, random_mle_list};
use ark_ff::PrimeField;
use ark_poly::{evaluations, DenseMultilinearExtension, MultilinearExtension};
use ark_ec::pairing::Pairing;
use subroutines::PolynomialCommitmentScheme;
use ark_serialize::CanonicalSerialize;

use ark_std::{
    end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::Add, sync::Arc};

use uuid::Uuid;

use super::virtual_polynomial::*;

pub struct PolyID(String);

pub struct IOPClaimTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    // TODO: Change claim polys to be `HashMap<PolyID, Vec<(E::ScalarField, Vec<PolyID>)>`
    pub claim_polys: HashMap<String, Vec<(E::ScalarField, Vec<String>)>>,               // virtual polynomials, keyed by label
    pub materialized_polys: HashMap<String, Arc<LabeledPolynomial<E::ScalarField>>>,    // underlying materialized polynomials, keyed by label
    pub claim_comms: HashMap<String, Vec<(E::ScalarField, Vec<String>)>>,
    pub materialized_comms: HashMap<String, Arc<LabeledCommitment<E, PCS>>>,
    pub sum_check_claims: Vec::<TrackerSumcheckClaim<E::ScalarField>>,
    pub zero_check_claims: Vec::<TrackerZerocheckClaim<E::ScalarField>>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> IOPClaimTracker<E, PCS> {
    pub fn new() -> Self {
        Self {
            claim_polys: HashMap::new(),
            materialized_polys: HashMap::new(),
            claim_comms: HashMap::new(),
            materialized_comms: HashMap::new(),
            sum_check_claims: Vec::new(),
            zero_check_claims: Vec::new(),
        }
    }
    
    pub fn new_polynomial(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>
    ) -> PolyID {
        // Instead of generating PolyID  as a UUID, maintain a counter and increment it.
        // Generate new PolyID
        // Add mapping to HashMap (PolyID -> polynomial)
        // Return PolyID
        todo!()
    }
    
    pub fn get_polynomial(&self, id: PolyID) -> Option<&DenseMultilinearExtension<E::ScalarField>> {
        todo!()
    }
     
    // adds a virtual polynomial to the tracker and its materialized polys to the map
    pub fn record_virtual_claim_poly(
        &mut self,
        poly: LabeledVirtualPolynomial<E::ScalarField>,
    ) {
        // record the structure of the virtual polynomial
        self.claim_polys.insert(poly.label.clone(), poly.products.clone());
        // record the underlying materialized polynomials
        for (label, poly) in poly.labeled_polys.iter() {
            self.materialized_polys.insert(label.clone(), poly.clone());
        }
    }

    pub fn add_sumcheck_claim(
        &mut self, 
        poly: LabeledVirtualPolynomial<E::ScalarField>, 
        claimed_sum: E::ScalarField
    ) {
        // assert_eq!(poly.label, comm.label, "IOPClaimTracker label mismatch");
        let label = poly.label.clone();
        self.sum_check_claims.push(TrackerSumcheckClaim::new(label.clone(), claimed_sum));
    }

    pub fn add_zerocheck_claim(
        &mut self, 
        poly: LabeledVirtualPolynomial<E::ScalarField>, 
    ) {
        // assert_eq!(poly.label, comm.label, "IOPClaimTracker label mismatch");
        let label = poly.label.clone();
        self.zero_check_claims.push(TrackerZerocheckClaim::new(label.clone()));
    }

    pub fn add_sumcheck_claim_from_virtual_poly(
        &mut self, 
        poly: LabeledVirtualPolynomial<E::ScalarField>, 
        claimed_sum: E::ScalarField
    ) {
        let claim = TrackerSumcheckClaim::from_labeled_poly(poly.clone(), claimed_sum);
        self.sum_check_claims.push(claim);
        self.record_virtual_claim_poly(poly.clone());
    }

    pub fn add_zerocheck_claim_from_virtual_poly(
        &mut self, 
        poly: LabeledVirtualPolynomial<E::ScalarField>, 
    ) {
        let claim = TrackerZerocheckClaim::from_labeled_poly(poly.clone());
        self.zero_check_claims.push(claim);
        self.record_virtual_claim_poly(poly.clone());
    }


}

pub struct TrackedPoly<E: Pairing> {
    pub id: PolyID,
    pub tracker: Rc<RefCell<IOPClaimTracker<E>>>,
}

impl<E: Pairing> TrackedPoly<E> {
    pub fn new(id: PolyID, tracker: Rc<RefCell<IOPClaimTracker<E>>>) -> Self {
        Self { id, tracker }
    }
    
    pub fn add(self, other: TrackedPoly<E>) -> Self {
        // Add the two polynomials together
        // Add the new polynomial to the tracker
        // Return the new polynomial
        todo!()
    }
    
    pub fn evaluations(&self) -> &[E::ScalarField] {
        // Get the evaluations of the polynomial
        todo!()
    }
}


// TODO: These should be virtual commitments instead of straight up polys and commitments
// TODO: Seperate prover claims and verifier claims





#[derive(Clone, Debug, Default, PartialEq)]
pub struct LabeledCommitment<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub label: String,
    pub commitment: PCS::Commitment,
}
impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> LabeledCommitment<E, PCS> {
    pub fn new(label: String, commitment: PCS::Commitment) -> Self {
        Self { label, commitment }
    }
}

pub struct TrackerSumcheckClaim<F: PrimeField> {
    label: String, // a label refering to a polynomial stored in the tracker
    claimed_sum: F,
} 

impl <F: PrimeField> TrackerSumcheckClaim<F> {
    pub fn new(label: String, claimed_sum: F) -> Self {
        Self { label, claimed_sum }
    }
    pub fn from_labeled_poly(poly: LabeledVirtualPolynomial<F>, claimed_sum: F) -> Self {
        Self { label: poly.label, claimed_sum}
    }
}


pub struct TrackerZerocheckClaim<F: PrimeField> {
    label: String, // a label refering to a polynomial stored in the tracker
    pub phantom: PhantomData<F>,
}

impl <F: PrimeField> TrackerZerocheckClaim<F> {
    pub fn new(label: String) -> Self {
        Self { label, phantom: PhantomData::default() }
    }
    pub fn from_labeled_poly(poly: LabeledVirtualPolynomial<F>) -> Self {
        Self { label: poly.label, phantom: PhantomData::default() }
    }
}