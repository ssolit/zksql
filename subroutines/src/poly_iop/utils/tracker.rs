use arithmetic::{ArithErrors, random_zero_mle_list, random_mle_list};
use crate::poly_iop::PrimeField;
use ark_poly::{evaluations, DenseMultilinearExtension, MultilinearExtension};
use ark_ec::pairing::Pairing;
use crate::PolynomialCommitmentScheme;
use ark_serialize::CanonicalSerialize;

use ark_std::{
    end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use rayon::prelude::*;
use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::Add, sync::Arc};

use uuid::Uuid;

use super::virtual_polynomial::*;


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
pub struct IOPClaimTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub polys: HashMap<String, LabeledVirtualPolynomial<E::ScalarField>>,
    pub poly_comms: HashMap<String, LabeledCommitment<E, PCS>>,
    pub sum_check_claims: Vec::<TrackerSumcheckClaim<E::ScalarField>>,
    pub sum_check_comms: Vec::<LabeledCommitment<E, PCS>>,
    pub zero_check_claims: Vec::<TrackerZerocheckClaim<E::ScalarField>>,
    pub zero_check_comms: Vec::<LabeledCommitment<E,PCS>>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> IOPClaimTracker<E, PCS> {
    pub fn new() -> Self {
        Self {
            polys: HashMap::new(),
            poly_comms: HashMap::new(),
            sum_check_claims: Vec::new(),
            sum_check_comms: Vec::new(),
            zero_check_claims: Vec::new(),
            zero_check_comms: Vec::new(),
        }
    }

    pub fn add_sumcheck_claim(
        &mut self, 
        poly: LabeledVirtualPolynomial<E::ScalarField>, 
        comm: LabeledCommitment<E, PCS>,
        claimed_sum: E::ScalarField
    ) {
        assert_eq!(poly.label, comm.label, "IOPClaimTracker label mismatch");
        let label = poly.label.clone();
        self.polys.insert(label.clone(), poly);
        self.poly_comms.insert(label.clone(), comm);
        self.sum_check_claims.push(TrackerSumcheckClaim::new(label.clone(), claimed_sum));
    }

    pub fn add_zerocheck_claim(
        &mut self, 
        poly: LabeledVirtualPolynomial<E::ScalarField>, 
        comm: LabeledCommitment<E, PCS>,
    ) {
        assert_eq!(poly.label, comm.label, "IOPClaimTracker label mismatch");
        let label = poly.label.clone();
        self.polys.insert(label.clone(), poly);
        self.poly_comms.insert(label.clone(), comm);
        self.zero_check_claims.push(TrackerZerocheckClaim::new(label.clone()));
    }
}


// TODO: These should be virtual commitments instead of straight up polys and commitments
// TODO: Seperate prover claims and verifier claims


// In tracker, when add virtual poly, give it a label