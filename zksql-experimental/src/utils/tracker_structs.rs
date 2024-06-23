use ark_ff::PrimeField;
use std::marker::PhantomData;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TrackerID(pub usize);

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerSumcheckClaim<F: PrimeField> {
    label: TrackerID, // a label refering to a polynomial stored in the tracker
    claimed_sum: F,
} 

impl <F: PrimeField> TrackerSumcheckClaim<F> {
    pub fn new(label: TrackerID, claimed_sum: F) -> Self {
        Self { label, claimed_sum }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerZerocheckClaim<F: PrimeField> {
    label: TrackerID, // a label refering to a polynomial stored in the tracker
    pub phantom: PhantomData<F>,
}

impl <F: PrimeField> TrackerZerocheckClaim<F> {
    pub fn new(label: TrackerID) -> Self {
        Self { label, phantom: PhantomData::default() }
    }
}