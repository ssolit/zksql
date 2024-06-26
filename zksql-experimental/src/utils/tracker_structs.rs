use ark_ff::PrimeField;
use std::marker::PhantomData;
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TrackerID(pub usize);

impl Display for TrackerID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerSumcheckClaim<F: PrimeField> {
    pub label: TrackerID, // a label refering to a polynomial stored in the tracker
    pub claimed_sum: F,
} 

impl <F: PrimeField> TrackerSumcheckClaim<F> {
    pub fn new(label: TrackerID, claimed_sum: F) -> Self {
        Self { label, claimed_sum }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerZerocheckClaim<F: PrimeField> {
    pub label: TrackerID, // a label refering to a polynomial stored in the tracker
    pub phantom: PhantomData<F>,
}

impl <F: PrimeField> TrackerZerocheckClaim<F> {
    pub fn new(label: TrackerID) -> Self {
        Self { label, phantom: PhantomData::default() }
    }
}