use arithmetic::{ArithErrors, random_zero_mle_list, random_mle_list};
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;

use ark_std::{
    end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use rayon::prelude::*;
use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::{Add, Deref}, sync::Arc};

use uuid::Uuid;

// LabeledPolynomial stuff
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LabeledPolynomial<F: PrimeField> {
    pub label: String,
    pub poly: DenseMultilinearExtension<F>,
    pub phantom: PhantomData<F>,
}

impl<F: PrimeField> LabeledPolynomial<F> {
    pub fn generate_new_label() -> String {
        Uuid::new_v4().to_string()
    }

    pub fn new(label: String, poly: DenseMultilinearExtension<F>) -> Self {
        Self { label, poly, phantom: PhantomData::default() }
    }

    pub fn get_label(&self) -> &str {
        &self.label
    }
}

impl<F: PrimeField> Deref for LabeledPolynomial<F> {
    type Target = DenseMultilinearExtension<F>;

    fn deref(&self) -> &Self::Target {
        &self.poly
    }
}