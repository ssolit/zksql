use crate::{errors::ArithErrors, multilinear_polynomial::random_zero_mle_list, random_mle_list};
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use ark_std::{
    end_timer,
    rand::{Rng, RngCore},
    start_timer,
};
use rayon::prelude::*;
use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::Add, sync::Arc};


pub struct ShadowMultilinearExtension<F: Field> {
    pub num_vars: usize,
    pub eval_fn: Box<dyn Fn(&[F]) -> Option<F>>,
}

impl<F: Field> ShadowMultilinearExtension<F> {
    pub fn from_evaluations_vec(num_vars: usize, evaluations: Vec<F>) -> Self {
        let dense_mle = DenseMultilinearExtension::from_evaluations_vec(num_vars, evaluations);
        Self {
            num_vars,
            eval_fn: Box::new(|x| dense_mle.evaluate(x)),
        }
    }

    pub fn from_evaluations_slice(num_vars: usize, evaluations: &[F]) -> Self {
        let dense_mle = DenseMultilinearExtension::from_evaluations_slice(num_vars, evaluations);
        Self {
            num_vars,
            eval_fn: Box::new(|x| dense_mle.evaluate(x)),
        }
    }
}

impl<F: Field> MultilinearExtension<F> for ShadowMultilinearExtension<F> {
    fn num_vars(&self) -> usize {
        self.num_vars
    }

    fn evaluate(&self, point: &[F]) -> Option<F> {
        self.eval_fn(point)
    }
}

