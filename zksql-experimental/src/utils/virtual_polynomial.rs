// use arithmetic::{ArithErrors, random_zero_mle_list, random_mle_list};
// use ark_ff::PrimeField;
// use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
// use ark_serialize::CanonicalSerialize;

// use ark_std::{
//     end_timer,
//     rand::{Rng, RngCore},
//     start_timer,
// };
// use rayon::prelude::*;
// use std::{cmp::max, collections::HashMap, marker::PhantomData, ops::{Add, Deref}, sync::Arc};

// use uuid::Uuid;





// // Start of LabeledVirtualPolynomial
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct LabeledVirtualPolynomial<F: PrimeField> {
//     pub label: String,
//     /// Aux information about the multilinear polynomial
//     pub aux_info: VPAuxInfo<F>,
//     /// list of reference to products, stored as Vec<(coefficient, Vec<Label>)>
//     pub products: Vec<(F, Vec<String>)>, 
//     /// Stores underlying labeled polynomials in which product multiplicand can refer
//     pub labeled_polys: HashMap<String, Arc<LabeledPolynomial<F>>>,
// }

// #[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize)]
// /// Auxiliary information about the multilinear polynomial
// pub struct VPAuxInfo<F: PrimeField> {
//     /// max number of multiplicands in each product
//     pub max_degree: usize,
//     /// number of variables of the polynomial
//     pub num_variables: usize,
//     /// Associated field
//     #[doc(hidden)]
//     pub phantom: PhantomData<F>,
// }

// impl<F: PrimeField> Add for &LabeledVirtualPolynomial<F> {
//     type Output = LabeledVirtualPolynomial<F>;
//     fn add(self, other: &LabeledVirtualPolynomial<F>) -> Self::Output {
//         let start = start_timer!(|| "virtual poly add");
//         let mut res = self.clone();
        
//         for products in other.products.iter() {
//              // make list of cloned pointers to be added to the res
//             let cur_prod: Vec<Arc<LabeledPolynomial<F>>> = products
//                 .1
//                 .iter()
//                 .map(|label| other.labeled_polys[&label.clone()].clone())
//                 .collect();

//             // add the list as a new product to the res
//             res.add_mle_list(cur_prod, products.0)
//                 .expect("add product failed");
//         }
//         end_timer!(start);
//         res
//     }
// }

// impl<F: PrimeField> LabeledVirtualPolynomial<F> {
//     /// Creates an empty virtual polynomial with `num_variables`.
//     pub fn new(num_variables: usize) -> Self {
//         LabeledVirtualPolynomial {
//             label: LabeledPolynomial::<F>::generate_new_label(),
//             aux_info: VPAuxInfo {
//                 max_degree: 0,
//                 num_variables,
//                 phantom: PhantomData::default(),
//             },
//             products: Vec::new(),
//             labeled_polys: HashMap::new(),
//         }
//     }

//     pub fn new_with_label_prefix(prefix: String, num_variables: usize) -> Self {
//         LabeledVirtualPolynomial {
//             label: LabeledPolynomial::<F>::generate_new_label_with_prefix(prefix),
//             aux_info: VPAuxInfo {
//                 max_degree: 0,
//                 num_variables,
//                 phantom: PhantomData::default(),
//             },
//             products: Vec::new(),
//             labeled_polys: HashMap::new(),
//         }
//     }

//     /// Creates an new virtual polynomial from a MLE and its coefficient.
//     pub fn new_from_unlabeled_mle(mle: &Arc<DenseMultilinearExtension<F>>, coefficient: F) -> Self {
//         let labeled_mle  = Arc::new(LabeledPolynomial::new_without_label(mle.clone()));
//         let mut labeled_polys = HashMap::new();
//         labeled_polys.insert(labeled_mle.label.clone(), labeled_mle.clone());
//         LabeledVirtualPolynomial {
//             label: LabeledPolynomial::<F>::generate_new_label(),
//             aux_info: VPAuxInfo {
//                 // Max degree of any individual variable. For a basic MLE this is 1 by definition.
//                 max_degree: 1,
//                 num_variables: mle.num_vars(),
//                 phantom: PhantomData::default(),
//             },
//             // here `0` points to the first polynomial of `flattened_ml_extensions`
//             products: vec![(coefficient, vec![labeled_mle.label.clone()])],
//             labeled_polys: labeled_polys,
//         }
//     }

//     /// Creates an new virtual polynomial from a MLE and its coefficient.
//     pub fn new_from_mle(mle: &Arc<LabeledPolynomial<F>>, coefficient: F) -> Self {
//         let mut labeled_polys = HashMap::new();
//         labeled_polys.insert(mle.label.clone(), mle.clone());
//         LabeledVirtualPolynomial {
//             label: LabeledPolynomial::<F>::generate_new_label(),
//             aux_info: VPAuxInfo {
//                 // Max degree of any individual variable. For a basic MLE this is 1 by definition.
//                 max_degree: 1,
//                 num_variables: mle.num_vars(),
//                 phantom: PhantomData::default(),
//             },
//             // here `0` points to the first polynomial of `flattened_ml_extensions`
//             products: vec![(coefficient, vec![mle.label.clone()])],
//             labeled_polys: labeled_polys,
//         }
//     }

//     /// Add a product of list of multilinear extensions to self
//     /// Returns an error if the list is empty, or the MLE has a different
//     /// `num_vars` from self.
//     ///
//     /// The MLEs will be multiplied together, and then multiplied by the scalar
//     /// `coefficient`.
//     pub fn add_mle_list(
//         &mut self,
//         mle_list: impl IntoIterator<Item = Arc<LabeledPolynomial<F>>>,
//         coefficient: F,
//     ) -> Result<(), ArithErrors> {
//         let mle_list: Vec<Arc<LabeledPolynomial<F>>> = mle_list.into_iter().collect();
//         let mut product_labels = Vec::with_capacity(mle_list.len());

//         if mle_list.is_empty() {
//             return Err(ArithErrors::InvalidParameters(
//                 "input mle_list is empty".to_string(),
//             ));
//         }

//         self.aux_info.max_degree = max(self.aux_info.max_degree, mle_list.len());

//         for mle in mle_list {
//             if mle.num_vars() != self.aux_info.num_variables {
//                 return Err(ArithErrors::InvalidParameters(format!(
//                     "product has a multiplicand with wrong number of variables {} vs {}",
//                     mle.num_vars(), self.aux_info.num_variables
//                 )));
//             }
//             let label = mle.label.clone();

//             // Add the labeled poly to the underlying labeled_polys map
//             if self.labeled_polys.contains_key(&label) {
//                 #[cfg(debug_assertions)] {
//                     assert_eq!(self.labeled_polys[&label], mle, "add_mle_list Error: mle's with the same label are not the same");
//                 }
//             } else {
//                 self.labeled_polys.insert(label.clone(), mle);
//             }

//             product_labels.push(label);
//         }
//         self.products.push((coefficient, product_labels));
//         Ok(())
//     }

//     pub fn add_unlabeled_mle_list(
//         &mut self,
//         unlabeled_mle_list: impl IntoIterator<Item = Arc<DenseMultilinearExtension<F>>>,
//         coefficient: F,
//     ) -> Result<(), ArithErrors> {
//         let labeled_mle_list: Vec<Arc<LabeledPolynomial<F>>> = unlabeled_mle_list.into_iter().map(|x| Arc::new(LabeledPolynomial::new_without_label(x))).collect();
//         self.add_mle_list(labeled_mle_list, coefficient)
//     }
    

//     /// Multiple the current LabeledVirtualPolynomial by an MLE:
//     /// - add the MLE to the MLE list;
//     /// - multiply each product by MLE and its coefficient.
//     /// Returns an error if the MLE has a different `num_vars` from self.
//     pub fn mul_by_mle(
//         &mut self,
//         mle: Arc<LabeledPolynomial<F>>,
//         coefficient: F,
//     ) -> Result<(), ArithErrors> {
//         let start = start_timer!(|| "mul by mle");

//         if mle.num_vars() != self.aux_info.num_variables {
//             return Err(ArithErrors::InvalidParameters(format!(
//                 "product has a multiplicand with wrong number of variables {} vs {}",
//                 mle.num_vars(), self.aux_info.num_variables
//             )));
//         }

//         // Add the labeled poly to the underlying labeled_polys map
//         let label = mle.label.clone();
//         if self.labeled_polys.contains_key(&label) {
//             #[cfg(debug_assertions)] {
//                 assert_eq!(self.labeled_polys[&label], mle, "add_mle_list Error: mle's with the same label are not the same");
//             }
//         } else {
//             self.labeled_polys.insert(label.clone(), mle);
//         }

//         for (prod_coef, label_list) in self.products.iter_mut() {
//             // - add the MLE to the MLE list;
//             // - multiple each product by MLE and its coefficient.
//             label_list.push(label.clone());
//             *prod_coef *= coefficient;
//         }

//         // increase the max degree by one as the MLE has degree 1.
//         self.aux_info.max_degree += 1;
//         end_timer!(start);
//         Ok(())
//     }

//     /// Evaluate the virtual polynomial at point `point`.
//     /// Returns an error is point.len() does not match `num_variables`.
//     pub fn evaluate(&self, point: &[F]) -> Result<F, ArithErrors> {
//         let start = start_timer!(|| "evaluation");

//         if self.aux_info.num_variables != point.len() {
//             return Err(ArithErrors::InvalidParameters(format!(
//                 "wrong number of variables {} vs {}",
//                 self.aux_info.num_variables,
//                 point.len()
//             )));
//         }

//         let mut evals: HashMap<String, F> = HashMap::new();
//         self
//             .labeled_polys
//             .iter()
//             .for_each(|(label, poly)| {
//                 let _ = evals.insert(label.clone(), poly.evaluate(point).unwrap()); // safe unwrap here since we have
//                                                                                     // already checked that num_var matches
//             });

//         println!("labels: {:?}", self.labeled_polys.keys());
//         println!("evals: {:?}", evals);

//         let res = self
//             .products
//             .iter()
//             .map(|(coeff, prod_labels)| *coeff * prod_labels.iter().map(|label| evals[&label.clone()]).product::<F>())
//             .sum();

//         end_timer!(start);
//         Ok(res)
//     }

//     /// Sample a random virtual polynomial, return the polynomial and its sum.
//     pub fn rand<R: RngCore>(
//         nv: usize,
//         num_multiplicands_range: (usize, usize),
//         num_products: usize,
//         rng: &mut R,
//     ) -> Result<(Self, F), ArithErrors> {
//         let start = start_timer!(|| "sample random virtual polynomial");

//         let mut sum = F::zero();
//         let mut poly = LabeledVirtualPolynomial::new(nv);
//         for _ in 0..num_products {
//             let num_multiplicands =
//                 rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
//             let (product, product_sum) = random_mle_list(nv, num_multiplicands, rng);
//             let coefficient = F::rand(rng);
//             poly.add_unlabeled_mle_list(product.into_iter(), coefficient)?;
//             sum += product_sum * coefficient;
//         }

//         end_timer!(start);
//         Ok((poly, sum))
//     }

//     /// Sample a random virtual polynomial that evaluates to zero everywhere
//     /// over the boolean hypercube.
//     pub fn rand_zero<R: RngCore>(
//         nv: usize,
//         num_multiplicands_range: (usize, usize),
//         num_products: usize,
//         rng: &mut R,
//     ) -> Result<Self, ArithErrors> {
//         let mut poly = LabeledVirtualPolynomial::new(nv);
//         for _ in 0..num_products {
//             let num_multiplicands =
//                 rng.gen_range(num_multiplicands_range.0..num_multiplicands_range.1);
//             let product = random_zero_mle_list(nv, num_multiplicands, rng);
//             let coefficient = F::rand(rng);
//             poly.add_unlabeled_mle_list(product.into_iter(), coefficient)?;
//         }

//         Ok(poly)
//     }

//     // Input poly f(x) and a random vector r, output
//     //      \hat f(x) = \sum_{x_i \in eval_x} f(x_i) eq(x, r)
//     // where
//     //      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
//     //
//     // This function is used in ZeroCheck.
//     pub fn build_f_hat(&self, r: &[F]) -> Result<Self, ArithErrors> {
//         let start = start_timer!(|| "zero check build hat f");

//         if self.aux_info.num_variables != r.len() {
//             return Err(ArithErrors::InvalidParameters(format!(
//                 "r.len() is different from number of variables: {} vs {}",
//                 r.len(),
//                 self.aux_info.num_variables
//             )));
//         }

//         let eq_x_r = build_eq_x_r(r)?;
//         let mut res = self.clone();
//         res.mul_by_mle(eq_x_r, F::one())?;

//         end_timer!(start);
//         Ok(res)
//     }

//     /// Print out the evaluation map for testing. Panic if the num_vars > 5.
//     pub fn print_evals(&self) {
//         if self.aux_info.num_variables > 5 {
//             panic!("this function is used for testing only. cannot print more than 5 num_vars")
//         }
//         for i in 0..1 << self.aux_info.num_variables {
//             let point = bit_decompose(i, self.aux_info.num_variables);
//             let point_fr: Vec<F> = point.iter().map(|&x| F::from(x)).collect();
//             println!("{} {}", i, self.evaluate(point_fr.as_ref()).unwrap())
//         }
//         println!()
//     }

//     pub fn materialize(&self) -> LabeledPolynomial<F> {
//         let nv = self.aux_info.num_variables;
//         let mut eval_vec = Vec::<F>::new();
//         for pt in 0..2_usize.pow(nv as u32) {
//             let pt_eval = 
//             self.products
//             .iter()
//             .map(|(coeff, prod)| *coeff * prod.iter().map(|label| self.labeled_polys[&label.clone()].poly.evaluations[pt]).product::<F>())
//             .sum();

//             eval_vec.push(pt_eval);
//         }
//         return LabeledPolynomial::new_without_label(Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, eval_vec)));
//     }

   
// }

// // /// Evaluate eq polynomial.
// // pub fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> Result<F, ArithErrors> {
// //     if x.len() != y.len() {
// //         return Err(ArithErrors::InvalidParameters(
// //             "x and y have different length".to_string(),
// //         ));
// //     }
// //     let start = start_timer!(|| "eq_eval");
// //     let mut res = F::one();
// //     for (&xi, &yi) in x.iter().zip(y.iter()) {
// //         let xi_yi = xi * yi;
// //         res *= xi_yi + xi_yi - xi - yi + F::one();
// //     }
// //     end_timer!(start);
// //     Ok(res)
// // }

// /// This function build the eq(x, r) polynomial for any given r.
// ///
// /// Evaluate
// ///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
// /// over r, which is
// ///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
// pub fn build_eq_x_r<F: PrimeField>(
//     r: &[F],
// ) -> Result<Arc<LabeledPolynomial<F>>, ArithErrors> {
//     let evals = build_eq_x_r_vec(r)?;
//     let mle = LabeledPolynomial::from_evaluations_vec(r.len(), evals);

//     Ok(Arc::new(mle))
// }
// /// This function build the eq(x, r) polynomial for any given r, and output the
// /// evaluation of eq(x, r) in its vector form.
// ///
// /// Evaluate
// ///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
// /// over r, which is
// ///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
// pub fn build_eq_x_r_vec<F: PrimeField>(r: &[F]) -> Result<Vec<F>, ArithErrors> {
//     // we build eq(x,r) from its evaluations
//     // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
//     // for example, with num_vars = 4, x is a binary vector of 4, then
//     //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
//     //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
//     //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
//     //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
//     //  ....
//     //  1 1 1 1 -> r0       * r1        * r2        * r3
//     // we will need 2^num_var evaluations

//     let mut eval = Vec::new();
//     build_eq_x_r_helper(r, &mut eval)?;

//     Ok(eval)
// }

// /// A helper function to build eq(x, r) recursively.
// /// This function takes `r.len()` steps, and for each step it requires a maximum
// /// `r.len()-1` multiplications.
// fn build_eq_x_r_helper<F: PrimeField>(r: &[F], buf: &mut Vec<F>) -> Result<(), ArithErrors> {
//     if r.is_empty() {
//         return Err(ArithErrors::InvalidParameters("r length is 0".to_string()));
//     } else if r.len() == 1 {
//         // initializing the buffer with [1-r_0, r_0]
//         buf.push(F::one() - r[0]);
//         buf.push(r[0]);
//     } else {
//         build_eq_x_r_helper(&r[1..], buf)?;

//         // suppose at the previous step we received [b_1, ..., b_k]
//         // for the current step we will need
//         // if x_0 = 0:   (1-r0) * [b_1, ..., b_k]
//         // if x_0 = 1:   r0 * [b_1, ..., b_k]
//         // let mut res = vec![];
//         // for &b_i in buf.iter() {
//         //     let tmp = r[0] * b_i;
//         //     res.push(b_i - tmp);
//         //     res.push(tmp);
//         // }
//         // *buf = res;

//         let mut res = vec![F::zero(); buf.len() << 1];
//         res.par_iter_mut().enumerate().for_each(|(i, val)| {
//             let bi = buf[i >> 1];
//             let tmp = r[0] * bi;
//             if i & 1 == 0 {
//                 *val = bi - tmp;
//             } else {
//                 *val = tmp;
//             }
//         });
//         *buf = res;
//     }

//     Ok(())
// }

// /// Decompose an integer into a binary vector in little endian.
// pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
//     let mut res = Vec::with_capacity(num_var);
//     let mut i = input;
//     for _ in 0..num_var {
//         res.push(i & 1 == 1);
//         i >>= 1;
//     }
//     res
// }


// #[cfg(test)]
// mod test {
//     use super::*;
//     use ark_bls12_381::Fr;
//     use ark_ff::UniformRand;
//     use ark_std::test_rng;

//     #[test]
//     fn test_virtual_polynomial_additions() -> Result<(), ArithErrors> {
//         let mut rng = test_rng();
//         for nv in 2..5 {
//             for num_products in 2..5 {
//                 let base: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

//                 let (a, _a_sum) =
//                     LabeledVirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
//                 let (b, _b_sum) =
//                     LabeledVirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
//                 let c = &a + &b;

//                 assert_eq!(
//                     a.evaluate(base.as_ref())? + b.evaluate(base.as_ref())?,
//                     c.evaluate(base.as_ref())?
//                 );
//             }
//         }

//         Ok(())
//     }

//     #[test]
//     fn test_virtual_polynomial_mul_by_mle() -> Result<(), ArithErrors> {
//         let mut rng = test_rng();
//         for nv in 2..5 {
//             for num_products in 2..5 {
//                 let base: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

//                 let (a, _a_sum) =
//                     LabeledVirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
//                 let (b, _b_sum) = random_mle_list(nv, 1, &mut rng);
//                 let b_mle = Arc::new(LabeledPolynomial::new_without_label(b[0].clone()));
//                 let coeff = Fr::rand(&mut rng);
//                 let b_vp = LabeledVirtualPolynomial::new_from_mle( &b_mle, coeff);

//                 let mut c = a.clone();

//                 c.mul_by_mle(b_mle, coeff)?;

//                 assert_eq!(
//                     a.evaluate(base.as_ref())? * b_vp.evaluate(base.as_ref())?,
//                     c.evaluate(base.as_ref())?
//                 );
//             }
//         }

//         Ok(())
//     }

//     #[test]
//     fn test_eq_xr() {
//         let mut rng = test_rng();
//         for nv in 4..10 {
//             let r: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
//             let eq_x_r = build_eq_x_r(r.as_ref()).unwrap();
//             let eq_x_r2 = build_eq_x_r_for_test(r.as_ref());
//             assert_eq!(eq_x_r.poly, eq_x_r2.poly);
//             assert_ne!(eq_x_r, eq_x_r2);

//             let eq_x_r2_poly = eq_x_r2.poly.clone();
//             let eq_x_r_clone = Arc::new(LabeledPolynomial::new_with_label(eq_x_r.label.clone(), eq_x_r2_poly));
//             assert_eq!(eq_x_r.poly, eq_x_r_clone.poly);
//         }
//     }

//     /// Naive method to build eq(x, r).
//     /// Only used for testing purpose.
//     // Evaluate
//     //      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
//     // over r, which is
//     //      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
//     fn build_eq_x_r_for_test<F: PrimeField>(r: &[F]) -> Arc<LabeledPolynomial<F>> {
//         // we build eq(x,r) from its evaluations
//         // we want to evaluate eq(x,r) over x \in {0, 1}^num_vars
//         // for example, with num_vars = 4, x is a binary vector of 4, then
//         //  0 0 0 0 -> (1-r0)   * (1-r1)    * (1-r2)    * (1-r3)
//         //  1 0 0 0 -> r0       * (1-r1)    * (1-r2)    * (1-r3)
//         //  0 1 0 0 -> (1-r0)   * r1        * (1-r2)    * (1-r3)
//         //  1 1 0 0 -> r0       * r1        * (1-r2)    * (1-r3)
//         //  ....
//         //  1 1 1 1 -> r0       * r1        * r2        * r3
//         // we will need 2^num_var evaluations

//         // First, we build array for {1 - r_i}
//         let one_minus_r: Vec<F> = r.iter().map(|ri| F::one() - ri).collect();

//         let num_var = r.len();
//         let mut eval = vec![];

//         for i in 0..1 << num_var {
//             let mut current_eval = F::one();
//             let bit_sequence = bit_decompose(i, num_var);

//             for (&bit, (ri, one_minus_ri)) in
//                 bit_sequence.iter().zip(r.iter().zip(one_minus_r.iter()))
//             {
//                 current_eval *= if bit { *ri } else { *one_minus_ri };
//             }
//             eval.push(current_eval);
//         }

//         let mle = DenseMultilinearExtension::from_evaluations_vec(num_var, eval);

//         Arc::new(LabeledPolynomial::new_with_label_prefix("eq_x_r".to_string(), Arc::new(mle)))
//     }
// }