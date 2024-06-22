/// The Tracker is a data structure for creating and managing virtual polynomials and their commitments.
/// It is in charge of  
///                      1) Recording the structure of virtual polynomials and their products
///                      2) Recording the structure of virtual polynomials and their products
///                      3) Recording the commitments of virtual polynomials and their products
///                      4) Providing methods for adding virtual polynomials together
/// 
/// 

use arithmetic::{ArithErrors, random_zero_mle_list, random_mle_list};
use ark_ff::PrimeField;
use ark_poly::{evaluations, DenseMultilinearExtension, MultilinearExtension};
use ark_ec::pairing::Pairing;
use displaydoc::Display;
use subroutines::{PolynomialCommitmentScheme, MultilinearKzgPCS};
use ark_serialize::CanonicalSerialize;

use ark_std::One;
use ark_std::Zero;
use core::panic;
use std::{collections::HashMap, ops::Add, sync::Arc};
use std::cell::RefCell;
use std::rc::Rc;
use std::marker::PhantomData;
use transcript::IOPTranscript;

use std::ops::Deref;
use std::borrow::{Borrow, BorrowMut};
use std::cell::Ref;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Display, Copy)]
pub struct PolyID(usize);

#[derive(Clone, Display)]
pub struct ProverTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly_counter: usize,
    pub materialized_polys: HashMap<PolyID, Arc<DenseMultilinearExtension<E::ScalarField>>>, // underlying materialized polynomials, keyed by label
    pub virtual_polys: HashMap<PolyID, Vec<(E::ScalarField, Vec<PolyID>)>>, // virtual polynomials, keyed by label. Invariant: values contain only material PolyIDs
    pub materialized_comms: HashMap<PolyID, Arc<PCS::Commitment>>,
    pub virtual_comms: HashMap<PolyID, Vec<(E::ScalarField, Vec<PolyID>)>>,
    pub transcript: IOPTranscript<E::ScalarField>,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> ProverTracker<E, PCS> {
    pub fn new() -> Self {
        Self {
            poly_counter: 0,
            virtual_polys: HashMap::new(),
            materialized_polys: HashMap::new(),
            virtual_comms: HashMap::new(),
            materialized_comms: HashMap::new(),
            transcript: IOPTranscript::<E::ScalarField>::new(b"ProverTracker"),
        }
    }

    pub fn gen_poly_id(&mut self) -> PolyID {
        let id = self.poly_counter;
        self.poly_counter += 1;
        PolyID(id)
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> PolyID {
        // Create the new PolyID
        let poly_id = self.gen_poly_id();

        // Add the polynomial to the materialized map
        self.materialized_polys.insert(poly_id.clone(), Arc::new(polynomial));

        // Return the new PolyID
        poly_id
    }

    pub fn get_mat_poly(&self, id: PolyID) -> Option<&Arc<DenseMultilinearExtension<E::ScalarField>>> {
        self.materialized_polys.get(&id)
    }

    pub fn get_virt_poly(&self, id: PolyID) -> Option<&Vec<(E::ScalarField, Vec<PolyID>)>> {
        self.virtual_polys.get(&id)
    }

    pub fn add_polys(
        &mut self, 
        p1_id: PolyID, 
        p2_id: PolyID
    ) -> PolyID {
        let p1_mat = self.get_mat_poly(p1_id.clone());
        let p1_virt = self.get_virt_poly(p1_id.clone());
        let p2_mat = self.get_mat_poly(p2_id.clone());
        let p2_virt = self.get_virt_poly(p2_id.clone());

        let mut new_virt_rep = Vec::new();
        match (p1_mat.is_some(), p1_virt.is_some(), p2_mat.is_some(), p2_virt.is_some()) {
            // Bad Case: p1 not found
            (false, false, _, _) => {
                panic!("Unknown p1 PolyID {:?}", p1_id);
            }
            // Bad Case: p2 not found
            (_, _, false, false) => {
                panic!("Unknown p2 PolyID {:?}", p2_id);
            }
            // Case 1: both p1 and p2 are materialized
            (true, false, true, false) => {
                new_virt_rep.push((E::ScalarField::one(), vec![p1_id]));
                new_virt_rep.push((E::ScalarField::one(), vec![p2_id]));
            },
            // Case 2: p1 is materialized and p2 is virtual
            (true, false, false, true) => {
                new_virt_rep.push((E::ScalarField::one(), vec![p1_id]));
                new_virt_rep.append(&mut p2_virt.unwrap().clone());
            },
            // Case 3: p2 is materialized and p1 is virtual
            (false, true, true, false) => {
                new_virt_rep.append(&mut p1_virt.unwrap().clone());
                new_virt_rep.push((E::ScalarField::one(), vec![p2_id]));
            },
            // Case 4: both p1 and p2 are virtual
            (false, true, false, true) => {
                new_virt_rep.append(&mut p1_virt.unwrap().clone());
                new_virt_rep.append(&mut p2_virt.unwrap().clone());
            },
            // Handling unexpected cases
            _ => {
                panic!("Internal tracker::add_polys error. This code should be unreachable");
            },
        }

        let poly_id = self.gen_poly_id();
        self.virtual_polys.insert(poly_id.clone(), new_virt_rep);
        poly_id
    }

    fn mul_polys(
        &mut self, 
        p1_id: PolyID, 
        p2_id: PolyID
    ) -> PolyID {
        let p1_mat = self.get_mat_poly(p1_id.clone());
        let p1_virt = self.get_virt_poly(p1_id.clone());
        let p2_mat = self.get_mat_poly(p2_id.clone());
        let p2_virt = self.get_virt_poly(p2_id.clone());

        let mut new_virt_rep = Vec::new();
        match (p1_mat.is_some(), p1_virt.is_some(), p2_mat.is_some(), p2_virt.is_some()) {
            // Bad Case: p1 not found
            (false, false, _, _) => {
                panic!("Unknown p1 PolyID {:?}", p1_id);
            }
            // Bad Case: p2 not found
            (_, _, false, false) => {
                panic!("Unknown p2 PolyID {:?}", p2_id);
            }
            // Case 1: both p1 and p2 are materialized
            (true, false, true, false) => {
                new_virt_rep.push((E::ScalarField::one(), vec![p1_id, p2_id]));
            },
            // Case 2: p1 is materialized and p2 is virtual
            (true, false, false, true) => {
                let p2_rep = p2_virt.unwrap();
                p2_rep.iter().for_each(|(coeff, prod)| {
                    let mut new_prod = prod.clone();
                    new_prod.push(p1_id.clone());
                    new_virt_rep.push((coeff.clone(), new_prod));
                });
            },
            // Case 3: p2 is materialized and p1 is virtual
            (false, true, true, false) => {
                let p1_rep = p1_virt.unwrap();
                p1_rep.iter().for_each(|(coeff, prod)| {
                    let mut new_prod = prod.clone();
                    new_prod.push(p2_id.clone());
                    new_virt_rep.push((coeff.clone(), new_prod));
                });
            },
            // Case 4: both p1 and p2 are virtual
            (false, true, false, true) => {
                let p1_rep = p1_virt.unwrap();
                let p2_rep = p2_virt.unwrap();
                p1_rep.iter().for_each(|(p1_coeff, p1_prod)| {
                    p2_rep.iter().for_each(|(p2_coeff, p2_prod)| {
                        let new_coeff = *p1_coeff * p2_coeff;
                        let mut new_prod_vec = p1_prod.clone();
                        new_prod_vec.extend(p2_prod.clone());
                        new_virt_rep.push((new_coeff, new_prod_vec));
                    })
                });
            },
            // Handling unexpected cases
            _ => {
                panic!("Internal tracker::mul_polys error. This code should be unreachable");
            },
        }

        let poly_id = self.gen_poly_id();
        self.virtual_polys.insert(poly_id.clone(), new_virt_rep);
        poly_id
    }

    fn evaluate(&self, id: PolyID, pt: &[E::ScalarField]) -> Option<E::ScalarField>{
        // if the poly is materialized, return the evaluation
        let mat_poly = self.materialized_polys.get(&id);
        if mat_poly.is_some() {
            return mat_poly.unwrap().evaluate(pt);
        }

        // look up the virtual polynomial
        let virt_poly = self.virtual_polys.get(&id);
        if virt_poly.is_none() {
            panic!("Unknown poly id: {:?}", id);
        }
        let virt_poly = virt_poly.unwrap(); // Invariant: contains only material PolyIDs

        // calculate the evaluation of each product list
        let prod_evals: Vec<E::ScalarField> = virt_poly.iter().map(|(coeff, prod)| {
            let mut res = coeff.clone();
            prod.iter().for_each(|poly| {
                res *= self.evaluate(poly.clone(), pt).unwrap();
            });
            res
        }).collect();

        // sum the evaluations of each product list
        let mut eval = E::ScalarField::zero();
        prod_evals.iter().for_each(|prod_eval| {
            eval += prod_eval;
        });

        // return the eval
        Some(eval)
    }
}

#[derive(Clone)]
pub struct ProverTrackerRef<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    tracker_rc: Rc<RefCell<ProverTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for ProverTrackerRef<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> ProverTrackerRef<E, PCS> {
    pub fn new(tracker: ProverTracker<E, PCS>) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(tracker)) }
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> TrackedPoly<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let res_id = tracker_ref_cell.borrow_mut().track_mat_poly(polynomial);
        TrackedPoly::new(res_id, self.tracker_rc.clone())
    }

    pub fn add_polys(
        &mut self, 
        p1_id: PolyID, 
        p2_id: PolyID,
    ) -> TrackedPoly<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let res_id = tracker_ref_cell.borrow_mut().add_polys(p1_id, p2_id);
        TrackedPoly::new(res_id, self.tracker_rc.clone())
    }

    pub fn mul_polys(
        &mut self, 
        p1_id: PolyID, 
        p2_id: PolyID,
    ) -> TrackedPoly<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let res_id = tracker_ref_cell.borrow_mut().mul_polys(p1_id, p2_id);
        TrackedPoly::new(res_id, self.tracker_rc.clone())
    }

    pub fn evaluate(&self, id: PolyID, pt: &[E::ScalarField]) -> Option<E::ScalarField> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().evaluate(id, pt)
    }

    pub fn get_mat_poly(&self, id: PolyID) -> Arc<DenseMultilinearExtension<E::ScalarField>> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_poly(id).unwrap().clone()
    }

    pub fn get_virt_poly(&self, id: PolyID) -> Vec<(E::ScalarField, Vec<PolyID>)> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_virt_poly(id).unwrap().clone()
    }
}

use derivative::Derivative;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct TrackedPoly<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub id: PolyID,
    pub tracker: Rc<RefCell<ProverTracker<E, PCS>>>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for TrackedPoly<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}


impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackedPoly<E, PCS> {
    pub fn new(id: PolyID, tracker: Rc<RefCell<ProverTracker<E, PCS>>>) -> Self {
        Self { id, tracker }
    }

    pub fn same_tracker(&self, other: &TrackedPoly<E, PCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedPoly<E, PCS>) {
        assert!(self.same_tracker(other), "TrackedPolys are not from the same tracker");
    }
    
    pub fn add(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.tracker.clone())
    }

    pub fn mul(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.tracker.clone())
    }

    pub fn evaluate(&self, pt: &[E::ScalarField]) -> Option<E::ScalarField>{
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        tracker_ref.borrow().evaluate(self.id.clone(), pt)
    }
}


#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrackerZerocheckClaim<F: PrimeField> {
    label: PolyID, // a label refering to a polynomial stored in the tracker
    pub phantom: PhantomData<F>,
}


#[cfg(test)]
mod test {
    use std::ops::Deref;

    use crate::utils::prover_tracker;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_bls12_381::Bls12_381;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use subroutines::MultilinearKzgPCS;
    use ark_std::Zero;

    #[test]
    fn test_track_mat_poly() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let mut tracker = ProverTrackerRef::new(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new());
        let nv = 4;

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone());
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone());
        
        // assert polys get different ids
        assert_ne!(poly1.id, poly2.id);

        // assert that we can get the polys back
        let lookup_poly1 = tracker.get_mat_poly(poly1.id);
        assert_eq!(*lookup_poly1.deref(), rand_mle_1);
        Ok(())
    }

    #[test]
    fn test_add_mat_polys() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let mut tracker = ProverTrackerRef::new(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new());
        let nv = 4;

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone());
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone());
        let sum_poly = poly1.add(&poly2);

        // assert addition list is constructed correctly
        let sum_poly_id_repr = tracker.get_virt_poly(sum_poly.id);
        assert_eq!(sum_poly_id_repr.len(), 2);
        assert_eq!(sum_poly_id_repr[0].0, Fr::one());
        assert_eq!(sum_poly_id_repr[0].1, vec![poly1.id]);
        assert_eq!(sum_poly_id_repr[1].0, Fr::one());
        assert_eq!(sum_poly_id_repr[1].1, vec![poly2.id]);

        // test evalutation at a random point
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let sum_eval = sum_poly.evaluate(&test_eval_pt).unwrap();
        let poly1_eval = rand_mle_1.evaluate(&test_eval_pt).unwrap();
        let poly2_eval = rand_mle_2.evaluate(&test_eval_pt).unwrap();
        assert_eq!(sum_eval, poly1_eval + poly2_eval);

        Ok(())
    }

    #[test]
    fn test_add_mat_poly_to_virtual_poly() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let mut tracker = ProverTrackerRef::new(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new());
        let nv = 4;

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone());
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone());
        let poly3 = tracker.track_mat_poly(rand_mle_3.clone());

        let p1_plus_p2 = poly1.add(&poly2);
        let p1_plus_p2_plus_p3 = p1_plus_p2.add(&poly3);
        let p3_plus_p1_plus_p2 = poly3.add(&p1_plus_p2);

        // assert addition list is constructed correctly
        let p1_plus_p2_plus_p3_repr = tracker.get_virt_poly(p1_plus_p2_plus_p3.id);
        assert_eq!(p1_plus_p2_plus_p3_repr.len(), 3);
        assert_eq!(p1_plus_p2_plus_p3_repr[0].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[0].1, vec![poly1.id]);
        assert_eq!(p1_plus_p2_plus_p3_repr[1].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[1].1, vec![poly2.id]);
        assert_eq!(p1_plus_p2_plus_p3_repr[2].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[2].1, vec![poly3.id]);

        let p3_plus_p1_plus_p2_repr = tracker.get_virt_poly(p3_plus_p1_plus_p2.id);
        assert_eq!(p3_plus_p1_plus_p2_repr.len(), 3);
        assert_eq!(p3_plus_p1_plus_p2_repr[0].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[0].1, vec![poly3.id]);
        assert_eq!(p3_plus_p1_plus_p2_repr[1].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[1].1, vec![poly1.id]);
        assert_eq!(p3_plus_p1_plus_p2_repr[2].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[2].1, vec![poly2.id]);

        // assert evaluations at a random point are equal
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let p1_plus_p2_plus_p3_eval = p1_plus_p2_plus_p3.evaluate(&test_eval_pt).unwrap();
        let p3_plus_p1_plus_p2_eval = p3_plus_p1_plus_p2.evaluate(&test_eval_pt).unwrap();
        assert_eq!(p1_plus_p2_plus_p3_eval, p3_plus_p1_plus_p2_eval);

        Ok(())
    }

    #[test]
    fn test_virtual_polynomial_additions() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let mut tracker = ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let nv = 4;
        
        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_4 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_5 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_6 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_7 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone());
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone());
        let poly3 = tracker.track_mat_poly(rand_mle_3.clone());
        let poly4 = tracker.track_mat_poly(rand_mle_4.clone());
        let poly5 = tracker.track_mat_poly(rand_mle_5.clone());
        let poly6 = tracker.track_mat_poly(rand_mle_6.clone());
        let poly7 = tracker.track_mat_poly(rand_mle_7.clone());

        let mut addend1 = tracker.add_polys(poly1, poly2);
        addend1 = tracker.mul_polys(addend1, poly3);
        addend1 = tracker.mul_polys(addend1, poly4);

        let mut addend2 = tracker.mul_polys(poly5, poly6);
        addend2 = tracker.add_polys(addend2, poly7);
        
        let sum = tracker.add_polys(addend1, addend2);

        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let addend1_expected_eval = (rand_mle_1.evaluate(&test_eval_pt).unwrap() + 
                                    rand_mle_2.evaluate(&test_eval_pt).unwrap()) * 
                                    rand_mle_3.evaluate(&test_eval_pt).unwrap() * 
                                    rand_mle_4.evaluate(&test_eval_pt).unwrap();
        let addend2_expected_eval = (rand_mle_5.evaluate(&test_eval_pt).unwrap() * 
                                    rand_mle_6.evaluate(&test_eval_pt).unwrap()) + 
                                    rand_mle_7.evaluate(&test_eval_pt).unwrap();
        let sum_expected_eval = addend1_expected_eval + addend2_expected_eval;

        let sum_eval = tracker.evaluate(sum, test_eval_pt.as_slice()).unwrap();
        assert_eq!(sum_expected_eval, sum_eval);

        Ok(())
    }

    #[test]
    fn test_tracked_poly_same_tracker() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let mut tracker1 = ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let mut tracker2 = ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let nv = 4;
        
        let rand_mle = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly_id_1 = tracker1.track_mat_poly(rand_mle.clone());
        let poly_id_2 = tracker2.track_mat_poly(rand_mle.clone());
        let poly1 = TrackedPoly::new(poly_id_1, Rc::new(RefCell::new(tracker1)));
        let poly2 = TrackedPoly::new(poly_id_2, Rc::new(RefCell::new(tracker2)));

        assert!(!poly1.same_tracker(&poly2));
        assert!(poly1.same_tracker(&poly1));
        Ok(())
    }
}