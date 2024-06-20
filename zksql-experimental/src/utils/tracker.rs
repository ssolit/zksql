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
use core::panic;
use std::{collections::HashMap, ops::Add, sync::Arc};
use std::cell::RefCell;
use std::rc::Rc;

use uuid::Uuid;

use std::ops::Deref;
use std::borrow::{Borrow, BorrowMut};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Display)]
pub struct PolyID(String);

#[derive(Clone, Debug, Default, PartialEq, Eq, Display)]
pub struct IOPClaimTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub materialized_polys: HashMap<PolyID, Arc<DenseMultilinearExtension<E::ScalarField>>>, // underlying materialized polynomials, keyed by label
    pub virtual_polys: HashMap<PolyID, Vec<(E::ScalarField, Vec<PolyID>)>>,                // virtual polynomials, keyed by label
    pub materialized_comms: HashMap<PolyID, Arc<PCS::Commitment>>,
    pub virtual_comms: HashMap<PolyID, Vec<(E::ScalarField, Vec<PolyID>)>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Display)]
pub struct TrackerRef<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    inner: Rc<RefCell<IOPClaimTracker<E, PCS>>>
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackerRef<E, PCS> {
    pub fn new(inner: Rc<RefCell<IOPClaimTracker<E, PCS>>>) -> Self {
        Self { inner }
    }
}
impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> Deref for TrackerRef<E, PCS> {
    type Target = Rc<RefCell<IOPClaimTracker<E, PCS>>>;

    fn deref(&self) -> &Self::Target {
        // (*self.inner).borrow()
        // *self.inner.borrow()
        // self.inner.borrow()
        // let thing = self.inner.borrow_mut();
        let thing2: &Rc<RefCell<IOPClaimTracker<E, PCS>>> = self.inner.borrow();
        // let thing3 = self.borrow();
        // let thing4 = thing2.borrow();
        return thing2;
    }
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> IOPClaimTracker<E, PCS> {
    pub fn new() -> TrackerRef<E, PCS> {
        TrackerRef::new(Rc::new(RefCell::new(Self {
            virtual_polys: HashMap::new(),
            materialized_polys: HashMap::new(),
            virtual_comms: HashMap::new(),
            materialized_comms: HashMap::new(),
        })))
    }

    pub fn gen_poly_id(&self) -> PolyID {
        let id_str = Uuid::new_v4().to_string();
        PolyID(id_str)
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> TrackedPoly<E, PCS> {
        // Create the new PolyID
        let poly_id = self.gen_poly_id();

        // Add the polynomial to the materialized map
        self.materialized_polys.insert(poly_id.clone(), Arc::new(polynomial));

        // Return the new TrackedPoly
        let tracker_ref = TrackerRef::new(Rc::new(RefCell::new(*self)));
        TrackedPoly::new(poly_id, tracker_ref, true)
    }

    pub fn get_mat_poly(
        &self, 
        id: PolyID
    ) -> Option<&Arc<DenseMultilinearExtension<E::ScalarField>>> {
        self.materialized_polys.get(&id)
    }

    pub fn get_virt_poly(&self, id: PolyID) -> Option<&Vec<(E::ScalarField, Vec<PolyID>)>> {
        self.virtual_polys.get(&id)
    }

    pub fn add_polys(
        &mut self, 
        p1_id: PolyID, 
        p2_id: PolyID
    ) -> TrackedPoly<E, PCS> {
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
        let tracker_ref = TrackerRef::new(Rc::new(RefCell::new(*self)));
        TrackedPoly::new(poly_id, tracker_ref, false)
    }

    fn mul_polys(
        &mut self, 
        p1_id: PolyID, 
        p2_id: PolyID
    ) -> TrackedPoly<E, PCS> {
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
        let tracker_ref = TrackerRef::new(Rc::new(RefCell::new(*self)));
        TrackedPoly::new(poly_id, tracker_ref, false)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Display)]
pub struct TrackedPoly<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub id: PolyID,
    pub tracker: TrackerRef<E, PCS>,
    pub is_materialized: bool,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackedPoly<E, PCS> {
    pub fn new(id: PolyID, tracker: TrackerRef<E, PCS>, is_materialized: bool) -> Self {
        Self { id, tracker, is_materialized }
    }

    pub fn evaluations(&self) -> &[E::ScalarField] {
        // Get the evaluations of the polynomial
        todo!()
    }
}




// TODO: These should be virtual commitments instead of straight up polys and commitments
// TODO: Seperate prover claims and verifier claims





// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct LabeledCommitment<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
//     pub label: PolyID,
//     pub commitment: PCS::Commitment,
// }
// impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> LabeledCommitment<E, PCS> {
//     pub fn new(label: PolyID, commitment: PCS::Commitment) -> Self {
//         Self { label, commitment }
//     }
// }

// pub struct TrackerSumcheckClaim<F: PrimeField> {
//     label: PolyID, // a label refering to a polynomial stored in the tracker
//     claimed_sum: F,
// } 

// impl <F: PrimeField> TrackerSumcheckClaim<F> {
//     pub fn new(label: PolyID, claimed_sum: F) -> Self {
//         Self { label, claimed_sum }
//     }
//     pub fn from_labeled_poly(poly: LabeledVirtualPolynomial<F>, claimed_sum: F) -> Self {
//         Self { label: poly.label, claimed_sum}
//     }
// }


// pub struct TrackerZerocheckClaim<F: PrimeField> {
//     label: PolyID, // a label refering to a polynomial stored in the tracker
//     pub phantom: PhantomData<F>,
// }

// impl <F: PrimeField> TrackerZerocheckClaim<F> {
//     pub fn new(label: PolyID) -> Self {
//         Self { label, phantom: PhantomData::default() }
//     }
//     pub fn from_labeled_poly(poly: LabeledVirtualPolynomial<F>) -> Self {
//         Self { label: poly.label, phantom: PhantomData::default() }
//     }
// }



#[cfg(test)]
mod test {
    use std::ops::Deref;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_bls12_381::Bls12_381;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use subroutines::MultilinearKzgPCS;

    
    #[test]
    fn shit_code() {
        let tracker = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let thing = tracker.inner;
        let thing2: &IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>> = thing.borrow();
    }

    #[test]
    fn test_track_mat_poly() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let tracker = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let nv = 4;

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_1.clone());
        let poly2 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_2.clone());
        
        // assert polys get different ids
        assert_ne!(poly1.id, poly2.id);

        // assert that we can get the polys back
        let lookup_poly1 = tracker.get_mat_poly(poly1.id).unwrap();
        assert_eq!(*lookup_poly1.deref(), rand_mle_1);
        Ok(())
    }

    #[test]
    fn test_add_mat_polys() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let tracker = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let nv = 4;

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_1.clone());
        let poly2 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_2.clone());
        let sum_poly = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::add_polys(tracker.clone(), poly1.id.clone(), poly2.id.clone());

        // assert addition list is constructed correctly
        let tracker_ref = tracker.borrow();
        let sum_poly_id_repr = tracker_ref.get_virt_poly(sum_poly.id.clone()).unwrap();
        assert_eq!(sum_poly_id_repr.len(), 2);
        assert_eq!(sum_poly_id_repr[0].0, Fr::one());
        assert_eq!(sum_poly_id_repr[0].1, vec![poly1.id.clone()]);
        assert_eq!(sum_poly_id_repr[1].0, Fr::one());
        assert_eq!(sum_poly_id_repr[1].1, vec![poly2.id.clone()]);
        Ok(())
    }

    #[test]
    fn test_add_mat_poly_to_virtual_poly() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let tracker = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        let nv = 4;

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_1.clone());
        let poly2 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_2.clone());
        let poly3 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::track_mat_poly(tracker.clone(), rand_mle_3.clone());

        let p1_plus_p2 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::add_polys(tracker.clone(), poly1.id.clone(), poly2.id.clone());
        let p1_plus_p2_plus_p3 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::add_polys(tracker.clone(), p1_plus_p2.id.clone(), poly3.id.clone());
        let p3_plus_p1_plus_p2 = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::add_polys(tracker.clone(), poly3.id.clone(), p1_plus_p2.id.clone());

        // assert addition list is constructed correctly
        let tracker_ref = tracker.borrow();
        let p1_plus_p2_plus_p3_repr = tracker_ref.get_virt_poly(p1_plus_p2_plus_p3.id.clone()).unwrap();
        assert_eq!(p1_plus_p2_plus_p3_repr.len(), 3);
        assert_eq!(p1_plus_p2_plus_p3_repr[0].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[0].1, vec![poly1.id.clone()]);
        assert_eq!(p1_plus_p2_plus_p3_repr[1].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[1].1, vec![poly2.id.clone()]);
        assert_eq!(p1_plus_p2_plus_p3_repr[2].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[2].1, vec![poly3.id.clone()]);

        let p3_plus_p1_plus_p2_repr = tracker_ref.get_virt_poly(p3_plus_p1_plus_p2.id.clone()).unwrap();
        assert_eq!(p3_plus_p1_plus_p2_repr.len(), 3);
        assert_eq!(p3_plus_p1_plus_p2_repr[0].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[0].1, vec![poly3.id.clone()]);
        assert_eq!(p3_plus_p1_plus_p2_repr[1].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[1].1, vec![poly1.id.clone()]);
        assert_eq!(p3_plus_p1_plus_p2_repr[2].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[2].1, vec![poly2.id.clone()]);

        Ok(())
    }

    fn test_virtual_polynomial_additions() -> Result<(), ArithErrors> {
        let mut rng = test_rng();
        let tracker = IOPClaimTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new();
        for nv in 2..5 {
            for num_products in 2..5 {
                let base: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

                let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
                let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);



            //     let (a, _a_sum) =
            //         DenseMultilinearExtension::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
            //     let (b, _b_sum) =
            //         LabeledVirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
            //     let c = &a + &b;

            //     assert_eq!(
            //         a.evaluate(base.as_ref())? + b.evaluate(base.as_ref())?,
            //         c.evaluate(base.as_ref())?
            //     );
            }
        }

        Ok(())
    }

    // #[test]
    // fn test_virtual_polynomial_mul_by_mle() -> Result<(), ArithErrors> {
    //     let mut rng = test_rng();
    //     for nv in 2..5 {
    //         for num_products in 2..5 {
    //             let base: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();

    //             let (a, _a_sum) =
    //                 LabeledVirtualPolynomial::<Fr>::rand(nv, (2, 3), num_products, &mut rng)?;
    //             let (b, _b_sum) = random_mle_list(nv, 1, &mut rng);
    //             let b_mle = Arc::new(LabeledPolynomial::new_without_label(b[0].clone()));
    //             let coeff = Fr::rand(&mut rng);
    //             let b_vp = LabeledVirtualPolynomial::new_from_mle( &b_mle, coeff);

    //             let mut c = a.clone();

    //             c.mul_by_mle(b_mle, coeff)?;

    //             assert_eq!(
    //                 a.evaluate(base.as_ref())? * b_vp.evaluate(base.as_ref())?,
    //                 c.evaluate(base.as_ref())?
    //             );
    //         }
    //     }

    //     Ok(())
    // }
}