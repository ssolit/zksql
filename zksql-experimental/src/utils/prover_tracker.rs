/// The Tracker is a data structure for creating and managing virtual polynomials and their commitments.
/// It is in charge of  
///                      1) Recording the structure of virtual polynomials and their products
///                      2) Recording the structure of virtual polynomials and their products
///                      3) Recording the commitments of virtual polynomials and their products
///                      4) Providing methods for adding virtual polynomials together
/// 
/// 

use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_ec::pairing::Pairing;
use ark_std::{One, Zero};
use derivative::Derivative;
use displaydoc::Display;
use subroutines::{pcs::PolynomialCommitmentScheme, PCSError};
use transcript::{IOPTranscript, TranscriptError};

use std::{
    borrow::Borrow, cell::RefCell, collections::HashMap, ops::Neg, panic, rc::Rc, sync::Arc
};

use ark_serialize::CanonicalSerialize;

use crate::utils::tracker_structs::{TrackerID, TrackerSumcheckClaim, TrackerZerocheckClaim};


use subroutines::poly_iop::sum_check::{SumCheck, SumCheckSubClaim};
use subroutines::{PolyIOP, IOPProof};


#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    Default(bound = "PCS: PolynomialCommitmentScheme<E>"),
    Debug(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct CompiledZKSQLProof<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub sum_check_claims: HashMap<TrackerID, E::ScalarField>, // id -> [ sum_{i=0}^n p(i) ]
    pub comms: HashMap<TrackerID, Arc<PCS::Commitment>>,
    pub polynomial_evals: HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>, // (id, point) -> eval, // id -> p(comm_opening_point) 
    pub opening_point: Vec<E::ScalarField>,
    pub opening_proof: Vec<PCS::Proof>,
}


#[derive(Derivative, Display)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct ProverTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>>{
    pub pcs_param: PCS::ProverParam,
    pub transcript: IOPTranscript<E::ScalarField>,
    pub id_counter: usize,
    pub materialized_polys: HashMap<TrackerID, Arc<DenseMultilinearExtension<E::ScalarField>>>, // underlying materialized polynomials, keyed by label
    pub virtual_polys: HashMap<TrackerID, Vec<(E::ScalarField, Vec<TrackerID>)>>, // virtual polynomials, keyed by label. Invariant: values contain only material TrackerIDs
    pub materialized_comms: HashMap<TrackerID, Arc<PCS::Commitment>>,
    pub sum_check_claims: Vec<TrackerSumcheckClaim<E::ScalarField>>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim<E::ScalarField>>,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> ProverTracker<E, PCS> {
    pub fn new(pcs_param: PCS::ProverParam) -> Self {
        Self {
            pcs_param: pcs_param,
            transcript: IOPTranscript::<E::ScalarField>::new(b"Initializing Tracnscript"),
            id_counter: 0,
            virtual_polys: HashMap::new(),
            materialized_polys: HashMap::new(),
            materialized_comms: HashMap::new(),
            sum_check_claims: Vec::new(),
            zero_check_claims: Vec::new(),
        }
    }

    /// Generates a new `TrackerID`.
    ///
    /// This function increments an internal counter and returns a new `TrackerID`
    /// based on the current value of the counter. It ensures that each generated
    /// `TrackerID` is unique.
    pub fn gen_id(&mut self) -> TrackerID {
        let id = self.id_counter;
        self.id_counter += 1;
        TrackerID(id)
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<TrackerID, PCSError> {
        // Create the new TrackerID
        let poly_id = self.gen_id();

        // Add the polynomial to the materialized map
        let polynomial = Arc::new(polynomial);
        self.materialized_polys.insert(poly_id.clone(), polynomial.clone());

        // commit to the polynomial and add to the commitment map
        let commitment = PCS::commit(self.pcs_param.clone(), &polynomial)?;
        self.materialized_comms.insert(poly_id.clone(), Arc::new(commitment.clone()));

        // add commitment to the transcript
        self.transcript.append_serializable_element(b"comm", &commitment)?;

        // Return the new TrackerID
        Ok(poly_id)
    }

    fn track_virt_poly(
        &mut self, 
        virt: Vec<(E::ScalarField, Vec<TrackerID>)>
    ) -> TrackerID {
        let poly_id = self.gen_id();
        self.virtual_polys.insert(poly_id, virt);
        // No need to commit to virtual polynomials
        poly_id
    }
       
    pub fn get_mat_poly(&self, id: TrackerID) -> Option<&Arc<DenseMultilinearExtension<E::ScalarField>>> {
        self.materialized_polys.get(&id)
    }

    pub fn get_virt_poly(&self, id: TrackerID) -> Option<&Vec<(E::ScalarField, Vec<TrackerID>)>> {
        self.virtual_polys.get(&id)
    }

    pub fn add_polys(
        &mut self, 
        p1_id: TrackerID, 
        p2_id: TrackerID
    ) -> TrackerID {
        let p1_mat = self.get_mat_poly(p1_id.clone());
        let p1_virt = self.get_virt_poly(p1_id.clone());
        let p2_mat = self.get_mat_poly(p2_id.clone());
        let p2_virt = self.get_virt_poly(p2_id.clone());

        let mut new_virt_rep = Vec::new();
        match (p1_mat.is_some(), p1_virt.is_some(), p2_mat.is_some(), p2_virt.is_some()) {
            // Bad Case: p1 not found
            (false, false, _, _) => {
                panic!("Unknown p1 TrackerID {:?}", p1_id);
            }
            // Bad Case: p2 not found
            (_, _, false, false) => {
                panic!("Unknown p2 TrackerID {:?}", p2_id);
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
        return self.track_virt_poly(new_virt_rep);
    }

    pub fn sub_polys(
        &mut self, 
        p1_id: TrackerID, 
        p2_id: TrackerID
    ) -> TrackerID {
        let neg_p2_id = self.track_virt_poly(vec![(E::ScalarField::one().neg(), vec![p2_id])]);
        self.add_polys(p1_id, neg_p2_id)
    }

    pub fn mul_polys(
        &mut self, 
        p1_id: TrackerID, 
        p2_id: TrackerID
    ) -> TrackerID {
        let p1_mat = self.get_mat_poly(p1_id.clone());
        let p1_virt = self.get_virt_poly(p1_id.clone());
        let p2_mat = self.get_mat_poly(p2_id.clone());
        let p2_virt = self.get_virt_poly(p2_id.clone());

        let mut new_virt_rep = Vec::new();
        match (p1_mat.is_some(), p1_virt.is_some(), p2_mat.is_some(), p2_virt.is_some()) {
            // Bad Case: p1 not found
            (false, false, _, _) => {
                panic!("Unknown p1 TrackerID {:?}", p1_id);
            }
            // Bad Case: p2 not found
            (_, _, false, false) => {
                panic!("Unknown p2 TrackerID {:?}", p2_id);
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
        return self.track_virt_poly(new_virt_rep);
    }

    pub fn evaluate(&self, id: TrackerID, pt: &[E::ScalarField]) -> Option<E::ScalarField>{
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
        let virt_poly = virt_poly.unwrap(); // Invariant: contains only material TrackerIDs

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

    pub fn evaluations(&self, id: TrackerID) -> Vec<E::ScalarField> {
        // if the poly is materialized, return the evaluations
        let mat_poly = self.materialized_polys.get(&id);
        if mat_poly.is_some() {
            return mat_poly.unwrap().evaluations.clone();
        }

        // look up the virtual polynomial
        let virt_poly = self.virtual_polys.get(&id);
        if virt_poly.is_none() {
            panic!("Unknown poly id: {:?}", id);
        }
        let virt_poly = virt_poly.unwrap(); // Invariant: contains only material PolyIDs

        // figure out the number of variables, assume they all have this nv
        let first_id = virt_poly[0].1[0].clone();
        let nv: usize = self.get_mat_poly(first_id).unwrap().num_vars();

        // calculate the evaluation of each product list
        let prod_evaluations: Vec<Vec<E::ScalarField>> = virt_poly.iter().map(|(coeff, prod)| {
            let mut res = vec![coeff.clone(); 2_usize.pow(nv as u32)];
            prod.iter().for_each(|poly| {
                let poly_evals = self.evaluations(*poly);
                res = res.iter()
                    .zip(poly_evals.iter())
                    .map(|(a, b)| *a * b)
                    .collect()
            });
            res
        }).collect();

        // sum the evaluations of each product list
        let mut evals = vec![E::ScalarField::zero(); 2_usize.pow(nv as u32)];
        prod_evaluations.iter().for_each(|prod_eval| {
            evals = evals.iter()
                .zip(prod_eval.iter())
                .map(|(a, b)| *a + b)
                .collect()
        });

        // return the evals
        return evals;
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<E::ScalarField, TranscriptError> {
        self.transcript.get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        self.transcript.append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: E::ScalarField) {
        self.sum_check_claims.push(TrackerSumcheckClaim::new(poly_id, claimed_sum));
    }
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        self.zero_check_claims.push(TrackerZerocheckClaim::new(poly_id));
    }

    pub fn compile_proof(&mut self) -> CompiledZKSQLProof<E, PCS> {
        // creates a finished proof based off the subclaims that have been recorded
        // 1) aggregates the subclaims into a single MLE
        // 2) generates a sumcheck proof
        // 3) create a batch opening proofs for the sumcheck point
        // 4) takes all relevant stuff and returns a CompiledProof

        // // 1) aggregate the subclaims into a single MLE
        let nv = self.materialized_polys.iter().map(|(id, p)| p.num_vars()).max().unwrap();
        // let mut agg_mle = DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(nv, vec![E::ScalarField::zero(); 2_usize.pow(nv as u32)]);
        // let mut agg_sum = E::ScalarField::zero();
        // let sumcheck_claims = self.sum_check_claims.clone();
        // for claim in sumcheck_claims.iter() {
        //     let challenge = self.get_and_append_challenge(b"sumcheck challenge").unwrap();
        //     let claim_poly_id = claim.label.clone();
        //     let claim_mat_poly = self.materialized_polys.get(&claim_poly_id).unwrap();
        //     let poly_times_challenge_evals = claim_mat_poly.evaluations.iter().map(|x| *x * challenge).collect::<Vec<_>>();
        //     let poly_times_challenge = DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(claim_mat_poly.num_vars(), poly_times_challenge_evals);
        //     agg_mle += poly_times_challenge;
        //     agg_sum += claim.claimed_sum * challenge;
        // };

        // // 2) generate a sumcheck proof
        // let agg_mle = VirtualPolynomial::new_from_mle(&Arc::new(agg_mle), agg_sum);
        // let sumcheck_proof: IOPProof<E::ScalarField> = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&agg_mle, &mut self.transcript).unwrap();
        
        // 3) create a batch opening proofs for the sumcheck point
        // let eval_pt = sumcheck_proof.point.clone();
        // let mut polynomials: Vec<DenseMultilinearExtension<E::ScalarField>> = Vec::new();
        // let mut points: Vec<Vec<E::ScalarField>> = Vec::new();
        // let mut evals: Vec<E::ScalarField> = Vec::new();
        // for (id, poly) in self.materialized_polys.iter() {
        //     let p: DenseMultilinearExtension<E::ScalarField> = (*poly).clone();
        //     polynomials.push(p);
        //     points.push(eval_pt.clone());
        //     evals.push(poly.evaluate(eval_pt.as_slice()).unwrap());
        // }
        // let batch_opening_proof = PCS::multi_open(&self.pcs_param, &polynomials, &points, &evals, &mut self.transcript).unwrap();





        // 4) create the CompiledProof
        // TODO: actually make a sumcheck proof and get these value
        // made a default value for now for testing
        let mut sumcheck_val_map: HashMap<TrackerID, E::ScalarField> = HashMap::new();
        for claim in self.sum_check_claims.iter() {
            sumcheck_val_map.insert(claim.label.clone(), claim.claimed_sum);
        }

        let placeholder_opening_point = vec![E::ScalarField::zero(); nv];
        let mut placeholder_poly_evals: HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField> = HashMap::new();
        for (id, _) in self.materialized_polys.iter() {
            placeholder_poly_evals.insert((id.clone(), placeholder_opening_point.clone()), E::ScalarField::zero());
        }

        let placeholder_opening_proof = PCS::open(&self.pcs_param, &DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(nv, vec![E::ScalarField::zero(); 2_usize.pow(nv as u32)]), &placeholder_opening_point).unwrap().0;
        CompiledZKSQLProof {
            sum_check_claims: sumcheck_val_map,
            comms: self.materialized_comms.clone(),
            polynomial_evals: placeholder_poly_evals,
            opening_point: placeholder_opening_point,
            opening_proof: vec![placeholder_opening_proof],
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct ProverTrackerRef<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    tracker_rc: Rc<RefCell<ProverTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for ProverTrackerRef<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> ProverTrackerRef<E, PCS> {
    pub fn new(tracker_rc: Rc<RefCell<ProverTracker<E, PCS>>>) -> Self {
        Self {tracker_rc}
    }

    pub fn new_from_tracker(tracker: ProverTracker<E, PCS>) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(tracker)) }
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<TrackedPoly<E, PCS>, PCSError> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let num_vars = polynomial.num_vars();
        let res_id = tracker_ref_cell.borrow_mut().track_mat_poly(polynomial)?;
       Ok(TrackedPoly::new(res_id, num_vars, self.tracker_rc.clone()))
    }

    pub fn get_mat_poly(&self, id: TrackerID) -> Arc<DenseMultilinearExtension<E::ScalarField>> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_poly(id).unwrap().clone()
    }

    pub fn get_virt_poly(&self, id: TrackerID) -> Vec<(E::ScalarField, Vec<TrackerID>)> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_virt_poly(id).unwrap().clone()
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<E::ScalarField, TranscriptError> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(
        &mut self, 
        poly_id: TrackerID, 
        claimed_sum: E::ScalarField
    ) {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_sumcheck_claim(poly_id, claimed_sum);
    }

    pub fn add_zerocheck_claim(
        &mut self, 
        poly_id: TrackerID
    ) {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_zerocheck_claim(poly_id);
    }

    pub fn compile_proof(&mut self) -> CompiledZKSQLProof<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().compile_proof()
    }

    // used for testing
    pub fn clone_underlying_tracker(&self) -> ProverTracker<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        (*tracker).clone()
    }
}


#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct TrackedPoly<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub id: TrackerID,
    pub num_vars: usize,
    pub tracker: Rc<RefCell<ProverTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for TrackedPoly<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackedPoly<E, PCS> {
    pub fn new(id: TrackerID, num_vars: usize, tracker: Rc<RefCell<ProverTracker<E, PCS>>>) -> Self {
        Self { id, num_vars, tracker }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn same_tracker(&self, other: &TrackedPoly<E, PCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedPoly<E, PCS>) {
        assert!(self.same_tracker(other), "TrackedPolys are not from the same tracker");
    }
    
    pub fn add(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn sub(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().sub_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars,self.tracker.clone())
    }

    pub fn evaluate(&self, pt: &[E::ScalarField]) -> Option<E::ScalarField>{
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        tracker_ref.borrow().evaluate(self.id.clone(), pt)
    }

    pub fn evaluations(&self) -> Vec<E::ScalarField> {
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        tracker_ref.borrow().evaluations(self.id.clone())
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_bls12_381::Bls12_381;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use subroutines::MultilinearKzgPCS;
    use crate::utils::errors::PolyIOPErrors;

    #[test]
    fn test_track_mat_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param));
        

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone())?;
        
        // assert polys get different ids
        assert_ne!(poly1.id, poly2.id);

        // assert that we can get the polys back
        let lookup_poly1 = tracker.get_mat_poly(poly1.id);
        assert_eq!(lookup_poly1, Arc::new(rand_mle_1));
        Ok(())
    }

    #[test]
    fn test_add_mat_polys() -> Result<(),  PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param));

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone())?;
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
    fn test_add_mat_poly_to_virtual_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param));

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_mat_poly(rand_mle_3.clone())?;

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
    fn test_virtual_polynomial_additions() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param));
        
        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_4 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_5 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_6 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_7 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_mat_poly(rand_mle_3.clone())?;
        let poly4 = tracker.track_mat_poly(rand_mle_4.clone())?;
        let poly5 = tracker.track_mat_poly(rand_mle_5.clone())?;
        let poly6 = tracker.track_mat_poly(rand_mle_6.clone())?;
        let poly7 = tracker.track_mat_poly(rand_mle_7.clone())?;

        let mut addend1 = poly1.add(&poly2);
        addend1 = addend1.mul(&poly3);
        addend1 = addend1.mul(&poly4);

        let mut addend2 = poly5.mul(&poly6);
        addend2 = addend2.add(&poly7);
        
        let sum = addend1.add(&addend2);

        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let addend1_expected_eval = (rand_mle_1.evaluate(&test_eval_pt).unwrap() + 
                                    rand_mle_2.evaluate(&test_eval_pt).unwrap()) * 
                                    rand_mle_3.evaluate(&test_eval_pt).unwrap() * 
                                    rand_mle_4.evaluate(&test_eval_pt).unwrap();
        let addend2_expected_eval = (rand_mle_5.evaluate(&test_eval_pt).unwrap() * 
                                    rand_mle_6.evaluate(&test_eval_pt).unwrap()) + 
                                    rand_mle_7.evaluate(&test_eval_pt).unwrap();
        let sum_expected_eval = addend1_expected_eval + addend2_expected_eval;

        let sum_eval = sum.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(sum_expected_eval, sum_eval);

        Ok(())
    }

    #[test]
    fn test_tracked_poly_same_tracker() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker1 = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param.clone()));
        let mut tracker2 = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param));
        
        let rand_mle = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly_1a = tracker1.track_mat_poly(rand_mle.clone())?;
        let poly_2a = tracker2.track_mat_poly(rand_mle.clone())?;
        let poly_1b = TrackedPoly::new(poly_1a.id, poly_1a.num_vars, tracker1.tracker_rc.clone());

        assert!(!poly_1a.same_tracker(&poly_2a));
        assert!(poly_1a.same_tracker(&poly_1b));
        Ok(())
    }

    #[test]
    fn test_tracked_poly_mat_evaluations() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param.clone()));
        
        let rand_mle = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly = tracker.track_mat_poly(rand_mle.clone())?;

        // assert evaluations correctly returns evals for a mat poly
        let evals = poly.evaluations();
        assert_eq!(evals, rand_mle.evaluations);
        Ok(())
    }

    #[test]
    fn test_tracked_poly_virt_evaluations() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::new_from_tracker(ProverTracker::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new(pcs_param.clone()));
        
        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_mat_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_mat_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_mat_poly(rand_mle_3.clone())?;

        let virt_poly = poly1.add(&poly2).mul(&poly3);
        let virt_poly_evals = virt_poly.evaluations();
        let mut expected_poly_evals = (rand_mle_1 + rand_mle_2).to_evaluations();
        for i in 0..expected_poly_evals.len() {
            expected_poly_evals[i] *= rand_mle_3[i];
        }
        assert_eq!(virt_poly_evals, expected_poly_evals);
        Ok(())
    }
}