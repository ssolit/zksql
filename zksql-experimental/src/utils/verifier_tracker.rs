/// The Tracker is a data structure for creating and managing virtual commnomials and their commitments.
/// It is in charge of  
///                      1) Recording the structure of virtual commnomials and their products
///                      2) Recording the structure of virtual commnomials and their products
///                      3) Recording the commitments of virtual commnomials and their products
///                      4) Providing methods for adding virtual commnomials together
/// 
/// 

use ark_ec::pairing::Pairing;
use displaydoc::Display;

use ark_serialize::CanonicalSerialize;
use ark_std::One;
use core::panic;
use std::cell::RefMut;
use derivative::Derivative;
use subroutines::PolynomialCommitmentScheme;
use subroutines::PCSError;
use std::{
    collections::HashMap,
    ops::Neg,
    // ops::Add,
    sync::Arc,
    cell::RefCell,
    rc::Rc,
    borrow::Borrow,
};
use transcript::{IOPTranscript, TranscriptError};
use std::sync::Mutex;


use crate::utils::prover_tracker;
use crate::utils::tracker_structs::{TrackerID, TrackerSumcheckClaim, TrackerZerocheckClaim};
use crate::utils::prover_tracker::CompiledZKSQLProof;

#[derive(Derivative, Display)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct VerifierTracker<'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub pcs_params: PCS::VerifierParam,
    pub transcript: IOPTranscript<E::ScalarField>,
    pub id_counter: usize,
    pub materialized_comms: HashMap<TrackerID, Arc<PCS::Commitment>>, // map from id to Commitment
    pub virtual_comms: Rc<RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>>>, // id -> eval_fn
    pub query_map: Rc<RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>>>, // (poly_id, point) -> eval
    pub sum_check_claims: Vec<TrackerSumcheckClaim<E::ScalarField>>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim<E::ScalarField>>,
    pub proof: CompiledZKSQLProof<E, PCS>,
}

impl<'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> VerifierTracker<'a, E, PCS> {
    pub fn new(pcs_params: PCS::VerifierParam, proof: CompiledZKSQLProof<E, PCS>) -> Self {
        Self {
            pcs_params,
            transcript: IOPTranscript::<E::ScalarField>::new(b"Initializing Tracnscript"),
            id_counter: 0,
            materialized_comms: HashMap::new(),
            virtual_comms: Rc::new(RefCell::new(HashMap::new())),
            query_map: Rc::new(RefCell::new(HashMap::new())),
            sum_check_claims: Vec::new(),
            zero_check_claims: Vec::new(),
            proof,
        }
    }

    pub fn gen_id(&mut self) -> TrackerID {
        let id = self.id_counter;
        self.id_counter += 1;
        TrackerID(id)
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        TrackerID(self.id_counter)
    }

    pub fn track_mat_comm(&mut self, comm: Arc<PCS::Commitment>) -> TrackerID {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // create the virtual commitment for the interaction and decision phases
        let query_map_clone = self.query_map.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(move |point: &[E::ScalarField]| {
                println!("looking up mat comm (id: {:?}, point: {:?})", id.clone(), point.clone());
                let query_map_ref_cell: &RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>> = query_map_clone.borrow();
                let query_map = query_map_ref_cell.borrow();
                println!("query map: {:?}", query_map);
                let query_res = query_map.get(&(id.clone(), point.to_vec())).unwrap();
                println!("query: {:?}", query_res);
                Ok(query_res.clone())
            })
        );

        // add the commitment to the transcript and store it in the materialized comms map
        self.transcript.append_serializable_element(b"comm", &comm);
        self.materialized_comms.insert(id.clone(), comm);

        // return the new TrackerID
        id
    }

    pub fn track_virtual_comm(
        &mut self, 
        eval_fn: Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PCSError> + 'a>,
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            eval_fn,
        );
        id
    }

    pub fn set_compiled_proof(&mut self, proof: CompiledZKSQLProof<E, PCS>) {
        self.proof = proof;
    }

    pub fn get_mat_comm(&self, id: TrackerID) -> Option<&Arc<PCS::Commitment>> {
        self.materialized_comms.get(&id)
    }
    
    pub fn add_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // Create the new evaluation function using the retrieved references and 
        // insert the new evaluation function into the virtual comms map
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    println!("in the add comms closure");
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    println!("got virtual comms");
                    let c1_eval_box: &Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PCSError>> = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    println!("c1_eval: {:?}", c1_eval);
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    println!("c2_eval: {:?}", c2_eval);
                    let new_eval: <E as Pairing>::ScalarField = c1_eval + c2_eval; // add the scalars
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    pub fn sub_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // Create the new evaluation function using the retrieved references and 
        // insert the new evaluation function into the virtual comms map
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = c1_eval - c2_eval; // sub the scalars
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    fn mul_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // Create the new evaluation function using the retrieved references and 
        // insert the new evaluation function into the virtual comms map
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = c1_eval * c2_eval; // mul the scalars
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    fn eval_virtual_comm( 
        &self, 
        comm_id: TrackerID, 
        point: &[E::ScalarField],
    ) -> Result<E::ScalarField, PCSError> {
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PCSError> + 'a>>> = self.virtual_comms.borrow();
        let virtual_comms = virtual_comms_ref_cell.borrow();
        let comm_box = virtual_comms.get(&comm_id).unwrap();
        let eval = comm_box(point)?;
        Ok(eval)
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

    pub fn get_prover_comm(&self, id: TrackerID) -> Option<&Arc<PCS::Commitment>> { 
        self.proof.comms.get(&id) 
    }
    // pub fn get_prover_polynomial_eval(&self, id: TrackerID) -> Option<&E::ScalarField> {
    //     self.proof.polynomial_evals.get(&id)
    // }

    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> Option<&E::ScalarField> {
        self.proof.sum_check_claims.get(&id)
    }

    pub fn transfer_proof_poly_evals(&mut self) {
        let query_map_ref_cell: &RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>> = self.query_map.borrow();
        let mut query_map = query_map_ref_cell.borrow_mut();
        for (key, value) in &self.proof.polynomial_evals {
            query_map.insert(key.clone(), value.clone());
        }
        // println!("transferred proof poly evals");
        // println!("query map: {:?}", query_map);
        // println!("query mapp address: {:?}", &query_map);
    }

    

}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct VerifierTrackerRef<'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    tracker_rc: Rc<RefCell<VerifierTracker<'a, E, PCS>>>,
}
impl <'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for VerifierTrackerRef<'a, E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl <'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> VerifierTrackerRef<'a, E, PCS> {
    pub fn new(tracker_rc: Rc<RefCell<VerifierTracker<'a, E, PCS>>>) -> Self {
        Self {tracker_rc}
    }

    pub fn new_from_tracker(tracker: VerifierTracker<'a, E, PCS>) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(tracker)) }
    }

    pub fn track_mat_comm(
        &self,
        comm: PCS::Commitment,
    ) -> TrackedComm<'a, E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let mut tracker: RefMut<VerifierTracker<E, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.track_mat_comm(Arc::new(comm));
        TrackedComm::new(res_id, self.tracker_rc.clone())
    }

    pub fn track_virtual_comm(
        &self,
        eval_fn: Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PCSError> + 'a>,
    ) -> TrackedComm<'a, E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let mut tracker: RefMut<VerifierTracker<E, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.track_virtual_comm(eval_fn);
        TrackedComm::new(res_id, self.tracker_rc.clone())
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_next_id()
    }

    pub fn set_compiled_proof(&mut self, proof: CompiledZKSQLProof<E, PCS>) {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().set_compiled_proof(proof);
    }

    pub fn get_mat_comm(&'a self, id: TrackerID) -> Arc<PCS::Commitment> {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_comm(id).unwrap().clone()
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<E::ScalarField, TranscriptError> {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: E::ScalarField) {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_sumcheck_claim(poly_id, claimed_sum);
    }
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_zerocheck_claim(poly_id);
    }

    // pub fn get_prover_polynomial_eval(&self, id: TrackerID) -> E::ScalarField {
    //     let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
    //     let tracker = tracker_ref_cell.borrow();
    //     let eval = tracker.get_prover_polynomial_eval(id).unwrap().clone();
    //     return eval;
    // }

    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> E::ScalarField {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        let sum = tracker.get_prover_claimed_sum(id).unwrap().clone();
        return sum;
    }

    pub fn transfer_proof_poly_evals(&mut self) {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
        let mut tracker = tracker_ref_cell.borrow_mut();
        tracker.transfer_proof_poly_evals();
    }

    // pub fn transfer_prover_comm(&mut self, id: TrackerID) -> TrackedComm<E, PCS> {
    //     let new_id: TrackerID;
    //     let comm: Arc<PCS::Commitment>;
    //     let val: E::ScalarField;
    //     let tracker_ref_cell: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker_rc.borrow();
    //     {
    //         // Scope the immutable borrow
    //         let tracker = tracker_ref_cell.borrow();
    //         let comm_opt: Option<&Arc<PCS::Commitment>> = tracker.proof.comms.get(&id);
    //         match comm_opt {
    //             Some(value) => {
    //                 comm = value.clone();
    //             },
    //             None => {
    //                 panic!("VerifierTracker Error: attempted to transfer prover comm, but id not found: {}", id);
    //             }
    //         }
    //         val = tracker.get_prover_polynomial_eval(id).unwrap().clone();
    //     } 
    //     let mut tracker = tracker_ref_cell.borrow_mut();
    //     new_id = tracker.track_mat_comm(comm);

    //     #[cfg(debug_assertions)] {
    //         assert_eq!(id, new_id, "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}", id, new_id);
    //     }
    
    //     TrackedComm::new(new_id, self.tracker_rc.clone())
    // }

    // used for testing
    pub fn clone_underlying_tracker(&self) -> VerifierTracker<'a, E, PCS> {
        let tracker_ref_cell: &RefCell<VerifierTracker<'a,E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        (*tracker).clone()
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct TrackedComm<'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub id: TrackerID,
    pub tracker: Rc<RefCell<VerifierTracker<'a, E, PCS>>>,
}
impl <'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for TrackedComm<'a, E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<'a, E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackedComm<'a, E, PCS> {
    pub fn new(id: TrackerID, tracker: Rc<RefCell<VerifierTracker<'a, E, PCS>>>) -> Self {
        Self { id, tracker }
    }

    // pub fn same_tracker(&self, other: &TrackedComm<E, PCS>) -> bool {
    //     Rc::ptr_eq(&self.tracker, &other.tracker)
    // }

    // pub fn assert_same_tracker(&self, other: &TrackedComm<E, PCS>) {
    //     let same_tracker = self.same_tracker(other);
    //     assert!(self.same_tracker(other), "TrackedComms are not from the same tracker");
    // }
    
    pub fn add(&self, other: &TrackedComm<E, PCS>) -> Self {
        // self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let mut tracker: RefMut<VerifierTracker<E, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.add_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn sub(&self, other: &TrackedComm<E, PCS>) -> Self {
        // self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().sub_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn mul(&self, other: &TrackedComm<E, PCS>) -> Self {
        // self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<'a, E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn eval_virtual_comm( 
        &self, 
        point: &[E::ScalarField],
    ) -> Result<E::ScalarField, PCSError> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let eval = tracker_ref.borrow().eval_virtual_comm(self.id.clone(), point)?;
        Ok(eval)
    }
}




#[test]
fn test_eval_comm() -> Result<(), PCSError> {
    use subroutines::MultilinearKzgPCS;
    use ark_bls12_381::{Fr, Bls12_381};
    use ark_std::test_rng;
    use ark_poly::DenseMultilinearExtension;
    use ark_poly::MultilinearExtension;
    use ark_std::UniformRand;

    println!("starting eval comm test");
    // set up randomness
    let mut rng = test_rng();
    const nv: usize = 4;
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // set up a mock conpiled proof
    let poly1 = DenseMultilinearExtension::<Fr>::rand(nv, &mut rng);
    let poly2 = DenseMultilinearExtension::<Fr>::rand(nv, &mut rng);
    let point = [Fr::rand(&mut rng); nv].to_vec();
    let eval1 = poly1.evaluate(&point).unwrap();
    let eval2 = poly2.evaluate(&point).unwrap();
    let mut proof: CompiledZKSQLProof<Bls12_381, MultilinearKzgPCS<Bls12_381>> = CompiledZKSQLProof {
        sum_check_claims: HashMap::new(),
        comms: HashMap::new(),
        polynomial_evals: HashMap::new(),
        opening_point: vec![],
        opening_proof: vec![],
    };
    proof.polynomial_evals.insert((TrackerID(0), point.clone()), eval1.clone());
    proof.polynomial_evals.insert((TrackerID(1), point.clone()), eval2.clone());
    

    // simulate interaction phase
    // [(p(x) + gamma) * phat(x)  - 1]
    println!("making virtual comms");
    let mut tracker = VerifierTrackerRef::new_from_tracker(VerifierTracker::new(pcs_verifier_param, proof));
    let comm1 = tracker.track_mat_comm(MultilinearKzgPCS::<Bls12_381>::commit(&pcs_prover_param, &poly1.clone())?);
    let comm2 = tracker.track_mat_comm(MultilinearKzgPCS::<Bls12_381>::commit(&pcs_prover_param, &poly2.clone())?);
    let one_comm = tracker.track_virtual_comm(Box::new(|_: &[Fr]| -> Result<Fr, PCSError> {
        Ok(Fr::one())
    }));
    let gamma = tracker.get_and_append_challenge(b"gamma")?;
    let gamma_comm = tracker.track_virtual_comm(Box::new(move |_: &[Fr]| -> Result<Fr, PCSError> {
        Ok(gamma)
    }));
    let mut res_comm = comm1.add(&gamma_comm);
    res_comm = res_comm.mul(&comm2);
    let res_comm = res_comm.sub(&one_comm);

    // simulate decision phase
    println!("evaluating virtual comm");
    tracker.transfer_proof_poly_evals();
    let res_eval = res_comm.eval_virtual_comm(&point)?;
    let expected_eval = (eval1 + gamma) * eval2 - Fr::one();
    assert_eq!(expected_eval, res_eval);

    Ok(())
}


