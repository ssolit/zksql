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
use derivative::Derivative;
use subroutines::PolynomialCommitmentScheme;
use crate::tracker::errors::PolyIOPErrors;
use std::{
    collections::HashMap,
    cell::RefCell,
    rc::Rc,
    borrow::Borrow,
};
use transcript::{IOPTranscript, TranscriptError};
use ark_std::Zero;

use crate::tracker::tracker_structs::{TrackerID, TrackerSumcheckClaim, TrackerZerocheckClaim};
use crate::tracker::prover_tracker::CompiledZKSQLProof;

use subroutines::{
    PolyIOP,
    poly_iop::prelude::{SumCheck, ZeroCheck},
};

#[derive(Derivative, Display)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct VerifierTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub pcs_params: PCS::VerifierParam,
    pub transcript: IOPTranscript<E::ScalarField>,
    pub id_counter: usize,
    pub materialized_comms: HashMap<TrackerID, PCS::Commitment>, // map from id to Commitment
    pub virtual_comms: Rc<RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>>>, // id -> eval_fn
    pub query_map: Rc<RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>>>, // (poly_id, point) -> eval
    pub sum_check_claims: Vec<TrackerSumcheckClaim<E::ScalarField>>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim<E::ScalarField>>,
    pub proof: CompiledZKSQLProof<E, PCS>,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> VerifierTracker<E, PCS> {
    pub fn new(pcs_params: PCS::VerifierParam) -> Self {
        Self {
            pcs_params,
            transcript: IOPTranscript::<E::ScalarField>::new(b"Initializing Tracnscript"),
            id_counter: 0,
            materialized_comms: HashMap::new(),
            virtual_comms: Rc::new(RefCell::new(HashMap::new())),
            query_map: Rc::new(RefCell::new(HashMap::new())),
            sum_check_claims: Vec::new(),
            zero_check_claims: Vec::new(),
            proof: CompiledZKSQLProof::default(),
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

    pub fn track_mat_comm(&mut self, comm: PCS::Commitment) -> Result<TrackerID, PolyIOPErrors> {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // create the virtual commitment for the interaction and decision phases
        let query_map_clone = self.query_map.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(move |point: &[E::ScalarField]| {
                let query_map_ref_cell: &RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>> = query_map_clone.borrow();
                let query_map = query_map_ref_cell.borrow();
                let query_res = query_map.get(&(id.clone(), point.to_vec())).unwrap();
                Ok(query_res.clone())
            })
        );

        // add the commitment to the transcript and store it in the materialized comms map
        self.transcript.append_serializable_element(b"comm", &comm)?;
        self.materialized_comms.insert(id.clone(), comm);

        // return the new TrackerID
        Ok(id)
    }

    pub fn track_virtual_comm(
        &mut self, 
        eval_fn: Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>,
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            eval_fn,
        );
        id
    }

    pub fn set_compiled_proof(&mut self, proof: CompiledZKSQLProof<E, PCS>) {
        self.proof = proof;
    }

    pub fn get_mat_comm(&self, id: TrackerID) -> Option<&PCS::Commitment> {
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
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box: &Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PolyIOPErrors>> = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
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
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box: &Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PolyIOPErrors>> = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    Ok(c1_eval - c2_eval)
                }
            ),
        );
        id
    }

    pub fn mul_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
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

    pub fn add_scalar(
        &mut self, 
        poly_id: TrackerID, 
        c: E::ScalarField
    ) -> TrackerID {
        let _ = self.gen_id(); // burn a tracker id to match how prover_tracker::add_scalar works
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let poly_eval_box = virtual_comms.get(&poly_id).unwrap();
                    let poly_eval: <E as Pairing>::ScalarField = poly_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = poly_eval + c; // c + old eval
                    Ok(new_eval)
                }
            ),
        );
        id
    }

    pub fn mul_scalar(
        &mut self, 
        poly_id: TrackerID, 
        c: E::ScalarField
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let poly_eval_box = virtual_comms.get(&poly_id).unwrap();
                    let poly_eval: <E as Pairing>::ScalarField = poly_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = c.clone() * poly_eval; // c * old eval
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    pub fn eval_virtual_comm( 
        &self, 
        comm_id: TrackerID, 
        point: &[E::ScalarField],
    ) -> Result<E::ScalarField, PolyIOPErrors> {
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
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

    pub fn get_prover_comm(&self, id: TrackerID) -> Option<&PCS::Commitment> { 
        self.proof.comms.get(&id) 
    }

    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> Option<&E::ScalarField> {
        self.proof.sum_check_claims.get(&id)
    }

    pub fn transfer_proof_poly_evals(&mut self) {
        let query_map_ref_cell: &RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>> = self.query_map.borrow();
        let mut query_map = query_map_ref_cell.borrow_mut();
        for (key, value) in &self.proof.query_map {
            query_map.insert(key.clone(), value.clone());
        }
    }

    pub fn verify_claims(&mut self) -> Result<(), PolyIOPErrors> {
        let zero_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::zero())};
        let mut zerocheck_comm = self.track_virtual_comm(Box::new(zero_closure));
        let zero_check_claims = self.zero_check_claims.clone();
        for claim in zero_check_claims {
            let challenge = self.get_and_append_challenge(b"zerocheck challenge").unwrap();
            let claim_poly_id = self.mul_scalar(claim.label.clone(), challenge);
            zerocheck_comm = self.add_comms(zerocheck_comm, claim_poly_id);
        }

        let zero_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::zero())};
        let mut sumcheck_comm = self.track_virtual_comm(Box::new(zero_closure));
        let sumcheck_claims = self.sum_check_claims.clone();
        for claim in sumcheck_claims.iter() {
            let challenge = self.get_and_append_challenge(b"sumcheck challenge").unwrap();
            let claim_poly_id = self.mul_scalar(claim.label.clone(), challenge);
            sumcheck_comm = self.add_comms(sumcheck_comm, claim_poly_id);
        };

        <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::verify(&self.proof.zc_proof, &self.proof.zc_aux_info, &mut self.transcript).unwrap();
        <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::verify(self.proof.sc_sum, &self.proof.sc_proof, &self.proof.sc_aux_info, &mut self.transcript).unwrap();

        Ok(())
    }
}