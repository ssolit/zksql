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

use ark_std::One;
use core::panic;
use subroutines::PolynomialCommitmentScheme;
use transcript::IOPTranscript;

use std::{
    collections::HashMap,
    // ops::Add,
    sync::Arc,
    // cell::RefCell,
    // rc::Rc,
    // marker::PhantomData,
    // borrow::{Borrow, BorrowMut},
};


#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Display)]
pub struct TrackerID(usize);

#[derive(Display)]
pub struct VerifierTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>>{
    pub id_counter: usize,
    pub materialized_comms: HashMap<TrackerID, Arc<PCS::Commitment>>,
    pub virtual_comms: HashMap<TrackerID, Vec<(E::ScalarField, Vec<TrackerID>)>>,
    pub transcript: IOPTranscript<E::ScalarField>,
    pub eval_maps: HashMap<TrackerID, Box<dyn Fn(TrackerID, E::ScalarField) -> E::ScalarField>>,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> VerifierTracker<E, PCS> {
    pub fn new() -> Self {
        Self {
            id_counter: 0,
            virtual_comms: HashMap::new(),
            materialized_comms: HashMap::new(),
            transcript: IOPTranscript::<E::ScalarField>::new(b"ProverTracker"),
            eval_maps: HashMap::new(),
        }
    }

    pub fn gen_id(&mut self) -> TrackerID {
        let id = self.id_counter;
        self.id_counter += 1;
        TrackerID(id)
    }

    pub fn track_mat_comm(&mut self, commitment: PCS::Commitment, f: impl Fn(TrackerID, E::ScalarField) -> E::ScalarField + 'static) -> TrackerID {
        // Create the new TrackerID
        let id = self.gen_id();

        // Add the commitment to the materialized map
        self.materialized_comms.insert(id.clone(), Arc::new(commitment));

        // Add the efficient method to evaluate the commitment
        self.eval_maps.insert(id.clone(), Box::new(f));

        // Return the new TrackerID
        id
    }

    pub fn get_mat_comm(&self, id: TrackerID) -> Option<&Arc<PCS::Commitment>> {
        self.materialized_comms.get(&id)
    }

    pub fn get_virt_comm(&self, id: TrackerID) -> Option<&Vec<(E::ScalarField, Vec<TrackerID>)>> {
        self.virtual_comms.get(&id)
    }

    pub fn add_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        let c1_mat = self.get_mat_comm(c1_id.clone());
        let c1_virt = self.get_virt_comm(c1_id.clone());
        let c2_mat = self.get_mat_comm(c2_id.clone());
        let c2_virt = self.get_virt_comm(c2_id.clone());

        let mut new_virt_rep = Vec::new();
        match (c1_mat.is_some(), c1_virt.is_some(), c2_mat.is_some(), c2_virt.is_some()) {
            // Bad Case: c1 not found
            (false, false, _, _) => {
                panic!("Unknown c1 TrackerID {:?}", c1_id);
            }
            // Bad Case: c2 not found
            (_, _, false, false) => {
                panic!("Unknown c2 TrackerID {:?}", c2_id);
            }
            // Case 1: both c1 and c2 are materialized
            (true, false, true, false) => {
                new_virt_rep.push((E::ScalarField::one(), vec![c1_id]));
                new_virt_rep.push((E::ScalarField::one(), vec![c2_id]));
            },
            // Case 2: c1 is materialized and c2 is virtual
            (true, false, false, true) => {
                new_virt_rep.push((E::ScalarField::one(), vec![c1_id]));
                new_virt_rep.append(&mut c2_virt.unwrap().clone());
            },
            // Case 3: c2 is materialized and c1 is virtual
            (false, true, true, false) => {
                new_virt_rep.append(&mut c1_virt.unwrap().clone());
                new_virt_rep.push((E::ScalarField::one(), vec![c2_id]));
            },
            // Case 4: both c1 and c2 are virtual
            (false, true, false, true) => {
                new_virt_rep.append(&mut c1_virt.unwrap().clone());
                new_virt_rep.append(&mut c2_virt.unwrap().clone());
            },
            // Handling unexpected cases
            _ => {
                panic!("Internal verifier_tracker::add_comms error. This code should be unreachable");
            },
        }

        let comm_id = self.gen_id();
        self.virtual_comms.insert(comm_id.clone(), new_virt_rep);
        comm_id
    }

    fn mul_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        let c1_mat = self.get_mat_comm(c1_id.clone());
        let c1_virt = self.get_virt_comm(c1_id.clone());
        let c2_mat = self.get_mat_comm(c2_id.clone());
        let c2_virt = self.get_virt_comm(c2_id.clone());

        let mut new_virt_rep = Vec::new();
        match (c1_mat.is_some(), c1_virt.is_some(), c2_mat.is_some(), c2_virt.is_some()) {
            // Bad Case: c1 not found
            (false, false, _, _) => {
                panic!("Unknown c1 TrackerID {:?}", c1_id);
            }
            // Bad Case: c2 not found
            (_, _, false, false) => {
                panic!("Unknown c2 TrackerID {:?}", c2_id);
            }
            // Case 1: both c1 and c2 are materialized
            (true, false, true, false) => {
                new_virt_rep.push((E::ScalarField::one(), vec![c1_id, c2_id]));
            },
            // Case 2: c1 is materialized and c2 is virtual
            (true, false, false, true) => {
                let c2_rep = c2_virt.unwrap();
                c2_rep.iter().for_each(|(coeff, prod)| {
                    let mut new_prod = prod.clone();
                    new_prod.push(c1_id.clone());
                    new_virt_rep.push((coeff.clone(), new_prod));
                });
            },
            // Case 3: c2 is materialized and c1 is virtual
            (false, true, true, false) => {
                let c1_rep = c1_virt.unwrap();
                c1_rep.iter().for_each(|(coeff, prod)| {
                    let mut new_prod = prod.clone();
                    new_prod.push(c2_id.clone());
                    new_virt_rep.push((coeff.clone(), new_prod));
                });
            },
            // Case 4: both c1 and c2 are virtual
            (false, true, false, true) => {
                let c1_rep = c1_virt.unwrap();
                let c2_rep = c2_virt.unwrap();
                c1_rep.iter().for_each(|(c1_coeff, c1_prod)| {
                    c2_rep.iter().for_each(|(c2_coeff, c2_prod)| {
                        let new_coeff = *c1_coeff * c2_coeff;
                        let mut new_prod_vec = c1_prod.clone();
                        new_prod_vec.extend(c2_prod.clone());
                        new_virt_rep.push((new_coeff, new_prod_vec));
                    })
                });
            },
            // Handling unexpected cases
            _ => {
                panic!("Internal tracker::mul_comms error. This code should be unreachable");
            },
        }

        let comm_id = self.gen_id();
        self.virtual_comms.insert(comm_id.clone(), new_virt_rep);
        comm_id
    }

    // like evalutate for prover tracker
    // actually don't thing I need this, since verifier_compiled_proof will do everything
    // fn open_comm( 
    //     &self, 
    //     comm_id: TrackerID, 
    //     point: Vec<E::ScalarField>, 
    //     value: E::ScalarField, 
    //     proof: PCS::Proof, 
    // ) -> Result<bool, PCSError> {
    //     todo!()
    // }

}


// fn verifier(proof: Proof, tracker: &mut VerifierTracker) -> bool {
//     // Verifier expects a commitment from the prover
//     tracker.add_concrete_cm(&proof.commitments, |id, x| proof.evaluations[(id, x)]);
//     let challenge = tracker.challenge();
//     let evaluation = tracker.evaluate(id, challenge);
//     tracker.verify_compiled_proof() // invokes PCS::verify
// }

