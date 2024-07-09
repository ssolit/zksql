/// The Tracker is a data structure for creating and managing virtual polynomials and their commitments.
/// It is in charge of  
///                      1) Recording the structure of virtual polynomials and their products
///                      2) Recording the structure of virtual polynomials and their products
///                      3) Recording the commitments of virtual polynomials and their products
///                      4) Providing methods for adding virtual polynomials together
/// 
/// 
use std::{
    collections::HashMap, 
    ops::Neg, 
    panic, 
    sync::Arc,
};

use ark_ec::pairing::Pairing;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use ark_std::{One, Zero};

use arithmetic::VirtualPolynomial;

use crate::tracker::{
    dmle_utils::dmle_increase_nv,
    tracker_structs::{TrackerID, TrackerSumcheckClaim, TrackerZerocheckClaim, CompiledZKSQLProof},
};

use derivative::Derivative;
use displaydoc::Display;

use subroutines::{
    pcs::PolynomialCommitmentScheme,
    PCSError,
    PolyIOP,
    poly_iop::prelude::{SumCheck, ZeroCheck},
};

use transcript::{IOPTranscript, TranscriptError};






#[derive(Derivative, Display)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct ProverTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>>{
    pub pcs_param: PCS::ProverParam,
    pub transcript: IOPTranscript<E::ScalarField>,
    pub id_counter: usize,
    pub materialized_polys: HashMap<TrackerID, Arc<DenseMultilinearExtension<E::ScalarField>>>, // underlying materialized polynomials, keyed by label
    pub virtual_polys: HashMap<TrackerID, Vec<(E::ScalarField, Vec<TrackerID>)>>, // virtual polynomials, keyed by label.Invariant: a virt poly contains only material TrackerIDs
    pub materialized_comms: HashMap<TrackerID, PCS::Commitment>,
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
    ) -> TrackerID {
        // Create the new TrackerID
        let poly_id = self.gen_id();

        // Add the polynomial to the materialized map
        let polynomial = Arc::new(polynomial);
        self.materialized_polys.insert(poly_id.clone(), polynomial.clone());

        // Return the new TrackerID
        poly_id
    }

    pub fn track_and_commit_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<TrackerID, PCSError> {
        // commit to the p[olynomial
        let commitment = PCS::commit(self.pcs_param.clone(), &polynomial)?;

        // track the polynomial and get its id
        let poly_id = self.track_mat_poly(polynomial);

        // add the commitment to the commitment map and transcript
        self.materialized_comms.insert(poly_id.clone(), commitment.clone());
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

    pub fn get_poly_nv(&self, id: TrackerID) -> usize {
        let mat_poly = self.materialized_polys.get(&id);
        if mat_poly.is_some() {
            return mat_poly.unwrap().num_vars();
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
        nv
    }

    pub fn add_sub_polys(
        &mut self, 
        p1_id: TrackerID, 
        p2_id: TrackerID,
        do_sub: bool,
    ) -> TrackerID {

        let sign_coeff: E::ScalarField;
        if do_sub {
            sign_coeff = E::ScalarField::one().neg();
        } else {
            sign_coeff = E::ScalarField::one();
        }

        let p1_mat = self.get_mat_poly(p1_id.clone());
        let p1_virt = self.get_virt_poly(p1_id.clone());
        let p2_mat = self.get_mat_poly(p2_id.clone());
        let p2_virt = self.get_virt_poly(p2_id.clone());

        let mut new_virt_rep = Vec::new(); // Invariant: contains only material TrackerIDs
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
                new_virt_rep.push((sign_coeff.clone(), vec![p2_id]));
            },
            // Case 2: p1 is materialized and p2 is virtual
            (true, false, false, true) => {
                new_virt_rep.push((E::ScalarField::one(), vec![p1_id]));
                p2_virt.unwrap().iter().for_each(|(coeff, prod)| {
                    new_virt_rep.push((sign_coeff * coeff.clone(), prod.clone()));
                });
            },
            // Case 3: p2 is materialized and p1 is virtual
            (false, true, true, false) => {
                p1_virt.unwrap().iter().for_each(|(coeff, prod)| {
                    new_virt_rep.push((coeff.clone(), prod.clone()));
                });
                new_virt_rep.push((sign_coeff.clone(), vec![p2_id]));
            },
            // Case 4: both p1 and p2 are virtual
            (false, true, false, true) => {
                p1_virt.unwrap().iter().for_each(|(coeff, prod)| {
                    new_virt_rep.push((coeff.clone(), prod.clone()));
                });
                p2_virt.unwrap().iter().for_each(|(coeff, prod)| {
                    new_virt_rep.push((sign_coeff * coeff.clone(), prod.clone()));
                });
            },
            // Handling unexpected cases
            _ => {
                panic!("Internal tracker::add_polys error. This code should be unreachable");
            },
        }
        return self.track_virt_poly(new_virt_rep);
    }

    pub fn add_polys(
        &mut self, 
        p1_id: TrackerID, 
        p2_id: TrackerID
    ) -> TrackerID {
        self.add_sub_polys(p1_id, p2_id, false)
    }

    pub fn sub_polys(
        &mut self, 
        p1_id: TrackerID, 
        p2_id: TrackerID
    ) -> TrackerID {
        self.add_sub_polys(p1_id, p2_id, true)
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

        let mut new_virt_rep = Vec::new(); // Invariant: contains only material TrackerIDs
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

    pub fn add_scalar(
        &mut self, 
        poly_id: TrackerID, 
        c: E::ScalarField
    ) -> TrackerID { 
       let nv = self.get_poly_nv(poly_id);
       let scalar_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![c; 2_usize.pow(nv as u32)]);
       let scalar_id = self.track_mat_poly(scalar_mle);
       let new_id = self.add_polys(poly_id, scalar_id);
       new_id
    }

    pub fn mul_scalar(
        &mut self, 
        poly_id: TrackerID, 
        c: E::ScalarField
    ) -> TrackerID {
        let mut new_virt_rep = Vec::new(); // Invariant: contains only material TrackerIDs

        let p_mat = self.get_mat_poly(poly_id);
        if p_mat.is_some() {
            new_virt_rep.push((c.clone(), vec![poly_id]));
        } else {
            let p_virt = self.get_virt_poly(poly_id);
            p_virt.unwrap().iter().for_each(|(coeff, prod)| {
                new_virt_rep.push((*coeff * c, prod.clone()));
            });
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

    pub fn to_arithmatic_virtual_poly(&self, id: TrackerID) -> VirtualPolynomial<E::ScalarField> {
        let mat_poly = self.materialized_polys.get(&id);
        if mat_poly.is_some() {
            return VirtualPolynomial::new_from_mle(mat_poly.unwrap(), E::ScalarField::one());
        }

        let poly = self.virtual_polys.get(&id);
        if poly.is_none() {
            panic!("Unknown poly id: {:?}", id);
        }
        let poly = poly.unwrap(); // Invariant: contains only material PolyIDs
        let first_id = poly[0].1[0].clone();
        let nv: usize = self.get_mat_poly(first_id).unwrap().num_vars();

        let mut arith_virt_poly: VirtualPolynomial<E::ScalarField> = VirtualPolynomial::new(nv);
        for (prod_coef, prod) in poly.iter() {
            let prod_mle_list = prod.iter().map(|poly_id| self.get_mat_poly(poly_id.clone()).unwrap().clone()).collect::<Vec<Arc<DenseMultilinearExtension<E::ScalarField>>>>();
            arith_virt_poly.add_mle_list(prod_mle_list, prod_coef.clone()).unwrap();
        }

        arith_virt_poly
    }

    // iterates through the materialized polynomials and increases the number of variables
    // to the max number of variables in the tracker
    // Used as a preprocessing step before batching polynomials
    pub fn equalize_materialized_poly_nv(&mut self) -> usize {
        let nv: usize = self.materialized_polys.iter().map(|(_, p)| p.num_vars()).max().ok_or(1).unwrap();
        for (_, poly) in self.materialized_polys.iter_mut() {
            *poly = dmle_increase_nv(poly, nv);
        }
        nv
    }

    pub fn compile_proof(&mut self) -> CompiledZKSQLProof<E, PCS> {
        // creates a finished proof based off the subclaims that have been recorded
        // 1) aggregates the subclaims into a single MLE
        // 2) generates a sumcheck proof
        // 3) create a batch opening proofs for the sumcheck point
        // 4) takes all relevant stuff and returns a CompiledProof

        let nv = self.equalize_materialized_poly_nv();


        // // 1) aggregate the subclaims into a single MLE
        // //    start with zero checks, then sumchecks

        let mut zerocheck_poly = self.track_mat_poly(DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(nv, vec![E::ScalarField::zero(); 2_usize.pow(nv as u32)]));
        let zero_check_claims = self.zero_check_claims.clone();
        for claim in zero_check_claims {
            let challenge = self.get_and_append_challenge(b"zerocheck challenge").unwrap();
            let claim_poly_id = self.mul_scalar(claim.label.clone(), challenge);
            // let claim_poly_raw_evals = self.evaluations(claim_poly_id);
            // let claim_mle = DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(log2(claim_poly_raw_evals.len()) as usize, claim_poly_raw_evals);
            // let claim_mle = dmle_increase_nv(&claim_mle, nv);
            zerocheck_poly = self.add_polys(zerocheck_poly, claim_poly_id);
        }

        let mut sumcheck_poly = self.track_mat_poly(DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(nv, vec![E::ScalarField::zero(); 2_usize.pow(nv as u32)]));
        let sumcheck_claims = self.sum_check_claims.clone();
        for claim in sumcheck_claims.iter() {
            let challenge = self.get_and_append_challenge(b"sumcheck challenge").unwrap();
            let claim_poly_id = self.mul_scalar(claim.label.clone(), challenge);
            sumcheck_poly = self.add_polys(zerocheck_poly, claim_poly_id);
        };

        // // 2) generate a sumcheck proof
        let avp = self.to_arithmatic_virtual_poly(zerocheck_poly);
        let zc_aux_info = avp.aux_info.clone();
        let zc_proof = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(&avp, &mut self.transcript).unwrap();
        let sc_sum = self.evaluations(sumcheck_poly).iter().sum::<E::ScalarField>();
        let avp = self.to_arithmatic_virtual_poly(sumcheck_poly);
        let sc_aux_info = avp.aux_info.clone();
        let sc_proof = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::prove(&avp, &mut self.transcript).unwrap();
        
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


        let placeholder_query_map: HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField> = HashMap::new();

        let placeholder_opening_point = vec![E::ScalarField::zero(); nv];
        let mut placeholder_poly_evals: HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField> = HashMap::new();
        for (id, _) in self.materialized_polys.iter() {
            placeholder_poly_evals.insert((id.clone(), placeholder_opening_point.clone()), E::ScalarField::zero());
        }

        let placeholder_opening_proof = PCS::open(&self.pcs_param, &DenseMultilinearExtension::<E::ScalarField>::from_evaluations_vec(nv, vec![E::ScalarField::zero(); 2_usize.pow(nv as u32)]), &placeholder_opening_point).unwrap().0;
        CompiledZKSQLProof {
            sum_check_claims: sumcheck_val_map,
            sc_proof,
            sc_sum,
            sc_aux_info,
            zc_proof,
            zc_aux_info,
            query_map: placeholder_query_map,
            comms: self.materialized_comms.clone(),
            opening_proof: vec![placeholder_opening_proof],
        }
    }
}