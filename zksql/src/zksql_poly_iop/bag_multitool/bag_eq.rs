// use arithmetic::VPAuxInfo;
// use ark_ec::pairing::Pairing;
// use ark_ff::PrimeField;
// use ark_poly::DenseMultilinearExtension;
// use ark_std::{end_timer, One, start_timer};
// use std::{fmt::Debug, marker::PhantomData, sync::Arc};
// use subroutines::{
//     pcs::PolynomialCommitmentScheme,
//     poly_iop::{
//         errors::PolyIOPErrors,
//         prelude::{IOPProof, ZeroCheckIOPSubClaim, SumCheckIOPSubClaim},
//     },
//     PCSError,
// };
// use transcript::IOPTranscript;

// use super::bag_multitool::{Bag, BagMultiToolIOP, BagMultiToolIOPProof};

// pub struct BagEqIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagEqIOPProof<
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
// > {
//     pub fhat_comm: PCS::Commitment,
//     pub ghat_comm: PCS::Commitment,
//     pub v: E::ScalarField,
//     pub lhs_sumcheck_proof: IOPProof<E::ScalarField>,
//     pub rhs_sumcheck_proof: IOPProof<E::ScalarField>,
//     pub fhat_zerocheck_proof: IOPProof<E::ScalarField>,
//     pub ghat_zerocheck_proof: IOPProof<E::ScalarField>,
// }

// /// A BagEqCheck check subclaim consists of
// /// two sumcheck subclaims, and the value v they should both equal
// /// the random challenge gamma
// /// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
// #[derive(Clone, Debug, Default, PartialEq)]
// pub struct BagEqIOPSubClaim<F: PrimeField> {
//     pub lhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
//     pub rhs_sumcheck_subclaim: SumCheckIOPSubClaim<F>,
//     pub fhat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
//     pub ghat_zerocheck_subclaim: ZeroCheckIOPSubClaim<F>,
// }

// impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagEqIOP<E, PCS> 
// where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>> {
//     pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
//         IOPTranscript::<E::ScalarField>::new(b"Initializing BagEqCheck transcript")
//     }

//     pub fn prove(
//         pcs_param: &PCS::ProverParam,
//         fx: &Bag<E>,
//         gx: &Bag<E>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<
//         (
//             BagEqIOPProof<E, PCS>,
//         ),
//         PolyIOPErrors,
//     > {
//         let start = start_timer!(|| "BagEqCheck prove");
//         // check input shape is correct
//         if fx.num_vars != gx.num_vars {
//             return Err(PolyIOPErrors::InvalidParameters(
//                 "BagEqIOP Error: fx and gx have different number of variables".to_string(),
//             ));
//         }
//         let nv = fx.num_vars;

//         // initialize multiplicity vector
//         let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
//         let mx = vec![one_const_poly.clone()];

//         // call the bag_multitool prover
//         // the null_offset is set to zero here because we assume it is an exact permutation without extra nulls
//         let (bag_multitool_proof,) = BagMultiToolIOP::<E, PCS>::prove(pcs_param, &[fx.clone()], &[gx.clone()], &mx.clone(), &mx.clone(), transcript)?;
//         let bag_eq_check_proof =  BagEqIOPProof::<E, PCS>{
//             fhat_comm: bag_multitool_proof.fhat_comms[0].clone(),
//             ghat_comm: bag_multitool_proof.ghat_comms[0].clone(),
//             v:  bag_multitool_proof.lhs_vs[0],
//             lhs_sumcheck_proof: bag_multitool_proof.lhs_sumcheck_proofs[0].clone(),
//             rhs_sumcheck_proof: bag_multitool_proof.rhs_sumcheck_proofs[0].clone(),
//             fhat_zerocheck_proof: bag_multitool_proof.fhat_zerocheck_proofs[0].clone(),
//             ghat_zerocheck_proof: bag_multitool_proof.ghat_zerocheck_proofs[0].clone(),
//         };

//         end_timer!(start);
//         Ok((bag_eq_check_proof,))
//     }

//     pub fn verification_info (
//         pcs_param: &PCS::ProverParam,
//         fx: &Bag<E>,
//         gx: &Bag<E>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> (Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>, Vec<VPAuxInfo<E::ScalarField>>) {
//         let nv = fx.num_vars;
//         let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
//         let mx = vec![one_const_poly.clone()];
//         let (f_sc_info, f_zc_info, g_sc_info, g_zc_info) = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, &[fx.clone()], &[gx.clone()], &mx.clone(), &mx.clone(),transcript);
//         return (f_sc_info, f_zc_info, g_sc_info, g_zc_info)
//     }

//     pub fn verify(
//         pcs_param: &PCS::ProverParam,
//         proof: &BagEqIOPProof<E, PCS>,
//         f_sc_info: &Vec<VPAuxInfo<E::ScalarField>>,
//         f_zc_info: &Vec<VPAuxInfo<E::ScalarField>>,
//         g_sc_info: &Vec<VPAuxInfo<E::ScalarField>>,
//         g_zc_info: &Vec<VPAuxInfo<E::ScalarField>>,
//         transcript: &mut IOPTranscript<E::ScalarField>,
//     ) -> Result<BagEqIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
//         let start = start_timer!(|| "BagEqCheck verify");
//         let nv = f_sc_info[0].num_variables;

//         let bag_multitool_proof = Self::bageq_proof_to_bagmulti_proof(pcs_param, nv, proof)?;
//         let bag_multitool_subclaim = BagMultiToolIOP::verify(&bag_multitool_proof, f_sc_info, f_zc_info, g_sc_info, g_zc_info, transcript)?;
 
//          end_timer!(start);
//          Ok(BagEqIOPSubClaim{
//             lhs_sumcheck_subclaim: bag_multitool_subclaim.lhs_sumcheck_subclaims[0].clone(), 
//             rhs_sumcheck_subclaim: bag_multitool_subclaim.rhs_sumcheck_subclaims[0].clone(),
//             fhat_zerocheck_subclaim: bag_multitool_subclaim.fhat_zerocheck_subclaims[0].clone(),
//             ghat_zerocheck_subclaim: bag_multitool_subclaim.ghat_zerocheck_subclaims[0].clone(),
//         })
//     }

//     fn bageq_proof_to_bagmulti_proof(pcs_param: &PCS::ProverParam, nv: usize, bageq_proof: &BagEqIOPProof<E, PCS>) -> Result<BagMultiToolIOPProof::<E, PCS>, PCSError> {
//         // initialize multiplicity vector of all ones
//         let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
//         let m_comm = PCS::commit(pcs_param, &one_const_poly)?; 
        
//         // reformat proof to a BagMultiToolCheck proof
//         let bag_multitool_proof: BagMultiToolIOPProof::<E, PCS> = BagMultiToolIOPProof{
//             lhs_sumcheck_proofs: vec![bageq_proof.lhs_sumcheck_proof.clone()],
//             rhs_sumcheck_proofs: vec![bageq_proof.rhs_sumcheck_proof.clone()],
//             lhs_vs:  vec![bageq_proof.v],
//             rhs_vs:  vec![bageq_proof.v],
//             fhat_zerocheck_proofs: vec![bageq_proof.fhat_zerocheck_proof.clone()],
//             ghat_zerocheck_proofs: vec![bageq_proof.ghat_zerocheck_proof.clone()],
//             mf_comms: vec![m_comm.clone()],
//             mg_comms: vec![m_comm.clone()],
//             fhat_comms: vec![bageq_proof.fhat_comm.clone()],
//             ghat_comms: vec![bageq_proof.ghat_comm.clone()],
//         };

//         return Ok(bag_multitool_proof)
//     }
// }