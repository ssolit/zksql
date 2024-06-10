use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer, Zero};
use std::{fmt::Debug, marker::PhantomData, sync::Arc};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::errors::PolyIOPErrors,
};
use transcript::IOPTranscript;

use super::{
    bag_multitool::BagMultiToolIOP,
    bag_eq::{BagEqIOP, BagEqIOPProof, BagEqIOPSubClaim},
};

pub struct BagPrescPermIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);


#[derive(Clone, Debug, PartialEq)]
pub struct BagPrescPermIOPProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
> {
    fx_comm: PCS::Commitment,
    gx_comm: PCS::Commitment,
    perm_comm: PCS::Commitment,
    bag_eq_proof: BagEqIOPProof<E, PCS>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagPrescPermIOPSubClaim<F: PrimeField> {
    bag_eq_subclaim: BagEqIOPSubClaim<F>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagPrescPermIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E, Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>> {
    pub fn init_transcript() -> IOPTranscript<E::ScalarField> {
        IOPTranscript::<E::ScalarField>::new(b"Initializing BagPrescPermCheck transcript")
    }

    pub fn prove(
        pcs_param: &PCS::ProverParam,
        fx: Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: Arc<DenseMultilinearExtension<E::ScalarField>>,
        perm: Arc<DenseMultilinearExtension<E::ScalarField>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<
        (
            BagPrescPermIOPProof<E, PCS>,
        ),
        PolyIOPErrors,
    > {
        let start = start_timer!(|| "BagPrescPermCheck prove");
        // check input shape is correct
        if fx.num_vars != gx.num_vars {
            return Err(PolyIOPErrors::InvalidParameters(
                "fx and gx have different number of variables".to_string(),
            ));
        }
        if fx.num_vars != perm.num_vars {
            return Err(PolyIOPErrors::InvalidParameters(
                "fx and perm have different number of variables".to_string(),
            ));
        }
        let nv = fx.num_vars;

        // create shifted permutation poly and helpers
        // 	    create first vector s=(0, 1, ..) and another that is the permuted version of it t=(2^{nv}, 0, 1, ..)
        // 	    (p,q) are p is orig, q is p offset by 1 with wraparound
        let ordered_evals: Vec<E::ScalarField> = (0..2_usize.pow(nv as u32)).map(|x| E::ScalarField::from(x as u64)).collect();
        let ordered_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, ordered_evals));

        // get a verifier challenge gamma
        let fx_comm = PCS::commit(pcs_param, &fx)?;
        let gx_comm = PCS::commit(pcs_param, &gx)?;
        let perm_comm = PCS::commit(pcs_param, &perm)?;
        transcript.append_serializable_element(b"fx", &fx_comm)?;
        transcript.append_serializable_element(b"gx", &gx_comm)?;
        transcript.append_serializable_element(b"perm", &perm_comm)?;
        let gamma = transcript.get_and_append_challenge(b"gamma")?;

        // calculate f_hat = s+gamma*p and g_hat = t+gamma*q, and prove these were created correctly
        let fhat_evals = (0..2_usize.pow(fx.num_vars as u32)).map(|i| ordered_poly[i] + gamma * fx.evaluations[i]).collect::<Vec<_>>();
        let ghat_evals = (0..2_usize.pow(gx.num_vars as u32)).map(|i| perm[i] + gamma * gx.evaluations[i]).collect::<Vec<_>>();
        let fhat = Arc::new(DenseMultilinearExtension::from_evaluations_vec(fx.num_vars, fhat_evals));
        let ghat = Arc::new(DenseMultilinearExtension::from_evaluations_vec(gx.num_vars, ghat_evals));
        // let fhat_comm = PCS::commit(pcs_param, &fhat)?;
        // let ghat_comm = PCS::commit(pcs_param, &ghat)?;
       
        


        // TODO: prove these were created correctly
        // Might happen on verifier side instead?
        // let fhat_zero_check_proof = ZeroCheckIOP::<E::ScalarField>::prove(&fhat, &mut transcript)?;



        // prove f_hat, g_hat are bag_eq
        let (bag_eq_proof,) = BagEqIOP::<E, PCS>::prove(pcs_param, fhat.clone(), ghat.clone(), &mut transcript.clone())?;
        let bag_presc_perm_proof =  BagPrescPermIOPProof::<E, PCS>{
            fx_comm,
            gx_comm,
            perm_comm,
            // fhat_comm,
            // ghat_comm,
            bag_eq_proof,
        };

        end_timer!(start);
        Ok((bag_presc_perm_proof,))
    }

    pub fn verification_info (
        pcs_param: &PCS::ProverParam,
        fx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        gx: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        _: &Arc<DenseMultilinearExtension<E::ScalarField>>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> VPAuxInfo<E::ScalarField> {
        let nv = fx.num_vars;
        let one_const_poly = Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]));
        let mx = vec![one_const_poly.clone()];
        let (f_aux_info, _) = BagMultiToolIOP::<E, PCS>::verification_info(pcs_param, &[fx.clone()], &[gx.clone()], &mx.clone(), &mx.clone(), E::ScalarField::zero(), transcript);
        return f_aux_info[0].clone()
    }

    pub fn verify(
        pcs_param: &PCS::ProverParam,
        proof: &BagPrescPermIOPProof<E, PCS>,
        aux_info: &VPAuxInfo<E::ScalarField>,
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<BagPrescPermIOPSubClaim<E::ScalarField>, PolyIOPErrors> {
        let start = start_timer!(|| "BagPrescPermCheck verify");

        transcript.append_serializable_element(b"fx", &proof.fx_comm)?;
        transcript.append_serializable_element(b"gx", &proof.gx_comm)?;
        transcript.append_serializable_element(b"perm", &proof.perm_comm)?;
        let _ = transcript.get_and_append_challenge(b"gamma")?;
        
        let bag_eq_subclaim = BagEqIOP::<E, PCS>::verify(pcs_param, &proof.bag_eq_proof, &aux_info, &mut transcript.clone())?;

         end_timer!(start);
         Ok(BagPrescPermIOPSubClaim{
            bag_eq_subclaim: BagEqIOPSubClaim{
                lhs_sumcheck_subclaim: bag_eq_subclaim.lhs_sumcheck_subclaim,
                rhs_sumcheck_subclaim: bag_eq_subclaim.rhs_sumcheck_subclaim,
                fhat_zerocheck_subclaim: bag_eq_subclaim.fhat_zerocheck_subclaim,
                ghat_zerocheck_subclaim: bag_eq_subclaim.ghat_zerocheck_subclaim,
            },
        })
    }
}