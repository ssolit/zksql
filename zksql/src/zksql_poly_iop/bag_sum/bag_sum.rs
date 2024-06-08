use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, Zero, One};
use std::{sync::Arc, usize};
use subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{errors::PolyIOPErrors, prelude::SumCheck, PolyIOP}, PCSError,
    ZeroCheck,
};
use transcript::IOPTranscript;

use crate::zksql_poly_iop::bag_multitool::bag_multitool::{BagMultiToolCheck, BagMultiToolCheckProof};

/// A BagSumCheck check subclaim consists of
/// two sumcheck subclaims, and the value v they should both equal
/// the random challenge gamma
/// two zerocheck claims to show denoms (fhat, ghat) in the sumcheck were constructed correctly
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagEqCheckSubClaim<F: PrimeField, ZC: ZeroCheck<F>, SC: SumCheck<F>> {
    // the SubClaim from the ZeroCheck
    pub lhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub rhs_sumcheck_subclaim: SC::SumCheckSubClaim,
    pub v: F,
    pub gamma: F,
    pub fhat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
    pub ghat_zerocheck_subclaim: ZC::ZeroCheckSubClaim,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct BagEqCheckProof<
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
    SC: SumCheck<E::ScalarField>,
    ZC: ZeroCheck<E::ScalarField>,
> {
    pub lhs_sumcheck_proof: SC::SumCheckProof,
    pub rhs_sumcheck_proof: SC::SumCheckProof,
    pub v: E::ScalarField,
    pub fhat_zero_check_proof: ZC::ZeroCheckProof,
    pub ghat_zero_check_proof: ZC::ZeroCheckProof,
    pub fhat_comm: PCS::Commitment,
    pub ghat_comm: PCS::Commitment,
}



//     return Err(PolyIOPErrors::InvalidParameters("unimplimented".to_string()))
// }

// #[test]
// fn test_msetsum_check() -> Result<(), PolyIOPErrors> {
//     use ark_std::test_rng;
//     use ark_bls12_381::{Bls12_381, Fr};

//     let mut rng = test_rng();
//     let nv = 4;

//     let f1: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::rand(nv, &mut rng);
//     let f2: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::rand(nv, &mut rng);
//     let g: Arc<DenseMultilinearExtension<Fr>> = arithmetic::merge_polynomials(&[Arc::new(f1.clone()), Arc::new(f2.clone())])?;
//     let g_bad: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::rand(nv+1, &mut rng);
    
    
//     // make proof
//     let proofs = msetsum_check(f1, f2, g)?;

//     // check proof verifies

//     // check bad_path

//     Ok(())
// }
