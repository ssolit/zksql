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

// fn msetsum_check<F: PrimeField>(
//     f1: DenseMultilinearExtension<F>,
//     f2: DenseMultilinearExtension<F>,
//     g: DenseMultilinearExtension<F>,
// ) -> Result<Vec<IOPProof<F>>, PolyIOPErrors> {



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
