
// use arithmetic::VirtualPolynomial;
// use ark_ff::{One, PrimeField};
// use ark_poly::{MultilinearExtension, DenseMultilinearExtension};
// use ark_std::{end_timer, start_timer};
// use subroutines::{
//     poly_iop::{
//         errors::PolyIOPErrors,
//         zero_check::ZeroCheck,
//         PolyIOP,
//     },
//     IOPProof,
// };
// use std::{sync::Arc, vec};

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
