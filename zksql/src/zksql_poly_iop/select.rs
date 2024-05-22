
// making a test case
// create 1_polynomial 
// create table - vector of columns
// run the product check on the table


use  subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        zero_check::ZeroCheck,
        PolyIOP,
    },
};
use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_ff::{One, PrimeField, Zero};
use ark_poly::{MultilinearExtension, DenseMultilinearExtension};
use ark_std::{end_timer, start_timer};
use std::sync::Arc;
use transcript::IOPTranscript;

fn test_selection_proof() -> Result<(), PolyIOPErrors> { 
    use ark_bls12_381::{Bls12_381, Fr};
    use subroutines::MultilinearKzgPCS;
    use arithmetic::VirtualPolynomial;
    use ark_std::test_rng;
    use std::ops::Neg;


    let nv = 2;
    let mut rng = test_rng();

    let c1_elem:[Fr; 4] = [
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(4u64),
    ];
    let c2_elem:[Fr; 4] = [
        Fr::from(5u64),
        Fr::from(6u64),
        Fr::from(7u64),
        Fr::from(8u64),
    ];
    let sel_elem:[Fr; 4] = [
        Fr::from(0u64),
        Fr::from(1u64),
        Fr::from(0u64),
        Fr::from(1u64),
    ];
    let result_c1_elem:[Fr; 4] = [
        Fr::from(0u64),
        Fr::from(2u64),
        Fr::from(0u64),
        Fr::from(4u64),
    ];
    let result_c2_elem:[Fr; 4] = [
        Fr::from(0u64),
        Fr::from(6u64),
        Fr::from(0u64),
        Fr::from(8u64),
    ];

    let c1: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &c1_elem);
    let c2: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &c2_elem);
    let sel: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &sel_elem);
    let result_c1: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &result_c1_elem);
    let result_c2: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &result_c2_elem);
    
    // build a virtual polynomial for the ZeroTest. v = (c1 * sel) - result_c1
    let mut c1_check_poly = VirtualPolynomial::new_from_mle(&Arc::new(c1), Fr::one());
    c1_check_poly.mul_by_mle(Arc::new(sel), Fr::one()).unwrap();
    c1_check_poly.add_mle_list(vec![Arc::new(result_c1)], Fr::one().neg()).unwrap();    

    // todo: invoke zero check
    let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;
    let proof = <PolyIOP<Fr> as ZeroCheck<Fr>>::prove(&c1_check_poly, &mut transcript)?;

    let poly = c1_check_poly.clone();
    let poly_info = poly.aux_info.clone();
    let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;
    let zero_subclaim =
        <PolyIOP<Fr> as ZeroCheck<Fr>>::verify(&proof, &poly_info, &mut transcript)?;
    assert!(
        poly.evaluate(&zero_subclaim.point)? == zero_subclaim.expected_evaluation,
        "wrong subclaim"
    );


    // exit successfully 
    Ok(())
}



#[test]
fn my_test() {
    let res = test_selection_proof();
    res.unwrap();
}