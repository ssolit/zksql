
// making a test case
// create 1_polynomial 
// create table - vector of columns
// run the product check on the table

use arithmetic::VirtualPolynomial;
use ark_ff::{One, PrimeField};
use ark_poly::{MultilinearExtension, DenseMultilinearExtension};
use ark_std::{end_timer, start_timer};
use subroutines::{
    poly_iop::{
        errors::PolyIOPErrors,
        zero_check::ZeroCheck,
        PolyIOP,
    },
    IOPProof,
};
use std::{sync::Arc, vec};



fn select_check<F: PrimeField>(
    table: &Vec<DenseMultilinearExtension<F>>,
    sel: &DenseMultilinearExtension<F>,
    result: &Vec<DenseMultilinearExtension<F>>,
) -> Result<Vec<IOPProof<F>>, PolyIOPErrors> {

    if table.len() != result.len() {
        return Err(PolyIOPErrors::InvalidParameters(
            "Table and result vectors must be the same length".to_string(),
        ));
    }

    let mut proofs = vec![];
    for i in 0..table.len() {
        // build a virtual polynomial for the ZeroTest. v = (c1 * sel) - result_c1
        let mut poly = VirtualPolynomial::new_from_mle(&Arc::new(table[i].clone()), F::one());
        poly.mul_by_mle(Arc::new(*sel), F::one()).unwrap();
        poly.add_mle_list(vec![Arc::new(result[i].clone())], F::one().neg()).unwrap();

        // invoke zero check
        let mut transcript = <PolyIOP<F> as ZeroCheck<F>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;
        let proof = <PolyIOP<F> as ZeroCheck<F>>::prove(&poly, &mut transcript)?;
        proofs.push(proof);


        
        // // test verificiation
        // let poly_info = poly.aux_info.clone();
        // println!("poly info 1: {:?}", poly_info);

        // let mut ver_transcript = <PolyIOP<F> as ZeroCheck<F>>::init_transcript();
        // ver_transcript.append_message(b"testing", b"initializing transcript for testing")?;
        // let zero_subclaim =
        //     <PolyIOP<F> as ZeroCheck<F>>::verify(&proofs[i].clone(), &poly_info, &mut ver_transcript)?;
    }
    
    return Ok(proofs);
}


fn test_selection_proof() -> Result<(), PolyIOPErrors> { 
    // import specific types and other 
    use ark_bls12_381::{Fr};
    use subroutines::MultilinearKzgPCS;
    use ark_std::test_rng;
    use ark_std::Zero;
   
    // create concrete values for testing 
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
    let table = vec![c1, c2];
    let sel: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &sel_elem);
    let result_c1: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &result_c1_elem);
    let result_c2: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &result_c2_elem);
    let result = vec![result_c1, result_c2];
    
    // call select_check
    let proofs = select_check::<Fr>(&table, &sel, &result)?;
    
    // verify proof passes
    let mut poly_info = VirtualPolynomial::new_from_mle(&Arc::new(table[0].clone()), Fr::one()).aux_info.clone();
    poly_info.max_degree += 1; // add one because shape gets larger from combining multiple virtual poly
    for proof in proofs {
        println!("here, len(proof.proofs): {}", proof.proofs.len());
        let mut transcript = <PolyIOP<Fr> as ZeroCheck<Fr>>::init_transcript();
        transcript.append_message(b"testing", b"initializing transcript for testing")?;
        let zero_subclaim =
            <PolyIOP<Fr> as ZeroCheck<Fr>>::verify(&proof, &poly_info, &mut transcript)?;
    }

    // exit successfully 
    Ok(())
}



#[test]
fn my_test() {
    let res = test_selection_proof();
    res.unwrap();
}