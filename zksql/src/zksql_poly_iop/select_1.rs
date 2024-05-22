
// making a test case
// create 1_polynomial 
// create table - vector of columns
// run the product check on the table


use  subroutines::{
    pcs::PolynomialCommitmentScheme,
    poly_iop::{
        errors::PolyIOPErrors,
        // prod_check::util::{compute_frac_poly, compute_product_poly, prove_zero_check},
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


// fn test_selection_proof<E, PCS>(
//     pcs_param: &PCS::ProverParam,
//     table: [&[E::MultilinearExtension]],
//     s: &[E::MultilinearExtension],
//     transcript: &mut IOPTranscript<E::ScalarField>,
// ) -> Result<
//     (
//         PolyIOP<E::ScalarField>::ProductCheckProof,
//         E::MultilinearExtension,
//         E::MultilinearExtension,
//     ),
//     PolyIOPErrors,
// >
// where
//     E: Pairing,
//     PCS: PolynomialCommitmentScheme<E>,
// {
//     let start = start_timer!(|| "selection_proof");
//     let frac_poly = compute_frac_poly(fxs, gxs)?;
//     let prod_x = compute_product_poly(&frac_poly)?;
//     let (zero_check_proof, _) =
//         prove_zero_check(fxs, gxs, &frac_poly, &prod_x, &alpha, transcript)?;
//     end_timer!(start);

//     Ok((
//         PolyIOP::ProductCheckProof {
//             zero_check_proof,
//             prod_x_comm,
//             frac_comm,
//         },
//         prod_x,
//         frac_poly,
//     ))
// }

fn test_selection_proof() -> Result<(), PolyIOPErrors> { 
    use ark_bls12_381::{Bls12_381, Fr};
    use subroutines::MultilinearKzgPCS;
    use ark_std::test_rng;


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
    // let table = vec![c1, c2];
    let sel: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &c1_elem);
    let result_c1: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &result_c1_elem);
    let result_c2: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_slice(nv, &result_c2_elem);
    // let result = vec![result_c1, result_c2];

    let bad_c =  DenseMultilinearExtension::rand(nv, &mut rng);

    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
    let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;

    // test_product_check_helper::<Bls12_381, MultilinearKzgPCS<Bls12_381>>(
    //     &vec![Arc::new(c1), Arc::new(sel)], &vec![Arc::new(result_c1)], &vec![Arc::new(bad_c)], &pcs_param,
    // )?;

    let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;

    let (proof, prod_x, frac_poly) = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::prove(
        pcs_param,
        fs,
        gs,
        &mut transcript,
    )?;


    Ok(())
}

fn test_product_check_helper<E, PCS>(
    fs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    gs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    hs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    pcs_param: &PCS::ProverParam,
) -> Result<(), PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<
        E,
        Polynomial = Arc<DenseMultilinearExtension<E::ScalarField>>,
    >,
{
    use subroutines::ProductCheck;
    use std::marker::PhantomData;

    let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;

    let (proof, prod_x, frac_poly) = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::prove(
        pcs_param,
        fs,
        gs,
        &mut transcript,
    )?;

    let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;

    // what's aux_info for?
    let aux_info = VPAuxInfo {
        max_degree: fs.len() + 1,
        num_variables: fs[0].num_vars,
        phantom: PhantomData::default(),
    };
    let prod_subclaim = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::verify(
        &proof,
        &aux_info,
        &mut transcript,
    )?;
    assert_eq!(
        prod_x.evaluate(&prod_subclaim.final_query.0).unwrap(),
        prod_subclaim.final_query.1,
        "different product"
    );
    check_frac_poly::<E>(&frac_poly, fs, gs);

    // bad path
    let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;

    let (bad_proof, prod_x_bad, frac_poly) = <PolyIOP<E::ScalarField> as ProductCheck<
        E,
        PCS,
    >>::prove(
        pcs_param, fs, hs, &mut transcript
    )?;

    let mut transcript = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::init_transcript();
    transcript.append_message(b"testing", b"initializing transcript for testing")?;
    let bad_subclaim = <PolyIOP<E::ScalarField> as ProductCheck<E, PCS>>::verify(
        &bad_proof,
        &aux_info,
        &mut transcript,
    )?;
    assert_ne!(
        prod_x_bad.evaluate(&bad_subclaim.final_query.0).unwrap(),
        bad_subclaim.final_query.1,
        "can't detect wrong proof"
    );
    // the frac_poly should still be computed correctly
    check_frac_poly::<E>(&frac_poly, fs, hs);

    Ok(())
}
fn check_frac_poly<E>(
    frac_poly: &Arc<DenseMultilinearExtension<E::ScalarField>>,
    fs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
    gs: &[Arc<DenseMultilinearExtension<E::ScalarField>>],
) where
    E: Pairing,
{
    let mut flag = true;
    let num_vars = frac_poly.num_vars;
    for i in 0..1 << num_vars {
        let nom = fs
            .iter()
            .fold(E::ScalarField::from(1u8), |acc, f| acc * f.evaluations[i]);
        let denom = gs
            .iter()
            .fold(E::ScalarField::from(1u8), |acc, g| acc * g.evaluations[i]);
        if denom * frac_poly.evaluations[i] != nom {
            flag = false;
            break;
        }
    }
    assert!(flag);
}


#[test]
fn my_test() {
    test_selection_proof();
}