use std::sync::Arc;
use ark_poly::DenseMultilinearExtension;
use ark_ff::Field;


/// Decompose an integer into a binary vector in little endian.
pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}

pub fn binary_decompose<F: Field>(input: u64, num_var: usize) -> Vec<F> {
    let bit_sequence = bit_decompose(input, num_var);
    bit_sequence.iter().map(|&x| F::from(x as u64)).collect()
}

/// Increase the number of variables of a multilinear polynomial
/// The output dmle will use its first mle.num_vars() for evaluations, 
/// while the rest will be ignored
pub fn dmle_increase_nv<F: Field>(
    mle: &Arc<DenseMultilinearExtension<F>>,
    new_nv: usize
) -> Arc<DenseMultilinearExtension<F>> {
    if mle.num_vars == new_nv {
        return mle.clone();
    } if mle.num_vars > new_nv {
        panic!("dmle_increase_nv Error: old_len > new_len");
    }

    let old_len = 2_usize.pow(mle.num_vars as u32);
    let new_len = 2_usize.pow(new_nv as u32);
    let ratio = new_len / old_len;
    let mut evals = mle.evaluations.clone();
    evals.resize(new_len, F::default());
    for i in old_len..new_len {
        evals[i] = evals[i % ratio];
    }
    Arc::new(DenseMultilinearExtension::from_evaluations_vec(new_nv, evals))
}



mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;
    use ark_poly::MultilinearExtension;
    use ark_std::{test_rng};

    #[test]
    fn test_dmle_increase_nv() {
        let mut rng = test_rng();
        let small_nv = 4;
        let large_nv = 8;
        
        let small_mle: DenseMultilinearExtension<Fr> = arithmetic::random_permutation_mles(small_nv, 1, &mut rng)[0].clone();
        let large_mle = dmle_increase_nv(&Arc::new(small_mle.clone()), large_nv);
        let large_eval_pt: Vec<Fr> = (0..large_nv).map(|_| Fr::rand(&mut rng)).collect();
        let small_eval_pt: Vec<Fr> = large_eval_pt[0..small_nv].to_vec();

        assert_eq!(large_mle.num_vars(), large_nv);
        assert_eq!(large_mle.evaluations[0..2_usize.pow(small_nv as u32)], small_mle.evaluations);
        assert_eq!(large_mle.evaluate(&large_eval_pt).unwrap(), small_mle.evaluate(&small_eval_pt).unwrap());
    }
}