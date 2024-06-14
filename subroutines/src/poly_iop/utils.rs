// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! useful macros.


use crate::poly_iop::PrimeField;
use ark_poly::DenseMultilinearExtension;
use std::sync::Arc;
use ark_ec::pairing::Pairing;
use crate::PolynomialCommitmentScheme;

/// Takes as input a struct, and converts them to a series of bytes. All traits
/// that implement `CanonicalSerialize` can be automatically converted to bytes
/// in this manner.
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed($x, &mut buf).map(|_| buf)
    }};
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use ark_std::One;

    #[test]
    fn test_to_bytes() {
        let f1 = Fr::one();

        let mut bytes = ark_std::vec![];
        f1.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(bytes, to_bytes!(&f1).unwrap());
    }
}


pub struct LabeledPolynomial<F: PrimeField> {
    pub label: String,
    pub poly: Arc<DenseMultilinearExtension<F>>,
}

impl<F: PrimeField> LabeledPolynomial<F> {
    pub fn new(label: String, poly: Arc<DenseMultilinearExtension<F>>) -> Self {
        Self { label, poly }
    }
}

pub struct LabeledCommitment<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub label: String,
    pub commitment: PCS::Commitment,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> LabeledCommitment<E, PCS> {
    pub fn new(label: String, commitment: PCS::Commitment) -> Self {
        Self { label, commitment }
    }
}