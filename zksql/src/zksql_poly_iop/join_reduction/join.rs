// use ark_ec::pairing::Pairing;
// use std::marker::PhantomData;

// use subroutines::pcs::PolynomialCommitmentScheme;
// use crate::{
//     tracker::prelude::*,
//     zksql_poly_iop::{
//         bag_multitool::{bag_multitool::BagMultitoolIOP, bag_inclusion::BagInclusionIOP, bag_sum::BagSumIOP}, bag_no_zeros::BagNoZerosIOP, set_disjoint::set_disjoint::SetDisjointIOP, set_union::set_union::SetUnionIOP
//     },
// };
// use crate::zksql_poly_iop::join_reduction::util::bag_lmr_split;

// pub struct JoinReductionIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

// impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> JoinReductionIOP<E, PCS> 
// where PCS: PolynomialCommitmentScheme<E> {
//     pub fn prove(
//         prover_tracker: &mut ProverTrackerRef<E, PCS>,
//         bag_a: &Bag<E, PCS>,
//         bag_b: &Bag<E, PCS>,
//         range_bag: &Bag<E, PCS>, // needed for SetDisjointIOP
//     ) -> Result<(), PolyIOPErrors> {

//         // calculate join reduction result stuff
//         let (l_bag, m_bag, r_bag, l_mul, ma_mul, mb_mul, r_mul) = bag_lmr_split(prover_tracker, bag_a, bag_b)?;

//         // prove L \mutlisetsum mid_a = A
//         BagMultitoolIOP::<E, PCS>::prove(
//             prover_tracker,
//             &[l_bag, m_bag],
//             &[bag_a],
//             &[l_mul, ma_mul],
//             &[],
//         )?;

//         // prove mid_b \mutlisetsum R = B
//         BagMultitoolIOP::<E, PCS>::prove(
//             prover_tracker,
//             &[m_bag, r_bag],
//             &[],
//             &[mb_mul, r_mul],
//             &[],
//         )?;

//         // Prove L and R are disjoint
//         SetDisjointIOP::<E, PCS>::prove(
//             prover_tracker,
//             &l_bag,
//             &r_bag,
//             &range_bag,
//         )?;

//         // prove mid_a and mid_b have the same support
//         BagInclusionIOP::<E, PCS>::prove(
//             prover_tracker,
//             bag_mid_a,
//             bag_mid_b,
//             mid_b_mult
//         )?;
//        BagInclusionIOP::<E, PCS>::prove(
//             prover_tracker,
//             bag_mid_b,
//             bag_mid_a,
//             mid_a_mult
//         )?;

//         // prove the join result is the join product of mid_a and mid_b
        
//         Ok(())
//     }

//     pub fn verify(
//         verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
//         bag_a: &BagComm<E, PCS>,
//         bag_b: &BagComm<E, PCS>,
//         bag_l: &BagComm<E, PCS>,
//         bag_mid_a: &BagComm<E, PCS>,
//         bag_mid_b: &BagComm<E, PCS>,
//         bag_r: &BagComm<E, PCS>,
//         mid_a_mult: &TrackedComm<E, PCS>,
//         mid_b_mult: &TrackedComm<E, PCS>,
//         range_bag: &BagComm<E, PCS>,
//     ) -> Result<(), PolyIOPErrors> {

//         // verify L \mutlisetsum mid_a = A
//         BagSumIOP::<E, PCS>::verify(
//             verifier_tracker, 
//             bag_l, 
//             bag_mid_a,
//             bag_a,
//         )?;

//         // verify mid_b \mutlisetsum R = B
//         BagSumIOP::<E, PCS>::verify(
//             verifier_tracker, 
//             bag_mid_b,
//             bag_r, 
//             bag_b,
//         )?;

//         // verify L and R are disjoint
//         SetDisjointIOP::<E, PCS>::verify(
//             verifier_tracker,
//             bag_l,
//             bag_r,
//             range_bag,
//         )?;

//         // verify mid_a and mid_b have the same support
//         BagInclusionIOP::<E, PCS>::verify(
//             verifier_tracker,
//             bag_mid_a,
//             bag_mid_b,
//             mid_b_mult
//         )?;
//         BagInclusionIOP::<E, PCS>::verify(
//             verifier_tracker,
//             bag_mid_b,
//             bag_mid_a,
//             mid_a_mult
//         )?;

//         Ok(())
//     }
// }