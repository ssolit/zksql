/// the process of group by is 
/// 1. get the support and prove its correct
/// 2. go through the list of aggregation instructions and prove each one on the relevant column

use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use std::collections::HashMap;
use std::marker::PhantomData;

use subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::{
        bag_multitool::bag_multitool::BagMultitoolIOP, bag_supp::{bag_supp::BagSuppIOP, utils::calc_bag_supp_advice}
    },
};

pub enum AggregationTypes {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    // MEDIAN()
    // MODE()
    // STDDEV()
    // COUNT(DISTINCT)
    // PERCENTILE_CONT()
    // ...
}

pub struct GroupByInstruction {
    grouping_cols: Vec<usize>,
    agg_instr: Vec<(usize, AggregationTypes)>, // (col_idx, agg_type)
}

pub struct GroupByInstructionWithAdvice<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    grouping_cols: Vec<usize>,
    support_cols: Vec<TrackedPoly<E, PCS>>,
    support_sel: TrackedPoly<E, PCS>,
    support_multiplicity: TrackedPoly<E, PCS>,
    agg_instr: Vec<(usize, AggregationTypes, TrackedPoly<E, PCS>)>, // (col_idx, agg_type, agg_poly)
}

pub struct GroupByIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> GroupByIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        input_table: &Table<E, PCS>,
        group_by_instructions: &GroupByInstruction,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // input validation
        if group_by_instructions.grouping_cols.len() > 1 {
            return Err(PolyIOPErrors::InvalidParameters(format!("GroupByIOP Error: only 1 grouping column is supported for now")));
        }
        let grouping_col_idx = group_by_instructions.grouping_cols[0];
        if grouping_col_idx >= input_table.col_vals.len() {
            return Err(PolyIOPErrors::InvalidParameters(format!("GroupByIOP Error: grouping column index {} is out of bounds", grouping_col_idx)));
        }
        for (col_idx, _) in group_by_instructions.agg_instr.iter() {
            if *col_idx >= input_table.col_vals.len() {
                return Err(PolyIOPErrors::InvalidParameters(format!("GroupByIOP Error: aggregation column index {} is out of bounds", *col_idx)));
            }
        }

        // calculate the support of the grouping column and put into the prover tracker
        let pre_grouping_col_bag = Bag::new(input_table.col_vals[grouping_col_idx].clone(), input_table.selector.clone());
        let (support_mle, support_sel_mle, support_multiplicity_mle) = calc_bag_supp_advice(&pre_grouping_col_bag)?;

        let supp_poly = prover_tracker.track_and_commit_poly(support_mle)?;
        let supp_sel_poly = prover_tracker.track_and_commit_poly(support_sel_mle)?;
        let support_multiplicity_poly = prover_tracker.track_and_commit_poly(support_multiplicity_mle)?;

        // TODO:
        // iterate through the list of aggregation instructions and calculate results/advice
        // put everything into a GroupByInstructionWithAdvice struct
        // call prove_with_advice
        

        todo!();
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<E, PCS>,
        input_table: &Table<E, PCS>,
        group_by_instructions: &GroupByInstructionWithAdvice<E, PCS>,
        range_bag: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // 0. input validation
        if group_by_instructions.grouping_cols.len() > 1 {
            return Err(PolyIOPErrors::InvalidParameters(format!("GroupByIOP Error: only 1 grouping column is supported for now")));
        }
        let grouping_col_idx = group_by_instructions.grouping_cols[0];
        if grouping_col_idx >= input_table.col_vals.len() {
            return Err(PolyIOPErrors::InvalidParameters(format!("GroupByIOP Error: grouping column index {} is out of bounds", grouping_col_idx)));
        }
        for (col_idx, _, _) in group_by_instructions.agg_instr.iter() {
            if *col_idx >= input_table.col_vals.len() {
                return Err(PolyIOPErrors::InvalidParameters(format!("GroupByIOP Error: aggregation column index {} is out of bounds", *col_idx)));
            }
        }
        let supp_poly = group_by_instructions.support_cols[0].clone();
        let supp_sel_poly = group_by_instructions.support_sel.clone();
        let support_multiplicity_poly = group_by_instructions.support_multiplicity.clone();
        let pre_grouping_col_bag = Bag::new(input_table.col_vals[grouping_col_idx].clone(), input_table.selector.clone());

        // 1. prove the grouping bag is a the support of the pre-grouping bag
        //    as part of this proof, it shows that support_multiplicity_poly is the relevent multiplicity vector for proving 
        //    the grouping bag is a subset of the support of the pre-grouping bag
        let grouped_col_bag = Bag::new(supp_poly.clone(), supp_sel_poly.clone());
        BagSuppIOP::<E, PCS>::prove_with_advice(
            prover_tracker,
            &pre_grouping_col_bag.clone(),
            &grouped_col_bag.clone(),
            &support_multiplicity_poly.clone(),
            range_bag,
        )?;
        let mut res_table_col_polys = Vec::<TrackedPoly<E, PCS>>::with_capacity(1 + group_by_instructions.agg_instr.len());
        res_table_col_polys.push(supp_poly.clone());
        let mut res_table = Table::new(res_table_col_polys, supp_sel_poly.clone());

        // 2. go through the list of aggregation instructions and prove each one on the relevant column
        for (col_idx, agg_instr, agg_poly) in group_by_instructions.agg_instr.iter() {
            match agg_instr {
                AggregationTypes::Count => {
                    // the column that results from the count aggregation is the same as the support_multiplicity_poly
                    res_table.col_vals.push(support_multiplicity_poly.clone());
                },
                AggregationTypes::Sum => {
                    let pre_agg_poly = input_table.col_vals[*col_idx].clone();
                    // prove the sum aggregation is correct
                    // use bag_multitool with the grouping columns as values and the agg_poly as multiplicities
                    BagMultitoolIOP::<E, PCS>::prove(
                        prover_tracker,
                        &vec![pre_grouping_col_bag.clone()],
                        &vec![grouped_col_bag.clone()],
                        &vec![pre_agg_poly],
                        &vec![agg_poly.clone()],
                    )?;
                },
                AggregationTypes::Avg => {
                    // prove the avg aggregation is correct
                    todo!();
                },
                AggregationTypes::Min => {
                    // prove the min aggregation is correct
                    todo!();
                },
                AggregationTypes::Max => {
                    // prove the max aggregation is correct
                    todo!();
                },
            }
        }

        todo!()
    }

    pub fn verify(
    ) -> Result<(), PolyIOPErrors> {
        todo!()
    }
}

