const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ID_LEN: usize = max(PARTY_0::ID_LEN, PARTY_1::ID_LEN);

/// A garble program that checks if any element in `measles_procedure_file_state_ids`
/// is in `vaccinated_file_state_ids` as well. If yes, the program returns `true`,
/// otherwise it returns `false`.
///
/// To optimize the size of the resulting circuit, we use two different approaches,
/// depending on the size of `measles_procedure_file_state_ids`:
/// 1. Pairwise check: we go through the elements in `measles_procedure_file_state_ids`
/// and compare them with the elements in `vaccinated_file_state_ids` and record if a
/// match exists.
/// 2. Join with private set intersection for many elements: for more elements in
/// `measles_procedure_file_state_ids` it is not worth it to go through the larger
/// `vaccinated_file_state_ids` that many times. In this case, we use an approach with
/// private set intersection, where the two sets are joined and `true` is returned if the
/// join is non-empty and `false` is returned when it is empty.
pub fn main(
    measles_procedure_file_state_ids: [[u8; ID_LEN]; ROWS_0],
    vaccinated_file_state_ids: [[u8; ID_LEN]; ROWS_1],
) -> bool {
    if ROWS_0 < 3 {
        pairwise_check(measles_procedure_file_state_ids, vaccinated_file_state_ids)
    } else {
        join_iter_check(measles_procedure_file_state_ids, vaccinated_file_state_ids)
    }
}

pub fn pairwise_check(
    measles_procedure_file_state_ids: [[u8; ID_LEN]; ROWS_0],
    vaccinated_file_state_ids: [[u8; ID_LEN]; ROWS_1],
) -> bool {
    let mut is_vaccinated: bool = false;
    for procedure_file_state_id in measles_procedure_file_state_ids {
        for school_exam in vaccinated_file_state_ids {
            is_vaccinated |= (procedure_file_state_id == school_exam);
        }
    }
    is_vaccinated
}

pub fn join_iter_check(
    measles_procedure_file_state_ids: [[u8; ID_LEN]; ROWS_0],
    vaccinated_file_state_ids: [[u8; ID_LEN]; ROWS_1],
) -> bool {
    let mut is_vaccinated: bool = false;
    // We need to work around an issue in garble which requires the arguments
    // to `join_iter` to be tuples. The following loops and index increments
    // should all be optimized out, as they're not depending on inputs.
    let mut measles: [([u8; ID_LEN]); ROWS_0] = [([0u8; ID_LEN],); ROWS_0];
    let mut vaccinated: [([u8; ID_LEN]); ROWS_1] = [([0u8; ID_LEN],); ROWS_1];
    let mut i: usize = 0;
    for state_id in measles_procedure_file_state_ids {
        measles[i] = (state_id,);
        i += 1;
    }
    i = 0;
    for state_id in vaccinated_file_state_ids {
        vaccinated[i] = (state_id,);
        i += 1;
    }

    for joined in join_iter(measles, vaccinated) {
        is_vaccinated = true;
    }
    is_vaccinated
}
