const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ID_LEN: usize = max(PARTY_0::ID_LEN, PARTY_1::ID_LEN);

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
    let mut vaccinated: bool = false;
    for procedure_file_state_id in measles_procedure_file_state_ids {
        for school_exam in vaccinated_file_state_ids {
            vaccinated |= (procedure_file_state_id == school_exam);
        }
    }
    vaccinated
}

pub fn join_iter_check(
    measles_procedure_file_state_ids: [[u8; ID_LEN]; ROWS_0],
    vaccinated_file_state_ids: [[u8; ID_LEN]; ROWS_1],
) -> bool {
    let mut is_vaccinated: bool = false;
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
