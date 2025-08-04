const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ID_LEN: usize = max(PARTY_0::ID_LEN, PARTY_1::ID_LEN);

pub fn main(
    measles_cases: [[u8; ID_LEN]; ROWS_0],
    school_examinations: [[u8; ID_LEN]; ROWS_1],
) -> [(bool, [u8; ID_LEN]); const { ROWS_0 + ROWS_1 - 1usize}] {
    bitonic_join(measles_cases, school_examinations)
}
