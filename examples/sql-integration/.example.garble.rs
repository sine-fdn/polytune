const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ID_LEN: usize = max(PARTY_0::ID_LEN, PARTY_1::ID_LEN);

pub fn main(
    missing_screenings: [([u8; ID_LEN]); ROWS_0],
    special_educational_needs: [([u8; ID_LEN]); ROWS_1],
) -> [(u16, u16); 1] {
    let mut joined = 0u16;
    let mut total = ROWS_1 as u16;
    for _ in join(missing_screenings, special_educational_needs) {
        joined = joined + 1u16;
    }
    [(joined, total)]
}
