const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ID_LEN: usize = max(PARTY_0::ID_LEN, PARTY_1::ID_LEN);

pub fn main(
    location: [([u8; ID_LEN], u8); ROWS_0],
    disability: [([u8; ID_LEN], u8); ROWS_1],
) -> [u16; 10] {
    let mut result: [u16; 10] = [0u16; 10];
    for joined in join(location, disability) {
        let ((_, loc), (_, care_level)) = joined;
        if care_level >= 4 {
            result[loc as usize] += 1u16;
        }
    }
    result
}
