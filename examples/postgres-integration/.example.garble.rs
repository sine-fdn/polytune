const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ROWS_RESULT: usize = max(PARTY_0::ROWS, PARTY_1::ROWS);
const STR_LEN: usize = max(PARTY_0::STR_LEN, PARTY_1::STR_LEN);

pub fn main(
    residents: [(i32, [u8; STR_LEN], i32); ROWS_0],
    insurance: [(i32, [u8; STR_LEN], bool); ROWS_1],
) -> [[u8; STR_LEN]; ROWS_RESULT] {
    let mut result = [[0u8; STR_LEN]; ROWS_RESULT];
    let mut i = 0usize;
    for resident in residents {
        for insurance in insurance {
            let (_, name0, age) = resident;
            let (_, name1, health_problems) = insurance;
            if name0 == name1 && health_problems == true && age > 65i32 {
                result[i] = name0;
                i = i + 1usize;
            }
        }
    }
    result
}
