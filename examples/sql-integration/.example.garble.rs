const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ROWS_RESULT: usize = max(PARTY_0::ROWS, PARTY_1::ROWS);
const STR_LEN: usize = max(PARTY_0::STR_LEN, PARTY_1::STR_LEN);

enum InsuranceStatus {
    Foo,
    Bar,
    FooBar,
}

pub fn main(
    residents: [(i32, [u8; STR_LEN], i32); ROWS_0],
    insurance: [(i32, [u8; STR_LEN], InsuranceStatus); ROWS_1],
) -> [[u8; STR_LEN]; ROWS_RESULT] {
    let mut result = [[0u8; STR_LEN]; ROWS_RESULT];
    let mut i = 0usize;
    for resident in residents {
        for insurance in insurance {
            let (_, name0, age) = resident;
            let (_, name1, insurance_status) = insurance;
            if name0 == name1 && age > 65i32 {
                match insurance_status {
                    InsuranceStatus::Foo => {
                        result[i] = name0;
                        i = i + 1usize;
                    }
                    InsuranceStatus::Bar => {
                        result[i] = name0;
                        i = i + 1usize;
                    }
                    _ => {}
                }
            }
        }
    }
    result
}
