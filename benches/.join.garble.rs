const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;

enum ScreeningStatus {
    Recent,
    OutOfDate,
    Missing,
}

pub fn main(
    screenings: [([u8; 20], ScreeningStatus); ROWS_0],
    school_examinations: [([u8; 20], u8); ROWS_1],
) -> [(u16, u16); 1] {
    let mut missing_screenings_with_special_ed_needs = 0u16;
    let mut total = ROWS_1 as u16;
    for joined in join_iter(screenings, school_examinations) {
        let ((_, screening), (_, special_ed_needs)) = joined;
        if special_ed_needs <= 2u8 {
            match screening {
                ScreeningStatus::Missing => {
                    missing_screenings_with_special_ed_needs =
                        missing_screenings_with_special_ed_needs + 1u16;
                }
                _ => {}
            }
        }
    }
    [(missing_screenings_with_special_ed_needs, total)]
}
