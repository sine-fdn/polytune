enum Row0 {
    None,
    Some(i32, [u8; 16], i32),
}

enum Row1 {
    None,
    Some(i32, [u8; 16], bool),
}

pub fn main(residents: [Row0; 4], insurance: [Row1; 4], age_threshold: u32) -> [[u8; 16]; 4] {
    let mut result = [[0u8; 16]; 4];
    let mut i = 0usize;
    for resident in residents {
        for insurance in insurance {
            match (resident, insurance) {
                (Row0::Some(_, name0, age), Row1::Some(_, name1, health_problems)) => {
                    if name0 == name1 && health_problems == true && age > (age_threshold as i32) {
                        result[i] = name0;
                        i = i + 1usize;
                    }
                }
                _ => {}
            }
        }
    }
    result
}
