enum Row0 {
    None,
    Some(i32, i32),
}

enum Row1 {
    None,
    Some(i32, bool),
}

pub fn main(residents: [Row0; 10], insurance: [Row1; 10], z: u32) -> u32 {
    let mut result = 0u32;
    for row in residents {
        match row {
            Row0::Some(id, age) => result = result + (age as u32),
            Row0::None => {}
        }
    }
    for row in insurance {
        match row {
            Row1::Some(id, disabled) => {
                if disabled == true {
                    result = result + 1u32;
                }
            }
            Row1::None => {}
        }
    }
    result + z
}
