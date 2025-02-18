enum Bucket {
    Above,
    Within,
    Below,
}

fn bucket(p: i32, min: i32, max: i32) -> Bucket {
    if p > max {
        Bucket::Above
    } else if p < min {
        Bucket::Below
    } else {
        Bucket::Within
    }
}

pub fn main(x: i32, y: i32, z: i32) -> [Bucket; 3] {
    let avg = (x + y + z) * 1000 / 3;
    let range_in_percent = 10;
    let min = avg * (100 - range_in_percent) / 100;
    let max = avg * (100 + range_in_percent) / 100;
    [
        bucket(x * 1000, min, max),
        bucket(y * 1000, min, max),
        bucket(z * 1000, min, max),
    ]
}
