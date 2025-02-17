enum Bucket {
    Above,
    Within,
    Below,
}

pub fn main(x: i32, y: i32, z: i32) -> [Bucket; 3] {
    let avg = (x + y + z) * 1000 / 3;
    let range_in_percent = 10;
    let max = avg * (100 + range_in_percent) / 100;
    let min = avg * (100 - range_in_percent) / 100;

    let mut buckets = [Bucket::Within; 3];
    for (i, p) in [(0, x), (1, y), (2, z)] {
        buckets[i] = if p * 1000 > max {
            Bucket::Above
        } else if p * 1000 < min {
            Bucket::Below
        } else {
            Bucket::Within
        };
    }
    buckets
}
