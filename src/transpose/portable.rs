use wide::{i64x2, i8x16};

/// Transpose a bit matrix.
///
/// # Panics
/// - If `rows < 16`
/// - If `rows` is not divisible by 16
/// - If `input.len()` is not divisible by `rows`
/// - If the number of columns, computed as `input.len() * 8 / rows` is less
///   than 16
/// - If the number of columns is not divisible by 8
pub fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    assert!(rows >= 16, "rows must be at least 16");
    assert_eq!(0, rows % 16, "rows must be divisible by 16");
    assert_eq!(
        0,
        input.len() % rows,
        "input.len() must be divisible by rows"
    );
    let cols = input.len() * 8 / rows;
    assert!(cols >= 16, "columns must be at least 16. Columns {cols}");
    assert_eq!(
        0,
        cols % 8,
        "Number of bitmatrix columns must be divisable by 8. columns: {cols}"
    );

    let mut row: usize = 0;
    while row <= rows - 16 {
        let mut col = 0;
        while col < cols {
            let mut v = load_bytes(input, row, col, cols);
            // reverse iterator because we start writing the msb of each byte, then shift
            // left for i = 0, we write the previous lsb
            for i in (0..8).rev() {
                // get msb of each byte
                let msbs = v.move_mask().to_le_bytes();
                // write msbs to output at transposed position
                let idx = out(row, col + i, rows) as isize;
                // This should result in only one bounds check for the output
                let out_bytes = &mut output[idx as usize..idx as usize + 2];
                out_bytes[0] = msbs[0];
                out_bytes[1] = msbs[1];

                let v: &mut i64x2 = bytemuck::must_cast_mut(&mut v);
                // shift each byte by one to the left (by shifting it as two i64)
                *v = *v << 1;
            }
            col += 8;
        }
        row += 16;
    }
}

#[inline]
fn inp(x: usize, y: usize, cols: usize) -> usize {
    x * cols / 8 + y / 8
}
#[inline]
fn out(x: usize, y: usize, rows: usize) -> usize {
    y * rows / 8 + x / 8
}

#[inline]
// get col byte of row to row + 15
fn load_bytes(b: &[u8], row: usize, col: usize, cols: usize) -> i8x16 {
    let bytes = std::array::from_fn(|i| b[inp(row + i, col, cols)] as i8);
    i8x16::from(bytes)
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use super::*;

    fn arbitrary_bitmat(max_row: usize, max_col: usize) -> BoxedStrategy<(Vec<u8>, usize, usize)> {
        (
            (16..max_row).prop_map(|row| row / 16 * 16),
            (16..max_col).prop_map(|col| col / 16 * 16),
        )
            .prop_flat_map(|(rows, cols)| {
                (vec![any::<u8>(); rows * cols / 8], Just(rows), Just(cols))
            })
            .boxed()
    }

    proptest! {
        #[cfg(not(miri))]
        #[test]
        fn test_double_transpose((v, rows, cols) in arbitrary_bitmat(16 * 30, 16 * 30)) {
            let mut transposed = vec![0; v.len()];
            let mut double_transposed = vec![0; v.len()];
            transpose_bitmatrix(&v,&mut transposed, rows);
            transpose_bitmatrix(&transposed, &mut double_transposed, cols);

            prop_assert_eq!(v, double_transposed);
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")] // miri doesn't know the intrinsics on e.g. ARM
    fn test_double_transpose_miri() {
        let rows = 32;
        let cols = 16;
        let v = vec![0; rows * cols];
        let mut transposed = vec![0; v.len()];
        let mut double_transposed = vec![0; v.len()];
        transpose_bitmatrix(&v, &mut transposed, rows);
        transpose_bitmatrix(&transposed, &mut double_transposed, cols);
        assert_eq!(v, double_transposed);
    }
}
