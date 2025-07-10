//! Implementation of AVX2 BitMatrix transpose based on libOTe.
use std::{arch::x86_64::*, cmp};

use bytemuck::{must_cast_slice, must_cast_slice_mut};
use seq_macro::seq;

/// Performs a 2x2 bit transpose operation on two 256-bit vectors representing a
/// 4x128 matrix.
#[inline]
#[target_feature(enable = "avx2")]
fn transpose_2x2_matrices(x: &mut __m256i, y: &mut __m256i) {
    // x = [x_H | x_L] and y = [y_H | y_L]
    // u = [y_L | x_L] u is the low 128 bits of x and y
    let u = _mm256_permute2x128_si256(*x, *y, 0x20);
    // v = [y_H | x_H] v is the high 128 bits of x and y
    let v = _mm256_permute2x128_si256(*x, *y, 0x31);
    // Shift v by one left so each element in at (i, j) aligns with (i+1, j-1) and
    // compute the difference. the row shift i+1 is done by the permute
    // instructions before and the column by the sll instruction
    let mut diff = _mm256_xor_si256(u, _mm256_slli_epi16(v, 1));
    // select all odd indices of diff and zero out even indices. the idea is to
    // calculate the difference of all odd numbered indices j of the even
    // numbered row i with the even numbered indices j-1 in row i+1.
    // These are precisely the elements in the 2x2 matrices that make up x and y
    // that potentially need to be swapped for the transpose if they differ
    diff = _mm256_and_si256(diff, _mm256_set1_epi16(0b1010101010101010_u16 as i16));
    // perform the swaps in u, which corresponds the lower bits of x and y by XORing
    // the diff
    let u = _mm256_xor_si256(u, diff);
    // for the bottom row in the 2x2 matrices (the high bits of x and y) we need to
    // shift the diff by 1 to the right so it aligns with the even numbered indices
    let v = _mm256_xor_si256(v, _mm256_srli_epi16(diff, 1));
    // the permuted 2x2 matrices are split over u and v, with the upper row in u and
    // the lower in v. We perform the same permutation as in the beginning, thereby
    // writing the 2x2 permuted bits of x and y back
    *x = _mm256_permute2x128_si256(u, v, 0x20);
    *y = _mm256_permute2x128_si256(u, v, 0x31);
}

/// Performs a general bit-level transpose.
///
/// `SHIFT_AMOUNT` is the constant shift value (e.g., 2, 4, 8, 16, 32) for the
/// intrinsics. `MASK` is the bitmask for the XOR-swap.
#[inline]
#[target_feature(enable = "avx2")]
fn partial_swap_sub_matrices<const SHIFT_AMOUNT: i32, const MASK: u64>(
    x: &mut __m256i,
    y: &mut __m256i,
) {
    // calculate the diff of the bits that need to be potentially swapped
    let mut diff = _mm256_xor_si256(*x, _mm256_slli_epi64::<SHIFT_AMOUNT>(*y));
    diff = _mm256_and_si256(diff, _mm256_set1_epi64x(MASK as i64));
    // swap the bits in x by xoring the difference
    *x = _mm256_xor_si256(*x, diff);
    // and in y
    *y = _mm256_xor_si256(*y, _mm256_srli_epi64::<SHIFT_AMOUNT>(diff));
}

/// Performs a partial 64x64 bit matrix swap. This is used to swap the rows in
/// the upper right quadrant with those of the lower left in the 128x128 matrix.
#[inline]
#[target_feature(enable = "avx2")]
fn partial_swap_64x64_matrices(x: &mut __m256i, y: &mut __m256i) {
    let out_x = _mm256_unpacklo_epi64(*x, *y);
    let out_y = _mm256_unpackhi_epi64(*x, *y);
    *x = out_x;
    *y = out_y;
}

/// Transpose a 128x128 bit matrix using AVX2 intrinsics.
///
/// # Safety
/// AVX2 needs to be enabled.
#[target_feature(enable = "avx2")]
fn avx_transpose128x128(in_out: &mut [__m256i; 64]) {
    // This algorithm implements a bit-transpose of a 128x128 bit matrix using a
    // divide-and-conquer algorithm. The idea is that for
    // A = [ A B ]
    //     [ C D ]
    // A^T is equal to
    //     [ A^T C^T ]
    //     [ B^T D^T ]
    //
    // We first divide our matrix into 2x2 bit matrices which we transpose at the
    // bit level. Then we swap the 2x2 bit matrices to complete a 4x4
    // transpose. We swap the 4x4 bit matrices to complete a 8x8 transpose and so on
    // until we swap 64x64 bit matrices and thus complete the intended 128x128 bit
    // transpose.

    // Part 1: Specialized 2x2 block transpose transposing individual bits
    for chunk in in_out.chunks_exact_mut(2) {
        if let [x, y] = chunk {
            transpose_2x2_matrices(x, y);
        } else {
            unreachable!("chunk size is 2")
        }
    }

    // Phases 1-5: swap sub-matrices of size 2x2, 4x4, 8x8, 16x16, 32x32 bit
    // Using seq_macro to reduce repetition
    seq!(N in 1..=5 {
        const SHIFT_~N: i32 = 1 << N;
        // Our mask selects the part of the sub-matrix that needs to be potentially
        // swapped allong the diagonal. The lower 2^SHIFT bits are 0 and the following
        // 2^SHIFT bits are 1, repeated to a 64 bit mask
        const MASK_~N: u64 = match N {
            1 => mask(0b1100, 4),
            2 => mask(0b11110000, 8),
            3 => mask(0b1111111100000000, 16),
            4 => mask(0b11111111111111110000000000000000, 32),
            5 => 0xffffffff00000000,
            _ => unreachable!(),
        };
        // The offset between x and y for matrix rows that need to be swapped in terms
        // of 256 bit elements. In the first iteration we swap the 2x2 matrices that
        // are at positions in_out[i] and in_out[j], so the offset is 1. For 4x4 matrices
        // the offset is 2
        #[allow(clippy::eq_op)] // false positive due to use of seq!
        const OFFSET~N: usize = 1 << (N - 1);

        for chunk in in_out.chunks_exact_mut(2 * OFFSET~N) {
            let (x_chunk, y_chunk) = chunk.split_at_mut(OFFSET~N);
            // For larger matrices, and larger offsets, we need to iterate over all
            // rows of the sub-matrices
            for (x, y) in x_chunk.iter_mut().zip(y_chunk.iter_mut()) {
                partial_swap_sub_matrices::<SHIFT_~N, MASK_~N>(x, y);
            }
        }
    });

    // Phase 6: swap 64x64 bit-matrices therefore completing the 128x128 bit
    // transpose
    const SHIFT_6: usize = 6;
    const OFFSET_6: usize = 1 << (SHIFT_6 - 1); // 32

    for chunk in in_out.chunks_exact_mut(2 * OFFSET_6) {
        let (x_chunk, y_chunk) = chunk.split_at_mut(OFFSET_6);
        for (x, y) in x_chunk.iter_mut().zip(y_chunk.iter_mut()) {
            partial_swap_64x64_matrices(x, y);
        }
    }
}

/// Create a u64 bit mask based on the pattern which is repeated to fill the u54
const fn mask(pattern: u64, pattern_len: u32) -> u64 {
    let mut mask = pattern;
    let mut current_block_len = pattern_len;

    // We keep doubling the effective length of our repeating block
    // until it covers 64 bits.
    while current_block_len < 64 {
        mask = (mask << current_block_len) | mask;
        current_block_len *= 2;
    }

    mask
}

/// Transpose a bit matrix using AVX2.
///
/// This implementation is specifically tuned for transposing `128 x l` matrices
/// as done in OT protocols. Performance might be better if `input` is 16-byte
/// aligned and the number of columns is divisable by 512 on systems with
/// 64-byte cache lines.
///
/// # Panics
/// If `input.len() != output.len()`
/// If the number of rows is less than 128.
/// If `input.len()` is not divisible by rows.
/// If the number of rows is not divisable by 128.
/// If the number of columns (= input.len() * 8 / rows) is not divisable by 8.
///
/// # Safety
/// AVX2 instruction set must be available.
#[target_feature(enable = "avx2")]
pub(super) fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    assert_eq!(input.len(), output.len());
    assert!(rows >= 128, "Number of rows must be >= 128.");
    assert_eq!(
        0,
        input.len() % rows,
        "input.len(), must be divisble by rows"
    );
    assert_eq!(0, rows % 128, "Number of rows must be a multiple of 128.");
    let cols = input.len() * 8 / rows;
    assert_eq!(0, cols % 8, "Number of columns must be a multiple of 8.");

    // Buffer to hold a 4 128x128 bit squares (64 * 4 __m256i registers = 2048 * 4
    // bytes)
    let mut buf = [_mm256_setzero_si256(); 64 * 4];
    let in_stride = cols / 8; // Stride in bytes for input rows
    let out_stride = rows / 8; // Stride in bytes for output rows

    // Number of 128x128 bit squares in rows and columns
    let r_main = rows / 128;
    let c_main = cols / 128;
    let c_rest = cols % 128;

    // Iterate through each 128x128 bit square in the matrix
    // Row block index
    for i in 0..r_main {
        // Column block index
        let mut j = 0;
        while j < c_main {
            let input_offset = i * 128 * in_stride + j * 16;
            let curr_addr = input[input_offset..].as_ptr().addr();
            let next_cache_line_addr = (curr_addr + 1).next_multiple_of(64); // cache line size
            let blocks_in_cache_line = (next_cache_line_addr - curr_addr) / 16;

            let remaining_blocks_in_cache_line = if blocks_in_cache_line == 0 {
                // will cross over a cache line, but if the blocks are not 16-byte aligned, this
                // is the best we can do
                4
            } else {
                blocks_in_cache_line
            };
            // Ensure we don't read OOB of the input
            let remaining_blocks_in_cache_line =
                cmp::min(remaining_blocks_in_cache_line, c_main - j);

            let buf_as_bytes: &mut [u8] = must_cast_slice_mut(&mut buf);

            // The loading loop loads the input data into the buf. By using a macro and
            // matching on 4 blocks in a cache line (each row in a block is 16 bytes, so the
            // rows 4 consecutive blocks are 64 bytes long) the optimizer uses a loop
            // unrolled version for this case.
            macro_rules! loading_loop {
                ($remaining_blocks_in_cache_line:expr) => {
                    for k in 0..128 {
                        let src_slice = &input[input_offset + k * in_stride
                            ..input_offset + k * in_stride + 16 * remaining_blocks_in_cache_line];

                        for block in 0..remaining_blocks_in_cache_line {
                            buf_as_bytes[block * 2048 + k * 16..block * 2048 + (k + 1) * 16]
                                .copy_from_slice(&src_slice[block * 16..(block + 1) * 16]);
                        }
                    }
                };
            }

            // This gets optimized to the unrolled loop for the default case of 4 blocks
            match remaining_blocks_in_cache_line {
                4 => loading_loop!(4),
                #[allow(unused_variables)] // false positive
                other => loading_loop!(other),
            }

            for block in 0..remaining_blocks_in_cache_line {
                avx_transpose128x128(
                    (&mut buf[block * 64..(block + 1) * 64])
                        .try_into()
                        .expect("slice has length 64"),
                );
            }

            let mut output_offset = j * 128 * out_stride + i * 16;
            let buf_as_bytes: &[u8] = must_cast_slice(&buf);

            if out_stride == 16 {
                // if the out_stride is 16 bytes, the transposed sub-matrices are in contiguous
                // memory in the output, so we can use a single copy_from_slice. This is
                // especially helpful for the case of transposing a 128xl matrix as done in OT
                // extension.
                let dst_slice = &mut output
                    [output_offset..output_offset + 16 * 128 * remaining_blocks_in_cache_line];
                dst_slice.copy_from_slice(&buf_as_bytes[..remaining_blocks_in_cache_line * 2048]);
            } else {
                for block in 0..remaining_blocks_in_cache_line {
                    for k in 0..128 {
                        let src_slice =
                            &buf_as_bytes[block * 2048 + k * 16..block * 2048 + (k + 1) * 16];
                        let dst_slice = &mut output
                            [output_offset + k * out_stride..output_offset + k * out_stride + 16];
                        dst_slice.copy_from_slice(src_slice);
                    }
                    output_offset += 128 * out_stride;
                }
            }

            j += remaining_blocks_in_cache_line;
        }

        if c_rest > 0 {
            handle_rest_cols(input, output, &mut buf, in_stride, out_stride, c_rest, i, j);
        }
    }
}

// Inline never to reduce code size of `transpose_bitmatrix` method. This is method is only
// called once row block if the columns are not divisble by 128. Since this is only rarely
// executed opposed to the core loop of `transpose_bitmatrix` we annotate it with inline(never)
// to ensure the optimizer doesn't inline it which could negatively impact performance
// due to larger code size and potentially more instruction cache misses. This is an assumption
// and not verified by a benchmark, but even if it were wrong, it shouldn't negatively impact
// runtime because this method is called rarely in our use cases where we have 128 rows and many
// columns.
#[inline(never)]
#[target_feature(enable = "avx2")]
#[allow(clippy::too_many_arguments)]
fn handle_rest_cols(
    input: &[u8],
    output: &mut [u8],
    buf: &mut [__m256i; 256],
    in_stride: usize,
    out_stride: usize,
    c_rest: usize,
    i: usize,
    j: usize,
) {
    let input_offset = i * 128 * in_stride + j * 16;
    let remaining_cols_bytes = c_rest / 8;
    buf[0..64].fill(_mm256_setzero_si256());
    let buf_as_bytes: &mut [u8] = must_cast_slice_mut(buf);

    for k in 0..128 {
        let src_row_offset = input_offset + k * in_stride;
        let src_slice = &input[src_row_offset..src_row_offset + remaining_cols_bytes];
        // we use 16 because we still transpose a 128x128 matrix, of which only a part
        // is filled
        let buf_offset = k * 16;
        buf_as_bytes[buf_offset..buf_offset + remaining_cols_bytes].copy_from_slice(src_slice);
    }

    avx_transpose128x128((&mut buf[..64]).try_into().expect("slice has length 64"));

    let output_offset = j * 128 * out_stride + i * 16;
    let buf_as_bytes: &[u8] = must_cast_slice(&*buf);

    for k in 0..c_rest {
        let src_slice = &buf_as_bytes[k * 16..(k + 1) * 16];
        let dst_slice =
            &mut output[output_offset + k * out_stride..output_offset + k * out_stride + 16];
        dst_slice.copy_from_slice(src_slice);
    }
}

#[cfg(all(test, target_feature = "avx2"))]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::arch::x86_64::_mm256_setzero_si256;

    use rand::{RngCore, SeedableRng, rngs::StdRng};

    use super::{avx_transpose128x128, transpose_bitmatrix};

    #[test]
    fn test_avx_transpose128() {
        unsafe {
            let mut v = [_mm256_setzero_si256(); 64];
            StdRng::seed_from_u64(42).fill_bytes(bytemuck::cast_slice_mut(&mut v));

            let orig = v;
            avx_transpose128x128(&mut v);
            avx_transpose128x128(&mut v);
            let mut failed = false;
            for (i, (o, t)) in orig.into_iter().zip(v).enumerate() {
                let o = bytemuck::cast::<_, [u128; 2]>(o);
                let t = bytemuck::cast::<_, [u128; 2]>(t);
                if o != t {
                    eprintln!("difference in block {i}");
                    eprintln!("orig: {o:?}");
                    eprintln!("tran: {t:?}");
                    failed = true;
                }
            }
            if failed {
                panic!("double transposed is different than original")
            }
        }
    }

    #[test]
    fn test_avx_transpose() {
        let rows = 128 * 2;
        let cols = 128 * 2;
        let mut v = vec![0_u8; rows * cols / 8];
        StdRng::seed_from_u64(42).fill_bytes(&mut v);

        let mut avx_transposed = v.clone();
        let mut sse_transposed = v.clone();
        unsafe {
            transpose_bitmatrix(&v, &mut avx_transposed, rows);
        }
        crate::transpose::portable::transpose_bitmatrix(&v, &mut sse_transposed, rows);

        assert_eq!(sse_transposed, avx_transposed);
    }

    #[test]
    fn test_avx_transpose_unaligned_data() {
        let rows = 128 * 2;
        let cols = 128 * 2;
        let mut v = vec![0_u8; rows * (cols + 128) / 8];
        StdRng::seed_from_u64(42).fill_bytes(&mut v);

        let v = {
            let addr = v.as_ptr().addr();
            let offset = addr.next_multiple_of(3) - addr;
            &v[offset..offset + rows * cols / 8]
        };
        assert_eq!(0, v.as_ptr().addr() % 3);
        // allocate out bufs with same dims
        let mut avx_transposed = v.to_owned();
        let mut sse_transposed = v.to_owned();

        unsafe {
            transpose_bitmatrix(v, &mut avx_transposed, rows);
        }
        crate::transpose::portable::transpose_bitmatrix(v, &mut sse_transposed, rows);

        assert_eq!(sse_transposed, avx_transposed);
    }

    #[test]
    fn test_avx_transpose_larger_cols_divisable_by_4_times_128() {
        let rows = 128;
        let cols = 128 * 8;
        let mut v = vec![0_u8; rows * cols / 8];
        StdRng::seed_from_u64(42).fill_bytes(&mut v);

        let mut avx_transposed = v.clone();
        let mut sse_transposed = v.clone();
        unsafe {
            transpose_bitmatrix(&v, &mut avx_transposed, rows);
        }
        crate::transpose::portable::transpose_bitmatrix(&v, &mut sse_transposed, rows);

        assert_eq!(sse_transposed, avx_transposed);
    }

    #[test]
    fn test_avx_transpose_larger_cols_divisable_by_8() {
        let rows = 128;
        let cols = 128 + 32;
        let mut v = vec![0_u8; rows * cols / 8];
        StdRng::seed_from_u64(42).fill_bytes(&mut v);

        let mut avx_transposed = v.clone();
        let mut sse_transposed = v.clone();
        unsafe {
            transpose_bitmatrix(&v, &mut avx_transposed, rows);
        }
        crate::transpose::portable::transpose_bitmatrix(&v, &mut sse_transposed, rows);

        assert_eq!(sse_transposed, avx_transposed);
    }
}
