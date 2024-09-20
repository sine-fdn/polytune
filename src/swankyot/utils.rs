//! Utils module of swanky

use scuttlebutt::Block;

#[inline]
fn get_bit(src: &[u8], i: usize) -> u8 {
    let byte = src[i / 8];
    let bit_pos = i % 8;
    (byte & (1 << bit_pos) != 0) as u8
}

#[inline]
fn set_bit(dst: &mut [u8], i: usize, b: u8) {
    let bit_pos = i % 8;
    if b == 1 {
        dst[i / 8] |= 1 << bit_pos;
    } else {
        dst[i / 8] &= !(1 << bit_pos);
    }
}

#[inline]
fn transpose_naive_inplace(dst: &mut [u8], src: &[u8], m: usize) {
    assert_eq!(src.len() % m, 0);
    let l = src.len() * 8;
    let n = l / m;

    for i in 0..l {
        let bit = get_bit(src, i);
        let (row, col) = (i / m, i % m);
        set_bit(dst, col * n + row, bit);
    }
}

#[inline]
fn transpose_naive(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    assert_eq!(nrows * ncols, input.len() * 8);
    let mut output = vec![0u8; nrows * ncols / 8];

    transpose_naive_inplace(&mut output, input, ncols);
    output
}

/// transpose a matrix of bits
#[inline]
pub fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    transpose_naive(m, nrows, ncols)
}

/// boolvec to u8vec
#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}

/// u8vec to boolvec
#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
}

/// XOR two blocks
#[inline(always)]
pub fn xor_two_blocks(x: &(Block, Block), y: &(Block, Block)) -> (Block, Block) {
    (x.0 ^ y.0, x.1 ^ y.1)
}
