//! Block
//Later look into replacing this to __m128i, e.g., using https://docs.rs/safe_arch/latest/src/safe_arch/x86_x64/m128i_.rs.html#19

use rand::rngs::OsRng;
use rand::RngCore;

/// Block type
pub type Block = u128;

/// Generate a 128-bit value from two 64-bit values
pub fn make_block(high: u64, low: u64) -> u128 {
    let high = (high as u128) << 64;
    let low = low as u128;
    high | low
}

/// All zero block
pub const ZERO_BLOCK: Block = 0;

/// All one block
//pub const ALL_ONE_BLOCK: Block = u128::MAX;

/// XOR blocks
pub fn xor_blocks_arr(x: Vec<Block>, y: Vec<Block>, nblocks: usize) -> Vec<Block> {
    let mut res: Vec<Block> = vec![ZERO_BLOCK; nblocks];
    for i in 0..nblocks {
        res[i] = x[i] ^ y[i];
    }
    res
}

///XOR Blocks
pub fn xor_blocks_arr_single(x: Vec<Block>, y: Block, nblocks: usize) -> Vec<Block> {
    let mut res: Vec<Block> = vec![ZERO_BLOCK; nblocks];
    for i in 0..nblocks {
        res[i] = x[i] ^ y;
    }
    res
}

/// Compare blocks
pub fn cmp_block(x: Vec<Block>, y: Vec<Block>, nblocks: usize) -> bool {
    for i in 0..nblocks {
        if x[i] != y[i] {
            return false;
        }
    }
    true
}

pub fn get_lsb(x: Block) -> bool {
    (x & 1) == 1
}

pub fn block_to_bool(mut b: Block) -> Vec<bool> {
    let mut res: Vec<bool> = vec![false; 128];
    for i in 0..128 {
        res[i] = (b & 1) == 1;
        b >>= 1;
    }
    res
}

fn bool_to_int(data: &[bool]) -> u64 {
    let mut ret: u64 = 0;

    for i in 0..std::mem::size_of::<u64>() * 8 {
        let s: u64 = (data[i] as u8).into();
        let s = s << i;
        ret |= s;
    }

    ret
}

pub fn bool_to_block(data: &[bool]) -> Block {
    assert_eq!(data.len(), 128); // Ensure data has exactly 128 elements

    let lo = bool_to_int(&data[64..]);
    let hi = bool_to_int(&data[..64]);

    make_block(hi, lo)
}

pub fn random_block(rng: &mut OsRng) -> Block {
    let upper = rng.next_u64() as u128;
    let lower = rng.next_u64() as u128;
    (upper << 64) | lower
}
