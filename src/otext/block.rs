//! Block
//Later look into replacing this to __m128i, e.g., using https://docs.rs/safe_arch/latest/src/safe_arch/x86_x64/m128i_.rs.html#19

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
pub const ALL_ONE_BLOCK: Block = u128::MAX;

/// XOR blocks
pub fn xor_blocks_arr(res: &mut [Block], x: &[Block], y: &[Block], nblocks: usize) {
    for i in 0..nblocks {
        res[i] = x[i] ^ y[i];
    }
}

/// XOR single block
pub fn xor_blocks_arr_single(res: &mut [Block], x: &[Block], y: Block, nblocks: usize) {
    for i in 0..nblocks {
        res[i] = x[i] ^ y;
    }
}

/// Compare blocks
pub fn cmp_block(x: &[Block], y: &[Block], nblocks: usize) -> bool {
    for i in 0..nblocks {
        if x[i] != y[i] {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_block() {
        let high = 0x0123456789ABCDEF;
        let low = 0xFEDCBA9876543210;
        let block = make_block(high, low);
        assert_eq!(block, 0x0123456789ABCDEF_FEDCBA9876543210);
    }

    #[test]
    fn test_xor_blocks_arr() {
        let x = vec![make_block(1, 2); 3];
        let y = vec![make_block(3, 4); 3];
        let mut res = vec![ZERO_BLOCK; 3];

        xor_blocks_arr(&mut res, &x, &y, 3);

        for block in &res {
            assert_eq!(*block, make_block(1 ^ 3, 2 ^ 4));
        }
    }

    #[test]
    fn test_xor_blocks_arr_single() {
        let x = vec![make_block(1, 2); 3];
        let y = make_block(5, 6);
        let mut res = vec![ZERO_BLOCK; 3];

        xor_blocks_arr_single(&mut res, &x, y, 3);

        for block in &res {
            assert_eq!(*block, make_block(1 ^ 5, 2 ^ 6));
        }
    }

    #[test]
    fn test_cmp_block() {
        let x = vec![make_block(1, 2); 3];
        let y = vec![make_block(1, 2); 3];
        let z = vec![make_block(3, 4); 3];

        assert!(cmp_block(&x, &y, 3)); // Should be true
        assert!(!cmp_block(&x, &z, 3)); // Should be false
    }
}