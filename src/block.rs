//! A 128-bit [`Block`] type.
//!
//! Operations on [`Block`]s will use SIMD instructions where possible.
use std::{
    fmt,
    ops::{Add, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl, Shr},
};

use aes::cipher::{self, array::sizes};
use bytemuck::{Pod, Zeroable};
use rand::{Rng, distr::StandardUniform, prelude::Distribution};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use thiserror::Error;
use wide::{u8x16, u64x2};

// TODO remove this once OT implementations are refactored and we know
// what parts we need and which not
#[allow(dead_code)]
mod gf128;

/// A 128-bit block. Uses SIMD operations where available.
///
/// This type is publicly re-exported when the private `__bench` feature
/// is enabled at [`crate::bench_reexports::Block`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, Pod, Zeroable)]
#[repr(transparent)]
pub struct Block(u8x16);

impl Block {
    /// All bits set to 0.
    pub const ZERO: Self = Self(u8x16::ZERO);
    /// All bits set to 1.
    pub const ONES: Self = Self(u8x16::MAX);
    /// Lsb set to 1, all others zero.
    pub const ONE: Self = Self::new(1_u128.to_ne_bytes());
    /// Mask to mask off the LSB of a Block.
    /// ```rust,ignore
    /// let b = Block::ONES;
    /// let masked = b & Block::MASK_LSB;
    /// assert_eq!(masked, Block::ONES << 1)
    /// ```
    pub const MASK_LSB: Self = Self::pack(u64::MAX << 1, u64::MAX);

    /// 16 bytes in a Block.
    pub const BYTES: usize = 16;
    /// 128 bits in a block.
    pub const BITS: usize = 128;

    /// Create a new block from bytes.
    #[inline]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(u8x16::new(bytes))
    }

    /// Create a block with all bytes set to `byte`.
    #[inline]
    pub const fn splat(byte: u8) -> Self {
        Self::new([byte; 16])
    }

    /// Pack two `u64` into a Block. Usable in const context.
    ///
    /// In non-const contexts, using `Block::from([low, high])` is likely
    /// faster.
    #[inline]
    pub const fn pack(low: u64, high: u64) -> Self {
        let mut bytes = [0; 16];
        let low = low.to_ne_bytes();
        let mut i = 0;
        while i < low.len() {
            bytes[i] = low[i];
            i += 1;
        }

        let high = high.to_ne_bytes();
        let mut i = 0;
        while i < high.len() {
            bytes[i + 8] = high[i];
            i += 1;
        }

        Self::new(bytes)
    }

    /// Bytes of the block.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_array_ref()
    }

    /// Mutable bytes of the block.
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 16] {
        self.0.as_array_mut()
    }

    /// Hash the block with a [`random_oracle`].
    #[inline]
    pub fn ro_hash(&self) -> blake3::Hash {
        blake3::hash(self.as_bytes())
    }

    ///  Create a block from 128 [`Choice`]s.
    ///
    /// # Panics
    /// If choices.len() != 128
    #[inline]
    pub fn from_choices(choices: &[Choice]) -> Self {
        assert_eq!(128, choices.len(), "choices.len() must be 128");
        let mut bytes = [0_u8; 16];
        for (chunk, byte) in choices.chunks_exact(8).zip(&mut bytes) {
            for (i, choice) in chunk.iter().enumerate() {
                *byte ^= choice.unwrap_u8() << i;
            }
        }
        Self::new(bytes)
    }

    /// Low 64 bits of the block.
    #[inline]
    pub fn low(&self) -> u64 {
        let inner: &u64x2 = bytemuck::must_cast_ref(&self.0);
        inner.as_array_ref()[0]
    }

    /// High 64 bits of the block.
    #[inline]
    pub fn high(&self) -> u64 {
        let inner: &u64x2 = bytemuck::must_cast_ref(&self.0);
        inner.as_array_ref()[1]
    }

    /// Least significant bit of the block
    #[inline]
    pub fn lsb(&self) -> bool {
        *self & Block::ONE == Block::ONE
    }

    /// Iterator over bits of the Block.
    #[inline]
    pub fn bits(&self) -> impl Iterator<Item = bool> + use<> {
        struct BitIter {
            blk: Block,
            idx: usize,
        }
        impl Iterator for BitIter {
            type Item = bool;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                if self.idx < Block::BITS {
                    self.idx += 1;
                    let bit = (self.blk >> (self.idx - 1)) & Block::ONE != Block::ZERO;
                    Some(bit)
                } else {
                    None
                }
            }
        }
        BitIter { blk: *self, idx: 0 }
    }

    /// Computes self * b, where b is `bool` in constant time.
    #[inline]
    pub fn const_mul(&self, b: bool) -> Block {
        Block::conditional_select(&Block::ZERO, self, Choice::from(u8::from(b)))
    }
}

// Implement standard operators for more ergonomic usage
impl BitAnd for Block {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Block {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOr for Block {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Block {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXor for Block {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Block {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl<Rhs> Shl<Rhs> for Block
where
    u128: Shl<Rhs, Output = u128>,
{
    type Output = Block;

    #[inline]
    fn shl(self, rhs: Rhs) -> Self::Output {
        Self::from(u128::from(self) << rhs)
    }
}

impl<Rhs> Shr<Rhs> for Block
where
    u128: Shr<Rhs, Output = u128>,
{
    type Output = Block;

    #[inline]
    fn shr(self, rhs: Rhs) -> Self::Output {
        Self::from(u128::from(self) >> rhs)
    }
}

impl Not for Block {
    type Output = Self;

    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        let a: u128 = (*self).into();
        let b: u128 = (*other).into();
        a.ct_eq(&b).into()
    }
}

impl Eq for Block {}

impl Distribution<Block> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        Block::new(bytes)
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for Block {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl From<Block> for cipher::Array<u8, sizes::U16> {
    #[inline]
    fn from(value: Block) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<cipher::Array<u8, sizes::U16>> for Block {
    #[inline]
    fn from(value: cipher::Array<u8, sizes::U16>) -> Self {
        Self::new(value.0)
    }
}

impl From<[u8; 16]> for Block {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self::new(value)
    }
}

impl From<Block> for [u8; 16] {
    fn from(value: Block) -> Self {
        *value.as_bytes()
    }
}

impl From<[i64; 2]> for Block {
    #[inline]
    fn from(value: [i64; 2]) -> Self {
        bytemuck::must_cast(value)
    }
}

impl From<Block> for [i64; 2] {
    #[inline]
    fn from(value: Block) -> Self {
        bytemuck::must_cast(value)
    }
}

impl From<[u64; 2]> for Block {
    #[inline]
    fn from(value: [u64; 2]) -> Self {
        bytemuck::must_cast(value)
    }
}

impl From<Block> for [u64; 2] {
    #[inline]
    fn from(value: Block) -> Self {
        bytemuck::must_cast(value)
    }
}

impl From<Block> for u128 {
    #[inline]
    fn from(value: Block) -> Self {
        u128::from_ne_bytes(*value.as_bytes())
    }
}

impl From<&Block> for u128 {
    #[inline]
    fn from(value: &Block) -> Self {
        u128::from_ne_bytes(*value.as_bytes())
    }
}

impl From<usize> for Block {
    fn from(value: usize) -> Self {
        (value as u128).into()
    }
}

impl From<u128> for Block {
    #[inline]
    fn from(value: u128) -> Self {
        Self::new(value.to_ne_bytes())
    }
}

impl From<&u128> for Block {
    #[inline]
    fn from(value: &u128) -> Self {
        Self::new(value.to_ne_bytes())
    }
}

#[derive(Debug, Error)]
#[error("slice must have length of 16")]
pub struct WrongLength;

impl TryFrom<&[u8]> for Block {
    type Error = WrongLength;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let arr = value.try_into().map_err(|_| WrongLength)?;
        Ok(Self::new(arr))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod from_arch_impls {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    use super::Block;

    impl From<__m128i> for Block {
        #[inline]
        fn from(value: __m128i) -> Self {
            bytemuck::must_cast(value)
        }
    }

    impl From<&__m128i> for Block {
        #[inline]
        fn from(value: &__m128i) -> Self {
            bytemuck::must_cast(*value)
        }
    }

    impl From<Block> for __m128i {
        #[inline]
        fn from(value: Block) -> Self {
            bytemuck::must_cast(value)
        }
    }

    impl From<&Block> for __m128i {
        #[inline]
        fn from(value: &Block) -> Self {
            bytemuck::must_cast(*value)
        }
    }
}

impl ConditionallySelectable for Block {
    #[inline]
    // adapted from https://github.com/dalek-cryptography/subtle/blob/369e7463e85921377a5f2df80aabcbbc6d57a930/src/lib.rs#L510-L517
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // if choice = 0, mask = (-0) = 0000...0000
        // if choice = 1, mask = (-1) = 1111...1111
        let mask = Block::new((-(choice.unwrap_u8() as i128)).to_le_bytes());
        *a ^ (mask & (*a ^ *b))
    }
}

impl Add for Block {
    type Output = Block;

    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        // todo is this a sensible implementation?
        let a: u128 = self.into();
        let b: u128 = rhs.into();
        Self::from(a.wrapping_add(b))
    }
}

impl fmt::Binary for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Binary::fmt(&u128::from(*self), f)
    }
}

#[cfg(test)]
mod tests {
    use subtle::{Choice, ConditionallySelectable};

    use super::Block;

    #[test]
    fn test_block_cond_select() {
        let choice = Choice::from(0);
        assert_eq!(
            Block::ZERO,
            Block::conditional_select(&Block::ZERO, &Block::ONES, choice)
        );
        let choice = Choice::from(1);
        assert_eq!(
            Block::ONES,
            Block::conditional_select(&Block::ZERO, &Block::ONES, choice)
        );
    }

    #[test]
    fn test_block_low_high() {
        let b = Block::from(1_u128);
        assert_eq!(1, b.low());
        assert_eq!(0, b.high());
    }

    #[test]
    fn test_from_into_u64_arr() {
        let b = Block::from([42_u64, 65]);
        assert_eq!(42, b.low());
        assert_eq!(65, b.high());
        assert_eq!([42, 65], <[u64; 2]>::from(b));
    }

    #[test]
    fn test_pack() {
        let b = Block::pack(42, 123);
        assert_eq!(42, b.low());
        assert_eq!(123, b.high());
    }

    #[test]
    fn test_mask_lsb() {
        assert_eq!(Block::ONES ^ Block::ONE, Block::MASK_LSB);
    }

    #[test]
    fn test_bits() {
        let b: Block = 0b101_u128.into();
        let mut iter = b.bits();
        assert_eq!(Some(true), iter.next());
        assert_eq!(Some(false), iter.next());
        assert_eq!(Some(true), iter.next());
        for rest in iter {
            assert!(!rest);
        }
    }

    #[test]
    fn test_from_choices() {
        let mut choices = vec![Choice::from(0); 128];
        choices[2] = Choice::from(1);
        choices[16] = Choice::from(1);
        let blk = Block::from_choices(&choices);
        assert_eq!(Block::from(1_u128 << 2 | 1_u128 << 16), blk);
    }
}
