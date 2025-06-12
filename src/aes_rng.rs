//! RNG based on AES in CTR mode.
//!
//! This implementation is based on the implementation given in the
//! [scuttlebutt](https://github.com/GaloisInc/swanky/blob/4455754abadee07f168079ac45ef33535b0df27d/scuttlebutt/src/rand_aes.rs)
//! crate. Instead of using an own AES implementation, [`AesRng`](`AesRng`) uses
//! the [aes](`aes`) crate.
//!
//! On platforms wwith hardware accelerated AES instructions, the [`AesRng`] can
//! generate multiple GiB of random data per second. Make sure to compile with
//! the `aes` target feature enabled to have optimal performance without runtime
//! detection of the feature.
use std::mem;

use aes::{
    cipher::{BlockCipherEncrypt, KeyInit},
    Aes128,
};
use rand::rand_core::block::{BlockRng, BlockRngCore, CryptoBlockRng};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

use crate::block::Block;

// TODO i think softspoken ot has some implementation performance optimizations
// see sect 7 https://eprint.iacr.org/2022/192.pdf

/// This uses AES in a counter-mode to implement a PRG. TODO: Citation for
/// why/when this is secure.
#[derive(Clone, Debug)]
pub struct AesRng(BlockRng<AesRngCore>);

impl RngCore for AesRng {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let block_size = mem::size_of::<aes::Block>();
        let block_len = dest.len() / block_size * block_size;
        let (block_bytes, rest_bytes) = dest.split_at_mut(block_len);
        // fast path so we don't unnecessarily copy u32 from BlockRngCore::generate into
        // dest
        let blocks = bytemuck::cast_slice_mut::<_, aes::Block>(block_bytes);
        for chunk in blocks.chunks_mut(AES_PAR_BLOCKS) {
            for block in chunk.iter_mut() {
                *block = aes::cipher::Array(self.0.core.state.to_le_bytes());
                self.0.core.state += 1;
            }
            self.0.core.aes.encrypt_blocks(chunk);
        }
        // handle the tail
        self.0.fill_bytes(rest_bytes)
    }
}

impl SeedableRng for AesRng {
    type Seed = Block;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        AesRng(BlockRng::<AesRngCore>::from_seed(seed))
    }
}

impl CryptoRng for AesRng {}

impl AesRng {
    /// Create a new random number generator using a random seed from
    /// `rand::random`.
    #[inline]
    pub fn new() -> Self {
        let seed = rand::random::<Block>();
        AesRng::from_seed(seed)
    }

    /// Create a new RNG using a random seed from this one.
    #[inline]
    pub fn fork(&mut self) -> Self {
        let seed = self.random::<Block>();
        AesRng::from_seed(seed)
    }
}

impl Default for AesRng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The core of `AesRng`, used with `BlockRng`.
#[derive(Clone)]
pub struct AesRngCore {
    aes: Aes128,
    state: u128,
}

impl std::fmt::Debug for AesRngCore {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "AesRngCore {{}}")
    }
}

impl BlockRngCore for AesRngCore {
    type Item = u32;
    // This is equivalent to `[Block; AES_PAR_BLOCKS]`
    type Results = hidden::ParBlockWrapper;

    // Compute `E(state)` nine times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Results) {
        let blocks = bytemuck::cast_slice_mut::<_, aes::Block>(results.as_mut());
        blocks.iter_mut().for_each(|blk| {
            // aes::Block is a type alias to Array, but type aliases can't be used as
            // constructors
            *blk = aes::cipher::Array(self.state.to_le_bytes());
            self.state += 1;
        });
        self.aes.encrypt_blocks(blocks);
    }
}

mod hidden {
    use crate::aes_rng::AES_PAR_BLOCKS;

    /// Equivalent to [aes::Block; AES_PAR_BLOCKS]. Since large arrays arrays don't impl Default we write a
    /// wrapper.
    #[derive(Copy, Clone)]
    pub struct ParBlockWrapper([u32; AES_PAR_BLOCKS * 4]);

    impl Default for ParBlockWrapper {
        fn default() -> Self {
            Self([0; AES_PAR_BLOCKS * 4])
        }
    }

    impl AsMut<[u32]> for ParBlockWrapper {
        fn as_mut(&mut self) -> &mut [u32] {
            &mut self.0
        }
    }

    impl AsRef<[u32]> for ParBlockWrapper {
        fn as_ref(&self) -> &[u32] {
            &self.0
        }
    }
}

impl SeedableRng for AesRngCore {
    type Seed = Block;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        let aes = Aes128::new(&seed.into());
        AesRngCore {
            aes,
            state: Default::default(),
        }
    }
}

impl CryptoBlockRng for AesRngCore {}

impl From<AesRngCore> for AesRng {
    #[inline]
    fn from(core: AesRngCore) -> Self {
        AesRng(BlockRng::new(core))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let mut rng = AesRng::new();
        let a = rng.random::<[Block; 8]>();
        let b = rng.random::<[Block; 8]>();
        assert_ne!(a, b);
    }
}

/// Number of Blocks for which hardware accelerated AES can make use of ILP.
///
/// This corresponds to `ParBlocksSize` in [`aes::cipher::ParBlocksSizeUser`]
/// for the SIMD backend on the target architecture. This means, that this
/// constant depends on the target architecture and is different on `x86_64` and
/// `aarch64`.
/// Do not depend on the value of the constant. Using this constant must not result
/// in any observable differences in the execution except performance. Its value
/// must not influence correctness or network messages.
// https://github.com/RustCrypto/block-ciphers/blob/4da9b802de52a3326fdc74d559caddd57042fed2/aes/src/ni.rs#L43
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const AES_PAR_BLOCKS: usize = 9;
#[cfg(target_arch = "aarch64")]
// https://github.com/RustCrypto/block-ciphers/blob/4da9b802de52a3326fdc74d559caddd57042fed2/aes/src/armv8.rs#L32
pub const AES_PAR_BLOCKS: usize = 21;
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
// TODO what should the fallback be?
pub const AES_PAR_BLOCKS: usize = 4;

#[cfg(all(test, not(miri), target_feature = "aes"))]
mod aes_par_blocks_tests {
    use aes::{
        cipher::{
            BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit, ParBlocksSizeUser,
        },
        Aes128,
    };

    use super::AES_PAR_BLOCKS;

    /// This test checks that the value of the [`AES_PAR_BLOCKS`] constant is still correct.
    /// The way to test this is a little convoluted because of the way the aes crate
    /// dispatches to the correct implementation on different architectures.`
    #[test]
    fn aes_par_block_size() {
        use aes::cipher::typenum::Unsigned;

        struct GetParBlockSize;
        impl BlockSizeUser for GetParBlockSize {
            type BlockSize = aes::cipher::array::sizes::U16;
        }
        impl BlockCipherEncClosure for GetParBlockSize {
            fn call<B: aes::cipher::BlockCipherEncBackend<BlockSize = Self::BlockSize>>(
                self,
                _backend: &B,
            ) {
                assert_eq!(
                    AES_PAR_BLOCKS,
                    // size_of ArrayType<u8> is equal to its length
                    <<B as ParBlocksSizeUser>::ParBlocksSize as Unsigned>::USIZE,
                );
            }
        }
        let aes = Aes128::new(&Default::default());
        aes.encrypt_with_backend(GetParBlockSize);
    }
}
