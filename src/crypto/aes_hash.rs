//! Correlation robust AES hash.
//!
//! This implementation of a correlation robust AES hash function
//! is based on the findings of <https://eprint.iacr.org/2019/074>.
use std::sync::LazyLock;

use aes::{
    Aes128,
    cipher::{BlockCipherEncrypt, Key, KeyInit},
};
use bytemuck::Pod;

use crate::{block::Block, crypto::AES_PAR_BLOCKS, utils::xor_inplace};

/// AES accelerated hashing of [`Block`]s.
#[derive(Clone)]
pub(crate) struct AesHash {
    aes: Aes128,
}

impl AesHash {
    /// Create a new `AesHash` with the given key.
    pub(crate) fn new(key: &Key<Aes128>) -> Self {
        Self {
            aes: Aes128::new(key),
        }
    }

    /// Compute the correlation robust hash of a block.
    ///
    /// Calculates `π(x) ^ x`.
    ///
    /// # Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    pub(crate) fn cr_hash_block(&self, x: Block) -> Block {
        let mut x_enc = x.into();
        self.aes.encrypt_block(&mut x_enc);
        x ^ x_enc.into()
    }

    /// Compute the correlation robust hashes of multiple blocks.
    ///
    /// Calculates `π(x) ^ x` and returns the hash.
    ///
    /// Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    pub(crate) fn cr_hash_blocks<const N: usize>(&self, x: &[Block; N]) -> [Block; N]
    where
        [Block; N]: Pod,
        [aes::Block; N]: Pod,
    {
        let mut blocks: [aes::Block; N] = bytemuck::cast(*x);
        self.aes.encrypt_blocks(&mut blocks);
        let mut blocks: [Block; N] = bytemuck::cast(blocks);
        xor_inplace(&mut blocks, x);
        blocks
    }

    /// Compute the correlation robust hashes of multiple blocks.
    ///
    /// Calculates `π(x) ^ x` and places the result in `out`.
    ///
    /// Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    ///
    /// # Panics
    /// If `N != out.len()`.
    pub(crate) fn cr_hash_blocks_b2b<const N: usize>(&self, inp: &[Block; N], out: &mut [Block])
    where
        [Block; N]: Pod,
        [aes::Block; N]: Pod,
    {
        assert_eq!(N, out.len(), "inp.len() must be equal to out.len()");
        let inp_aes: &[aes::Block; N] = bytemuck::cast_ref(inp);
        let out_aes: &mut [aes::Block] = bytemuck::cast_slice_mut(out);
        self.aes
            .encrypt_blocks_b2b(inp_aes, out_aes)
            .expect("buffer have equal size");
        xor_inplace(out, inp);
    }

    /// Correlation robust hash of a slice of blocks.
    ///
    /// Calculates `π(x) ^ x` in-place.
    ///
    /// Warning: only secure in semi-honest setting!
    /// See <https://eprint.iacr.org/2019/074> for details.
    ///
    /// In most cases, this method will be the most performant, as it can make
    /// use of AES instruction-level parallelism.
    pub(crate) fn cr_hash_slice_mut(&self, x: &mut [Block]) {
        let mut tmp = [aes::Block::default(); AES_PAR_BLOCKS];

        for chunk in x.chunks_mut(AES_PAR_BLOCKS) {
            self.aes
                .encrypt_blocks_b2b(bytemuck::cast_slice(chunk), &mut tmp[..chunk.len()])
                .expect("in and out always have same length");
            chunk
                .iter_mut()
                .zip(tmp)
                .for_each(|(x, x_enc)| *x ^= x_enc.into());
        }
    }

    /// Tweakable circular correlation robust hash function.
    ///
    /// Calculates `π(π(x) ^ tweak) ^ π(x)` for a single block.
    ///
    /// See <https://eprint.iacr.org/2019/074> for details. This is the TMMO function.
    pub(crate) fn tccr_hash_block(&self, tweak: Block, x: Block) -> Block {
        let mut x_enc = x.into();
        self.aes.encrypt_block(&mut x_enc);
        let mut x_enc_xor_tweak_enc = (Block::from(x_enc) ^ tweak).into();
        self.aes.encrypt_block(&mut x_enc_xor_tweak_enc);

        Block::from(x_enc_xor_tweak_enc) ^ Block::from(x_enc)
    }

    /// Tweakable circular correlation robust hash function.
    ///
    /// Calculates `π(π(x) ^ tweak(i)) ^ π(x)` in-place where i is the index of the block in x.
    ///
    /// See <https://eprint.iacr.org/2019/074> for details. This is the TMMO function.
    ///
    /// This function will likely be more performant than the [`AesHash::tccr_hash_block`]
    /// as it can make use of AES instruction-level parallelism.
    pub(crate) fn tccr_hash_slice_mut(
        &self,
        x: &mut [Block],
        mut tweak_fn: impl FnMut(usize) -> Block,
    ) {
        let mut tmp = [aes::Block::default(); AES_PAR_BLOCKS];
        for (chunk_idx, chunk) in x.chunks_mut(AES_PAR_BLOCKS).enumerate() {
            // Write π(x) to tmp
            self.aes
                .encrypt_blocks_b2b(bytemuck::cast_slice(chunk), &mut tmp[..chunk.len()])
                .expect("in and out always have same length");
            // Write π(x) ^ i to x
            chunk
                .iter_mut()
                .zip(&tmp)
                .enumerate()
                .for_each(|(idx, (dest, x_enc))| {
                    *dest = Block::from(*x_enc) ^ tweak_fn(chunk_idx * AES_PAR_BLOCKS + idx);
                });
            // write π(π(x) ^ i) to x
            self.aes.encrypt_blocks(bytemuck::cast_slice_mut(chunk));
            // write π(π(x) ^ i) ^ π(x) to x
            chunk
                .iter_mut()
                .zip(tmp)
                .for_each(|(x, x_enc)| *x ^= x_enc.into());
        }
    }
}

/// An `AesHash` with a fixed key.
pub(crate) static FIXED_KEY_HASH: LazyLock<AesHash> = LazyLock::new(|| {
    // The key was randomly chosen. Any key would be okay.
    let key = 193502124791825095790518994062991136444_u128
        .to_le_bytes()
        .into();
    AesHash::new(&key)
});
