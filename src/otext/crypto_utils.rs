//! Smaller crypto utilities
use blake3::Hasher;
use super::block::ZERO_BLOCK;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};

use super::block::{Block, xor_blocks_arr};

const AES_BATCH_SIZE: usize = 8;

/// Function to hash data using BLAKE3 and store the result in a Block[2] array
pub fn hash_once(dgst: &mut [Block; 2], data: &Block) {
    let mut hasher = Hasher::new();
    let data_bytes = data.to_le_bytes();
    hasher.update(&data_bytes);
    let hash = hasher.finalize();
    let hash_bytes = hash.as_bytes();
    dgst[0] = Block::from_le_bytes(hash_bytes[0..16].try_into().unwrap());
    dgst[1] = Block::from_le_bytes(hash_bytes[16..32].try_into().unwrap());
}

/// Galois Field multiplication function for Block
fn gfmul(a: Block, b: Block) -> Block {
    let mut p: Block = 0;
    let mut counter = 0;
    let mut hi = a;
    while hi != 0 {
        if (hi & 1) != 0 {
            p ^= b << counter;
        }
        hi >>= 1;
        counter += 1;
    }
    p
}

/// Function to generate coefficients for almost universal hash function
pub fn uni_hash_coeff_gen(coeff: &mut [Block], seed: Block, sz: usize) {
    // Handle the case with small `sz`
    coeff[0] = seed;
    if sz == 1 {
        return;
    }

    coeff[1] = gfmul(seed, seed);
    if sz == 2 {
        return;
    }

    coeff[2] = gfmul(coeff[1], seed);
    if sz == 3 {
        return;
    }

    let multiplier = gfmul(coeff[2], seed);
    coeff[3] = multiplier;
    if sz == 4 {
        return;
    }

    // Computing the rest with a batch of 4
    let mut i = 4;
    while i < sz - 3 {
        coeff[i] = gfmul(coeff[i - 4], multiplier);
        coeff[i + 1] = gfmul(coeff[i - 3], multiplier);
        coeff[i + 2] = gfmul(coeff[i - 2], multiplier);
        coeff[i + 3] = gfmul(coeff[i - 1], multiplier);
        i += 4;
    }

    // Cleaning up with the rest
    let remainder = sz % 4;
    if remainder != 0 {
        let start = sz - remainder;
        for j in start..sz {
            coeff[j] = gfmul(coeff[j - 1], seed);
        }
    }
}

/// Function to compute inner product of two Galois field vectors with reduction
pub fn vector_inn_prdt_sum_red(a: &[Block], b: &[Block], sz: usize) -> Block {
    let mut r = ZERO_BLOCK;

    // Ensure both vectors have the same size
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), sz);

    for i in 0..sz {
        let r1 = gfmul(a[i], b[i]);
        r ^= r1;
    }
    r
}

pub struct PRP {
    aes_key: Aes128,
}

impl PRP {
    // Constructor with no key
    pub fn new() -> PRP {
        PRP {
            aes_key: Aes128::new(&ZERO_BLOCK.to_le_bytes().into()),
        }
    }

    // Constructor with a key
    pub fn with_key(key: Block) -> PRP {
        PRP {
            aes_key: Aes128::new(&key.to_le_bytes().into()),
        }
    }

    // Permute blocks
    pub fn permute_block(&self, data: &mut [Block], nblocks: usize) {
        for chunk in data.chunks_exact_mut(AES_BATCH_SIZE) {
            for block in chunk.iter_mut() {
                let mut block_bytes = block.to_le_bytes();
                self.aes_key.encrypt_block((&mut block_bytes).into());
                *block = u128::from_le_bytes(block_bytes);
            }
        }

        let remainder = nblocks % AES_BATCH_SIZE;
        if remainder > 0 {
            let start = nblocks - remainder;
            for i in start..nblocks {
                let mut block_bytes = data[i].to_le_bytes();
                self.aes_key.encrypt_block((&mut block_bytes).into());
                data[i] = u128::from_le_bytes(block_bytes);
            }
        }
    }
}

pub struct CCRH {
    prp: PRP,
}

impl CCRH {
    pub fn new(key: Block) -> Self {
        CCRH { prp: PRP::with_key(key) }
    }

    pub fn h(&self, input: Block) -> Block {
        let t = sigma(input);
        self.prp.permute_block(&mut [t], 1);
        t ^ input
    }

    pub fn h_fixed<const N: usize>(&self, input: &[Block; N]) -> Vec<Block> {
        let mut tmp = [0u128; N];
        for i in 0..N {
            tmp[i] = sigma(input[i]);
        }
        self.prp.permute_block(&mut tmp, N);
        xor_blocks_arr(&tmp, input, N)
    }

    pub fn hn(&self, out: &mut Vec<Block>, input: &[Block], length: usize, scratch: Option<&mut [Block]>) -> Vec<Block> {
        let mut local_scratch = vec![0u128; length];
        let scratch = scratch.unwrap_or(local_scratch.as_mut());

        for i in 0..length {
            scratch[i] = sigma(input[i]);
            out[i] = scratch[i];
        }

        self.prp.permute_block(scratch, length);
        xor_blocks_arr(scratch, out, length)
    }
}

fn sigma(block: Block) -> Block {
    let xl = block >> 64;
    let xr = block << 64;
    let xlxl = xl ^ (xl << 64);
    xlxl ^ xr
}