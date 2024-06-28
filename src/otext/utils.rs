//! Smaller crypto utilities
use blake3::Hasher;
use super::block::ZERO_BLOCK;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockCipher, KeyInit};
use super::block::{Block, xor_blocks_arr};
use super::constants::AES_BATCH_SIZE;

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

pub struct GaloisFieldPacking {
    base: [Block; 128],
}

impl GaloisFieldPacking {
    pub fn new() -> Self {
        let mut gfp = GaloisFieldPacking {
            base: [0; 128],
        };
        gfp.packing_base_gen();
        gfp
    }

    fn packing_base_gen(&mut self) {
        let mut a: u64 = 0;
        let mut b: u64 = 1;
        for i in (0..64).step_by(4) {
            self.base[i] = ((a as Block) << 64) | (b as Block);
            self.base[i + 1] = ((a as Block) << 64) | ((b << 1) as Block);
            self.base[i + 2] = ((a as Block) << 64) | ((b << 2) as Block);
            self.base[i + 3] = ((a as Block) << 64) | ((b << 3) as Block);
            b <<= 4;
        }
        a = 1;
        b = 0;
        for i in (64..128).step_by(4) {
            self.base[i] = ((a as Block) << 64) | (b as Block);
            self.base[i + 1] = (((a << 1) as Block) << 64) | (b as Block);
            self.base[i + 2] = (((a << 2) as Block) << 64) | (b as Block);
            self.base[i + 3] = (((a << 3) as Block) << 64) | (b as Block);
            a <<= 4;
        }
    }

    pub fn packing(&self, res: &mut Block, data: &[Block]) {
        *res = vector_inn_prdt_sum_red(data, &self.base, 128);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AesKey {
    userkey: Block,
}

/// Encrypts multiple blocks using AES-128 in ECB mode
pub fn aes_ecb_encrypt_blks(blocks: Vec<Block>, nblks: usize, key: AesKey) -> Vec<Block> {
    let aes_key: [u8; 16] = key.userkey.to_le_bytes();
    let cipher = Aes128::new_from_slice(&aes_key).unwrap();
    let mut out: Vec<Block> = vec![ZERO_BLOCK; nblks];

    // Iterate over each block and encrypt it
    for i in 0..nblks {
        let mut block_bytes = blocks[i].to_be_bytes();
        let block_array: &mut [u8; 16] = &mut block_bytes;

        let mut block_cipher = aes::Block::clone_from_slice(block_array);
        cipher.encrypt_block(&mut block_cipher);

        out[i] = u128::from_be_bytes(block_cipher.into());
    }
    out
}

pub struct PRP{
    pub aes_key: AesKey,
}

impl PRP {
    // Constructor with no key
    fn new() -> PRP {
        PRP {
            aes_key: AesKey{ userkey:ZERO_BLOCK },
        }
    }

    // Constructor with a key
    pub fn with_key(key: Block) -> PRP {
        PRP {
            aes_key: AesKey{ userkey:key },
        }
    }

    // Permute blocks
    pub fn permute_block(&self, data: Vec<Block>, nblocks: usize) -> Vec<Block>{
        let mut out: Vec<Block> = vec![ZERO_BLOCK; data.len()];
        for i in 0..nblocks / AES_BATCH_SIZE {
            let start = i * AES_BATCH_SIZE;
            let end = start + AES_BATCH_SIZE;
            let batch = &data[start..end];
            let encrypted_batch = aes_ecb_encrypt_blks(batch.to_vec(), AES_BATCH_SIZE, self.aes_key);
            out[start..end].copy_from_slice(&encrypted_batch);
        }
        let remain = nblocks % AES_BATCH_SIZE;
        if remain > 0 {
            let start = nblocks - remain;
            let end = nblocks;
            let batch = &data[start..end];
            let encrypted_batch = aes_ecb_encrypt_blks(batch.to_vec(), remain, self.aes_key);
            out[start..end].copy_from_slice(&encrypted_batch);
        }
        out
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
        let tt:Vec<Block> = vec![t; 1];
        let mut out = self.prp.permute_block( tt, 1);
        t ^ input
    }

    pub fn h_fixed<const N: usize>(&self, input: &[Block; N]) -> Vec<Block> {
        let mut tmp = vec![ZERO_BLOCK; N];
        for i in 0..N {
            tmp[i] = sigma(input[i]);
        }
        let mut out = self.prp.permute_block(tmp, N);
        xor_blocks_arr(&mut out, input, N)
    }

    pub fn hn(&self, input: &[Block], length: usize, scratch: Option<&mut [Block]>) -> Vec<Block> {
        let mut out = vec![0u128; length];
        let local_scratch = vec![ZERO_BLOCK; length];
        let mut scratch = local_scratch;

        for i in 0..length {
            scratch[i] = sigma(input[i]);
            out[i] = scratch[i];
        }

        let mut res = self.prp.permute_block(scratch, length);
        xor_blocks_arr(&mut res, &out, length)
    }
}

fn sigma(block: Block) -> Block {
    let xl = block >> 64;
    let xr = block << 64;
    let xlxl = xl ^ (xl << 64);
    xlxl ^ xr
}