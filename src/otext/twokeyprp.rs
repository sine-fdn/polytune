//! The two-key PRP

extern crate aes;
extern crate block_modes;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

type Block = u128;

/// AES key
#[derive(Clone)]
pub struct AesKey {
    rd_key: [Block; 11]
}

impl AesKey {
    // Initialize AES_KEY with a given user key
    // TODO check correct way to do this based on emp-tool/aes.h
    fn new(userkey: Block) -> AesKey {
        let cipher = Aes128::new((&userkey.to_le_bytes()).into());
        let mut rd_key = [0u128; 11];
        rd_key[0] = userkey;

        for i in 1..11 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&rd_key[i - 1].to_le_bytes());
            cipher.encrypt_block((&mut block).into());
            rd_key[i] = u128::from_le_bytes(block);
        }

        AesKey { rd_key }
    }
}

/// AES encryption function
fn aes_encrypt(block: &mut Block, key: &AesKey) {
    let cipher = Aes128::new((&key.rd_key[0].to_le_bytes()).into());
    let mut block_bytes = block.to_le_bytes();
    cipher.encrypt_block((&mut block_bytes).into());
    *block = u128::from_le_bytes(block_bytes);
}

/// Parallel encryption function without SIMD
fn para_enc(num_keys: usize, num_encs: usize, blocks: &mut [Block], keys: &[AesKey]) {
    for _ in 0..9 {
        for i in 0..num_keys {
            let key = keys[i].clone();
            for j in 0..num_encs {
                aes_encrypt(&mut blocks[i * num_encs + j], &key);
            }
        }
    }
    for i in 0..num_keys {
        let key = keys[i].clone();
        let key_9 = key.rd_key[9];
        let key_10 = key.rd_key[10];
        for j in 0..num_encs {
            let block = &mut blocks[i * num_encs + j];
            let mut block_bytes = block.to_le_bytes();
            let cipher = Aes128::new((&key_9.to_le_bytes()).into());
            cipher.encrypt_block((&mut block_bytes).into());
            *block = u128::from_le_bytes(block_bytes) ^ key_10;
        }
    }
}

/// Two-key PRP
pub struct TwoKeyPRP {
    aes_key: [AesKey; 2],
}

impl TwoKeyPRP {
    /// Create Two key PRP
    pub fn new(seed0: Block, seed1: Block) -> TwoKeyPRP {
        let aes_key = [AesKey::new(seed0), AesKey::new(seed1)];
        TwoKeyPRP { aes_key }
    }

    /// Expand node 1 to 2
    pub fn node_expand_1to2(&self, parent: Block) -> Vec<Block> {
        let mut tmp: [Block; 2] = [parent, parent];
        para_enc(2, 1, &mut tmp, &self.aes_key);
        let mut children = vec![parent, parent];
        children[0] ^= tmp[0];
        children[1] ^= tmp[1];
        children
    }

    /// 2 to 4
    pub fn node_expand_2to4(&self, parent: &[Block; 2]) -> Vec<Block> {
        let mut tmp = [parent[0], parent[1], parent[0], parent[1]];
        para_enc(2, 2, &mut tmp, &self.aes_key);
        let mut children = vec![parent[0], parent[0], parent[1], parent[1]];
        children[0] ^= tmp[0];
        children[1] ^= tmp[2];
        children[2] ^= tmp[1];
        children[3] ^= tmp[3];
        children
    }

    /// 4 to 8
    pub fn node_expand_4to8(&self, parent: &[Block; 4]) -> Vec<Block> {
        let mut tmp = [
            parent[0], parent[1], parent[2], parent[3], parent[0], parent[1], parent[2], parent[3],
        ];
        let mut children = vec![
            parent[0], parent[0], parent[1], parent[1], parent[2], parent[2], parent[3], parent[3],
        ];
        para_enc(2, 4, &mut tmp, &self.aes_key);
        children[0] ^= tmp[0];
        children[1] ^= tmp[4];
        children[2] ^= tmp[1];
        children[3] ^= tmp[5];
        children[4] ^= tmp[2];
        children[5] ^= tmp[6];
        children[6] ^= tmp[3];
        children[7] ^= tmp[7];
        children
    }
}