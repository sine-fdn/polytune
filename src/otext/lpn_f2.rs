use rand::{thread_rng, Rng};

use super::utils::PRP;
use super::block::{Block, make_block};
use super::constants::ALICE;

pub struct LpnF2 {
    party: i32,
    n: usize,
    k: usize,
    mask: usize,
    seed: Block,
}

impl LpnF2 {
    pub fn new(party: i32, n: usize, k: usize) -> LpnF2 {
        let mut mask = 1;
        while mask < k {
            mask = (mask << 1) | 0x1;
        }

        LpnF2 {
            party,
            n,
            k,
            mask,
            seed: 0,
        }
    }

    fn __compute4(&self, nn: &mut [Block], kk: &[Block], i: usize, prp: &PRP) {
        let mut tmp = vec![0; 10];
        for m in 0..10 {
            tmp[m] = make_block(i as u64, m as u64);
        }
        prp.permute_block(&mut tmp, 10);
        let r: Vec<u32> = tmp.iter().flat_map(|&block| {
            block.to_le_bytes().chunks(4).map(|chunk| {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            }).collect::<Vec<_>>()  // Specify the type for the inner collect
        }).collect();
        for m in 0..4 {
            for j in 0..10 {
                let mut index = (r[m * 10 + j] as usize) & (self.mask as usize);
                if index >= self.k as usize {
                    index -= self.k as usize;
                }
                nn[i as usize + m] ^= kk[index];
            }
        }
    }

    fn __compute1(&self, nn: &mut [Block], kk: &[Block], i: usize, prp: &PRP) {
        let nr_blocks = 10 / 4 + if 10 % 4 != 0 { 1 } else { 0 };
        let mut tmp = vec![0; nr_blocks];
        for m in 0..nr_blocks {
            tmp[m] = make_block(i as u64, m as u64);
        }
        prp.permute_block(&mut tmp, nr_blocks);
        let r: Vec<u32> = tmp
        .iter()
        .flat_map(|&block| {
            block.to_le_bytes().chunks(4).map(|chunk| {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            }).collect::<Vec<_>>()  // Specify the type for the inner collect
        })
        .collect();
        for j in 0..10 {
            nn[i as usize] ^= kk[(r[j] % self.k as u32) as usize];
        }
    }

    fn task(&self, nn: &mut [Block], kk: &[Block], start: usize, end: usize) {
        let prp = PRP::with_key(self.seed);
        let mut j = start;
        while j < end - 4 {
            self.__compute4(nn, kk, j, &prp);
            j += 4;
        }
        while j < end {
            self.__compute1(nn, kk, j, &prp);
            j += 1;
        }
    }

    pub fn compute(&mut self, nn: &mut [Block], kk: &[Block]) {
        self.seed = self.seed_gen();
        self.task(nn, kk, 0, self.n);
    }

    fn seed_gen(&mut self) -> Block {
        let mut seed = 0;
        if self.party == ALICE {
            let mut prg = thread_rng();
            seed = prg.gen();
            //self.io.send_data(&seed.to_le_bytes());
        } else {
            let mut buf = [0u8; 16];
            //self.io.recv_data(&mut buf);
            seed = u128::from_le_bytes(buf);
        }
        seed
    }

    pub fn bench(&self, nn: &mut [Block], kk: &[Block]) {
        self.task(nn, kk, 0, self.n);
    }
}