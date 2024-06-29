use rand::{thread_rng, Rng};

use crate::{
    channel::{Channel, MsgChannel},
    otext::{
        block::{make_block, Block, ZERO_BLOCK},
        constants::{ALICE, BOB, D},
        utils::{aes_ecb_encrypt_blks, PRP},
    },
};

pub struct LpnF2 {
    party: usize,
    n: usize,
    k: usize,
    mask: usize,
    seed: Block,
}

impl LpnF2 {
    pub fn new(party: usize, n: usize, k: usize) -> LpnF2 {
        let mut mask = 1;
        while mask < k {
            mask = (mask << 1) | 0x1;
        }

        LpnF2 {
            party,
            n,
            k,
            mask,
            seed: ZERO_BLOCK,
        }
    }

    fn __compute4(&self, nn: &mut Vec<Block>, kk: Vec<Block>, i: usize, prp: &PRP) {
        let mut tmp = vec![ZERO_BLOCK; D];
        for m in 0..D {
            tmp[m] = make_block(i as u64, m as u64);
        }
        let out = aes_ecb_encrypt_blks(tmp, D, prp.aes_key);
        for m in 0..4 {
            for j in 0..D {
                let mut index = (out[m * D + j] as usize) & (self.mask as usize);
                if index >= self.k as usize {
                    index -= self.k as usize;
                }
                nn[i as usize + m] ^= kk[index];
            }
        }
    }

    fn __compute1(&self, nn: &mut Vec<Block>, kk: Vec<Block>, i: usize, prp: &PRP) {
        let nr_blocks = D / 4 + if D % 4 != 0 { 1 } else { 0 };
        let mut tmp = vec![0; nr_blocks];
        for m in 0..nr_blocks {
            tmp[m] = make_block(i as u64, m as u64);
        }
        let r: Vec<u128> = prp.permute_block(tmp, nr_blocks);
        for j in 0..D {
            nn[i as usize] ^= kk[(r[j] % self.k as u128) as usize];
        }
    }

    fn task(&self, nn: &mut Vec<Block>, kk: Vec<Block>, start: usize, end: usize) {
        let prp = PRP::with_key(self.seed);
        let mut j = start;
        while j < end - 4 {
            self.__compute4(nn, kk.clone(), j, &prp);
            j += 4;
        }
        while j < end {
            self.__compute1(nn, kk.clone(), j, &prp);
            j += 1;
        }
    }

    pub async fn compute(
        &mut self,
        nn: &mut Vec<Block>,
        kk: Vec<Block>,
        channel: &mut MsgChannel<impl Channel>,
    ) {
        self.seed = self.seed_gen(channel).await;
        self.task(nn, kk, 0, self.n);
    }

    async fn seed_gen(&mut self, channel: &mut MsgChannel<impl Channel>) -> Block {
        let seed: Block;
        if self.party == ALICE {
            let mut prg = thread_rng();
            seed = prg.gen();
            channel.send_to(BOB, "seed_gen", &seed).await.unwrap();
        } else {
            seed = channel.recv_from(ALICE, "seed_gen").await.unwrap();
        }
        seed
    }

    pub fn _bench(&mut self, nn: &mut Vec<Block>, kk: Vec<Block>) {
        self.task(nn, kk, 0, nn.len());
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::Error, otext::block::Block, otext::constants::FERRET_B13, otext::lpn_f2::LpnF2,
    };

    use rand::Rng;

    #[tokio::test]
    async fn test_lpn_f2() -> Result<(), Error> {
        //let mut channels = SimpleChannel::channels(2);
        //let mut msgchannel1 = MsgChannel(channels.pop().unwrap());
        //let mut msgchannel2 = MsgChannel(channels.pop().unwrap());
        let mut lpnf2: LpnF2 = LpnF2::new(1, FERRET_B13.n, FERRET_B13.k);
        let mut prg = rand::thread_rng();
        let mut nn: Vec<Block> = vec![prg.gen(); 20];
        let kk: Vec<Block> = vec![prg.gen(); 20];
        lpnf2._bench(&mut nn, kk);
        Ok(())
    }
}
