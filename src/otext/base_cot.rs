use rand::Rng;

use crate::{
    channel::{MsgChannel, Channel},
    otext::{
        block::{make_block, Block, ZERO_BLOCK, cmp_block, get_lsb},
        constants::{ALICE, BOB},
        preot::OTPre,
        iknp::Iknp,
    }
};

pub struct BaseCot {
    party: usize,
    one: Block,
    minusone: Block,
    ot_delta: Block,
    iknp: Iknp,
    malicious: bool,
}

impl BaseCot {
    pub fn new(party: usize, malicious: bool) -> Self {
        let iknp = Iknp::new(ZERO_BLOCK, malicious); //TODO Set this delta right later???
        let minusone = make_block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE);
        let one = make_block(0, 1);
        Self {
            party,
            one,
            minusone,
            ot_delta: 0,
            iknp,
            malicious,
        }
    }

    pub fn cot_gen_pre_delta(&mut self, deltain: Block) {
        if self.party == ALICE {
            self.ot_delta = deltain;
            //let delta_bool = block_to_bool(self.ot_delta);
            //self.iknp.setup_send(&delta_bool);
        } else {
            //self.iknp.setup_recv();
        }
    }
    
    pub fn cot_gen_pre(&mut self) {
        if self.party == ALICE {
            let mut prg = rand::thread_rng();
            let delta: Block = prg.gen();
            self.ot_delta = delta & self.minusone ^ self.one;
            //let delta_bool = block_to_bool(self.ot_delta);
            //self.iknp.setup_send(&delta_bool); //TODO If the implementation we take for IKNP includes the setup, this is not needed
        } else {
            //self.iknp.setup_recv();
        }
    }

    pub fn cot_gen(&mut self, ot_data: &mut Vec<Block>, size: usize) {
        if self.party == ALICE {
            self.iknp.send_cot(ot_data, size);
            for i in 0..size as usize {
                ot_data[i] &= self.minusone;
            }
        } else {
            let mut prg = rand::thread_rng();
            let pre_bool_ini = vec![prg.gen(); size as usize];
            self.iknp.recv_cot(ot_data, pre_bool_ini.clone(), size); //TODO Check: Is it ok to clone?
            let ch = [ZERO_BLOCK, make_block(0, 1)];
            for i in 0..size as usize {
                ot_data[i] = (ot_data[i] & self.minusone) ^ ch[pre_bool_ini[i] as usize];
            }
        }
    }

    pub fn cot_gen_pre_ot(&mut self, pre_ot: &mut OTPre, size: usize) {
        let mut ot_data = vec![0; size];
        if self.party == ALICE {
            self.iknp.send_cot(&mut ot_data, size);
            for i in 0..size as usize {
                ot_data[i] &= self.minusone;
            }
            pre_ot.send_pre(ot_data, self.ot_delta);
        } else {
            let mut prg = rand::thread_rng();
            let pre_bool_ini = vec![prg.gen(); size];
            self.iknp.recv_cot(&mut ot_data, pre_bool_ini.clone(), size); //TODO Check: Is it ok to clone?
            let ch = [ZERO_BLOCK, make_block(0, 1)];
            for i in 0..size as usize {
                ot_data[i] = (ot_data[i] & self.minusone) ^ ch[pre_bool_ini[i] as usize];
            }
            pre_ot.recv_pre(ot_data, pre_bool_ini);
        }
    }

    pub async fn check_cot(&self, data: Vec<Block>, len: i64, channel: &mut MsgChannel<impl Channel>) -> bool {
        if self.party == ALICE {
            channel.send_to(BOB, "ot_delta", &self.ot_delta).await.unwrap();
            channel.send_to(BOB, "data", &data).await.unwrap();
            true
        } else {
            let mut ch: [Block; 2]  = [ZERO_BLOCK, ZERO_BLOCK];
            ch[1] = channel.recv_from(ALICE, "ot_delta").await.unwrap();
            let mut tmp: Vec<Block> = channel.recv_from(ALICE, "data").await.unwrap();
            for i in 0..len as usize {
                tmp[i] ^= ch[get_lsb(data[i]) as usize];
            }
            cmp_block(tmp, data, len as usize)
        }
    }
}