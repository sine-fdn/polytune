use rand::Rng;

use super::block::{make_block, Block, ZERO_BLOCK, cmp_block, block_to_bool, get_lsb};
use super::constants::ALICE;

pub struct Iknp {
    malicious: bool,
}

impl Iknp {
    pub fn new(malicious: bool) -> Self {
        Self { malicious }
    }

    pub fn setup_send(&self, delta_bool: &[bool]) {
        // Implement setup_send logic
    }

    pub fn setup_recv(&self) {
        // Implement setup_recv logic
    }

    pub fn send_cot(&self, ot_data: &mut [Block], size: usize) {
        // Implement send_cot logic
    }

    pub fn recv_cot(&self, ot_data: &mut [Block], pre_bool_ini: &[bool], size: usize) {
        // Implement recv_cot logic
    }
}

pub struct BaseCot {
    party: i32,
    one: Block,
    minusone: Block,
    ot_delta: Block,
    iknp: Iknp,
    malicious: bool,
}

impl BaseCot {
    pub fn new(party: i32, malicious: bool) -> Self {
        let iknp = Iknp::new(malicious);
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

    pub fn cot_gen_pre(&mut self, deltain: Option<Block>) {
        if self.party == ALICE {
            self.ot_delta = deltain.unwrap_or_else(|| {
                let mut prg = rand::thread_rng();
                let delta: Block = prg.gen();
                delta & self.minusone ^ self.one
            });
            let mut delta_bool = [false; 128];
            block_to_bool(&mut delta_bool, self.ot_delta);
            self.iknp.setup_send(&delta_bool);
        } else {
            self.iknp.setup_recv();
        }
    }

    pub fn cot_gen(&mut self, ot_data: &mut [Block], size: usize) {
        if self.party == ALICE {
            self.iknp.send_cot(ot_data, size);
            for i in 0..size as usize {
                ot_data[i] &= self.minusone;
            }
        } else {
            let mut prg = rand::thread_rng();
            let pre_bool_ini = vec![prg.gen(); size as usize];
            self.iknp.recv_cot(ot_data, &pre_bool_ini, size);
            let ch = [ZERO_BLOCK, make_block(0, 1)];
            for i in 0..size as usize {
                ot_data[i] = (ot_data[i] & self.minusone) ^ ch[pre_bool_ini[i] as usize];
            }
        }
    }

    pub fn cot_gen_pre_ot(&mut self, size: usize) {
        let mut ot_data = vec![0; size];
        if self.party == ALICE {
            self.iknp.send_cot(&mut ot_data, size);
            for i in 0..size as usize {
                ot_data[i] &= self.minusone;
            }
            //pre_ot.send_pre(&ot_data, self.ot_delta);
        } else {
            let mut prg = rand::thread_rng();
            let pre_bool_ini = vec![prg.gen(); size];
            self.iknp.recv_cot(&mut ot_data, &pre_bool_ini, size);
            let ch = [ZERO_BLOCK, make_block(0, 1)];
            for i in 0..size as usize {
                ot_data[i] = (ot_data[i] & self.minusone) ^ ch[pre_bool_ini[i] as usize];
            }
            //pre_ot.recv_pre(&ot_data, &pre_bool_ini);
        }
    }

    pub fn check_cot(&self, data: &[Block], len: i64) -> bool {
        if self.party == ALICE {
            //self.io.send_block(&self.ot_delta, 1);
            //self.io.send_block(data, len as usize);
            true
        } else {
            let mut tmp = vec![0; len as usize];
            let ch = [ZERO_BLOCK, make_block(0, 1)];
            //self.io.recv_block(&mut ch[1..], 1);
            //self.io.recv_block(&mut tmp, len as usize);
            for i in 0..len as usize {
                tmp[i] ^= ch[get_lsb(data[i]) as usize];
            }
            cmp_block(&tmp, data, len as usize)
        }
    }
}