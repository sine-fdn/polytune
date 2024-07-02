use crate::{
    channel::{Channel, MsgChannel},
    otext::{
        constants::{ALICE, BOB},
        block::{cmp_block, get_lsb, Block, ZERO_BLOCK},
        spcot_recver::SpcotRecver,
        spcot_sender::SpcotSender,
        preot::OTPre,
        utils::{hash_once, GaloisFieldPacking},
    }
};

pub struct MpcotReg {
    party: usize,
    item_n: usize,
    pub tree_height: usize,
    leave_n: usize,
    pub tree_n: usize,
    pub consist_check_cot_num: usize,
    is_malicious: bool,
    delta_f2k: Block,
    consist_check_chi_alpha: Vec<Block>,
    consist_check_vw: Vec<Block>,
    item_pos_recver: Vec<u32>,
    pack: GaloisFieldPacking,
}

impl MpcotReg {
    pub fn new(party: usize, is_malicious: bool, t: usize, log_bin_sz: usize) -> Self {
        MpcotReg {
            party,
            item_n: t,
            tree_height: (log_bin_sz + 1) as usize,
            leave_n: 1 << (log_bin_sz as usize),
            tree_n: t as usize,
            consist_check_cot_num: 128,
            is_malicious,
            delta_f2k: ZERO_BLOCK,
            consist_check_chi_alpha: Vec::new(),
            consist_check_vw: Vec::new(),
            item_pos_recver: Vec::new(),
            pack: GaloisFieldPacking::new(),
        }
    }

    pub fn sender_init(&mut self, delta: Block) {
        self.delta_f2k = delta;
    }

    pub fn recver_init(&mut self) {
        self.item_pos_recver.resize(self.item_n as usize, 0);
    }

    pub async fn mpcot(&mut self, sparse_vector: &mut Vec<Block>, ot: &mut OTPre, channel: &mut MsgChannel<impl Channel>, pre_cot_data: &mut Vec<Block>) {
        if self.party == BOB {
            self.consist_check_chi_alpha = vec![ZERO_BLOCK; self.item_n as usize];
        }
        self.consist_check_vw = vec![ZERO_BLOCK; self.item_n as usize];

        let mut senders: Vec<SpcotSender> = Vec::new();
        let mut recvers: Vec<SpcotRecver> = Vec::new();

        if self.party == ALICE { 
            self.mpcot_init_sender(&mut senders, ot).await;
            self.exec_parallel_sender(&mut senders, ot, channel, sparse_vector).await;
        } else {
            self.mpcot_init_recver(&mut recvers, ot).await;
            self.exec_parallel_recver(&mut recvers, ot, channel, sparse_vector).await;
        }

        if self.is_malicious {
            self.consistency_check_f2k(channel, pre_cot_data).await;
        }

        self.consist_check_chi_alpha = vec![];
        self.consist_check_vw = vec![];

    }

    async fn mpcot_init_sender(&mut self, senders: &mut Vec<SpcotSender>, ot: &mut OTPre) {
        for _ in 0..self.tree_n {
            let sender = SpcotSender::new(self.tree_height as usize);
            senders.push(sender);
            ot.choices_sender();
        }
        ot.reset();
    }    

    async fn mpcot_init_recver(&mut self, recvers: &mut Vec<SpcotRecver>, ot: &mut OTPre) {
        for _ in 0..self.tree_n {
            let mut recver = SpcotRecver::new(self.tree_height as usize);
            ot.choices_recver(&mut recver.b);
            self.item_pos_recver.push(recver.get_index() as u32);
            recvers.push(recver);
        }
        ot.reset();
    }

    async fn exec_parallel_sender(&mut self, senders: &mut Vec<SpcotSender>, ot: &mut OTPre, channel: &mut MsgChannel<impl Channel>, sparse_vector: &mut Vec<Block>) {
        for i in 0..self.tree_n {
            let start = i * self.leave_n;
            let end = start + self.leave_n; //TODO or is it +i here???
            self.exec_f2k_sender(&mut senders[i], ot, channel, &mut sparse_vector[start..end].to_vec(), i).await;
        }
    }

    async fn exec_parallel_recver(&mut self, recvers: &mut Vec<SpcotRecver>, ot: &mut OTPre, channel: &mut MsgChannel<impl Channel>, sparse_vector: &mut Vec<Block>) {
        for i in 0..self.tree_n {
            let start = i * self.leave_n;
            let end = start + self.leave_n; //TODO or is it +i here???
            self.exec_f2k_recver(&mut recvers[i], ot, channel, &mut sparse_vector[start..end].to_vec(), i).await;
        }
    }

    async fn exec_f2k_sender(&mut self, sender: &mut SpcotSender, ot: &mut OTPre, channel: &mut MsgChannel<impl Channel>, ggm_tree_mem: &mut Vec<Block>, i: usize) {
        sender.compute(ggm_tree_mem, self.delta_f2k);
        sender.send_f2k(ot, channel, i).await;
        if self.is_malicious {
            self.consist_check_vw[i] = sender.consistency_check_msg_gen();
        }
    }

    async fn exec_f2k_recver(&mut self, recver: &mut SpcotRecver, ot: &mut OTPre, channel: &mut MsgChannel<impl Channel>, ggm_tree_mem: &mut [Block], i: usize) {
        recver.recv_f2k(ot, channel, i).await;
        recver.compute(ggm_tree_mem.to_vec()); //TODO CHECK
        if self.is_malicious {
            self.consist_check_chi_alpha[i] = recver.consistency_check_msg_gen(&mut self.consist_check_vw[i]);
        }
    }

    async fn consistency_check_f2k(&self, channel: &mut MsgChannel<impl Channel>, pre_cot_data: &mut Vec<Block>) {
         if self.party == ALICE {
            let mut r1 = self.consist_check_vw.iter().fold(0, |acc, &x| acc ^ x);
            //self.consist_check_vw.iter().take(num as usize).for_each(|block| r1 ^= *block);
            let x_prime: Vec<bool> = channel.recv_from(BOB, "x_prime").await.unwrap();
            for (i, &x) in x_prime.iter().enumerate() {
                if x {
                    pre_cot_data[i] ^= self.delta_f2k;
                }
            }
            let r2 = self.pack.packing(pre_cot_data.to_vec()); //TODO CHECK
            r1 ^= r2;
            let dig = hash_once(r1);
            channel.send_to(BOB, "digest", &dig).await.unwrap();
        } else {
            let mut r1 = self.consist_check_vw.iter().fold(0, |acc, &x| acc ^ x);
            let r2 = self.consist_check_chi_alpha.iter().fold(0, |acc, &x| acc ^ x);
            let mut pos: [u64; 2] = [r2 as u64, (r2 >> 64) as u64];
            let mut pre_cot_bool: Vec<bool> = vec![false; 128];
            for i in 0..2 {
                for j in 0..64 {
                    pre_cot_bool[i * 64 + j] = ((pos[i] & 1) == 1) ^ get_lsb(pre_cot_data[i * 64 + j]);
                    pos[i] >>= 1;
                }
            }
            channel.send_to(ALICE, "x_prime", &pre_cot_bool).await.unwrap();
        
            let r3 = self.pack.packing(pre_cot_data.to_vec()); //TODO CHECK
            r1 ^= r3;

            let dig = hash_once(r1);
            let digest: Block = channel.recv_from(ALICE, "digest").await.unwrap();
            if cmp_block(vec![dig; 1], vec![digest; 1], 1) {
                panic!("SPCOT consistency check fails");
            }
        }
    }
}
