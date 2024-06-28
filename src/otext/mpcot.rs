use super::block::{Block, ZERO_BLOCK};
use super::spcot_recver::SpcotRecver;
use super::spcot_sender::SpcotSender;
use super::preot::OTPre;
use super::utils::{hash_once, GaloisFieldPacking};

pub struct MpcotReg {
    party: usize,
    item_n: usize,
    idx_max: usize,
    m: i64,
    pub tree_height: usize,
    leave_n: i64,
    pub tree_n: usize,
    pub consist_check_cot_num: usize,
    is_malicious: bool,
    delta_f2k: Block,
    consist_check_chi_alpha: Option<Vec<Block>>,
    consist_check_vw: Option<Vec<Block>>,
    item_pos_recver: Vec<u32>,
    pack: GaloisFieldPacking,
}

impl MpcotReg {
    pub fn new(party: usize, n: usize, t: usize, log_bin_sz: usize) -> Self {
        MpcotReg {
            party,
            item_n: t,
            idx_max: n,
            m: 0, //TODO Check
            tree_height: (log_bin_sz + 1) as usize,
            leave_n: 1 << (log_bin_sz as usize),
            tree_n: t as usize,
            consist_check_cot_num: 128,
            is_malicious: false,
            delta_f2k: ZERO_BLOCK,
            consist_check_chi_alpha: None,
            consist_check_vw: None,
            item_pos_recver: Vec::new(),
            pack: GaloisFieldPacking::new(),
        }
    }

    pub fn set_malicious(&mut self) {
        self.is_malicious = true;
    }

    pub fn sender_init(&mut self, delta: Block) {
        self.delta_f2k = delta;
    }

    pub fn recver_init(&mut self) {
        self.item_pos_recver.resize(self.item_n as usize, 0);
    }

    pub async fn mpcot(&mut self, sparse_vector: &mut [Block], ot: &mut OTPre, pre_cot_data: &mut [Block]) {
        if self.party == 2 { // BOB
            self.consist_check_chi_alpha = Some(vec![ZERO_BLOCK; self.item_n as usize]);
        }
        self.consist_check_vw = Some(vec![ZERO_BLOCK; self.item_n as usize]);

        let mut senders: Vec<SpcotSender> = Vec::new();
        let mut recvers: Vec<SpcotRecver> = Vec::new();

        if self.party == 1 { // ALICE
            self.mpcot_init_sender(&mut senders, ot).await;
            self.exec_parallel_sender(&mut senders, ot, sparse_vector).await;
        } else {
            self.mpcot_init_recver(&mut recvers, ot).await;
            self.exec_parallel_recver(&mut recvers, ot, sparse_vector).await;
        }

        if self.is_malicious {
            self.consistency_check_f2k(pre_cot_data, self.tree_n).await;
        }

        if let Some(ref mut consist_check_chi_alpha) = self.consist_check_chi_alpha {
            drop(consist_check_chi_alpha);
        }
        if let Some(ref mut consist_check_vw) = self.consist_check_vw {
            drop(consist_check_vw);
        }
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

    async fn exec_parallel_sender(&mut self, senders: &mut [SpcotSender], ot: &mut OTPre, sparse_vector: &mut [Block]) {
        let sender_slice = senders;
        let sparse_vector_slice = sparse_vector;
    
        for (i, sender) in sender_slice.iter_mut().enumerate() {
            self.exec_f2k_sender(sender, ot, &mut sparse_vector_slice[i * self.leave_n as usize..], i).await;
        }
    }

    //Only one thread
    async fn exec_parallel_recver(&mut self, recvers: &mut [SpcotRecver], ot: &mut OTPre, sparse_vector: &mut [Block]) {
        let recver_slice = recvers;
        let sparse_vector_slice = sparse_vector;
    
        for (i, recver) in recver_slice.iter_mut().enumerate() {
            self.exec_f2k_recver(recver, ot, &mut sparse_vector_slice[i * self.leave_n as usize..], i).await;
        }
    }

    async fn exec_f2k_sender(&mut self, sender: &mut SpcotSender, ot: &mut OTPre, ggm_tree_mem: &mut [Block], i: usize) {
        sender.compute(ggm_tree_mem, self.delta_f2k);
        //sender.send_f2k(ot, io, i).await;
        if self.is_malicious {
            self.consist_check_vw.as_mut().unwrap()[i] = sender.consistency_check_msg_gen();
        }
    }

    async fn exec_f2k_recver(&mut self, recver: &mut SpcotRecver, ot: &mut OTPre, ggm_tree_mem: &mut [Block], i: usize) {
        //recver.recv_f2k(ot, io, i).await;
        recver.compute(ggm_tree_mem.to_vec());
        if self.is_malicious {
            self.consist_check_chi_alpha.as_mut().unwrap()[i] = recver.consistency_check_msg_gen(&mut self.consist_check_vw.as_mut().unwrap()[i]);
        }
    }

    async fn consistency_check_f2k(&self, pre_cot_data: &mut [Block], num: usize) {
         if self.party == 1 { // ALICE
            let mut r1 = ZERO_BLOCK;
            let mut r2 = ZERO_BLOCK;
            self.consist_check_vw.as_ref().unwrap().iter().take(num as usize).for_each(|block| r1 ^= *block);
            let x_prime = vec![false; 128];
            //self.netio.recv(&mut x_prime).await;
            for (i, &x) in x_prime.iter().enumerate() {
                if x {
                    pre_cot_data[i] ^= self.delta_f2k;
                }
            }
            self.pack.packing(&mut r2, pre_cot_data);
            r1 ^= r2;
            let mut dig = [ZERO_BLOCK; 2];
            hash_once(&mut dig, &r1);
            //self.netio.send(&dig).await;
        } else { // BOB
            let mut chi_alpha = ZERO_BLOCK;
            let mut v = ZERO_BLOCK;
            self.consist_check_chi_alpha.as_ref().unwrap().iter().take(num as usize).for_each(|block| chi_alpha ^= *block);
            self.consist_check_vw.as_ref().unwrap().iter().take(num as usize).for_each(|block| v ^= *block);
            //self.netio.send_bool_vec(&self.x_prime).await;
            let dig = [ZERO_BLOCK; 2];
            //self.netio.recv(&mut dig).await;
            let mut digest = [ZERO_BLOCK; 2];
            hash_once(&mut digest, &(chi_alpha ^ v));
            if digest != dig {
                panic!("Consistency check failed");
            }
        }
    }
}
