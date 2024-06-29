//! SPCOT sender implementation
use crate::{
    channel::{Channel, MsgChannel},
    otext::{
        block::{make_block, Block, ZERO_BLOCK},
        constants::BOB,
        preot::OTPre,
        twokeyprp::TwoKeyPRP,
        utils::{hash_once, uni_hash_coeff_gen, vector_inn_prdt_sum_red},
    },
};

/// SPCOT Sender, removed PRG
pub struct SpcotSender {
    seed: Block,
    delta: Block,
    ggm_tree: Vec<Block>,
    m: Vec<Block>,
    depth: usize,
    leave_n: usize,
    secret_sum_f2: Block,
}

/// SPCOT Sender
impl SpcotSender {
    /// Create SPCOT Sender
    pub fn new(depth: usize) -> Self {
        let leave_n: usize = 1 << (depth - 1);
        let m = vec![ZERO_BLOCK; (depth - 1) * 2];

        SpcotSender {
            seed: ZERO_BLOCK,
            delta: ZERO_BLOCK,
            ggm_tree: Vec::new(),
            m,
            depth,
            leave_n,
            secret_sum_f2: ZERO_BLOCK,
        }
    }

    /// Compute
    // TODO check correctness
    pub fn compute(&mut self, ggm_tree_mem: &mut Vec<Block>, secret: Block) {
        self.delta = secret;
        //TODO check indeces here!
        //TODO check if m needs to change here or not!!! Probably yes?
        self.ggm_tree_gen(&mut self.m[0..self.depth-1].to_vec(), &mut self.m[self.depth-1..].to_vec(), ggm_tree_mem, secret);
    }

    //TODO BOB or ALICE?
    pub async fn send_f2k(&mut self, ot: OTPre, channel: &mut MsgChannel<impl Channel>, s: usize) {
        //TODO check here the second arguments's length
        ot.send(
            self.m[0..self.depth - 1].to_vec(),
            self.m[self.depth - 1..self.depth - 1 + self.depth - 1].to_vec(),
            self.depth - 1,
            channel,
            s,
        );
        channel.send_to(BOB, "secret_sum", &self.secret_sum_f2).await.unwrap();
    }

    /// Tree generation
    fn ggm_tree_gen(
        &mut self,
        ot_msg_0: &mut Vec<Block>,
        ot_msg_1: &mut Vec<Block>,
        ggm_tree_mem: &mut Vec<Block>,
        secret: Block,
    ) {
        self.ggm_tree = ggm_tree_mem.to_vec();
        let prp = TwoKeyPRP::new(ZERO_BLOCK, make_block(0, 1));

        self.ggm_tree = prp.node_expand_1to2(self.seed);
        ot_msg_0[0] = self.ggm_tree[0];
        ot_msg_1[0] = self.ggm_tree[1];

        let parent: &mut [Block; 2] = &mut [self.ggm_tree[0], self.ggm_tree[1]];
        self.ggm_tree = prp.node_expand_2to4(parent); //TODO check
        ot_msg_0[1] = self.ggm_tree[0] ^ self.ggm_tree[2];
        ot_msg_1[1] = self.ggm_tree[1] ^ self.ggm_tree[3];

        for h in 2..self.depth - 1 {
            ot_msg_0[h] = ZERO_BLOCK;
            ot_msg_1[h] = ZERO_BLOCK;
            let sz = 1 << h;

            for i in (0..sz - 4).rev().step_by(4) {
                let parent: &mut [Block; 4] = &mut [
                    self.ggm_tree[sz-4],
                    self.ggm_tree[sz-3],
                    self.ggm_tree[sz-2],
                    self.ggm_tree[sz-2],
                ];
                //TODO I think it is not self.ggm_tree
                self.ggm_tree = prp.node_expand_4to8(parent);
                ot_msg_0[h] ^= self.ggm_tree[i * 2];
                ot_msg_0[h] ^= self.ggm_tree[i * 2 + 2];
                ot_msg_0[h] ^= self.ggm_tree[i * 2 + 4];
                ot_msg_0[h] ^= self.ggm_tree[i * 2 + 6];
                ot_msg_1[h] ^= self.ggm_tree[i * 2 + 1];
                ot_msg_1[h] ^= self.ggm_tree[i * 2 + 3];
                ot_msg_1[h] ^= self.ggm_tree[i * 2 + 5];
                ot_msg_1[h] ^= self.ggm_tree[i * 2 + 7];
            }
        }

        let one = make_block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE);
        for i in 0..self.leave_n {
            self.ggm_tree[i] &= one;
            self.secret_sum_f2 ^= self.ggm_tree[i];
        }
        self.secret_sum_f2 ^= secret;
    }

    /// Consistency check for malicious security
    pub fn consistency_check_msg_gen(&mut self) -> Block {
        let mut chi = vec![ZERO_BLOCK; self.leave_n];
        let digest = hash_once(self.secret_sum_f2);
        uni_hash_coeff_gen(&mut chi, digest, self.leave_n);
        vector_inn_prdt_sum_red(chi, &mut self.ggm_tree, self.leave_n)
    }
}
