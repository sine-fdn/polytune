//! SPCOT receiver implementation
use crate::{
    channel::{Channel, MsgChannel},
    otext::{
        block::{make_block, Block, ZERO_BLOCK},
        constants::ALICE,
        preot::OTPre,
        twokeyprp::TwoKeyPRP,
        utils::{hash_once, uni_hash_coeff_gen, vector_inn_prdt_sum_red},
    },
};

/// SPCOT Receiver
pub struct SpcotRecver {
    ggm_tree: Vec<Block>,
    m: Vec<Block>,
    pub b: Vec<bool>,
    choice_pos: usize,
    depth: usize,
    leave_n: usize,
    secret_sum_f2: Block,
}

///SPCOT Receiver
impl SpcotRecver {
    pub fn new(depth: usize) -> Self {
        let leave_n = 1 << (depth - 1);
        let m = vec![ZERO_BLOCK; depth - 1];
        let b = vec![false; depth - 1];

        SpcotRecver {
            ggm_tree: Vec::new(),
            m,
            b,
            choice_pos: 0,
            depth,
            leave_n,
            secret_sum_f2: ZERO_BLOCK,
        }
    }

    ///Get index
    pub fn get_index(&mut self) -> usize {
        self.choice_pos = 0;
        for &bi in self.b.iter() {
            self.choice_pos <<= 1;
            if !bi {
                self.choice_pos += 1;
            }
        }
        self.choice_pos
    }

    // TODO ALICE or BOB?
    pub async fn recv_f2k(&mut self, ot: OTPre, channel: &mut MsgChannel<impl Channel>, s: usize) {
        ot.recv(&mut self.m, &mut self.b, self.depth - 1, channel, s).await;
        self.secret_sum_f2 = channel.recv_from(ALICE, "secret_sum").await.unwrap();
    }

    // Receive the message and reconstruct the tree
    pub fn compute(&mut self, ggm_tree_mem: Vec<Block>) {
        self.ggm_tree = ggm_tree_mem;
        self.ggm_tree_reconstruction();
        self.ggm_tree[self.choice_pos] = ZERO_BLOCK;

        let mut nodes_sum = ZERO_BLOCK;
        let one = make_block(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE);
        for i in 0..self.leave_n {
            self.ggm_tree[i] &= one;
            nodes_sum ^= self.ggm_tree[i];
        }
        self.ggm_tree[self.choice_pos] = nodes_sum ^ self.secret_sum_f2;
    }

    /// Tree reconstruct
    fn ggm_tree_reconstruction(&mut self) {
        let mut to_fill_idx = 0;
        let prp = TwoKeyPRP::new(ZERO_BLOCK, make_block(0, 1));
        for i in 1..self.depth {
            to_fill_idx *= 2;
            self.ggm_tree[to_fill_idx] = ZERO_BLOCK;
            self.ggm_tree[to_fill_idx + 1] = ZERO_BLOCK;
            if !self.b[i - 1] {
                self.layer_recover(i, 0, to_fill_idx, self.m[i - 1], &prp);
                to_fill_idx += 1;
            } else {
                self.layer_recover(i, 1, to_fill_idx + 1, self.m[i - 1], &prp);
            }
        }
    }

    ///Recover layer
    fn layer_recover(
        &mut self,
        depth: usize,
        lr: usize,
        to_fill_idx: usize,
        sum: Block,
        prp: &TwoKeyPRP,
    ) {
        let layer_start = 0;
        let item_n = 1 << depth;
        let mut nodes_sum = ZERO_BLOCK;
        let lr_start = if lr == 0 {
            layer_start
        } else {
            layer_start + 1
        };
        for i in (lr_start..item_n).step_by(2) {
            nodes_sum ^= self.ggm_tree[i];
        }
        self.ggm_tree[to_fill_idx] = nodes_sum ^ sum;
        if depth == self.depth - 1 {
            return;
        }
        if item_n == 2 {
            let parent: &mut [Block; 2] = &mut [self.ggm_tree[0], self.ggm_tree[1]];
            self.ggm_tree = prp.node_expand_2to4(parent);
        } else {
            for _ in (0..item_n - 4).rev().step_by(4) {
                let parent: &mut [Block; 4] = &mut [
                    self.ggm_tree[0],
                    self.ggm_tree[2],
                    self.ggm_tree[4],
                    self.ggm_tree[6],
                ];
                self.ggm_tree = prp.node_expand_4to8(parent);
            }
        }
    }

    //Check
    pub fn consistency_check_msg_gen(&mut self, chi_alpha: &mut Block) -> Block {
        let mut chi = vec![ZERO_BLOCK; self.leave_n];
        let digest = hash_once(self.secret_sum_f2);
        uni_hash_coeff_gen(&mut chi, digest, self.leave_n);
        *chi_alpha = chi[self.choice_pos];
        vector_inn_prdt_sum_red(chi, &mut self.ggm_tree, self.leave_n)
    }
}
