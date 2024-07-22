use crate::channel::{Channel, MsgChannel};
use crate::otext::baseot::OTCO;
use crate::otext::block::{bool_to_block, Block, ZERO_BLOCK};
use rand::prelude::*;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};

use super::block::random_block;

const BLOCK_SIZE: usize = 1024 * 2;

pub struct Iknp {
    pub ot_delta: Block,
    base_ot: OTCO,
    setup: bool,
    local_out: [Block; BLOCK_SIZE],
    s: [bool; 128],
    local_r: [bool; 256],
    prg: OsRng,
    g0: [OsRng; 128],
    g1: [OsRng; 128],
    malicious: bool,
    k0: [Block; 128],
    k1: [Block; 128],
}

impl Iknp {
    pub fn new(delta: Block, malicious: bool) -> Self {
        Iknp {
            ot_delta: delta,
            base_ot: OTCO {},
            setup: false,
            local_out: [ZERO_BLOCK; BLOCK_SIZE],
            s: [false; 128],
            local_r: [false; 256],
            prg: OsRng,
            g0: [OsRng; 128],
            g1: [OsRng; 128],
            malicious,
            k0: [ZERO_BLOCK; 128],
            k1: [ZERO_BLOCK; 128],
        }
    }

    async fn setup_send_delta(&mut self, channel: &mut MsgChannel<impl Channel>, in_s: [bool; 128]) {
        self.setup = true;

        self.s.copy_from_slice(&in_s);

        self.base_ot
            .recv(channel, &mut self.k0.to_vec(), self.s.to_vec(), 128).await;

        //for i in 0..128 {
        //self.g0[i].reseed(&self.k0[i]);
        //TODO figure out reseeding here!
        //}
        self.ot_delta = bool_to_block(&self.s);
    }

    async fn setup_send(&mut self, channel: &mut MsgChannel<impl Channel>) {
        self.setup = true;
        for i in 0..128 {
            self.s[i] = self.prg.next_u32() % 2 == 1;
        }

        self.base_ot
            .recv(channel, &mut self.k0.to_vec(), self.s.to_vec(), 128).await;

        //for i in 0..128 {
        //self.g0[i].reseed(&self.k0[i]);
        //TODO figure out reseeding here!
        //}
        self.ot_delta = bool_to_block(&self.s);
    }

    async fn setup_recv(&mut self, channel: &mut MsgChannel<impl Channel>) {
        self.setup = true;

        for i in 0..128 {
            self.k0[i] = random_block(&mut self.prg);
            self.k1[i] = random_block(&mut self.prg);
        }        
        self.base_ot.send(channel, &mut self.k0.to_vec(),  &self.k1.to_vec(), 128).await;

        /*for i in 0..128 {
            self.g0[i].reseed(&self.k0[i]); // Assuming PRG has a reseed method
            self.g1[i].reseed(&self.k1[i]); // Assuming PRG has a reseed method
        }*/
    }

    pub fn recv_pre(&self, data: &mut Vec<Block>, b: Vec<bool>, length: usize) {
        // implement ALSZ OT
    }

    pub fn send_pre(&self, out: &mut Vec<Block>, length: usize) {
        // implement ALSZ OT
    }

    pub fn send_check(&self, out: &mut Vec<Block>, length: usize) -> bool {
        //implement KOS check
        true
    }

    pub fn recv_check(&self, out: &mut Vec<Block>, r: Vec<bool>, length: usize) {
        // implement KOS check
    }

    pub fn send_cot(&self, data: &mut Vec<Block>, length: usize) {
        self.send_pre(data, length);

        if self.malicious {
            if !self.send_check(data, length) {
                panic!("OT Extension check failed");
            }
        }
    }

    pub fn recv_cot(&self, data: &mut Vec<Block>, b: Vec<bool>, length: usize) {
        self.recv_pre(data, b.clone(), length);

        if self.malicious {
            self.recv_check(data, b, length);
        }
    }
}
