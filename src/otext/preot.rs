use super::block::{xor_blocks_arr, Block, ZERO_BLOCK};
use super::utils::CCRH;
use crate::channel::{Channel, MsgChannel};

pub struct OTPre {
    pre_data: Vec<Block>,
    bits: Vec<bool>,
    pub n: usize,
    ccrh: CCRH,
    length: usize,
    count: usize,
    delta: Block,
}

impl OTPre {
    pub fn new(length: usize, times: usize) -> Self {
        let n = length * times;
        OTPre {
            pre_data: vec![ZERO_BLOCK; 2 * n],
            bits: vec![false; n],
            n,
            ccrh: CCRH::new(0), // Initialize with zero key
            length,
            count: 0,
            delta: 0,
        }
    }

    pub fn send_pre(&mut self, data: Vec<Block>, in_delta: Block) {
        self.delta = in_delta;

        // Process with hn and update pre_data
        let hn_first_half = self.ccrh.hn(data, self.n, &mut self.pre_data[self.n..].to_vec());
        self.pre_data[..self.n].copy_from_slice(&hn_first_half);

        // Perform XOR with delta
        let delta_vec = vec![in_delta; self.n];
        let mut xor_result = vec![0u128; self.n];
        xor_result = xor_blocks_arr(hn_first_half, delta_vec, self.n);
        self.pre_data[self.n..2 * self.n].copy_from_slice(&xor_result);

        // Process the second half with hn
        let hn_second_half = self.ccrh.hn_null(self.pre_data[self.n..2 * self.n].to_vec(), self.n);
        self.pre_data[self.n..2 * self.n].copy_from_slice(&hn_second_half);
    }

    pub fn recv_pre(&mut self, data: Vec<Block>, b: Option<&[bool]>) {
        if let Some(b) = b {
            self.bits.copy_from_slice(b);
        } else {
            for (i, &block) in data.iter().enumerate() {
                self.bits[i] = block & 1 == 1;
            }
        }
        self.pre_data[..self.n].copy_from_slice(&self.ccrh.hn_null(data, self.n));
    }

    pub fn choices_sender(&mut self) {
        self.count += self.length;
    }

    pub fn choices_recver(&mut self, b: &mut [bool]) {
        b.copy_from_slice(&self.bits[self.count..self.count + self.length]);
        self.count += self.length;
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }

    pub fn send(&self, m0: Vec<Block>, m1: Vec<Block>, length: usize, channel2: &mut MsgChannel<impl Channel>, s: usize) {
        let mut pad = [0u128; 2];
        let mut k = s * length;
        let party = 1; //TODO party
        for i in 0..length {
            pad[0] = m0[i] ^ self.pre_data[k];
            pad[1] = m1[i] ^ self.pre_data[k + self.n];
            channel2.send_to(party, "spcot", &pad);
            k += 1;
        }
    }

    pub fn recv(&self, data: &mut [Block], b: &[bool], length: usize, channel2: &mut MsgChannel<impl Channel>, s: usize) {
        let mut k = s * length;
        let mut pad = [0u128; 2];
        let party = 1; //TODO party
        for i in 0..length {
            channel2.send_to(party, "spcot", &pad);
            let ind = if b[i] { 1 } else { 0 };
            data[i] = self.pre_data[k] ^ pad[ind];
            k += 1;
        }
    }
}