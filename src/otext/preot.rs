use crate::{
    channel::{Channel, MsgChannel},
    otext::{
        block::{xor_blocks_arr_single, Block, ZERO_BLOCK, get_lsb},
        utils::CCRH,
        constants::{ALICE, BOB},
    },
};

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
            ccrh: CCRH::new(0), // Initialize with zero key TODO check
            length,
            count: 0,
            delta: 0,
        }
    }

    //TODO CHECK
    pub fn send_pre(&mut self, data: Vec<Block>, in_delta: Block) {
        self.delta = in_delta;

        //self.pre_data = self.ccrh.hn(data, self.n, &mut self.pre_data[self.n..].to_vec());
        //let xor_result = xor_blocks_arr_single(data, self.delta, self.n);
        //self.pre_data[self.n..].copy_from_slice(&xor_result);

        // Process with hn and update pre_data
        let hn_first_half = self
            .ccrh
            .hn(data, self.n, &mut self.pre_data[self.n..].to_vec());
        self.pre_data[..self.n].copy_from_slice(&hn_first_half);

        // Perform XOR with delta
        let xor_result = xor_blocks_arr_single(hn_first_half, self.delta, self.n);
        self.pre_data[self.n..2 * self.n].copy_from_slice(&xor_result);

        // Process the second half with hn
        let hn_second_half = self
            .ccrh
            .hn_null(self.pre_data[self.n..2 * self.n].to_vec(), self.n);
        self.pre_data[self.n..2 * self.n].copy_from_slice(&hn_second_half);
    }

    pub fn recv_pre(&mut self, data: Vec<Block>, b: Vec<bool>) {
        self.bits[..self.n].copy_from_slice(&b[..self.n]);
        self.pre_data[..self.n].copy_from_slice(&self.ccrh.hn_null(data, self.n));
    }

    fn recv_pre_data(&mut self, data: Vec<Block>) {    
        for i in 0..self.n {
            self.bits[i] = get_lsb(data[i]);
        }
        self.pre_data[..self.n].copy_from_slice(&self.ccrh.hn_null(data, self.n));
    }

    pub fn choices_sender(&mut self) {
        self.count += self.length;
    }

    pub fn choices_recver(&mut self, b: &mut Vec<bool>) {
        b[..self.length].copy_from_slice(&self.bits[self.count..self.count+self.length]);
        self.count += self.length;
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }

    pub async fn send(
        &self,
        m0: Vec<Block>,
        m1: Vec<Block>,
        length: usize,
        channel: &mut MsgChannel<impl Channel>,
        s: usize,
    ) {
        let mut pad = [ZERO_BLOCK; 2];
        let mut k = s * length;
        let party = ALICE; //TODO party
        for i in 0..length {
            pad[0] = m0[i] ^ self.pre_data[k];
            pad[1] = m1[i] ^ self.pre_data[k + self.n];
            channel.send_to(party, "spcot", &pad).await.unwrap();
            k += 1;
        }
    }

    pub async fn recv(
        &self,
        data: &mut [Block],
        b: &[bool],
        length: usize,
        channel2: &mut MsgChannel<impl Channel>,
        s: usize,
    ) {
        let mut k = s * length;
        let party = BOB; //TODO party
        for i in 0..length {
            let pad: [Block; 2] = channel2.recv_from(party, "spcot").await.unwrap();
            let ind = if b[i] { 1 } else { 0 };
            data[i] = self.pre_data[k] ^ pad[ind];
            k += 1;
        }
    }
}
