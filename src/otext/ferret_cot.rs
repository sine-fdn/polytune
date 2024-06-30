use rand::Rng;
use std::fs::File;
use std::path::Path;

use crate::channel::{MsgChannel, Channel};

use super::base_cot::BaseCot;
use super::block::{make_block, Block, ZERO_BLOCK};
use super::constants::{PrimalLPNParameter, ALICE, BOB};
use super::lpn_f2::LpnF2;
use super::mpcot::MpcotReg;
use super::preot::OTPre;

pub struct FerretCOT {
    party: usize,
    m: usize,
    delta: Block,
    param: PrimalLPNParameter,
    ot_used: usize,
    ot_limit: usize,
    is_malicious: bool,
    extend_initialized: bool,
    ot_pre_data: Vec<Block>,
    ot_data: Vec<Block>,
    pre_ot_filename: String,
    base_cot: BaseCot,
    pre_ot: Option<OTPre>,
    mpcot: Option<MpcotReg>,
    lpn_f2: Option<LpnF2>,
    ch: [Block; 2],
    one: Block,
}

impl FerretCOT {
    pub async fn new(
        party: usize,
        malicious: bool,
        run_setup: bool,
        param: PrimalLPNParameter,
        pre_file: String,
        channel: &mut MsgChannel<impl Channel>
    ) -> Self {
        let base_cot = BaseCot::new(party, malicious);
        let one = make_block(0xFFFFFFFFFFFFFFFFu64, 0xFFFFFFFFFFFFFFFEu64);
        let mut cot = FerretCOT {
            party,
            m: 0,
            delta: ZERO_BLOCK,
            param,
            ot_used: 0,
            ot_limit: 0,
            is_malicious: malicious,
            extend_initialized: false,
            ot_pre_data: vec![],
            ot_data: vec![],
            pre_ot_filename: pre_file.clone(),
            base_cot,
            pre_ot: None,
            mpcot: None,
            lpn_f2: None,
            ch: [ZERO_BLOCK, ZERO_BLOCK],
            one,
        };

        if run_setup {
            if party == ALICE {
                let mut prg = rand::thread_rng();
                let mut delta: Block = prg.gen();
                delta &= cot.one;
                delta ^= Block::from(1u128);
                cot.setup(delta, pre_file.clone(), channel).await;
            } else {
                cot.setup_internal(pre_file.clone(), channel).await;
            }
        }

        cot
    }

    fn extend_initialization(&mut self) {
        // Initialize LpnF2
        self.lpn_f2 = Some(LpnF2::new(self.party, self.param.n, self.param.k));

        // Initialize MpcotReg
        self.mpcot = Some(MpcotReg::new(
            self.party,
            self.param.n,
            self.param.t,
            self.param.log_bin_sz,
        ));

        if self.is_malicious {
            if let Some(mpcot) = &mut self.mpcot {
                mpcot.set_malicious();
            }
        }

        // Initialize OTPre
        if let Some(mpcot) = &self.mpcot {
            self.pre_ot = Some(OTPre::new(mpcot.tree_height - 1, mpcot.tree_n));
        }

        // Calculate M, ot_limit, and set ot_used and extend_initialized
        if let Some(pre_ot) = &self.pre_ot {
            if let Some(mpcot) = &self.mpcot {
                self.m = self.param.k + pre_ot.n + mpcot.consist_check_cot_num;
                self.ot_limit = self.param.n - self.m;
                self.ot_used = self.ot_limit;
                self.extend_initialized = true;
            }
        }
    }

    pub async fn setup(&mut self, delta: Block, pre_file: String, channel: &mut MsgChannel<impl Channel>) {
        self.delta = delta;
        self.setup_internal(pre_file, channel).await;
        self.ch[1] = delta;
    }

    pub async fn setup_internal(&mut self, pre_file: String, channel: &mut MsgChannel<impl Channel>) {
        if pre_file != "" {
            self.pre_ot_filename = pre_file;
        } else {
            self.pre_ot_filename = if self.party == ALICE {
                "pre_ot_data_reg_send_file".to_string()
            } else {
                "pre_ot_data_reg_recv_file".to_string()
            };
        }

        self.extend_initialization();

        self.ot_pre_data = vec![ZERO_BLOCK; self.param.n_pre as usize];
        let (hasfile, hasfile2) = if self.party == ALICE {
            (self.file_exists(&self.pre_ot_filename), false)
        } else {
            (false, self.file_exists(&self.pre_ot_filename))
        };

        if hasfile && hasfile2 {
            self.delta = self.read_pre_data128_from_file(&self.pre_ot_filename);
        } else {
            if self.party == BOB {
                self.base_cot.cot_gen_pre();
            } else {
                self.base_cot.cot_gen_pre_delta(self.delta);
            }

            let mut mpcot_ini = MpcotReg::new(
                self.party,
                self.param.n_pre,
                self.param.t_pre,
                self.param.log_bin_sz_pre,
            );
            if self.is_malicious {
                mpcot_ini.set_malicious();
            }
            let mut pre_ot_ini = OTPre::new(mpcot_ini.tree_height - 1, mpcot_ini.tree_n);
            let mut lpn = LpnF2::new(self.party, self.param.n_pre, self.param.k_pre);

            let mut pre_data_ini =
                vec![ZERO_BLOCK; (self.param.k_pre + mpcot_ini.consist_check_cot_num) as usize];
            let n = pre_ot_ini.n;
            self.base_cot.cot_gen_pre_ot(&mut pre_ot_ini, n);
            self.base_cot.cot_gen(
                &mut pre_data_ini,
                self.param.k_pre + mpcot_ini.consist_check_cot_num,
            );

            // Move ot_pre_data out of self
            let mut ot_pre_data = std::mem::take(&mut self.ot_pre_data);

            self.extend(
                &mut ot_pre_data,
                &mut mpcot_ini,
                &mut pre_ot_ini,
                &mut lpn,
                &mut pre_data_ini,
                channel,
            ).await;

            // Move ot_pre_data back into self
            self.ot_pre_data = ot_pre_data;
        }
    }

    async fn extend(
        &mut self,
        ot_output: &mut Vec<Block>,
        mpcot: &mut MpcotReg,
        preot: &mut OTPre,
        lpn: &mut LpnF2,
        ot_input: &mut Vec<Block>,
        channel: &mut MsgChannel<impl Channel>
    ) {
        if self.party == ALICE {
            mpcot.sender_init(self.delta);
        } else {
            mpcot.recver_init();
        }
        mpcot.mpcot(ot_output, preot, ot_input).await;
        lpn.compute(ot_output, ot_input[mpcot.consist_check_cot_num..].to_vec(), channel).await;
    }

    async fn extend_f2k(&mut self, channel: &mut MsgChannel<impl Channel>) {
        let mut ot_data = std::mem::take(&mut self.ot_data);
        self.extend_f2k_base(&mut ot_data, channel).await;
        self.ot_data = ot_data;
    }

    async fn extend_f2k_base(&mut self, ot_buffer: &mut Vec<Block>, channel: &mut MsgChannel<impl Channel>) {
        let mut mpcot = self.mpcot.take().unwrap();
        let mut pre_ot = self.pre_ot.take().unwrap();
        let mut lpn_f2 = self.lpn_f2.take().unwrap();
        let mut ot_pre_data = self.ot_pre_data.clone(); // or self.ot_pre_data.take().unwrap(), if it's an Option

        if self.party == ALICE {
            // TODO: Implement send_pre if needed
        } else {
            // TODO: Implement recv_pre if needed
        }

        self.extend(
            ot_buffer,
            &mut mpcot,
            &mut pre_ot,
            &mut lpn_f2,
            &mut ot_pre_data,
            channel
        ).await;

        let offset = self.ot_limit as usize;
        let len = self.m as usize;
        ot_pre_data.copy_from_slice(&ot_buffer[offset..offset + len]);

        // Restore modified fields back to self
        self.mpcot = Some(mpcot);
        self.pre_ot = Some(pre_ot);
        self.lpn_f2 = Some(lpn_f2);
        self.ot_pre_data = ot_pre_data;

        self.ot_used = 0;
    }

    pub async fn rcot(&mut self, data: &mut [Block], num: usize, channel: &mut MsgChannel<impl Channel>) {
        if self.ot_data.is_empty() {
            self.ot_data = vec![ZERO_BLOCK; self.param.n as usize];
        }
        if !self.extend_initialized {
            panic!("Run setup before extending");
        }
        if num <= self.silent_ot_left() {
            data[..num as usize].copy_from_slice(
                &self.ot_data[self.ot_used as usize..(self.ot_used + num) as usize],
            );
            self.ot_used += num;
            return;
        }
        let mut pt = data;
        let gened = self.silent_ot_left();
        if gened > 0 {
            pt[..gened as usize].copy_from_slice(
                &self.ot_data[self.ot_used as usize..(self.ot_used + gened) as usize],
            );
            pt = &mut pt[gened as usize..];
        }
        let round_inplace = (num - gened - self.ot_limit) / self.ot_limit;
        let mut last_round_ot = num - gened - round_inplace * self.ot_limit;
        let round_memcpy = last_round_ot > self.ot_limit;
        if round_memcpy {
            last_round_ot -= self.ot_limit;
        }
        for _ in 0..round_inplace {
            self.extend_f2k_base(&mut pt.to_vec(), channel).await;
            self.ot_used = self.ot_limit;
            pt = &mut pt[self.ot_limit as usize..];
        }
        if round_memcpy {
            self.extend_f2k(channel).await;
            pt[..self.ot_limit as usize].copy_from_slice(&self.ot_data[..self.ot_limit as usize]);
            pt = &mut pt[self.ot_limit as usize..];
        }
        if last_round_ot > 0 {
            self.extend_f2k(channel).await;
            pt[..last_round_ot as usize].copy_from_slice(&self.ot_data[..last_round_ot as usize]);
            self.ot_used = last_round_ot;
        }
    }

    fn silent_ot_left(&self) -> usize {
        self.ot_limit - self.ot_used
    }

    fn write_pre_data128_to_file(&self, loc: &[Block], delta: Block, filename: &str) {
        let mut file = File::create(filename).expect("Unable to create file");
        let mut buffer = vec![];
        buffer.extend_from_slice(&self.party.to_le_bytes());
        if self.party == ALICE {
            buffer.extend_from_slice(&delta.to_le_bytes());
        }
        buffer.extend_from_slice(&self.param.n.to_le_bytes());
        buffer.extend_from_slice(&self.param.t.to_le_bytes());
        buffer.extend_from_slice(&self.param.k.to_le_bytes());
        buffer.extend_from_slice(&self.param.n_pre.to_le_bytes());
        for block in loc {
            buffer.extend_from_slice(&block.to_le_bytes());
        }
        //file.write_all(&buffer).expect("Unable to write data");
    }

    fn read_pre_data128_from_file(&self, filename: &str) -> Block {
        let file = File::open(filename).expect("Unable to open file");
        let buffer = vec![];
        //file.read_to_end(&mut buffer).expect("Unable to read data");

        let mut party = 0;
        let mut delta = Block::default();
        let mut n = 0;
        let mut t = 0;
        let mut k = 0;
        let mut n_pre = 0;
        let mut index = 0;

        party = usize::from_le_bytes(buffer[index..index + 8].try_into().unwrap());
        index += 8;
        if party != self.party {
            panic!("wrong party");
        }

        if self.party == ALICE {
            delta = Block::from_le_bytes(buffer[index..index + 16].try_into().unwrap());
            index += 16;
        }

        n = usize::from_le_bytes(buffer[index..index + 8].try_into().unwrap());
        index += 8;
        t = usize::from_le_bytes(buffer[index..index + 8].try_into().unwrap());
        index += 8;
        k = usize::from_le_bytes(buffer[index..index + 8].try_into().unwrap());
        index += 8;
        n_pre = usize::from_le_bytes(buffer[index..index + 8].try_into().unwrap());
        index += 8;

        if n != self.param.n || t != self.param.t || k != self.param.k {
            panic!("LPN parameters don't match");
        }
        /*self.ot_pre_data = vec![ZERO_BLOCK; n_pre as usize];
        for i in 0..n_pre {
            self.ot_pre_data[i as usize] = Block::from_le_bytes(buffer[index..index + 16].try_into().unwrap());
            index += 16;
        }*/
 //TODO

        delta
    }

    fn file_exists(&self, filename: &str) -> bool {
        Path::new(filename).exists()
    }
}

#[cfg(test)]
mod tests {
    use crate::otext::constants::FERRET_B13;
    use crate::otext::ferret_cot::FerretCOT;

    use crate::channel::{SimpleChannel, MsgChannel};

    #[test]
    fn test_ferret() {
        let party = 1; // Example party value
        let mut channels = SimpleChannel::channels(2);
        let mut msgchannel1 = MsgChannel(channels.pop().unwrap());
        FerretCOT::new(party, true, true, FERRET_B13, "file.txt".to_string(), &mut msgchannel1);
    }
}
