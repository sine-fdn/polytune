use rand::{
    Rng, SeedableRng,
    rngs::{StdRng, OsRng},
};

use crate::{
    channel::{Channel, MsgChannel},
    otext::{
        base_cot::BaseCot,
        block::{make_block, Block, ZERO_BLOCK},
        constants::{PrimalLPNParameter, ALICE, BOB},
        lpn_f2::LpnF2,
        mpcot::MpcotReg,
        preot::OTPre,
    }
};

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
    base_cot: BaseCot,
    pre_ot: Option<OTPre>,
    mpcot: Option<MpcotReg>,
    lpn_f2: Option<LpnF2>,
    ch: [Block; 2],
}

impl FerretCOT {
    pub async fn new(
        party: usize,
        is_malicious: bool,
        param: PrimalLPNParameter,
        channel: &mut MsgChannel<impl Channel>,
    ) -> Self {
        let base_cot = BaseCot::new(party, is_malicious);
        let one: u128 = make_block(0xFFFFFFFFFFFFFFFFu64, 0xFFFFFFFFFFFFFFFEu64);
        let mut cot = FerretCOT {
            party,
            m: 0,
            delta: ZERO_BLOCK,
            param,
            ot_used: 0,
            ot_limit: 0,
            is_malicious,
            extend_initialized: false,
            ot_pre_data: vec![],
            ot_data: vec![],
            base_cot,
            pre_ot: None,
            mpcot: None,
            lpn_f2: None,
            ch: [ZERO_BLOCK, ZERO_BLOCK],
        };

        if party == ALICE {
            let mut prg = StdRng::from_rng(OsRng).expect("Failed to create StdRng"); //TODO Change this!!!
            let mut delta: Block = prg.gen();
            delta &= one;
            delta ^= Block::from(1u128);
            cot.setup_delta(delta, channel).await;
        } else {
            cot.setup(channel).await;
        }

        cot
    }

    fn extend_initialization(&mut self) {
        // Initialize LpnF2
        self.lpn_f2 = Some(LpnF2::new(self.party, self.param.n, self.param.k));

        // Initialize MpcotReg
        self.mpcot = Some(MpcotReg::new(
            self.party,
            self.is_malicious,
            self.param.t,
            self.param.log_bin_sz,
        ));

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

    async fn extend(
        &mut self,
        ot_output: &mut Vec<Block>,
        mpcot: &mut MpcotReg,
        preot: &mut OTPre,
        lpn: &mut LpnF2,
        ot_input: &mut Vec<Block>,
        channel: &mut MsgChannel<impl Channel>,
    ) {
        if self.party == ALICE {
            mpcot.sender_init(self.delta);
        } else {
            mpcot.recver_init();
        }
        mpcot.mpcot(ot_output, preot, channel, ot_input).await;
        lpn.compute(
            ot_output,
            ot_input[mpcot.consist_check_cot_num..].to_vec(), //TODO CHECK
            channel,
        )
        .await;
    }

    async fn extend_f2k(&mut self, channel: &mut MsgChannel<impl Channel>) {
        let mut ot_data = std::mem::take(&mut self.ot_data);
        self.extend_f2k_base(&mut ot_data, channel).await;
        self.ot_data = ot_data;
    }

    async fn extend_f2k_base(
        &mut self,
        ot_buffer: &mut Vec<Block>,
        channel: &mut MsgChannel<impl Channel>,
    ) {
        let mut mpcot = self.mpcot.take().unwrap();
        let mut pre_ot = self.pre_ot.take().unwrap();
        let mut lpn_f2 = self.lpn_f2.take().unwrap();
        let mut ot_pre_data = self.ot_pre_data.clone();

        if self.party == ALICE {
            pre_ot.send_pre(ot_pre_data.clone(), self.delta);
        } else {
            pre_ot.recv_pre_data(ot_pre_data.clone()); //Clone should be fine here
        }

        self.extend(
            ot_buffer,
            &mut mpcot,
            &mut pre_ot,
            &mut lpn_f2,
            &mut ot_pre_data,
            channel,
        )
        .await;

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

    pub async fn setup_delta(&mut self, delta: Block, channel: &mut MsgChannel<impl Channel>) {
        self.delta = delta;
        self.setup(channel).await;
        self.ch[1] = delta;
    }

    pub async fn setup(&mut self, channel: &mut MsgChannel<impl Channel>) {
        self.extend_initialization();

        self.ot_pre_data = vec![ZERO_BLOCK; self.param.n_pre as usize];

        if self.party == BOB {
            self.base_cot.cot_gen_pre();
        } else {
            self.base_cot.cot_gen_pre_delta(self.delta);
        }

        let mut mpcot_ini = MpcotReg::new(
            self.party,
            self.is_malicious,
            self.param.t_pre,
            self.param.log_bin_sz_pre,
        );
        let mut pre_ot_ini = OTPre::new(mpcot_ini.tree_height - 1, mpcot_ini.tree_n);
        let mut lpn = LpnF2::new(self.party, self.param.n_pre, self.param.k_pre);

        let mut pre_data_ini =
            vec![ZERO_BLOCK; (self.param.k_pre + mpcot_ini.consist_check_cot_num) as usize];
        self.ot_pre_data = vec![ZERO_BLOCK; self.param.n_pre * 16]; //TODO CHECK WHY *16?

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
        )
        .await;

        // Move ot_pre_data back into self
        self.ot_pre_data = ot_pre_data;
    }

    pub async fn rcot(
        &mut self,
        data: &mut [Block],
        num: usize,
        channel: &mut MsgChannel<impl Channel>,
    ) {
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
        let mut data2 = data;
        let gened = self.silent_ot_left();
        if gened > 0 {
            data2[..gened as usize].copy_from_slice(
                &self.ot_data[self.ot_used as usize..(self.ot_used + gened) as usize],
            );
            data2 = &mut data2[gened as usize..]; //TODO CHECK pt+= gened ????
        }
        let round_inplace = (num - gened - self.ot_limit) / self.ot_limit;
        let mut last_round_ot = num - gened - round_inplace * self.ot_limit;
        let round_memcpy = last_round_ot > self.ot_limit;
        if round_memcpy {
            last_round_ot -= self.ot_limit;
        }
        for _ in 0..round_inplace {
            self.extend_f2k_base(&mut data2.to_vec(), channel).await;
            self.ot_used = self.ot_limit;
            data2 = &mut data2[self.ot_limit as usize..]; //TODO CHECK pt+=ot_limit ???
        }
        if round_memcpy {
            self.extend_f2k(channel).await;
            data2[..self.ot_limit as usize].copy_from_slice(&self.ot_data[..self.ot_limit as usize]);
            data2 = &mut data2[self.ot_limit as usize..];  //TODO CHECK pt+=ot_limit ???
        }
        if last_round_ot > 0 {
            self.extend_f2k(channel).await;
            data2[..last_round_ot as usize].copy_from_slice(&self.ot_data[..last_round_ot as usize]);
            self.ot_used = last_round_ot;
        }
    }

    fn silent_ot_left(&self) -> usize {
        self.ot_limit - self.ot_used
    }
}

#[cfg(test)]
mod tests {
    use crate::otext::constants::FERRET_B13;
    use crate::otext::ferret_cot::FerretCOT;

    use crate::channel::{MsgChannel, SimpleChannel};

    #[tokio::test]
    async fn test_ferret() {
        let party = 1; // Example party value
        let mut channels = SimpleChannel::channels(2);
        let mut msgchannel1 = MsgChannel(channels.pop().unwrap());
        FerretCOT::new(party, true, FERRET_B13, &mut msgchannel1).await;
    }
}
