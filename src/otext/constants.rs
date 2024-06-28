pub const ALICE: usize = 0;
pub const BOB: usize = 1;

//pub static PRE_OT_DATA_REG_SEND_FILE: &str = "./data/pre_ot_data_reg_send";
//pub static PRE_OT_DATA_REG_RECV_FILE: &str = "./data/pre_ot_data_reg_recv";

pub struct PrimalLPNParameter {
    pub n: usize,
    pub t: usize,
    pub k: usize,
    pub log_bin_sz: usize,
    pub n_pre: usize,
    pub t_pre: usize,
    pub k_pre: usize,
    pub log_bin_sz_pre: usize,
}

pub const AES_BATCH_SIZE: usize = 8;

pub const D: usize = 10;

//emp-ot implements a check on these parameters, but we take them as they are
pub const FERRET_B13: PrimalLPNParameter = PrimalLPNParameter {
    n: 10485760,
    t: 1280,
    k: 452000,
    log_bin_sz: 13,
    n_pre: 470016,
    t_pre: 918,
    k_pre: 32768,
    log_bin_sz_pre: 9,
};

pub const FERRET_B12: PrimalLPNParameter = PrimalLPNParameter {
    n: 10268672,
    t: 2507,
    k: 238000,
    log_bin_sz: 12,
    n_pre: 268800,
    t_pre: 1050,
    k_pre: 17384,
    log_bin_sz_pre: 8,
};

pub const FERRET_B11: PrimalLPNParameter = PrimalLPNParameter {
    n: 10180608,
    t: 4971,
    k: 124000,
    log_bin_sz: 11,
    n_pre: 178944,
    t_pre: 699,
    k_pre: 17384,
    log_bin_sz_pre: 8,
};
