//! Implementation of the Keller-Orsini-Scholl oblivious transfer extension
//! protocol (cf. <https://eprint.iacr.org/2015/546>).

use crate::{
    channel::{recv_from, recv_vec_from, send_to, Channel},
    faand::Error,
    swankyot::{
        alsz::{Receiver as AlszReceiver, Sender as AlszSender},
        cointoss, utils, CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer,
        Receiver as OtReceiver, Sender as OtSender,
    },
};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{AesRng, Block, Malicious, SemiHonest};

// The statistical security parameter.
const SSP: usize = 40;

/// Oblivious transfer extension sender.
pub struct Sender<OT: OtReceiver<Msg = Block> + Malicious> {
    pub(super) ot: AlszSender<OT>,
}

/// Oblivious transfer extension receiver.
pub struct Receiver<OT: OtSender<Msg = Block> + Malicious> {
    ot: AlszReceiver<OT>,
}

impl<OT: OtReceiver<Msg = Block> + Malicious> Sender<OT> {
    pub(super) async fn send_setup<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        m: usize,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<u8>, Error> {
        let m = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let ncols = m + 128 + SSP;
        let qs = self.ot.send_setup(channel, ncols, p_to).await?;
        // Check correlation
        let mut seed = Block::default();
        rng.fill_bytes(seed.as_mut());
        let seed = cointoss::send(channel, &[seed], p_to).await?;
        let mut rng = AesRng::from_seed(seed[0]);
        let mut check = (Block::default(), Block::default());
        let mut chi = Block::default();
        for j in 0..ncols {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            rng.fill_bytes(chi.as_mut());
            let [lo, hi] = q.carryless_mul_wide(chi);
            check = utils::xor_two_blocks(&check, &(lo, hi));
        }
        let (x, t0, t1) = recv_from::<(Block, Block, Block)>(channel, p_to, "KOS_OT_x_t0_t1")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        let [lo, hi] = x.carryless_mul_wide(self.ot.s_);
        let check = utils::xor_two_blocks(&check, &(lo, hi));
        if check != (t0, t1) {
            return Err(Error::ConsistencyCheckFailed);
        }
        Ok(qs)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> FixedKeyInitializer for Sender<OT> {
    async fn init_fixed_key<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let ot = AlszSender::<OT>::init_fixed_key(channel, s_, rng, p_to).await?;
        Ok(Self { ot })
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> OtSender for Sender<OT> {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let ot = AlszSender::<OT>::init(channel, rng, p_to).await?;
        Ok(Self { ot })
    }

    async fn send<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m, rng, p_to).await?;
        // Output result
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = self.ot.hash.tccr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ self.ot.s_;
            let y1 = self.ot.hash.tccr_hash(Block::from(j as u128), q) ^ input.1;
            send_to(channel, p_to, "KOS_OT_send", &[(y0, y1)]).await?;
        }
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> CorrelatedSender for Sender<OT> {
    async fn send_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(channel, m, rng, p_to).await?;
        let mut out = Vec::with_capacity(m);
        let mut ys: Vec<Block> = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = self.ot.hash.tccr_hash(Block::from(j as u128), q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.ot.s_;
            let y = self.ot.hash.tccr_hash(Block::from(j as u128), q) ^ x1;
            ys.push(y);
            out.push((x0, x1));
        }
        send_to(channel, p_to, "KOS_OT_corr", &ys).await?;
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> Receiver<OT> {
    pub(super) async fn recv_setup<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<u8>, Error> {
        let m = inputs.len();
        let m = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let m_ = m + 128 + SSP;
        let mut r = utils::boolvec_to_u8vec(inputs);
        r.extend((0..(m_ - m) / 8).map(|_| rand::random::<u8>()));
        let ts = self.ot.recv_setup(channel, &r, m_, p_to).await?;
        // Check correlation
        let mut seed = Block::default();
        rng.fill_bytes(seed.as_mut());
        let seed = cointoss::recv(channel, &[seed], p_to).await?;
        let mut rng = AesRng::from_seed(seed[0]);
        let mut x = Block::default();
        let mut t = (Block::default(), Block::default());
        let r_ = utils::u8vec_to_boolvec(&r);
        let mut chi = Block::default();
        for (j, xj) in r_.into_iter().enumerate() {
            let tj = &ts[j * 16..(j + 1) * 16];
            let tj: [u8; 16] = tj.try_into().unwrap();
            let tj = Block::from(tj);
            rng.fill_bytes(chi.as_mut());
            x ^= if xj { chi } else { Block::default() };
            let [lo, hi] = tj.carryless_mul_wide(chi);
            t = utils::xor_two_blocks(&t, &(lo, hi));
        }
        send_to(channel, p_to, "KOS_OT_x_t0_t1", &[(x, t.0, t.1)]).await?;
        Ok(ts)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> OtReceiver for Receiver<OT> {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let ot = AlszReceiver::<OT>::init(channel, rng, p_to).await?;
        Ok(Self { ot })
    }

    async fn recv<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Block>, Error> {
        let ts = self.recv_setup(channel, inputs, rng, p_to).await?;
        // Output result
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let (y0, y1) = recv_from::<(Block, Block)>(channel, p_to, "KOS_OT_send")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self
                .ot
                .hash
                .tccr_hash(Block::from(j as u128), Block::from(t));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + Malicious> CorrelatedReceiver for Receiver<OT> {
    async fn recv_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Self::Msg>, Error> {
        let ts = self.recv_setup(channel, inputs, rng, p_to).await?;
        let mut out = Vec::with_capacity(inputs.len());
        let ys: Vec<Block> = recv_vec_from(channel, p_to, "KOS_OT_corr", inputs.len()).await?;
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = ys[j];
            let y = if *b { y } else { Block::default() };
            let h = self
                .ot
                .hash
                .tccr_hash(Block::from(j as u128), Block::from(t));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + Malicious> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + Malicious> SemiHonest for Receiver<OT> {}
impl<OT: OtReceiver<Msg = Block> + Malicious> Malicious for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + Malicious> Malicious for Receiver<OT> {}
