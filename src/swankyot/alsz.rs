//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).

#![allow(non_upper_case_globals)]

use crate::{
    channel::{recv_from, send_to, Channel},
    faand::Error,
    swankyot::{
        utils, CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, Receiver as OtReceiver,
        Sender as OtSender,
    },
};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{utils as scutils, AesHash, AesRng, Block, SemiHonest, AES_HASH};
use std::marker::PhantomData;

/// Oblivious transfer sender.
pub struct Sender<OT: OtReceiver<Msg = Block> + SemiHonest> {
    _ot: PhantomData<OT>,
    pub(super) hash: AesHash,
    s: Vec<bool>,
    pub(super) s_: Block,
    rngs: Vec<AesRng>,
}
/// Oblivious transfer receiver.
pub struct Receiver<OT: OtSender<Msg = Block> + SemiHonest> {
    _ot: PhantomData<OT>,
    pub(super) hash: AesHash,
    rngs: Vec<(AesRng, AesRng)>,
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> FixedKeyInitializer for Sender<OT> {
    async fn init_fixed_key<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng, p_to).await?;
        let s = utils::u8vec_to_boolvec(&s_);
        let ks = ot.receive(channel, &s, rng, p_to).await?;
        let rngs = ks
            .into_iter()
            .map(AesRng::from_seed)
            .collect::<Vec<AesRng>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            hash: AES_HASH,
            s,
            s_: Block::from(s_),
            rngs,
        })
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> Sender<OT> {
    pub(super) async fn send_setup<C: Channel>(
        &mut self,
        channel: &mut C,
        m: usize,
        p_to: usize,
    ) -> Result<Vec<u8>, Error> {
        const nrows: usize = 128;
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut qs = vec![0u8; nrows * ncols / 8];
        let zero = vec![0u8; ncols / 8];
        for (j, (b, rng)) in self.s.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let q = &mut qs[range];
            let u: Vec<u8> = recv_from(channel, p_to, "ALSZ_OT_setup").await?;
            rng.fill_bytes(q);
            scutils::xor_inplace(q, if *b { &u } else { &zero });
        }
        Ok(utils::transpose(&qs, nrows, ncols))
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OtSender for Sender<OT> {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let mut s_ = [0u8; 16];
        rng.fill_bytes(&mut s_);
        Sender::<OT>::init_fixed_key(channel, s_, rng, p_to).await
    }

    async fn send<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        _: &mut RNG,
        p_to: usize,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m, p_to).await?;
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ self.s_;
            let y1 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.1;
            send_to(channel, p_to, "ALSZ_OT_y0y1", &[(y0, y1)]).await?;
        }
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> CorrelatedSender for Sender<OT> {
    async fn send_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        _: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(channel, m, p_to).await?;
        let mut out = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = self.hash.cr_hash(Block::from(j as u128), q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.s_;
            let y = self.hash.cr_hash(Block::from(j as u128), q) ^ x1;
            send_to(channel, p_to, "ALSZ_OT_y", &[y]).await?;
            out.push((x0, x1));
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> Receiver<OT> {
    pub(super) async fn receive_setup<C: Channel>(
        &mut self,
        channel: &mut C,
        r: &[u8],
        m: usize,
        p_to: usize,
    ) -> Result<Vec<u8>, Error> {
        const nrows: usize = 128;
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut g = vec![0u8; ncols / 8];
        for j in 0..self.rngs.len() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let t = &mut ts[range];
            self.rngs[j].0.fill_bytes(t);
            self.rngs[j].1.fill_bytes(&mut g);
            scutils::xor_inplace(&mut g, t);
            scutils::xor_inplace(&mut g, r);
            send_to(channel, p_to, "ALSZ_OT_setup", &g).await?;
        }
        Ok(utils::transpose(&ts, nrows, ncols))
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> OtReceiver for Receiver<OT> {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng, p_to).await?;
        let mut ks = Vec::with_capacity(128);
        let mut k0 = Block::default();
        let mut k1 = Block::default();
        for _ in 0..128 {
            rng.fill_bytes(k0.as_mut());
            rng.fill_bytes(k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(channel, &ks, rng, p_to).await?;
        let rngs = ks
            .into_iter()
            .map(|(k0, k1)| (AesRng::from_seed(k0), AesRng::from_seed(k1)))
            .collect::<Vec<(AesRng, AesRng)>>();
        Ok(Self {
            _ot: PhantomData::<OT>,
            hash: AES_HASH,
            rngs,
        })
    }

    async fn receive<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len(), p_to).await?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let (y0, y1): (Block, Block) = recv_from(channel, p_to, "ALSZ_OT_y0y1")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self.hash.cr_hash(Block::from(j as u128), Block::from(t));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> CorrelatedReceiver for Receiver<OT> {
    async fn receive_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len(), p_to).await?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = recv_from(channel, p_to, "ALSZ_OT_y")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;
            let y = if *b { y } else { Block::default() };
            let h = self.hash.cr_hash(Block::from(j as u128), Block::from(t));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}