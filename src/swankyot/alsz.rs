//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).
//!
//! This implementation is a modified version of the ocelot rust library
//! from <https://github.com/GaloisInc/swanky>. The original implementation
//! uses a different channel and is synchronous. We furthermore batched the
//! messages to reduce the number of communication rounds.

#![allow(non_upper_case_globals)]

use crate::{
    channel::{recv_vec_from, send_to, Channel},
    faand::Error,
    swankyot::{
        CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, Receiver as OtReceiver,
        Sender as OtSender,
    },
};

use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use scuttlebutt::{utils as scutils, AesHash, AesRng, Block, SemiHonest, AES_HASH};
use std::marker::PhantomData;

/// Oblivious transfer sender.
pub(crate) struct Sender<OT: OtReceiver<Msg = Block> + SemiHonest> {
    _ot: PhantomData<OT>,
    pub(super) hash: AesHash,
    s: Vec<bool>,
    pub(super) s_: Block,
    rngs: Vec<AesRng>,
}
/// Oblivious transfer receiver.
pub(crate) struct Receiver<OT: OtSender<Msg = Block> + SemiHonest> {
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
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng, p_to, shared_rand).await?;
        let s = u8vec_to_boolvec(&s_);
        let ks = ot.recv(channel, &s, rng, p_to, shared_rand).await?;
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
        let uvec: Vec<Vec<u8>> =
            recv_vec_from(channel, p_to, "ALSZ_OT_setup", self.rngs.len()).await?;
        for (j, (b, rng)) in self.s.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let q = &mut qs[range];
            rng.fill_bytes(q);
            scutils::xor_inplace(q, if *b { &uvec[j] } else { &zero });
        }
        Ok(transpose(&qs, nrows, ncols))
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OtSender for Sender<OT> {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Self, Error> {
        let mut s_ = [0u8; 16];
        rng.fill_bytes(&mut s_);
        Sender::<OT>::init_fixed_key(channel, s_, rng, p_to, shared_rand).await
    }

    async fn send<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        _: &mut RNG,
        p_to: usize,
        _: &mut ChaCha20Rng,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m, p_to).await?;
        let mut y0y1_vec: Vec<(Block, Block)> = vec![];
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ self.s_;
            let y1 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.1;
            y0y1_vec.push((y0, y1));
        }
        send_to(channel, p_to, "ALSZ_OT_y0y1", &y0y1_vec).await?;

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
        _: &mut ChaCha20Rng,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(channel, m, p_to).await?;
        let mut out = Vec::with_capacity(m);
        let mut yvec = vec![];
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = self.hash.cr_hash(Block::from(j as u128), q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.s_;
            let y = self.hash.cr_hash(Block::from(j as u128), q) ^ x1;
            yvec.push(y);
            out.push((x0, x1));
        }
        send_to(channel, p_to, "ALSZ_OT_y", &yvec).await?;
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> Receiver<OT> {
    pub(super) async fn recv_setup<C: Channel>(
        &mut self,
        channel: &mut C,
        r: &[u8],
        m: usize,
        p_to: usize,
    ) -> Result<Vec<u8>, Error> {
        const nrows: usize = 128;
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut ts = vec![0u8; nrows * ncols / 8];
        let mut gvec = vec![];
        for j in 0..self.rngs.len() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let t = &mut ts[range];
            self.rngs[j].0.fill_bytes(t);

            let mut g = vec![0u8; ncols / 8];
            self.rngs[j].1.fill_bytes(&mut g);
            scutils::xor_inplace(&mut g, t);
            scutils::xor_inplace(&mut g, r);
            gvec.push(g);
        }
        send_to(channel, p_to, "ALSZ_OT_setup", &gvec).await?;
        Ok(transpose(&ts, nrows, ncols))
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> OtReceiver for Receiver<OT> {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng, p_to, shared_rand).await?;
        let mut ks = Vec::with_capacity(128);
        let mut k0 = Block::default();
        let mut k1 = Block::default();
        for _ in 0..128 {
            rng.fill_bytes(k0.as_mut());
            rng.fill_bytes(k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(channel, &ks, rng, p_to, shared_rand).await?;
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

    async fn recv<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
        p_to: usize,
        _: &mut ChaCha20Rng,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = boolvec_to_u8vec(inputs);
        let ts = self.recv_setup(channel, &r, inputs.len(), p_to).await?;
        let mut out = Vec::with_capacity(inputs.len());
        let y0y1_vec =
            recv_vec_from::<(Block, Block)>(channel, p_to, "ALSZ_OT_y0y1", inputs.len()).await?;
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let (y0, y1) = y0y1_vec[j];
            let y = if *b { y1 } else { y0 };
            let y = y ^ self.hash.cr_hash(Block::from(j as u128), Block::from(t));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> CorrelatedReceiver for Receiver<OT> {
    async fn recv_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
        p_to: usize,
        _: &mut ChaCha20Rng,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = boolvec_to_u8vec(inputs);
        let ts = self.recv_setup(channel, &r, inputs.len(), p_to).await?;
        let mut out = Vec::with_capacity(inputs.len());
        let yvec = recv_vec_from(channel, p_to, "ALSZ_OT_y", inputs.len()).await?;
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = if *b { yvec[j] } else { Block::default() };
            let h = self.hash.cr_hash(Block::from(j as u128), Block::from(t));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}

/// u8vec to boolvec
#[inline]
pub(crate) fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
}

/// boolvec to u8vec
#[inline]
pub(crate) fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}

#[inline]
fn get_bit(src: &[u8], i: usize) -> u8 {
    let byte = src[i / 8];
    let bit_pos = i % 8;
    (byte & (1 << bit_pos) != 0) as u8
}

#[inline]
fn set_bit(dst: &mut [u8], i: usize, b: u8) {
    let bit_pos = i % 8;
    if b == 1 {
        dst[i / 8] |= 1 << bit_pos;
    } else {
        dst[i / 8] &= !(1 << bit_pos);
    }
}

#[inline]
fn transpose_naive_inplace(dst: &mut [u8], src: &[u8], m: usize) {
    assert_eq!(src.len() % m, 0);
    let l = src.len() * 8;
    let n = l / m;

    for i in 0..l {
        let bit = get_bit(src, i);
        let (row, col) = (i / m, i % m);
        set_bit(dst, col * n + row, bit);
    }
}

#[inline]
fn transpose_naive(input: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    assert_eq!(nrows * ncols, input.len() * 8);
    let mut output = vec![0u8; nrows * ncols / 8];

    transpose_naive_inplace(&mut output, input, ncols);
    output
}

/// transpose a matrix of bits
#[inline]
pub(crate) fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    transpose_naive(m, nrows, ncols)
}
