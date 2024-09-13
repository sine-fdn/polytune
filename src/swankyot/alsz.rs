//! Implementation of the Asharov-Lindell-Schneider-Zohner oblivious transfer
//! extension protocol (cf. <https://eprint.iacr.org/2016/602>, Protocol 4).

#![allow(non_upper_case_globals)]

use crate::swankyot::{
    utils, CorrelatedReceiver, CorrelatedSender, FixedKeyInitializer, Receiver as OtReceiver,
    Sender as OtSender,
};

use ocelot::Error;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use scuttlebutt::{
    utils as scutils, AbstractChannel, AesHash, AesRng, Block, SemiHonest, AES_HASH,
};
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
    fn init_fixed_key<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng)?;
        let s = utils::u8vec_to_boolvec(&s_);
        let ks = ot.receive(channel, &s, rng)?;
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
    pub(super) fn send_setup<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        m: usize,
    ) -> Result<Vec<u8>, Error> {
        const nrows: usize = 128;
        let ncols = if m % 8 != 0 { m + (8 - m % 8) } else { m };
        let mut qs = vec![0u8; nrows * ncols / 8];
        let mut u = vec![0u8; ncols / 8];
        let zero = vec![0u8; ncols / 8];
        for (j, (b, rng)) in self.s.iter().zip(self.rngs.iter_mut()).enumerate() {
            let range = j * ncols / 8..(j + 1) * ncols / 8;
            let q = &mut qs[range];
            channel.read_bytes(&mut u)?;
            rng.fill_bytes(q);
            scutils::xor_inplace(q, if *b { &u } else { &zero });
        }
        Ok(utils::transpose(&qs, nrows, ncols))
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> OtSender for Sender<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut s_ = [0u8; 16];
        rng.fill_bytes(&mut s_);
        Sender::<OT>::init_fixed_key(channel, s_, rng)
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        let m = inputs.len();
        let qs = self.send_setup(channel, m)?;
        for (j, input) in inputs.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let y0 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.0;
            let q = q ^ self.s_;
            let y1 = self.hash.cr_hash(Block::from(j as u128), q) ^ input.1;
            channel.write_block(&y0)?;
            channel.write_block(&y1)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> std::fmt::Display for Sender<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ALSZ Sender")
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> CorrelatedSender for Sender<OT> {
    fn send_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        _: &mut RNG,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error> {
        let m = deltas.len();
        let qs = self.send_setup(channel, m)?;
        let mut out = Vec::with_capacity(m);
        for (j, delta) in deltas.iter().enumerate() {
            let q = &qs[j * 16..(j + 1) * 16];
            let q: [u8; 16] = q.try_into().unwrap();
            let q = Block::from(q);
            let x0 = self.hash.cr_hash(Block::from(j as u128), q);
            let x1 = x0 ^ *delta;
            let q = q ^ self.s_;
            let y = self.hash.cr_hash(Block::from(j as u128), q) ^ x1;
            channel.write_block(&y)?;
            out.push((x0, x1));
        }
        channel.flush()?;
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> Receiver<OT> {
    pub(super) fn receive_setup<C: AbstractChannel>(
        &mut self,
        channel: &mut C,
        r: &[u8],
        m: usize,
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
            channel.write_bytes(&g)?;
        }
        channel.flush()?;
        Ok(utils::transpose(&ts, nrows, ncols))
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> OtReceiver for Receiver<OT> {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
    ) -> Result<Self, Error> {
        let mut ot = OT::init(channel, rng)?;
        let mut ks = Vec::with_capacity(128);
        let mut k0 = Block::default();
        let mut k1 = Block::default();
        for _ in 0..128 {
            rng.fill_bytes(k0.as_mut());
            rng.fill_bytes(k1.as_mut());
            ks.push((k0, k1));
        }
        ot.send(channel, &ks, rng)?;
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

    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y0 = channel.read_block()?;
            let y1 = channel.read_block()?;
            let y = if *b { y1 } else { y0 };
            let y = y ^ self.hash.cr_hash(Block::from(j as u128), Block::from(t));
            out.push(y);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> CorrelatedReceiver for Receiver<OT> {
    fn receive_correlated<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        _: &mut RNG,
    ) -> Result<Vec<Self::Msg>, Error> {
        let r = utils::boolvec_to_u8vec(inputs);
        let ts = self.receive_setup(channel, &r, inputs.len())?;
        let mut out = Vec::with_capacity(inputs.len());
        for (j, b) in inputs.iter().enumerate() {
            let t = &ts[j * 16..(j + 1) * 16];
            let t: [u8; 16] = t.try_into().unwrap();
            let y = channel.read_block()?;
            let y = if *b { y } else { Block::default() };
            let h = self.hash.cr_hash(Block::from(j as u128), Block::from(t));
            out.push(y ^ h);
        }
        Ok(out)
    }
}

impl<OT: OtSender<Msg = Block> + SemiHonest> std::fmt::Display for Receiver<OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ALSZ Receiver")
    }
}

impl<OT: OtReceiver<Msg = Block> + SemiHonest> SemiHonest for Sender<OT> {}
impl<OT: OtSender<Msg = Block> + SemiHonest> SemiHonest for Receiver<OT> {}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn get_bit(src: &[u8], i: usize) -> u8 {
    let byte = src[i / 8];
    let bit_pos = i % 8;
    (byte & (1 << bit_pos) != 0) as u8
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn set_bit(dst: &mut [u8], i: usize, b: u8) {
    let bit_pos = i % 8;
    if b == 1 {
        dst[i / 8] |= 1 << bit_pos;
    } else {
        dst[i / 8] &= !(1 << bit_pos);
    }
}

#[inline]
#[cfg(not(target_arch = "x86_64"))]
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
#[cfg(not(target_arch = "x86_64"))]
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
pub fn transpose(m: &[u8], nrows: usize, ncols: usize) -> Vec<u8> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        transpose_naive(m, nrows, ncols)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut m_ = vec![0u8; nrows * ncols / 8];
        _transpose(
            m_.as_mut_ptr() as *mut u8,
            m.as_ptr(),
            nrows as u64,
            ncols as u64,
        );
        m_
    }
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn _transpose(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64) {
    assert!(nrows >= 16);
    assert_eq!(nrows % 8, 0);
    assert_eq!(ncols % 8, 0);
    sse_trans(out, inp, nrows, ncols)
}

#[link(name = "transpose")]
#[cfg(target_arch = "x86_64")]
extern "C" {
    fn sse_trans(out: *mut u8, inp: *const u8, nrows: u64, ncols: u64);
}

/// boolvec to u8vec
#[inline]
pub fn boolvec_to_u8vec(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (i % 8);
    }
    v
}

/// u8vec to boolvec
#[inline]
pub fn u8vec_to_boolvec(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push((1 << i) & byte != 0);
        }
    }
    bv
}
