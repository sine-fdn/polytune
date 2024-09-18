//! Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
//! <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library and works over blocks rather than arbitrary
//! length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if the value
//! `x^i` produced by the receiver is not randomized, all the random-OTs
//! produced by the protocol will be the same. We fix this by hashing in `i`
//! during the key derivation phase.

use crate::{
    channel::{recv_vec_from, send_to, Channel},
    faand::Error,
    swankyot::{Receiver as OtReceiver, Sender as OtSender},
};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{Block, Malicious, SemiHonest};

/// Oblivious transfer sender.
pub struct Sender {
    y: Scalar,
    s: RistrettoPoint,
    counter: u128,
}

impl OtSender for Sender {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let y = Scalar::random(&mut rng);
        let s = &y * RISTRETTO_BASEPOINT_TABLE;
        send_to(channel, p_to, "CO_OT_s", s.compress().as_bytes().as_ref()).await?;
        Ok(Self { y, s, counter: 0 })
    }

    async fn send<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
        p_to: usize,
    ) -> Result<(), Error> {
        let ys = self.y * self.s;
        let mut ks = Vec::with_capacity(inputs.len());

        let r_bytes_vec: Vec<Vec<u8>> = recv_vec_from(channel, p_to, "CO_OT_r", 128).await?;
        for (i, r_bytes) in r_bytes_vec.into_iter().enumerate() {
            let r = convert_vec_to_point(r_bytes)?;
            let yr = self.y * r;
            let k0 = super::hash_pt(self.counter + i as u128, &yr);
            let k1 = super::hash_pt(self.counter + i as u128, &(yr - ys));
            ks.push((k0, k1));
        }
        self.counter += inputs.len() as u128;
        let mut c0c1vec = vec![];
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;
            c0c1vec.push((c0, c1));
        }
        send_to(channel, p_to, "CO_OT_c0c1", &c0c1vec).await?;
        Ok(())
    }
}

/// Oblivious transfer receiver.
pub struct Receiver {
    s: RistrettoBasepointTable,
    counter: u128,
}

impl OtReceiver for Receiver {
    type Msg = Block;

    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        _: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error> {
        let s_bytes: Vec<u8> = recv_vec_from(channel, p_to, "CO_OT_s", 32).await?;
        let s = convert_vec_to_point(s_bytes)?;
        let s = RistrettoBasepointTable::create(&s);
        Ok(Self { s, counter: 0 })
    }

    async fn recv<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Block>, Error> {
        let zero = &Scalar::ZERO * &self.s;
        let one = &Scalar::ONE * &self.s;
        let mut ks = Vec::with_capacity(inputs.len());

        let mut send_vec_vec: Vec<Vec<u8>> = vec![];
        for (i, b) in inputs.iter().enumerate() {
            let x = Scalar::random(&mut rng);
            let c = if *b { one } else { zero };
            let r = c + &x * RISTRETTO_BASEPOINT_TABLE;

            let send_vec = r.compress().as_bytes().to_vec();
            send_vec_vec.push(send_vec);

            let k = super::hash_pt(self.counter + i as u128, &(&x * &self.s));
            ks.push(k);
        }
        send_to(channel, p_to, "CO_OT_r", &send_vec_vec).await?;
        self.counter += inputs.len() as u128;

        let mut result = Vec::with_capacity(inputs.len());

        let c0c1vec: Vec<(Block, Block)> = recv_vec_from(channel, p_to, "CO_OT_c0c1", inputs.len()).await?;
        for ((b, k), (c0, c1)) in inputs.iter().zip(ks).zip(c0c1vec) {
            let c = k ^ if *b { c1 } else { c0 };
            result.push(c);
        }
        Ok(result)
    }
}

impl SemiHonest for Sender {}
impl Malicious for Sender {}
impl SemiHonest for Receiver {}
impl Malicious for Receiver {}

pub(crate) fn convert_vec_to_point(data: Vec<u8>) -> Result<RistrettoPoint, Error> {
    let dataarr: [u8; 32] = data.try_into().map_err(|_| Error::InvalidOTData)?;
    let compressed_pt =
        CompressedRistretto::from_slice(&dataarr).map_err(|_| Error::InvalidOTData)?;
    let pt = compressed_pt.decompress().ok_or(Error::InvalidOTData)?;
    Ok(pt)
}
