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
    channel::{recv_from, send_to, recv_vec_from, Channel},
    swankyot::{Receiver as OtReceiver, Sender as OtSender},
    faand::Error,
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
        send_to(channel, p_to, "CO_OT_s", &s.compress().as_bytes().to_vec()).await?;
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

        // Replace map with a loop to support async/await
        for i in 0..inputs.len() {
            let r_bytes: Vec<u8> = recv_vec_from(channel, p_to, "CO_OT_r", 32).await?;
            let r = convert_vec_to_point(r_bytes)?;
            let yr = self.y * r;
            let k0 = super::hash_pt(self.counter + i as u128, &yr);
            let k1 = super::hash_pt(self.counter + i as u128, &(yr - ys));
            ks.push((k0, k1));
        }
        self.counter += inputs.len() as u128;
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;

            send_to(channel, p_to, "CO_OT_c0c1", &[(c0, c1)]).await?;
        }
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

    async fn receive<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Block>, Error> {
        let zero = &Scalar::ZERO * &self.s;
        let one = &Scalar::ONE * &self.s;
        let mut ks = Vec::with_capacity(inputs.len());

        for (i, b) in inputs.iter().enumerate() {
            //this part was changes from swanky to async
            let x = Scalar::random(&mut rng);
            let c = if *b { one } else { zero };
            let r = c + &x * RISTRETTO_BASEPOINT_TABLE;

            let send_vec = r.compress().as_bytes().to_vec();
            send_to(channel, p_to, "CO_OT_r", &send_vec).await?;

            let k = super::hash_pt(self.counter + i as u128, &(&x * &self.s));
            ks.push(k);
        }
        self.counter += inputs.len() as u128;

        let mut result = Vec::with_capacity(inputs.len());

        // Now receive and calculate the result asynchronously
        for (b, k) in inputs.iter().zip(ks.into_iter()) {
            let (c0, c1): (Block, Block) = recv_from(channel, p_to, "CO_OT_c0c1")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;
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
    let pt = match CompressedRistretto::from_slice(&dataarr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .decompress()
    {
        Some(pt) => {
            pt
        }
        None => {
            return Err(Error::InvalidOTData);
        }
    };
    Ok(pt)
}