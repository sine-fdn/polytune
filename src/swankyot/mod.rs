//! Oblivious transfer traits + instantiations.
//!
//! This module provides traits for standard oblivious transfer (OT), correlated
//! OT, and random OT, alongside implementations of the following OT protocols:
//!
//! * `dummy`: a dummy and completely insecure OT for testing purposes.
//! * `naor_pinkas`: Naor-Pinkas semi-honest OT.
//! * `chou_orlandi`: Chou-Orlandi malicious OT.
//! * `alsz`: Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT).
//! * `kos`: Keller-Orsini-Scholl malicious OT extension (+ correlated and random OT).
//!

pub mod alsz;
pub mod kos;
pub mod chou_orlandi;
pub mod utils;

use curve25519_dalek::RistrettoPoint;
use rand::{CryptoRng, Rng};
use scuttlebutt::Block;

use crate::channel::Channel;
use crate::faand::Error;

pub(crate) fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Block {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    Block::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).unwrap())
}

/// Instantiation of the Chou-Orlandi OT sender.
pub type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = chou_orlandi::Receiver;
/// Instantiation of the ALSZ OT extension sender, using Chou-Orlandi as the base OT.
pub type AlszSender = alsz::Sender<ChouOrlandiReceiver>;
/// Instantiation of the ALSZ OT extension receiver, using Chou-Orlandi as the base OT.
pub type AlszReceiver = alsz::Receiver<ChouOrlandiSender>;
/// Instantiation of the KOS OT extension sender, using Chou-Orlandi as the base OT.
pub type KosSender = kos::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosReceiver = kos::Receiver<ChouOrlandiSender>;

/// Trait for one-out-of-two oblivious transfer from the sender's point-of-view.
pub trait Sender
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error>;
    /// Sends messages.
    async fn send<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<(), Error>;
}

/// Trait for initializing an oblivious transfer object with a fixed key.
pub trait FixedKeyInitializer
where
    Self: Sized,
{
    /// Runs any one-time initialization to create the oblivious transfer
    /// object with a fixed key.
    async fn init_fixed_key<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        s_: [u8; 16],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error>;
}

/// Trait for one-out-of-two oblivious transfer from the receiver's
/// point-of-view.
pub trait Receiver
where
    Self: Sized,
{
    /// Message type, restricted to types that are mutably-dereferencable as
    /// `u8` arrays.
    type Msg: Sized + AsMut<[u8]>;
    /// Runs any one-time initialization to create the oblivious transfer
    /// object.
    async fn init<C: Channel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Self, Error>;
    /// Receives messages.
    async fn receive<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the sender's
/// point-of-view.
pub trait CorrelatedSender: Sender
where
    Self: Sized,
{
    /// Correlated oblivious transfer send. Takes as input an array `deltas`
    /// which specifies the offset between the zero and one message.
    async fn send_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        deltas: &[Self::Msg],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the receiver's
/// point-of-view.
pub trait CorrelatedReceiver: Receiver
where
    Self: Sized,
{
    /// Correlated oblivious transfer receive.
    async fn receive_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
    ) -> Result<Vec<Self::Msg>, Error>;
}