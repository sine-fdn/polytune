//! Oblivious transfer traits + instantiations based on the swanky library suite.
//!
//! This module provides traits for standard oblivious transfer (OT), correlated
//! OT, and random OT, alongside implementations of the following OT protocols:
//!
//! * `chou_orlandi`: Chou-Orlandi malicious OT.
//! * `alsz`: Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT).
//! * `kos`: Keller-Orsini-Scholl malicious OT extension (+ correlated and random OT).
//!
//! This implementation is a modified version of the ocelot rust library
//! from <https://github.com/GaloisInc/swanky>. The original implementation
//! uses a different channel and is synchronous. We furthermore batched the
//! messages to reduce the number of communication rounds.

pub(crate) mod alsz;
pub(crate) mod chou_orlandi;
pub(crate) mod kos;

use curve25519_dalek::RistrettoPoint;
use maybe_async::maybe_async;
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;

use scuttlebutt::Block;

use crate::channel::{Channel, Error as ChannelError};

/// Errors occurring during preprocessing.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelErr(ChannelError),
    /// KOS consistency check failed.
    KOSConsistencyCheckFailed,
    /// A message was sent, but it contained no data.
    EmptyMsg,
    /// Invalid array length.
    InvalidLength,
}

/// Converts a `channel::Error` into a custom `Error` type.
impl From<ChannelError> for Error {
    fn from(e: ChannelError) -> Self {
        Self::ChannelErr(e)
    }
}

pub(crate) fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Block {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    Block::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).unwrap())
}

/// Instantiation of the Chou-Orlandi OT sender.
pub(crate) type ChouOrlandiSender = chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub(crate) type ChouOrlandiReceiver = chou_orlandi::Receiver;
/// Instantiation of the KOS OT extension sender, using Chou-Orlandi as the base OT.
pub(crate) type KosSender = kos::Sender<ChouOrlandiReceiver>;
/// Instantiation of the KOS OT extension receiver, using Chou-Orlandi as the base OT.
pub(crate) type KosReceiver = kos::Receiver<ChouOrlandiSender>;

/// Trait for one-out-of-two oblivious transfer from the sender's point-of-view.
#[maybe_async(AFIT)]
pub(crate) trait Sender
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
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Self, Error>;
    /// Sends messages.
    async fn send<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Self::Msg, Self::Msg)],
        rng: &mut RNG,
        p_to: usize,
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<(), Error>;
}

/// Trait for initializing an oblivious transfer object with a fixed key.
#[maybe_async(AFIT)]
pub(crate) trait FixedKeyInitializer
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
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Self, Error>;
}

/// Trait for one-out-of-two oblivious transfer from the receiver's
/// point-of-view.
#[maybe_async(AFIT)]
pub(crate) trait Receiver
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
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Self, Error>;
    /// Receives messages.
    async fn recv<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Vec<Self::Msg>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the sender's
/// point-of-view.
#[allow(clippy::type_complexity)]
#[maybe_async(AFIT)]
pub(crate) trait CorrelatedSender: Sender
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
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Vec<(Self::Msg, Self::Msg)>, Error>;
}

/// Trait for one-out-of-two _correlated_ oblivious transfer from the receiver's
/// point-of-view.
#[maybe_async(AFIT)]
pub(crate) trait CorrelatedReceiver: Receiver
where
    Self: Sized,
{
    /// Correlated oblivious transfer receive.
    async fn recv_correlated<C: Channel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        rng: &mut RNG,
        p_to: usize,
        shared_rand: &mut ChaCha20Rng,
    ) -> Result<Vec<Self::Msg>, Error>;
}
