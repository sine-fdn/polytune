//! Provides communication channels for sending and receiving messages between parties.
//!
//! This module defines the fundamental abstraction for communication in the form of the [`Channel`]
//! trait, which can be implemented to support various communication methods and environments.
//!
//! The core design philosophy is to separate the protocol logic from the specifics of message
//! transport. The protocol implementation does not need to be concerned with how messages are
//! physically transmitted - it only interacts with the abstract `Channel` interface. This means you
//! can switch between different channel implementations (network sockets, in-memory channels, etc.)
//! without changing protocol code.
//!
//! ## Message Transport
//!
//! Messages are serialized and transmitted in full. It is the responsibility of the caller to ensure
//! message sizes do not exceed transport limitations, i.e., message chunking may need to be
//! implemented.
//!
//! ## Serialization
//!
//! Messages are serialized using `bincode`, allowing for efficient binary encoding of structured
//! data. The channel primarily works with byte vectors, while higher-level send/receive functions
//! handle serialization and deserialization of application-level messages.

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicU64, Ordering};

use futures_util::future::{try_join, try_join_all};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender, channel},
};
#[cfg(not(target_arch = "wasm32"))]
use tracing::{Level, trace};

use crate::utils::{deserialize, serialize};

/// Errors related to sending / receiving / (de-)serializing messages.
#[derive(Debug)]
pub struct Error {
    /// The protocol phase during which the error occurred.
    pub phase: String,
    /// The specific error that was raised.
    pub reason: ErrorKind,
}

/// The specific error that occurred when trying to send / receive a message.
#[derive(Debug)]
pub enum ErrorKind {
    /// The (serialized) message could not be received over the channel.
    RecvError(String),
    /// The (serialized) message could not be sent over the channel.
    SendError(String),
    /// The message could not be serialized (before sending it out).
    SerdeError(String),
    /// The message is a Vec, but not of the expected length.
    InvalidLength,
}

/// A communication channel used to send/receive messages to/from another party.
///
/// This trait defines the core interface for message transport in the protocol.
/// Implementations of this trait determine how messages are physically sent and received,
/// which can vary based on the environment (network, in-process, etc.).
pub trait Channel {
    /// The error that can occur sending messages over the channel.
    type SendError: fmt::Debug;
    /// The error that can occur receiving messages over the channel.
    type RecvError: fmt::Debug;

    /// Sends a message to the party with the given index (must be between `0..participants`).
    // We allow the async_fn_in_trait lint because we don't need to place additional bounds on
    // the returned future. We don't want to enforce returning Send futures as that is not
    // compatible with the `examples/wasm-http-channels` implementation.
    #[allow(async_fn_in_trait)]
    async fn send_bytes_to(
        &self,
        party: usize,
        data: Vec<u8>,
        phase: &str,
    ) -> Result<(), Self::SendError>;

    /// Awaits a response from the party with the given index (must be between `0..participants`).
    #[allow(async_fn_in_trait)]
    async fn recv_bytes_from(&self, party: usize, phase: &str) -> Result<Vec<u8>, Self::RecvError>;
}

/// Serializes and sends an MPC message to the other party.
pub(crate) async fn send_to<S: Serialize + std::fmt::Debug>(
    channel: &impl Channel,
    party: usize,
    phase: &str,
    msg: &[S],
) -> Result<(), Error> {
    let data = serialize(msg).map_err(|e| Error {
        phase: format!("sending {phase}"),
        reason: ErrorKind::SerdeError(format!("{e:?}")),
    })?;
    channel
        .send_bytes_to(party, data, phase)
        .await
        .map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::SendError(format!("{e:?}")),
        })?;
    Ok(())
}

/// Receives and deserializes an MPC message from the other party.
pub(crate) async fn recv_from<T: DeserializeOwned + std::fmt::Debug>(
    channel: &impl Channel,
    party: usize,
    phase: &str,
) -> Result<Vec<T>, Error> {
    let data = channel
        .recv_bytes_from(party, phase)
        .await
        .map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::RecvError(format!("{e:?}")),
        })?;
    let msg: Vec<T> = deserialize(&data).map_err(|e| Error {
        phase: format!("receiving {phase}"),
        reason: ErrorKind::SerdeError(format!("{e:?}")),
    })?;
    Ok(msg)
}

/// Receives and deserializes a Vec from the other party (while checking the length).
pub(crate) async fn recv_vec_from<T: DeserializeOwned + std::fmt::Debug>(
    channel: &impl Channel,
    party: usize,
    phase: &str,
    len: usize,
) -> Result<Vec<T>, Error> {
    let v: Vec<T> = recv_from(channel, party, phase).await?;
    if v.len() == len {
        Ok(v)
    } else {
        Err(Error {
            phase: phase.to_string(),
            reason: ErrorKind::InvalidLength,
        })
    }
}

/// Broadcasts the same data to all parties except self and receives responses from all other parties.
///
/// All sending and receiving is done concurrently.
///
/// # Security
/// Note that this is an unverified broadcast. If you need a broadcast that verifies that
/// each party actually sends the same data to the others, use [`crate::faand::broadcast`].
///
/// # Arguments
/// * `channel` - The communication channel
/// * `own_party` - Index of the current party (won't send to itself)
/// * `num_parties` - Total number of parties
/// * `phase` - Protocol phase name for message identification
/// * `data` - Data to send to all other parties
/// * `expected_recv_len` - Expected length of received vectors
///
/// # Returns
/// A vector indexed by party ID, where `result[i]` contains the response from party `i`.
/// The entry for `own_party` will be empty.
pub(crate) async fn unverified_broadcast<T>(
    channel: &impl Channel,
    own_party: usize,
    num_parties: usize,
    phase: &str,
    data: &[T],
) -> Result<Vec<Vec<T>>, Error>
where
    T: Serialize + DeserializeOwned + std::fmt::Debug,
{
    let expected_recv_len = data.len();
    let send_fut = try_join_all(
        (0..num_parties)
            .filter(|p| *p != own_party)
            .map(|p| send_to(channel, p, phase, data)),
    );

    let recv_fut = try_join_all((0..num_parties).map(async |p| {
        if p != own_party {
            recv_vec_from(channel, p, phase, expected_recv_len).await
        } else {
            Ok(vec![])
        }
    }));

    let (_, responses) = try_join(send_fut, recv_fut).await?;
    Ok(responses)
}

/// Scatters different data to each party and receives responses from all other parties.
///
/// All sending and receiving is done concurrently.
///
/// # Arguments
/// * `channel` - The communication channel
/// * `own_party` - Index of the current party (won't send to itself)
/// * `phase` - Protocol phase name for message identification
/// * `data_per_party` - Vector where `data_per_party[i]` is sent to party `i` except
///   when `i == own_party`
/// * `expected_recv_len` - Expected length of received vectors
///
/// # Returns
/// A vector indexed by party ID, where `result[i]` contains the response from party `i`.
/// `result[own_party]` will be an empty `Vec`.
pub(crate) async fn scatter<T>(
    channel: &impl Channel,
    own_party: usize,
    phase: &str,
    data_per_party: &[Vec<T>],
) -> Result<Vec<Vec<T>>, Error>
where
    T: Serialize + DeserializeOwned + std::fmt::Debug,
{
    let num_parties = data_per_party.len();

    let mut expected_recv_len = None;

    for (p, data) in data_per_party.iter().enumerate() {
        if p == own_party {
            continue;
        }
        // The first time we see a non-zero length vector we initialize
        // expected_recv_len
        if expected_recv_len.is_none() && !data.is_empty() {
            expected_recv_len = Some(data.len());
            continue;
        }

        if let Some(len) = expected_recv_len
            && len != data.len()
        {
            return Err(Error {
                phase: phase.to_string(),
                reason: ErrorKind::InvalidLength,
            });
        }
    }
    let Some(expected_recv_len) = expected_recv_len else {
        // data_per_party is empty if expected_recv_len is None
        return Ok(vec![]);
    };

    let send_fut = try_join_all(
        (0..num_parties)
            .filter(|p| *p != own_party)
            .map(|p| send_to(channel, p, phase, &data_per_party[p])),
    );

    let recv_fut = try_join_all((0..num_parties).map(async |p| {
        if p != own_party {
            recv_vec_from(channel, p, phase, expected_recv_len).await
        } else {
            Ok(vec![])
        }
    }));

    let (_, responses) = try_join(send_fut, recv_fut).await?;
    Ok(responses)
}

/// A simple asynchronous channel using [`Sender`] and [`Receiver`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
#[allow(dead_code)]
#[doc(hidden)]
pub struct SimpleChannel {
    s: Vec<Option<Sender<Vec<u8>>>>,
    r: Vec<Option<Mutex<Receiver<Vec<u8>>>>>,
    /// The total number of bytes sent over the channel.
    bytes_sent: AtomicU64,
}

#[cfg(not(target_arch = "wasm32"))]
impl SimpleChannel {
    /// Creates channels for N parties to communicate with each other.
    pub fn channels(parties: usize) -> Vec<Self> {
        let buffer_capacity = 1024;
        let mut channels = vec![];
        for _ in 0..parties {
            let mut s = vec![];
            let mut r = vec![];
            for _ in 0..parties {
                s.push(None);
                r.push(None);
            }
            let bytes_sent = AtomicU64::new(0);
            channels.push(SimpleChannel { s, r, bytes_sent });
        }
        for a in 0..parties {
            for b in 0..parties {
                if a == b {
                    continue;
                }
                let (send_a_to_b, recv_a_to_b) = channel(buffer_capacity);
                let (send_b_to_a, recv_b_to_a) = channel(buffer_capacity);
                channels[a].s[b] = Some(send_a_to_b);
                channels[b].s[a] = Some(send_b_to_a);
                channels[a].r[b] = Some(Mutex::new(recv_b_to_a));
                channels[b].r[a] = Some(Mutex::new(recv_a_to_b));
            }
        }
        channels
    }

    /// Returns the total number of bytes sent on this channel.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }
}

/// The error raised by `recv` calls of a [`SimpleChannel`].
#[derive(Debug)]
#[cfg(not(target_arch = "wasm32"))]
#[doc(hidden)]
pub enum AsyncRecvError {
    /// The channel has been closed.
    Closed,
    /// No message was received before the timeout.
    TimeoutElapsed,
}

#[cfg(not(target_arch = "wasm32"))]
impl Channel for SimpleChannel {
    type SendError = tokio::sync::mpsc::error::SendError<Vec<u8>>;
    type RecvError = AsyncRecvError;

    #[tracing::instrument(level = Level::TRACE, skip(self, msg))]
    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        phase: &str,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<Vec<u8>>> {
        self.bytes_sent
            .fetch_add(msg.len() as u64, Ordering::Relaxed);
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        trace!(size = mb, "Sending msg");
        self.s[p]
            .as_ref()
            .unwrap_or_else(|| panic!("No sender for party {p}"))
            .send(msg)
            .await
    }

    #[tracing::instrument(level = Level::TRACE, skip(self), fields(phase = ?_phase))]
    async fn recv_bytes_from(&self, p: usize, _phase: &str) -> Result<Vec<u8>, AsyncRecvError> {
        let mut r = self.r[p]
            .as_ref()
            .unwrap_or_else(|| panic!("No receiver for party {p}"))
            .lock()
            .await;
        let data = r.recv();
        match tokio::time::timeout(std::time::Duration::from_secs(10 * 60), data).await {
            Ok(Some(data)) => {
                let mb = data.len() as f64 / 1024.0 / 1024.0;
                trace!(size = mb, "Received data");
                Ok(data)
            }
            Ok(None) => Err(AsyncRecvError::Closed),
            Err(_) => Err(AsyncRecvError::TimeoutElapsed),
        }
    }
}
