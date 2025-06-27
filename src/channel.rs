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
//! ## Message Chunking
//!
//! The module provides automatic chunking of large messages to avoid issues with message size
//! limits. Messages are split into chunks, serialized, and reassembled on the receiving end
//! transparently.
//!
//! ## Serialization
//!
//! Messages are serialized using `bincode`, allowing for efficient binary encoding of structured
//! data. The channel primarily works with byte vectors, while higher-level send/receive functions
//! handle serialization and deserialization of application-level messages.

use std::fmt;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex,
};
#[cfg(not(target_arch = "wasm32"))]
use tracing::{trace, Level};

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

/// A chunk of a message as bytes and the number of chunks remaining to be sent.
#[derive(Debug, Serialize)]
struct SendChunk<'a, T> {
    /// A chunk of a full message.
    chunk: &'a [T],
    /// The number of chunks that remain to be sent after the current one.
    remaining_chunks: usize,
}

/// A chunk of a message as bytes and the number of chunks remaining to be sent.
#[derive(Debug, Deserialize)]
struct RecvChunk<T> {
    /// A chunk of a full message.
    chunk: Vec<T>,
    /// The number of chunks that remain to be sent after the current one.
    remaining_chunks: usize,
}

/// Information about a sent message that can be useful for logging.
#[derive(Debug, Clone)]
pub struct SendInfo {
    phase: String,
    current_msg: usize,
    remaining_msgs: usize,
}

impl SendInfo {
    /// The name of the protocol phase that sent the message.
    pub fn phase(&self) -> &str {
        &self.phase
    }

    /// How many chunks have already been sent, 1 for the first message, 2 for the second, etc.
    pub fn sent(&self) -> usize {
        self.current_msg + 1
    }

    /// How many chunks have yet to be sent for the full message to be transmitted.
    pub fn remaining(&self) -> usize {
        self.remaining_msgs
    }

    /// The total number of chunks that make up the full message.
    pub fn total(&self) -> usize {
        self.sent() + self.remaining()
    }
}

/// Information about a received message that can be useful for logging.
#[derive(Debug, Clone)]
pub struct RecvInfo {
    phase: String,
    current_msg: usize,
    remaining_msgs: Option<usize>,
}

impl RecvInfo {
    /// The name of the protocol phase that sent the message.
    pub fn phase(&self) -> &str {
        &self.phase
    }

    /// How many chunks have already been sent, 1 for the first message, 2 for the second, etc.
    pub fn sent(&self) -> usize {
        self.current_msg + 1
    }

    /// How many chunks have yet to be sent for the full message to be transmitted.
    ///
    /// Will be `None` for the first message, before it is clear how many chunks need to be sent.
    pub fn remaining(&self) -> Option<usize> {
        self.remaining_msgs
    }

    /// The total number of chunks that make up the full message.
    ///
    /// Will be `None` for the first message, before it is clear how many chunks need to be sent.
    pub fn total(&self) -> Option<usize> {
        self.remaining().map(|remaining| self.sent() + remaining)
    }
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
        chunk: Vec<u8>,
        info: SendInfo,
    ) -> Result<(), Self::SendError>;

    /// Awaits a response from the party with the given index (must be between `0..participants`).
    #[allow(async_fn_in_trait)]
    async fn recv_bytes_from(
        &self,
        party: usize,
        info: RecvInfo,
    ) -> Result<Vec<u8>, Self::RecvError>;
}

/// Serializes and sends an MPC message to the other party.
pub(crate) async fn send_to<S: Serialize + std::fmt::Debug>(
    channel: &impl Channel,
    party: usize,
    phase: &str,
    msg: &[S],
) -> Result<(), Error> {
    let chunk_size = 5_000_000;
    let mut chunks: Vec<_> = msg.chunks(chunk_size).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let length = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let remaining_chunks = length - i - 1;
        let chunk = SendChunk {
            chunk,
            remaining_chunks,
        };
        let chunk = bincode::serialize(&chunk).map_err(|e| Error {
            phase: format!("sending {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })?;
        let info = SendInfo {
            phase: phase.to_string(),
            current_msg: i,
            remaining_msgs: remaining_chunks,
        };
        channel
            .send_bytes_to(party, chunk, info)
            .await
            .map_err(|e| Error {
                phase: phase.to_string(),
                reason: ErrorKind::SendError(format!("{e:?}")),
            })?;
    }
    Ok(())
}

/// Receives and deserializes an MPC message from the other party.
pub(crate) async fn recv_from<T: DeserializeOwned + std::fmt::Debug>(
    channel: &impl Channel,
    party: usize,
    phase: &str,
) -> Result<Vec<T>, Error> {
    let mut msg = vec![];
    let mut i = 0;
    let mut remaining = None;
    loop {
        let info = RecvInfo {
            phase: phase.to_string(),
            current_msg: i,
            remaining_msgs: remaining,
        };
        let chunk = channel
            .recv_bytes_from(party, info)
            .await
            .map_err(|e| Error {
                phase: phase.to_string(),
                reason: ErrorKind::RecvError(format!("{e:?}")),
            })?;
        let RecvChunk {
            chunk,
            remaining_chunks,
        }: RecvChunk<T> = bincode::deserialize(&chunk).map_err(|e| Error {
            phase: format!("receiving {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })?;
        msg.extend(chunk);
        if remaining_chunks == 0 {
            return Ok(msg);
        }
        remaining = Some(remaining_chunks);
        i += 1;
    }
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
        info: SendInfo,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<Vec<u8>>> {
        self.bytes_sent
            .fetch_add(msg.len() as u64, Ordering::Relaxed);
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        let i = info.sent();
        if i == 1 {
            trace!(size = mb, "Sending msg");
        } else {
            trace!(size = mb, "  (continued sending msg)");
        }
        self.s[p]
            .as_ref()
            .unwrap_or_else(|| panic!("No sender for party {p}"))
            .send(msg)
            .await
    }

    #[tracing::instrument(level = Level::TRACE, skip(self), fields(info = ?_info))]
    async fn recv_bytes_from(&self, p: usize, _info: RecvInfo) -> Result<Vec<u8>, AsyncRecvError> {
        let mut r = self.r[p]
            .as_ref()
            .unwrap_or_else(|| panic!("No receiver for party {p}"))
            .lock()
            .await;
        let chunk = r.recv();
        match tokio::time::timeout(std::time::Duration::from_secs(10 * 60), chunk).await {
            Ok(Some(chunk)) => {
                let mb = chunk.len() as f64 / 1024.0 / 1024.0;
                trace!(size = mb, "Received chunk");
                Ok(chunk)
            }
            Ok(None) => Err(AsyncRecvError::Closed),
            Err(_) => Err(AsyncRecvError::TimeoutElapsed),
        }
    }
}
