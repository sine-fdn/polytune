//! A communication channel used to send/receive messages to/from another party.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt,
    sync::mpsc::{Receiver as SyncReceiver, SendError as SyncSendError, Sender as SyncSender},
};
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::mpsc::{error::SendError, Receiver, Sender};

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

/// A communication channel used to send/receive messages to/from another party.
#[maybe_async::maybe_async(?Send)]
pub trait Channel {
    /// The error that can occur sending messages over the channel.
    type SendError: fmt::Debug;
    /// The error that can occur receiving messages over the channel.
    type RecvError: fmt::Debug;

    /// Sends a message to the party with the given index (must be between `0..participants`).
    async fn send_bytes_to(
        &mut self,
        party: usize,
        phase: &str,
        i: usize,
        remaining: usize,
        chunk: Vec<u8>,
    ) -> Result<(), Self::SendError>;

    /// Awaits a response from the party with the given index (must be between `0..participants`).
    async fn recv_bytes_from(
        &mut self,
        party: usize,
        phase: &str,
        i: usize,
    ) -> Result<Vec<u8>, Self::RecvError>;
}

/// Serializes and sends an MPC message to the other party.
#[maybe_async::maybe_async]
pub(crate) async fn send_to<S: Serialize + std::fmt::Debug>(
    channel: &mut impl Channel,
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
        channel
            .send_bytes_to(party, phase, i, remaining_chunks, chunk)
            .await
            .map_err(|e| Error {
                phase: phase.to_string(),
                reason: ErrorKind::SendError(format!("{e:?}")),
            })?;
    }
    Ok(())
}

/// Receives and deserializes an MPC message from the other party.
#[maybe_async::maybe_async]
pub(crate) async fn recv_from<T: DeserializeOwned + std::fmt::Debug>(
    channel: &mut impl Channel,
    party: usize,
    phase: &str,
) -> Result<Vec<T>, Error> {
    let mut msg = vec![];
    let mut i = 0;
    loop {
        let chunk = channel
            .recv_bytes_from(party, phase, i)
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
        i += 1;
    }
}

/// Receives and deserializes a Vec from the other party (while checking the length).
#[maybe_async::maybe_async]
pub(crate) async fn recv_vec_from<T: DeserializeOwned + std::fmt::Debug>(
    channel: &mut impl Channel,
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
pub struct SimpleAsyncChannel {
    s: Vec<Option<Sender<Vec<u8>>>>,
    r: Vec<Option<Receiver<Vec<u8>>>>,

    pub(crate) bytes_sent: usize,
}

#[cfg(not(target_arch = "wasm32"))]
#[maybe_async::async_impl]
impl SimpleAsyncChannel {
    /// Creates channels for N parties to communicate with each other.
    pub fn channels(parties: usize) -> Vec<Self> {
        let buffer_capacity = 1024;

        let mut channels = vec![];

        for _ in 0..parties {
            let mut s: Vec<Option<Sender<Vec<u8>>>> = vec![];
            let mut r: Vec<Option<Receiver<Vec<u8>>>> = vec![];
            for _ in 0..parties {
                s.push(None);
                r.push(None);
            }
            let bytes_sent = 0;
            channels.push(SimpleAsyncChannel { s, r, bytes_sent });
        }

        for a in 0..parties {
            for b in 0..parties {
                if a == b {
                    continue;
                }
                let (send_a_to_b, recv_a_to_b) = tokio::sync::mpsc::channel(buffer_capacity);
                let (send_b_to_a, recv_b_to_a) = tokio::sync::mpsc::channel(buffer_capacity);
                channels[a].s[b] = Some(send_a_to_b);
                channels[b].s[a] = Some(send_b_to_a);
                channels[a].r[b] = Some(recv_b_to_a);
                channels[b].r[a] = Some(recv_a_to_b);
            }
        }
        channels
    }
}

/// The error raised by `recv` calls of a [`SimpleChannel`].
#[derive(Debug)]
#[cfg(not(target_arch = "wasm32"))]
pub enum RecvError {
    /// The channel has been closed.
    Closed,
    /// No message was received before the timeout.
    TimeoutElapsed,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
/// Unified error type for sending messages over a [`SimpleChannel`].
pub enum UnifiedSendError {
    /// An error occurred while sending a message asynchronously.
    AsyncSend(SendError<Vec<u8>>),
    /// An error occurred while sending a message synchronously.
    SyncSend(SyncSendError<Vec<u8>>),
}

#[maybe_async::async_impl(?Send)]
impl Channel for SimpleAsyncChannel {
    type SendError = UnifiedSendError;
    type RecvError = RecvError;

    async fn send_bytes_to(
        &mut self,
        p: usize,
        phase: &str,
        i: usize,
        remaining: usize,
        msg: Vec<u8>,
    ) -> Result<(), UnifiedSendError> {
        self.bytes_sent += msg.len();
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        let i = i + 1;
        let total = i + remaining;
        if i == 1 {
            println!("Sending msg {phase} to party {p} ({mb:.2}MB), {i}/{total}...");
        } else {
            println!("  (sending msg {phase} to party {p} ({mb:.2}MB), {i}/{total})");
        }
        self.s[p]
            .as_ref()
            .unwrap_or_else(|| panic!("No sender for party {p}"))
            .send(msg)
            .await
            .map_err(UnifiedSendError::AsyncSend)
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _phase: &str,
        _i: usize,
    ) -> Result<Vec<u8>, RecvError> {
        let chunk = self.r[p]
            .as_mut()
            .unwrap_or_else(|| panic!("No receiver for party {p}"))
            .recv();
        match tokio::time::timeout(std::time::Duration::from_secs(10 * 60), chunk).await {
            Ok(Some(chunk)) => Ok(chunk),
            Ok(None) => Err(RecvError::Closed),
            Err(_) => Err(RecvError::TimeoutElapsed),
        }
    }
}

/// A simple synchronous channel using [`Sender`] and [`Receiver`].
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
#[allow(dead_code)]
pub struct SimpleSyncChannel {
    s: Vec<Option<SyncSender<Vec<u8>>>>,
    r: Vec<Option<SyncReceiver<Vec<u8>>>>,

    pub(crate) bytes_sent: usize,
}

#[maybe_async::sync_impl]
impl SimpleSyncChannel {
    /// Creates channels for N parties to communicate with each other.
    pub fn channels(parties: usize) -> Vec<Self> {
        let mut channels = vec![];

        for _ in 0..parties {
            let mut s: Vec<Option<SyncSender<Vec<u8>>>> = vec![];
            let mut r: Vec<Option<SyncReceiver<Vec<u8>>>> = vec![];
            for _ in 0..parties {
                s.push(None);
                r.push(None);
            }
            let bytes_sent = 0;
            channels.push(SimpleSyncChannel { s, r, bytes_sent });
        }

        for a in 0..parties {
            for b in 0..parties {
                if a == b {
                    continue;
                }
                let (send_a_to_b, recv_a_to_b) = std::sync::mpsc::channel::<Vec<u8>>();
                let (send_b_to_a, recv_b_to_a) = std::sync::mpsc::channel::<Vec<u8>>();
                channels[a].s[b] = Some(send_a_to_b);
                channels[b].s[a] = Some(send_b_to_a);
                channels[a].r[b] = Some(recv_b_to_a);
                channels[b].r[a] = Some(recv_a_to_b);
            }
        }
        channels
    }
}

#[maybe_async::sync_impl]
impl Channel for SimpleSyncChannel {
    type SendError = UnifiedSendError;
    type RecvError = RecvError;

    fn send_bytes_to(
        &mut self,
        p: usize,
        phase: &str,
        i: usize,
        remaining: usize,
        msg: Vec<u8>,
    ) -> Result<(), UnifiedSendError> {
        self.bytes_sent += msg.len();
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        let i = i + 1;
        let total = i + remaining;
        if i == 1 {
            println!("Sending msg {phase} to party {p} ({mb:.2}MB), {i}/{total}...");
        } else {
            println!("  (sending msg {phase} to party {p} ({mb:.2}MB), {i}/{total})");
        }
        self.s[p]
            .as_ref()
            .unwrap_or_else(|| panic!("No sender for party {p}"))
            .send(msg)
            .map_err(UnifiedSendError::SyncSend)
    }

    fn recv_bytes_from(&mut self, p: usize, _phase: &str, _i: usize) -> Result<Vec<u8>, RecvError> {
        let chunk = self.r[p]
            .as_mut()
            .unwrap_or_else(|| panic!("No receiver for party {p}"));

        match chunk.recv_timeout(std::time::Duration::from_secs(10 * 60)) {
            Ok(chunk) => Ok(chunk),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(RecvError::TimeoutElapsed),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(RecvError::Closed),
        }
    }
}
