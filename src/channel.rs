//! A communication channel used to send/receive messages to/from another party.

use std::{fmt, future::Future, time::Duration};

use serde::{de::DeserializeOwned, Serialize};
use tokio::{
    sync::mpsc::{channel, error::SendError, Receiver, Sender},
    time::timeout,
};

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
pub trait Channel {
    /// The error that can occur sending messages over the channel.
    type SendError: fmt::Debug;
    /// The error that can occur receiving messages over the channel.
    type RecvError: fmt::Debug;

    /// Sends a message to the party with the given index (must be between `0..participants`).
    fn send_bytes_to(
        &mut self,
        party: usize,
        msg: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::SendError>> + Send;

    /// Awaits a response from the party with the given index (must be between `0..participants`).
    fn recv_bytes_from(
        &mut self,
        party: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Self::RecvError>> + Send;
}

/// A wrapper around [`Channel`] that takes care of (de-)serializing messages.
#[derive(Debug)]
pub(crate) struct MsgChannel<C: Channel>(pub C);

impl<C: Channel> MsgChannel<C> {
    /// Serializes and sends an MPC message to the other party.
    pub(crate) async fn send_to(
        &mut self,
        party: usize,
        phase: &str,
        msg: &impl Serialize,
    ) -> Result<(), Error> {
        let msg = bincode::serialize(msg).map_err(|e| Error {
            phase: format!("sending {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })?;
        self.0.send_bytes_to(party, msg).await.map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::SendError(format!("{e:?}")),
        })
    }

    /// Receives and deserializes an MPC message from the other party.
    pub(crate) async fn recv_from<T: DeserializeOwned>(
        &mut self,
        party: usize,
        phase: &str,
    ) -> Result<T, Error> {
        let msg = self.0.recv_bytes_from(party).await.map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::RecvError(format!("{e:?}")),
        })?;
        bincode::deserialize(&msg).map_err(|e| Error {
            phase: format!("receiving {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })
    }

    /// Receives and deserializes a Vec from the other party (while checking the length).
    pub(crate) async fn recv_vec_from<T: DeserializeOwned>(
        &mut self,
        party: usize,
        phase: &str,
        len: usize,
    ) -> Result<Vec<T>, Error> {
        let v: Vec<T> = self.recv_from(party, phase).await?;
        if v.len() == len {
            Ok(v)
        } else {
            Err(Error {
                phase: phase.to_string(),
                reason: ErrorKind::InvalidLength,
            })
        }
    }
}

/// A simple synchronous channel using [`Sender`] and [`Receiver`].
#[derive(Debug)]
pub struct SimpleChannel {
    s: Vec<Option<Sender<Vec<u8>>>>,
    r: Vec<Option<Receiver<Vec<u8>>>>,
}

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
            channels.push(SimpleChannel { s, r });
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
                channels[a].r[b] = Some(recv_b_to_a);
                channels[b].r[a] = Some(recv_a_to_b);
            }
        }
        channels
    }
}

#[derive(Debug)]
/// The error raised by `recv` calls of a [`SimpleChannel`].
pub enum AsyncRecvError {
    /// The channel has been closed.
    Closed,
    /// No message was received before the timeout.
    TimeoutElapsed,
}

impl Channel for SimpleChannel {
    type SendError = SendError<Vec<u8>>;
    type RecvError = AsyncRecvError;

    async fn send_bytes_to(&mut self, p: usize, msg: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        println!("Sending msg to party {p} ({mb:.2}MB)...");
        let chunk_size = 100 * 1024 * 1024;
        let mut chunks: Vec<_> = msg.chunks(chunk_size).collect();
        if chunks.is_empty() {
            chunks.push(&[]);
        }
        let length = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            if length > 1 {
                println!("  (Sending chunk {}/{} to party {})", i + 1, length, p);
            }
            let mut msg = Vec::with_capacity(2 * 4 + chunk.len());
            msg.extend((i as u32).to_be_bytes());
            msg.extend((length as u32).to_be_bytes());
            msg.extend(chunk);
            self.s[p]
                .as_ref()
                .unwrap_or_else(|| panic!("No sender for party {p}"))
                .send(msg)
                .await?;
        }
        Ok(())
    }

    async fn recv_bytes_from(&mut self, p: usize) -> Result<Vec<u8>, AsyncRecvError> {
        let mut msg: Vec<u8> = vec![];
        loop {
            let chunk = self.r[p]
                .as_mut()
                .unwrap_or_else(|| panic!("No receiver for party {p}"))
                .recv();
            let chunk = match timeout(Duration::from_secs(10 * 60), chunk).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return Err(AsyncRecvError::Closed),
                Err(_) => return Err(AsyncRecvError::TimeoutElapsed),
            };
            let i = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let length = u32::from_be_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            msg.extend(&chunk[8..]);
            if i == length - 1 {
                break Ok(msg);
            }
        }
    }
}
