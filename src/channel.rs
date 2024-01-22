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

    /// Returns the number of participants.
    fn participants(&self) -> usize;
}

/// A wrapper around [`Channel`] that takes care of (de-)serializing messages.
#[derive(Debug)]
pub struct MsgChannel<C: Channel>(C);

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

    pub(crate) fn participants(&self) -> usize {
        self.0.participants()
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
    pub fn channels(parties: usize) -> Vec<MsgChannel<Self>> {
        let buffer_capacity = 1024;
        let mut channels = vec![];
        for _ in 0..parties {
            let mut s = vec![];
            let mut r = vec![];
            for _ in 0..parties {
                s.push(None);
                r.push(None);
            }
            channels.push(MsgChannel(SimpleChannel { s, r }));
        }
        for a in 0..parties {
            for b in 0..parties {
                if a == b {
                    continue;
                }
                let (send_a_to_b, recv_a_to_b) = channel(buffer_capacity);
                let (send_b_to_a, recv_b_to_a) = channel(buffer_capacity);
                channels[a].0.s[b] = Some(send_a_to_b);
                channels[b].0.s[a] = Some(send_b_to_a);
                channels[a].0.r[b] = Some(recv_b_to_a);
                channels[b].0.r[a] = Some(recv_a_to_b);
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

    async fn send_bytes_to(
        &mut self,
        party: usize,
        msg: Vec<u8>,
    ) -> Result<(), SendError<Vec<u8>>> {
        self.s[party].as_ref().unwrap().send(msg).await
    }

    async fn recv_bytes_from(&mut self, party: usize) -> Result<Vec<u8>, AsyncRecvError> {
        match timeout(
            Duration::from_secs(1),
            self.r[party].as_mut().unwrap().recv(),
        )
        .await
        {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(AsyncRecvError::Closed),
            Err(_) => Err(AsyncRecvError::TimeoutElapsed),
        }
    }

    fn participants(&self) -> usize {
        self.s.len()
    }
}
