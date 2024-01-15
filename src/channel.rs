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

    /// Sends a message to the other party.
    fn send_bytes(
        &mut self,
        msg: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::SendError>> + Send;

    /// Blocks until it receives a response from the other party.
    fn recv_bytes(&mut self) -> impl Future<Output = Result<Vec<u8>, Self::RecvError>> + Send;
}

/// A wrapper around [`Channel`] that takes care of (de-)serializing messages.
pub struct MsgChannel<C: Channel>(C);

impl<C: Channel> MsgChannel<C> {
    /// Serializes and sends an MPC message to the other party.
    pub(crate) async fn send(&mut self, phase: &str, msg: &impl Serialize) -> Result<(), Error> {
        let msg = bincode::serialize(msg).map_err(|e| Error {
            phase: format!("sending {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })?;
        self.0.send_bytes(msg).await.map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::SendError(format!("{e:?}")),
        })
    }

    /// Receives and deserializes an MPC message from the other party.
    pub(crate) async fn recv<T: DeserializeOwned>(&mut self, phase: &str) -> Result<T, Error> {
        let msg = self.0.recv_bytes().await.map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::RecvError(format!("{e:?}")),
        })?;
        bincode::deserialize(&msg).map_err(|e| Error {
            phase: format!("receiving {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })
    }

    /// Receives and deserializes a Vec from the other party (while checking the length).
    pub(crate) async fn recv_vec<T: DeserializeOwned>(
        &mut self,
        phase: &str,
        len: usize,
    ) -> Result<Vec<T>, Error> {
        let v: Vec<T> = self.recv(phase).await?;
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
pub struct SimpleChannel {
    s: Sender<Vec<u8>>,
    r: Receiver<Vec<u8>>,
}

impl SimpleChannel {
    /// Creates channels for 2 parties to communicate with each other.
    pub fn channels() -> (MsgChannel<Self>, MsgChannel<Self>) {
        let buffer_capacity = 1024;
        let (msg_a_send, msg_a_recv) = channel(buffer_capacity);
        let (msg_b_send, msg_b_recv) = channel(buffer_capacity);
        let a = MsgChannel(SimpleChannel {
            s: msg_a_send,
            r: msg_b_recv,
        });
        let b = MsgChannel(SimpleChannel {
            s: msg_b_send,
            r: msg_a_recv,
        });
        (a, b)
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

    async fn send_bytes(&mut self, msg: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        self.s.send(msg).await
    }

    async fn recv_bytes(&mut self) -> Result<Vec<u8>, AsyncRecvError> {
        match timeout(Duration::from_secs(1), self.r.recv()).await {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(AsyncRecvError::Closed),
            Err(_) => Err(AsyncRecvError::TimeoutElapsed),
        }
    }
}
