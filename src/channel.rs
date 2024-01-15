//! A communication channel used to send/receive messages to/from another party.

use std::{
    fmt,
    sync::mpsc::{channel, Receiver, RecvTimeoutError, SendError, Sender},
    time::Duration,
};

use serde::{de::DeserializeOwned, Serialize};

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
    fn send_bytes(&self, msg: Vec<u8>) -> Result<(), Self::SendError>;

    /// Blocks until it receives a response from the other party.
    fn recv_bytes(&self) -> Result<Vec<u8>, Self::RecvError>;

    /// Serializes and sends an MPC message to the other party.
    fn send(&self, phase: &str, msg: &impl Serialize) -> Result<(), Error> {
        let msg = bincode::serialize(msg).map_err(|e| Error {
            phase: format!("sending {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })?;
        self.send_bytes(msg).map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::SendError(format!("{e:?}")),
        })
    }

    /// Receives and deserializes an MPC message from the other party.
    fn recv<T: DeserializeOwned>(&self, phase: &str) -> Result<T, Error> {
        let msg = self.recv_bytes().map_err(|e| Error {
            phase: phase.to_string(),
            reason: ErrorKind::RecvError(format!("{e:?}")),
        })?;
        bincode::deserialize(&msg).map_err(|e| Error {
            phase: format!("receiving {phase}"),
            reason: ErrorKind::SerdeError(format!("{e:?}")),
        })
    }

    /// Receives and deserializes a Vec from the other party (while checking the length).
    fn recv_vec<T: DeserializeOwned>(&self, phase: &str, len: usize) -> Result<Vec<T>, Error> {
        let v: Vec<T> = self.recv(phase)?;
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

/// A simple synchronous channel that uses `[std::sync::mpsc::Sender]` and
/// `[std::sync::mpsc::Receiver]`.
pub struct SyncChannel {
    s: Sender<Vec<u8>>,
    r: Receiver<Vec<u8>>,
}

impl SyncChannel {
    /// Creates channels for 2 parties to communicate with each other.
    pub fn channels() -> (Self, Self) {
        let (msg_a_send, msg_a_recv) = channel();
        let (msg_b_send, msg_b_recv) = channel();
        let a = SyncChannel {
            s: msg_a_send,
            r: msg_b_recv,
        };
        let b = SyncChannel {
            s: msg_b_send,
            r: msg_a_recv,
        };
        (a, b)
    }
}

impl Channel for SyncChannel {
    type SendError = SendError<Vec<u8>>;
    type RecvError = RecvTimeoutError;

    fn send_bytes(&self, msg: Vec<u8>) -> Result<(), SendError<Vec<u8>>> {
        self.s.send(msg)
    }

    fn recv_bytes(&self) -> Result<Vec<u8>, RecvTimeoutError> {
        self.r.recv_timeout(Duration::from_secs(1))
    }
}
