use maybe_async::sync_impl;
use std::sync::mpsc::{Receiver, Sender};

/// A simple synchronous channel using [`Sender`] and [`Receiver`].
#[derive(Debug)]
#[allow(dead_code)]
pub struct SimpleSyncChannel {
    pub(crate) s: Vec<Option<Sender<Vec<u8>>>>,
    pub(crate) r: Vec<Option<Receiver<Vec<u8>>>>,
    pub bytes_sent: usize,
}

#[sync_impl]
impl SimpleSyncChannel {
    /// Creates channels for N parties to communicate with each other.
    pub fn channels(parties: usize) -> Vec<Self> {
        let mut channels = vec![];

        for _ in 0..parties {
            let mut s = vec![];
            let mut r = vec![];
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

/// The error raised by `recv` calls of a [`SimpleSyncChannel`].
#[derive(Debug)]
pub enum SyncRecvError {
    /// The channel has been closed.
    Closed,
    /// No message was received before the timeout.
    TimeoutElapsed,
}

#[sync_impl]
impl polytune::channel::Channel for SimpleSyncChannel {
    type SendError = std::sync::mpsc::SendError<Vec<u8>>;
    type RecvError = SyncRecvError;

    fn send_bytes_to(
        &mut self,
        p: usize,
        phase: &str,
        i: usize,
        remaining: usize,
        msg: Vec<u8>,
    ) -> Result<(), std::sync::mpsc::SendError<Vec<u8>>> {
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
    }

    fn recv_bytes_from(
        &mut self,
        p: usize,
        _phase: &str,
        _i: usize,
    ) -> Result<Vec<u8>, SyncRecvError> {
        let chunk = self.r[p]
            .as_mut()
            .unwrap_or_else(|| panic!("No receiver for party {p}"));

        match chunk.recv_timeout(std::time::Duration::from_secs(10 * 60)) {
            Ok(chunk) => Ok(chunk),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(SyncRecvError::TimeoutElapsed),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(SyncRecvError::Closed),
        }
    }
}
