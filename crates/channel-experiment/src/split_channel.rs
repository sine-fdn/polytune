//! ## Requirements
//! - Concurrent sending/receiving
//! - hierarchically organized multiplexed sub-channels
//!     - e.g. i have two separate channels c1 and c2. If I create a sub-channel on c1 and one on c2 concurrently,
//!     it is guaranteed that their correctly matched up (this can be achieved with a tree of IDs)
//! - can't send to the same party on the same channel at the same time (this could easily lead to corrupt data)
//! - actual implementations should be possible be done with QUIC (e.g. s2n_quic) or other transports (e.g. web sockets or HTTP requests)
//! 
//! The following design is based on the two-party communication abstraction implemented here https://github.com/robinhundt/CryProt/blob/main/cryprot-net/src/lib.rs
//! But tries to enable multi-party communication and does not restrict the transport to QUIC.

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(pub usize);

pub type Bytes = Vec<u8>;

trait SendChannel {
    type Error;

    fn parties(&self) -> &[PartyId];
    async fn send(&mut self, data: Bytes) -> Result<(), Self::Error>;
    async fn send_scatter(&mut self, data: Vec<Bytes>) -> Result<(), Self::Error>;
}

trait RecvChannel {
    type Error;

    fn parties(&self) -> &[PartyId];
    async fn recv(&mut self) -> Result<Vec<Bytes>, Self::Error>;
}

trait Channel {
    type Error;
    // Note: Drawback of having these potentially borrow self is that we can't use these
    // halfs in a spawned task, as they're not 'static
    // However, I think this might be fine if we only use it in the future which also created
    // the sub stream
    type SendChannel<'ch>: SendChannel
    where
        Self: 'ch;
    type RecvChannel<'ch>: RecvChannel
    where
        Self: 'ch;

    /// Maximum valid PartyId that can be passed to sub-channel.
    /// This Id might not be part of `channel_parties` but it must be valid to pass it to
    /// `sub_channel`, i.e. `sub_channel` can widen the parties a channel communicates with
    fn max_party_id(&self) -> PartyId;
    /// Parties this channel was created for.
    fn channel_parties(&self) -> &[PartyId];


    /// Open a sub-channel to potentially a subset of the other connected parties.
    /// 
    /// If a sub-channel is created for a subset of parties, it should be possible from this
    /// channel to create a sub-channel for a superset of the parties again.
    /// 
    /// TODO: What are the implications of this requirements, especially with respect to channel ID
    /// allocation?
    async fn sub_channel(&mut self, to: &[PartyId]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    async fn broadcast(&mut self, data: Bytes) -> Result<Vec<Bytes>, Self::Error> {
        let (mut send, mut recv) = self.split();
        let (_, res) = tokio::join!(send.send(data), recv.recv());
        Ok(res.map_err(|_| ()).unwrap())
    }

    async fn scatter(&mut self, data: Vec<Bytes>) -> Result<Vec<Bytes>, Self::Error> {
        let (mut send, mut recv) = self.split();
        let (_, res) = tokio::join!(send.send_scatter(data), recv.recv());
        Ok(res.map_err(|_| ()).unwrap())
    }

    fn split(&mut self) -> (Self::SendChannel<'_>, Self::RecvChannel<'_>);
}

mod example {
    use crate::split_channel::{Bytes, Channel, RecvChannel, SendChannel};

    struct Writer;

    impl Writer {
        async fn send(&mut self) {
            todo!()
        }
    }

    type ChannelId = Vec<u32>;

    struct Ch {
        writers: Vec<Writer>,
        channel_id: ChannelId,
        next_sub_channel_id: u32
    }

    struct SendCh<'ch> {
        writers: Vec<&'ch mut Writer>,
    }

    impl<'ch> SendChannel for SendCh<'ch> {
        type Error = ();

        fn parties(&self) -> &[super::PartyId] {
            todo!()
        }

        async fn send(&mut self, data: super::Bytes) -> Result<(), Self::Error> {
            // Do that for all writers
            self.writers[0].send().await;
            todo!()
        }

        async fn send_scatter(&mut self, data: Vec<Bytes>) -> Result<(), Self::Error> {
            todo!()
        }
    }

    struct RecvCh;
    impl RecvChannel for RecvCh {
        type Error = ();

        fn parties(&self) -> &[super::PartyId] {
            todo!()
        }

        async fn recv(&mut self) -> Result<Vec<super::Bytes>, Self::Error> {
            todo!()
        }
    }

    impl Channel for Ch {
        type Error = ();

        type SendChannel<'ch> = SendCh<'ch>;

        type RecvChannel<'ch> = RecvCh;

        async fn sub_channel(&mut self, to: &[super::PartyId]) -> Result<Self, Self::Error>
        where
            Self: Sized,
        {
            // construct next channel id of sub-channel in tree of channels
            let mut channel_id = self.channel_id.clone();
            channel_id.push(self.next_sub_channel_id);
            self.next_sub_channel_id += 1;

            // this Id is used with ChannelManager (not shown here and heavily depends on underlying transport)
            // to create new sub-channel
            // E.g. when using QUIC, you'd have a https://docs.rs/s2n-quic/latest/s2n_quic/connection/struct.Handle.html for each
            // party in the channel struct, this is used to `open_bidirectional_stream`s with each party and the channel_id is sent
            // as the first message. The ChannelManager has https://docs.rs/s2n-quic/latest/s2n_quic/connection/struct.StreamAcceptor.html 
            // for each party which is polled and when a new stream is accepted, the channel id sent as the first message is read. This channel id
            // is used to map the the newly created QuicStream to the correct SubChannel. The QuicStreams are communicated to the SubChannel via an in-memory
            // channel. An example of such a design is implemented here https://github.com/robinhundt/CryProt/blob/main/cryprot-net/src/lib.rs
            todo!()
        }

        fn split(&mut self) -> (Self::SendChannel<'_>, Self::RecvChannel<'_>) {
            let sender = SendCh {
                writers: self.writers.iter_mut().collect(),
            };
            (sender, RecvCh)
        }
        
        fn max_party_id(&self) -> super::PartyId {
            todo!()
        }
        
        fn channel_parties(&self) -> &[super::PartyId] {
            todo!()
        }
    }
}
