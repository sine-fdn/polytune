#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(pub usize);

pub type Bytes = Vec<u8>;

pub trait Channel: Sized {
    type Error: Send + Sync + 'static;
    type ChannelId;

    // TODO should this be mut?
    // TODO should it be possible to create a sub-channel to a subset of other parties?
    async fn open_sub_channel(&mut self) -> Result<Self, Self::Error>;
    fn chanel_id(&self) -> Self::ChannelId;

    async fn send(&mut self, to: PartyId, bytes: Bytes) -> Result<(), Self::Error>;
    async fn recv(&mut self, from: PartyId) -> Result<Bytes, Self::Error>;

    async fn send_all(&mut self, to: &[PartyId], bytes: Bytes) -> Result<(), Self::Error>;
    // Should this also return the data sent by the other parties?
    // There could also be a method that combines scatter_all and recv_all to do both,
    // but have the option for just the send part
    async fn scatter_all(&mut self, to: &[PartyId], data: &[Bytes]) -> Result<(), Self::Error>;
    async fn recv_all(&mut self, from: &[PartyId]) -> Result<Vec<Bytes>, Self::Error>;
}

mod reqwest_channel {
    // Note: while it is possible to implement the channel trait using HTTP calls, this is complex.
    // An easier approach for web targets is likely using web sockets which provide bi-directional streams

    use std::{
        collections::{HashMap, HashSet},
        fmt::Write,
        ops::DerefMut,
    };

    use futures::future::join_all;
    use reqwest::{Client, Url};
    use tokio::{
        select,
        sync::{
            Mutex, RwLock,
            mpsc::{self, Receiver, Sender},
            oneshot,
        },
    };

    use crate::complex_channel::{Bytes, Channel, PartyId};

    type ChannelId = Vec<u32>;

    enum Cmd {
        NewChannel(ChannelId, Vec<oneshot::Sender<Receiver<Bytes>>>),
    }

    struct ReqwestChannel {
        client: Client,
        urls: Vec<Url>,
        channel_id: ChannelId,
        next_channel_id: u32,
        recv: Vec<ReqwestChannelReceiver>,
        cmd_sender: Sender<Cmd>,
    }

    enum ReqwestChannelReceiver {
        Channel(oneshot::Receiver<Receiver<Bytes>>),
        Data(Receiver<Bytes>),
    }

    impl ReqwestChannel {
        fn parties(&self) -> usize {
            self.urls.len()
        }
    }

    impl Channel for ReqwestChannel {
        type Error = ();

        type ChannelId = ChannelId;

        async fn open_sub_channel(&mut self) -> Result<Self, Self::Error> {
            let mut channel_id = self.channel_id.clone();
            channel_id.push(self.next_channel_id);
            self.next_channel_id += 1;
            let (sender, recv): (Vec<_>, Vec<_>) = (0..self.parties())
                .map(|_| {
                    let (tx, rx) = oneshot::channel();
                    (tx, ReqwestChannelReceiver::Channel(rx))
                })
                .unzip();
            self.cmd_sender
                .send(Cmd::NewChannel(channel_id.clone(), sender))
                .await
                .unwrap();
            Ok(Self {
                client: self.client.clone(),
                channel_id,
                next_channel_id: 0,
                urls: self.urls.clone(),
                recv,
                cmd_sender: self.cmd_sender.clone(),
            })
        }

        fn chanel_id(&self) -> Self::ChannelId {
            self.channel_id.clone()
        }

        async fn send(&mut self, to: super::PartyId, bytes: Bytes) -> Result<(), Self::Error> {
            let mut url = self.urls[to.0].to_string();
            for cid in self.channel_id.iter() {
                write!(&mut url, "/{cid}").unwrap();
            }
            self.client.post(url).body(bytes).send().await.unwrap();
            Ok(())
        }

        async fn recv(&mut self, from: super::PartyId) -> Result<Bytes, Self::Error> {
            match &mut self.recv[from.0] {
                ReqwestChannelReceiver::Channel(receiver) => {
                    let receiver = receiver.await.unwrap();
                    self.recv[from.0] = ReqwestChannelReceiver::Data(receiver);
                    Box::pin(self.recv(from)).await
                }
                ReqwestChannelReceiver::Data(receiver) => Ok(receiver.recv().await.unwrap()),
            }
        }

        async fn send_all(&mut self, to: &[PartyId], bytes: Bytes) -> Result<(), Self::Error> {
            todo!()
        }

        async fn scatter_all(&mut self, to: &[PartyId], data: &[Bytes]) -> Result<(), Self::Error> {
            todo!()
        }

        async fn recv_all(&mut self, from: &[PartyId]) -> Result<Vec<Bytes>, Self::Error> {
            let from: HashSet<_> = from.iter().copied().collect();
            Ok(join_all(
                self.recv
                    .iter_mut()
                    .enumerate()
                    .filter_map(|(party, recv)| {
                        if from.contains(&PartyId(party)) {
                            Some(async move {
                                // Todo this should be a method or stream impl on ReqwestChannelReceiver
                                match recv {
                                    ReqwestChannelReceiver::Channel(receiver) => {
                                        let mut receiver = receiver.await.unwrap();
                                        let ret = receiver.recv().await.unwrap();
                                        *recv = ReqwestChannelReceiver::Data(receiver);
                                        ret
                                    }
                                    ReqwestChannelReceiver::Data(receiver) => {
                                        receiver.recv().await.unwrap()
                                    }
                                }
                            })
                        } else {
                            None
                        }
                    }),
            )
            .await)
        }
    }

    struct ReqwestChannelManager {
        cmd_receiver: Receiver<Cmd>,
        open_requests: HashMap<(PartyId, ChannelId), oneshot::Sender<Receiver<Bytes>>>,
        buffered_receivers: HashMap<(PartyId, ChannelId), Receiver<Bytes>>,
        // Sender is stored in AxumState
        recv: Receiver<(PartyId, ChannelId, Receiver<Bytes>)>,
    }

    impl ReqwestChannelManager {
        async fn start(&mut self) {
            // todo select on cmd_receiver and recv channel
            loop {
                select! {
                    Some(cmd) = self.cmd_receiver.recv() => {
                        match cmd {
                            Cmd::NewChannel(channel_id, senders) => {
                                for (party_id, sender) in senders.into_iter().enumerate() {
                                    // check if buffered_receivers contains receiver, if yes
                                    // send back via oneshot
                                    // if not, add oneshot to open_requests
                                }
                            },
                        }
                        // handle the command
                    }
                    Some((party_id, channel_id, receiver)) = self.recv.recv() => {
                        // check if there is a corresponding open_request, if yes
                        // send receiver via oneshot
                        // if not, add receiver to buffered_receivers
                    }
                }
            }
        }
    }

    struct AxumState {
        // receiver is stored in ReqwestChannelManager
        senders: RwLock<HashMap<(PartyId, ChannelId), Sender<Bytes>>>,
        receiver_sender: Sender<(PartyId, ChannelId, Receiver<Bytes>)>,
    }

    struct Path<T>(T);

    async fn axum_msg_route(
        mut state: AxumState,
        from: Path<PartyId>,
        channel_id: Path<ChannelId>,
        body: Bytes,
    ) {
        // check if there is a sender in state.senders
        // if yes: send bytes via sender
        // if not: create (sender, receiver) pair, send receiver via
        // state.receiver_sender, send bytes on sender and store sender in
        // state.senders
        // What is tricky is the locking, for inserting we need exclusive access, but
        // for sending, shared is sufficient
        // But if we use RwLock, first lock in read mode and then relock in write mode
        // if we need to insert, we must take care that a second call to axum_msg_rout with
        // the same party and channel_id between the read lock and write lock does not lead
        // to inconsistent state
    }
}

