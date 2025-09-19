use std::sync::mpsc::{Receiver, Sender};

use tokio::io::{AsyncRead, AsyncWrite};

type Bytes = Vec<u8>;
type PartyId = usize;

struct Channels<W: AsyncWrite, R: AsyncRead> {
    writers: Vec<W>,
    readers: Vec<R>,
    command_receiver: Receiver<ChannelCmd>,
    // Todo, this probably needs to be more complex than a Vec, especially with sub-channels
    channel_senders: Vec<Sender<ChannelCmd>>,
}

struct ChannelManager<W: AsyncWrite, R: AsyncRead> {
    channels: Channels<W, R>,
}

impl<W: AsyncWrite, R: AsyncRead> ChannelManager<W, R> {
    // Returns manager and top-level Channel
    fn new(channels: Channels<W, R>) -> (Self, Channel) {
        todo!()
    }

    async fn start(self) {
        // poll readers, and command_receiver
        // where to we write into self.writers ?
        todo!()
    }
}

enum ChannelCmd {
    NewChannel,
    SendData { data: Bytes, to: Vec<PartyId> },
    RecvData { data: Bytes, from: PartyId },
}

struct Channel {
    sender: Sender<ChannelCmd>,
    receiver: Receiver<ChannelCmd>,
}

impl Channel {
    async fn sub_channel() -> Self {
        todo!()
    }
}

// No longer generic
async fn mpc(channel: Channel /*other args */) {}

#[allow(unreachable_code)]
async fn main() {
    let channels: Channels<Bytes, &[u8]> = todo!();

    let (channel_manager, channel) = ChannelManager::new(channels);

    let jh = tokio::spawn(channel_manager.start());

    let result = mpc(channel).await;

    jh.await.expect("Error in Channel manager");
}
