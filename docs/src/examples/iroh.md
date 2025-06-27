# Peer-to-Peer Channels

The `iroh-p2p-channels` example shows how to use peer-to-peer communication with the `iroh` crate. This implementation enables direct connections between parties without relying on a custom server (although the relay server provided by iroh is used by default), while also handling NAT traversal. After establishing connections between peers, the participants communicate directly using QUIC.

The example uses Iroh's `Gossip` protocol (using the `iroh-gossip` crate), which provides a stream of messages that a group of peers can subscribe to. Since Polytune's MPC protocol is maliciously secure, a computation is private and secure even if the other participants can see all the messages that are being transmitted.

## Implementation

The core part of the example is the `IrohChannel`, which implements Polytune's `Channel` trait. It wraps Iroh's `GossipSender` and `GossipReceiver`. Since messages from other participants could arrive while the protocol is waiting for the message from a particular participants, the implementation stores messages that are not being used immediately and discards any messages that are meant for other participants (which it will nevertheless see because all messages are broadcast to all participants).

```rust
struct IrohChannel {
    sender: GossipSender,
    receiver: tokio::sync::Mutex<GossipReceiver>,
    received_msgs: Mutex<HashMap<usize, VecDeque<Vec<u8>>>>,
    party: usize,
}

impl Channel for IrohChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), Self::SendError> {
        tracing::info!("sending msg {} bytes from {} to {p}", msg.len(), self.party);
        let message = Message {
            from_party: self.party,
            to_party: p,
            data: msg,
        };
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        self.sender.broadcast(data).await?;
        Ok(())
    }

    // TODO this implementation seems really dubious to me... I'm really not sure if it behaves
    //  correctly in edge-cases
    async fn recv_bytes_from(&self, p: usize, _info: RecvInfo) -> Result<Vec<u8>, Self::RecvError> {
        tracing::info!("receiving message from {p}");
        {
            let mut msgs_lock = self.received_msgs.lock().expect("poisoned");
            if let Some(msgs) = msgs_lock.get_mut(&p) {
                if let Some(msg) = msgs.pop_front() {
                    tracing::info!("found stored message from {p}");
                    return Ok(msg);
                }
            }
        }
        tracing::info!("could not find stored message, waiting for message...");
        let mut receiver = self.receiver.lock().await;
        while let Some(event) = receiver.try_next().await? {
            if let Event::Gossip(GossipEvent::Received(msg)) = event {
                let msg: Message = postcard::from_bytes(&msg.content)?;
                if msg.to_party == self.party {
                    if msg.from_party == p {
                        tracing::info!("received {} bytes from {p}", msg.data.len());
                        return Ok(msg.data);
                    } else {
                        tracing::debug!(
                            "received {} bytes, storing message from {} for now",
                            msg.data.len(),
                            msg.from_party,
                        );
                        self.received_msgs
                            .lock()
                            .expect("poisoned")
                            .entry(msg.from_party)
                            .or_default()
                            .push_back(msg.data);
                    }
                } else {
                    tracing::debug!(
                        "Ignoring message from {} to {}",
                        msg.from_party,
                        msg.to_party
                    );
                }
            } else {
                tracing::trace!("{event:?}");
            }
        }
        bail!("Expected to receive an event!")
    }
}
```

## Differences from Previous Implementations

Compared to the HTTP-based and WebAssembly implementations:

1. **No Central Server** - Connects parties directly without a message relay server
2. **Connection Management** - Maintains long-lived QUIC connections between parties
3. **NAT Traversal** - Built-in capabilities to work across different networks
4. **Streaming Protocol** - Uses QUIC streams instead of discrete HTTP requests
5. **Message Broadcast** - Messages are broadcast to all participants

## Basic Usage Example

This will compute 2 + 2 + 2 using 3 parties:

```bash
# Start a new MPC session as party 0
$ cargo run --release -- --program=.add.garble.rs --party=0 --input=2 new
> opening chat room for topic b8a13fe83f6a88a4101b15dc26ef4fde6c1d26dfa2f88a980a57f1623313ee47
> our secret key: 5845b639ed926fde7922467655b35f66957e827aebad137af7cdbc035df69459
> our node id: 99dbc053090f77672ffe56d2c9fa5ea84171c46552d2ded82a1d9be8be2caefc
> ticket to join us: xcqt72b7nkekiea3cxocn32p3zwb2jw7ul4ivgakk7ywemyt5zdqdgo3ybjqsd3xm4x74vwszh5f5kcbohcgkuws33mcuhm35c7czlx4aerwq5duobztulzpmv2xomjngexhezlmmf4s42lsn5uc43tfor3w64tlfyxquaboxxcuz7f4amambkabjl6lyaybeaaqqgg4updaademoh5uyclg3h63yaybeaaqqgg4updaaii3txp7qpac4x63yaybeaaqqgg4updaapjil56crg3djp63yaybeaaqqgg4updaawlu4vd5c6utnl63yaybeaaqqgg4updabrktykued3y74363yaybeaaqqgg4updabudckq4z5diczt63yaybeaaqqgg4updabupp6dacbeypgt63yaybeaaqqgg4updabzh3wenvtbbp7t63yay
> waiting for peers to join us...
# Now join the session as party 1
$ cargo run --release -- --program=.add.garble.rs --party=1 --input=2 join xcqt72b7nkekiea3cxocn32p3zwb2jw7ul4ivgakk7ywemyt5zdqdgo3ybjqsd3xm4x74vwszh5f5kcbohcgkuws33mcuhm35c7czlx4aerwq5duobztulzpmv2xomjngexhezlmmf4s42lsn5uc43tfor3w64tlfyxquaboxxcuz7f4amambkabjl6lyaybeaaqqgg4updaademoh5uyclg3h63yaybeaaqqgg4updaaii3txp7qpac4x63yaybeaaqqgg4updaapjil56crg3djp63yaybeaaqqgg4updaawlu4vd5c6utnl63yaybeaaqqgg4updabrktykued3y74363yaybeaaqqgg4updabudckq4z5diczt63yaybeaaqqgg4updabupp6dacbeypgt63yaybeaaqqgg4updabzh3wenvtbbp7t63yay
> trying to decode ticket...
> joining chat room for topic b8a13fe83f6a88a4101b15dc26ef4fde6c1d26dfa2f88a980a57f1623313ee47
> our secret key: 7b98c0ebc64276f40f20ecc9393b2fb86cb81f1f66e3fbb123a029588fdd50aa
> our node id: 1c1e81fafc4ac39397e6d1672c3f6c10c5500ed4055071e1fc124a5cbdb59b65
> trying to connect to 1 peers...
> connected, other peers have 20 time to join before the computation starts!
# Finally join as party 2, starting the computation
$ cargo run --release -- --program=.add.garble.rs --party=2 --input=2 join xcqt72b7nkekiea3cxocn32p3zwb2jw7ul4ivgakk7ywemyt5zdqdgo3ybjqsd3xm4x74vwszh5f5kcbohcgkuws33mcuhm35c7czlx4aerwq5duobztulzpmv2xomjngexhezlmmf4s42lsn5uc43tfor3w64tlfyxquaboxxcuz7f4amambkabjl6lyaybeaaqqgg4updaademoh5uyclg3h63yaybeaaqqgg4updaaii3txp7qpac4x63yaybeaaqqgg4updaapjil56crg3djp63yaybeaaqqgg4updaawlu4vd5c6utnl63yaybeaaqqgg4updabrktykued3y74363yaybeaaqqgg4updabudckq4z5diczt63yaybeaaqqgg4updabupp6dacbeypgt63yaybeaaqqgg4updabzh3wenvtbbp7t63yay
> trying to decode ticket...
> joining chat room for topic b8a13fe83f6a88a4101b15dc26ef4fde6c1d26dfa2f88a980a57f1623313ee47
> our secret key: 7b98c0ebc64276f40f20ecc9393b2fb86cb81f1f66e3fbb123a029588fdd50aa
> our node id: 1c1e81fafc4ac39397e6d1672c3f6c10c5500ed4055071e1fc124a5cbdb59b65
> trying to connect to 1 peers...
> connected, other peers have 20 time to join before the computation starts!
> starting the computation...
```
