# Peer-to-Peer Channels

> ⚠️ **Note**  
> The iroh p2p example uses an old version of iroh and relies on a trusted dealer as a third party. We will update the example as soon as possible to use a more recent version of iroh and communicate without the need for another party.

The `IrohChannel` implements the `Channel` trait using peer-to-peer (P2P) communication powered by the Iroh network library. This implementation enables direct connections between parties without relying on a central relay server, while also handling NAT traversal.

## Key Features

- **True Peer-to-Peer Communication** - Direct connections between participants using QUIC
- **NAT Traversal** - Works across different networks using DERP relay servers
- **Connection Discovery** - Dynamic discovery of other participants through a coordinator
- **Efficient Streaming** - Uses QUIC's unidirectional streams for efficient message passing

The Iroh implementation uses a hybrid model:

1. One party (the preprocessor) acts as the initial coordinator
2. Other parties connect to the coordinator first
3. The coordinator shares connection information with all parties
4. Parties establish direct P2P connections with each other
5. MPC protocol runs across the established connections

## Implementation

The `IrohChannel` is remarkably simple, leveraging Iroh's networking capabilities:

```rust
pub(crate) struct IrohChannel {
    pub(crate) conns: Vec<Option<Connection>>,
    pub(crate) max_msg_bytes: usize,
}

impl Channel for IrohChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &mut self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), Self::SendError> {
        info!("sending {} bytes to {p}", msg.len());
        let mut send = self.conns[p].as_ref().unwrap().open_uni().await?;
        send.write_all(&msg).await?;
        send.finish().await?;
        Ok(())
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _info: RecvInfo,
    ) -> Result<Vec<u8>, Self::RecvError> {
        let mut recv = self.conns[p].as_ref().unwrap().accept_uni().await?;
        let msg = recv.read_to_end(self.max_msg_bytes).await?;
        info!("received {} bytes from {p}", msg.len());
        Ok(msg)
    }
}
```

## Differences from Previous Implementations

Compared to the HTTP-based and WebAssembly implementations:

1. **No Central Server** - Connects parties directly without a message relay server
2. **Connection Management** - Maintains long-lived QUIC connections between parties
3. **NAT Traversal** - Built-in capabilities to work across different networks
4. **Streaming Protocol** - Uses QUIC streams instead of discrete HTTP requests
5. **Coordination Phase** - Initial phase to discover and connect all parties

## Basic Usage Example

```bash
# Start the preprocessor (coordinator)
$ cargo run -- pre --parties=3
# The preprocessor outputs connection information

# Join as party 0
$ cargo run -- party --node-id=<NODE_ID> --addrs=<ADDRS> --derp-url=<URL> --program=prog.gb --party=0 --input="123u32"

# Join as party 1
$ cargo run -- party --node-id=<NODE_ID> --addrs=<ADDRS> --derp-url=<URL> --program=prog.gb --party=1 --input="456u32"

# Join as party 2
$ cargo run -- party --node-id=<NODE_ID> --addrs=<ADDRS> --derp-url=<URL> --program=prog.gb --party=2 --input="789u32"
```

## When to Use Iroh P2P Channels

This implementation is ideal for:

1. **Distributed Applications** - When you want to avoid central infrastructure
2. **High-Performance MPC** - For lower latency and higher throughput
3. **NAT-Traversal Requirements** - When parties are on different networks
4. **Strong Security Requirements** - For end-to-end encrypted communications
5. **Offline/Local Network Scenarios** - Can work without internet connectivity (for local peers)
