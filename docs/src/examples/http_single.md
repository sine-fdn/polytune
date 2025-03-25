# HTTP Single-Server Channels

The `PollingHttpChannel` provides an implementation of the `Channel` trait that uses a centralized HTTP server to relay messages between participants in a Multi-Party Computation (MPC) system.

## Key Differences from HTTP Multi-Server Channels

Unlike the previous `HttpChannel` implementation which establishes direct connections between parties, `PollingHttpChannel`:

1. **Uses a central relay server** - All communication passes through a dedicated server
2. **Employs session management** - Supports multiple concurrent MPC sessions on the same server
3. **Uses a polling mechanism** - Periodically checks for messages rather than maintaining open connections
4. **Has explicit participation tracking** - Parties must join a session before communication begins

## Implementation Highlights

```rust
pub(crate) struct PollingHttpChannel {
    pub(crate) url: String,
    pub(crate) session: String,
    pub(crate) party: usize,
    pub(crate) client: reqwest::Client,
}

impl Channel for PollingHttpChannel {
    type SendError = HttpChannelError;
    type RecvError = HttpChannelError;

    async fn send_bytes_to(
        &mut self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), HttpChannelError> {
        let url = format!("{}/send/{}/{}/{}", self.url, self.session, self.party, p);
        let resp: reqwest::Response = self.client.post(url).body(msg).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(HttpChannelError::UnexpectedStatusCode(resp.status()))
        }
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _info: RecvInfo,
    ) -> Result<Vec<u8>, HttpChannelError> {
        let url = format!("{}/recv/{}/{}/{}", self.url, self.session, p, self.party);
        let mut attempts = 0;
        loop {
            let resp = self.client.post(&url).send().await?;
            if resp.status() == StatusCode::BAD_REQUEST {
                attempts += 1;
                if attempts >= 10 {
                    return Err(HttpChannelError::Timeout);
                }
                sleep(Duration::from_millis(200)).await;
                continue;
            }
            if !resp.status().is_success() {
                return Err(HttpChannelError::UnexpectedStatusCode(resp.status()));
            }
            let bytes: Vec<u8> = resp.bytes().await?.into();
            return Ok(bytes);
        }
    }
}
```

## When to Use PollingHttpChannel

This implementation is ideal for:

1. **NAT/Firewall Traversal** - When direct connections between parties aren't possible due to network limitations
2. **Multiple Independent Sessions** - When you need to run multiple MPC computations concurrently
3. **Dynamic Participant Management** - When participants may join/leave at different times
4. **Simplified Deployment** - When you want to avoid configuring direct connections between all parties

## Usage Scenario

The typical usage pattern involves three roles:

1. **Relay Server** - A central server that routes messages between parties
2. **Trusted Dealer** - Optional pre-computation role that generates correlated randomness
3. **Computing Parties** - Participants that contribute inputs and receive results

### Basic Usage Example

```shell
// Start the relay server
$ polytune serve

// Initialize as trusted dealer (optional)
$ polytune pre http://server-address --session=my-session --parties=3

// Join as a computing party
$ polytune party http://server-address --session=my-session --program=my-program.garble --party=0 --input="123u32"
```

## Implementation Notes

1. **Session Management** - Each computation is identified by a unique session string
2. **Polling Mechanism** - Uses retries with backoff for message retrieval
3. **Participant Coordination** - Waits for all parties to join before computation begins
4. **Error Handling** - Custom error types for timeouts and connection issues

## Security Considerations

- This implementation sends data in plaintext - secure only for trusted networks
- The relay server can see all communication between parties
- Consider adding TLS for transport security in production environments
