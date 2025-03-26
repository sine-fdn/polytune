# HTTP Multi-Server Channels

The `HttpChannel` enables multi-party computation (MPC) over a network by sending messages between parties using HTTP requests. Each party runs a server to receive messages and a client to send them.

- Suitable for distributed environments where parties communicate over a network.
- Ideal when parties run on separate servers and need a simple, HTTP-based transport layer.

## How It Works

- Each party starts an HTTP server using `axum`.
- Messages are sent via HTTP `POST` requests using `reqwest`.
- Messages are received through an HTTP endpoint (`/msg/:from`) and forwarded to an async channel.

## Example Implementation: HTTP Channel

The following example shows how to implement a `Channel` trait using HTTP communication:

```rust
struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    recv: Vec<Receiver<Vec<u8>>>,
}

impl HttpChannel {
    async fn new(urls: Vec<Url>, party: usize) -> Result<Self, Error> {
        let port = urls[party].port().expect("All URLs must specify a port");
        let recv = serve(port, urls.len()).await?;
        Ok(Self { urls, party, recv })
    }
}

impl Channel for HttpChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &mut self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), Self::SendError> {
        let client = reqwest::Client::new();
        let url = format!("{}msg/{}", self.urls[p], self.party);
        loop {
            let Ok(resp) = client.post(&url).body(msg.clone()).send().await else {
                println!("Could not reach party {p} at {url}...");
                sleep(Duration::from_millis(200)).await;
                continue;
            };
            match resp.status() {
                StatusCode::OK => return Ok(()),
                StatusCode::NOT_FOUND => {
                    println!("Could not reach party {p} at {url}...");
                    sleep(Duration::from_millis(200)).await;
                }
                status => anyhow::bail!("Unexpected status code: {status}"),
            }
        }
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _info: RecvInfo,
    ) -> Result<Vec<u8>, Self::RecvError> {
        Ok(timeout(Duration::from_secs(1), self.recv[p].recv())
            .await
            .context("recv_bytes_from({p})")?
            .unwrap_or_default())
    }
}
```
