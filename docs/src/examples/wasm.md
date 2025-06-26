# WASM HTTP Channels

This example covers implementing the `Channel` trait for WebAssembly (WASM) environments, allowing MPC computation to run in web browsers. The implementation consists of two components:

1. **Message Broker Server** - A lightweight relay server that routes messages between parties
2. **WASM Client** - A browser-compatible implementation of the `Channel` trait

## Message Broker Server

The broker server acts as a central relay for messages between parties participating in MPC computations. It supports multiple concurrent sessions.

```rust
// Create a simple relay server with endpoints for sending and receiving messages
let app = Router::new()
    .route("/ping", get(ping))
    .route("/session/:session/send/:from/:to", post(send))
    .route("/session/:session/recv/:from/:to", post(recv))
    .with_state(state)
    // CORS enabled for browser compatibility
    .layer(cors)
    // Support large messages (up to 1000MB)
    .layer(DefaultBodyLimit::max(1000 * 1024 * 1024))
    .layer(TraceLayer::new_for_http());
```

Key features include:

- Session-based message queuing
- CORS support for browser access
- Long polling for message retrieval (with 30-second timeout)

## WASM Client Implementation

The WASM client implements the `Channel` trait to enable MPC computation in browsers.

```rust
impl Channel for HttpChannel {
    type SendError = String;
    type RecvError = String;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), Self::SendError> {
        let client = reqwest::Client::new();
        let url = format!("{}send/{}/{}", self.url, self.party, p);
        for _ in 0..50 {
            let Ok(resp) = client.post(&url).body(msg.clone()).send().await else {
                println!("Could not reach party {p} at {url}...");
                TimeoutFuture::new(100).await;
                continue;
            };
            match resp.status() {
                StatusCode::OK => return Ok(()),
                status => eprintln!("Unexpected status code: {status}"),
            }
            TimeoutFuture::new(100).await;
        }
        return Err(format!("Could not reach {url}"));
    }

    async fn recv_bytes_from(
        &mut self,
        p: usize,
        _info: RecvInfo,
    ) -> Result<Vec<u8>, Self::RecvError> {
        // Implementation with retries and timeouts
        // ...
    }
}
```

## When to Use WASM Channel Implementation

This implementation is ideal for:

1. **Browser-Based MPC** - When computation needs to run directly in web browsers
2. **Interactive Web Applications** - For user-facing applications requiring secure computation
3. **Cross-Platform Deployment** - When the same code needs to run on web and native platforms
4. **Public-Facing Applications** - When the MPC protocol needs to be accessed by many users

## Usage Pattern

The typical usage flow involves:

1. Deploy the message broker server (exposed publicly)
2. Compile the WASM client to JavaScript/WASM using `wasm-pack`
3. Import and use the WASM module in a web application

### JavaScript Integration Example

```javascript
import { compute } from "mpc-wasm";

async function runMpcComputation() {
  try {
    const result = await compute(
      "https://broker-server.example.com/session/demo-session/",
      0, // party ID
      42, // input value
      10 // range parameter
    );
    console.log("MPC result:", result);
  } catch (error) {
    console.error("MPC computation failed:", error);
  }
}
```

## Implementation Differences

Compared to the previous `Channel` implementations, the WASM version:

1. **Uses Simpler Error Types** - String-based errors for JS compatibility
2. **Employs Web-Compatible Timeouts** - Uses `gloo_timers` instead of Tokio's sleep
3. **Has Session Management Built-in** - URL patterns include session IDs
4. **Uses Long Polling** - Both client and server implement polling with retry logic
5. **Has CORS Support** - Enabled for cross-origin requests in browsers

## Security Considerations

- The broker server should be deployed with HTTPS in production
- No authentication mechanism is included (consider adding one for production)
- Browser security restrictions apply (CORS, etc.)
- All parties must trust the relay server not do drop messages
