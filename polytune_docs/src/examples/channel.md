# Customizable Communication Channels

The `Channel` trait in our MPC engine provides a flexible and extensible abstraction for message-passing between parties. It allows communication to be implemented in various ways, enabling users to choose between synchronous, asynchronous, and even platform-specific implementations. Polytune is deliberately communication-agnostic, while remaining quite flexible, offering the following features:

- **Customizable Transport**: Implement the `Channel` trait using any transport mechanism — HTTP, WebSockets, in-memory queues, or custom networking protocols.
- **Sync & Async Support**: Thanks to `maybe_async`, our trait seamlessly supports both synchronous and asynchronous implementations.
- **Serialization-Aware**: The trait ensures that messages can be efficiently serialized and chunked when necessary, making it ideal for large payloads.

We provide example implementations for:

- Rust async channels using `tokio::sync::mpsc`
- Rust sync channels using `std::sync::mpsc`
- HTTP channels for distributed deployments for servers
- WebAssembly-compatible HTTP channels for clients
- Peer-to-Peer channels

## `Channel` Trait Definition

The `Channel` trait defines two core methods for sending and receiving messages:

```rust
#[maybe_async(AFIT)]
pub trait Channel {
    type SendError: fmt::Debug;
    type RecvError: fmt::Debug;

    async fn send_bytes_to(
        &mut self,
        party: usize,
        phase: &str,
        i: usize,
        remaining: usize,
        chunk: Vec<u8>,
    ) -> Result<(), Self::SendError>;

    async fn recv_bytes_from(
        &mut self,
        party: usize,
        phase: &str,
        i: usize,
    ) -> Result<Vec<u8>, Self::RecvError>;
}
```
