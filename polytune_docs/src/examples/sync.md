# Sync Channels

We provide a `sync` implementation of our `Channel` trait in Polytune under `examples/sync-channel`. The example uses `SimpleSyncChannel`, a synchronous message-passing channel based on Rust's `std::sync::mpsc` module.

## `SimpleSyncChannel`

- Uses `Sender<Vec<u8>>` and `Receiver<Vec<u8>>` to facilitate communication between parties.
- Provides a method `channels(parties: usize)` to create communication channels between multiple parties.
- Tracks the number of bytes sent for debugging and performance monitoring.

The `SimpleSyncChannel` implements the `Channel` trait from Polytune with the following methods:

### `send_bytes_to`

```rust
fn send_bytes_to(
    &mut self,
    p: usize,
    phase: &str,
    i: usize,
    remaining: usize,
    msg: Vec<u8>
) -> Result<(), std::sync::mpsc::SendError<Vec<u8>>>;
```

- Sends a message to a specified party.
- Logs the progress and size of the message.
- Uses `send` to transmit data over the `Sender`.

### `recv_bytes_from`

```rust
fn recv_bytes_from(
    &mut self,
    p: usize,
    _phase: &str,
    _i: usize,
) -> Result<Vec<u8>, SyncRecvError>;
```

- Receives a message from a specified party.
- Uses `recv_timeout` to wait for messages, with a timeout of 10 minutes.
- Returns a custom error type `SyncRecvError` in case of failure (timeout or closed channel).
