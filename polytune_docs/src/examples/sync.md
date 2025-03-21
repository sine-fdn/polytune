# Sync Channels

We provide a `sync` implementation of our `Channel` trait in Polytune under `examples/sync-channel`. We call this a `SimpleSyncChannel` and implement the `send_bytes_to` and `recv_bytes_from` methods in a synchronous manner.

We provide a test that simulates an MPC computation using this `SimpleSyncChannel` for communication between the parties.
