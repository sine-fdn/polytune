# MPC Protocol

The [[WRK17]](https://eprint.iacr.org/2017/189.pdf) protocol is an MPC protocol designed to allow collaborative computation between multiple parties while maintaining strong security guarantees. It enables multiple parties to jointly compute a function over their private inputs **without revealing those inputs** to each other.

The WRK17 protocol is based on **garbled circuits** and **preprocessing-based MPC**, allowing efficient execution in **dishonest-majority settings**. In these settings, the privacy of the inputs is guaranteed even when up to all but one of the parties can be corrupt and collude to learn the honest parties' inputs.

**WRK17 achieves high performance through**:

- **Preprocessing Phase:** Correlated randomness can be generated ahead of time to speed up computation (either using an interactive preprocessing protocol or a so-called trusted dealer).
- **Efficient Online Phase:** The computation can be efficiently executed using the preprocessed data.
- **Scalability:** Designed to handle a large number of parties.

Our implementation of WRK17 provides the `mpc` function for executing MPC computations:

```rust
pub async fn mpc(
    channel: &impl Channel,
    circuit: &Circuit,
    inputs: &[bool],
    p_fpre: Preprocessor,
    p_eval: usize,
    p_own: usize,
    p_out: &[usize],
) -> Result<Vec<bool>, Error>
```

Let's look at the parameters in detail:

- `channel`: The communication channel for sending/receiving messages.
- `circuit`: The Boolean circuit representing the computation to be securely evaluated.
- `inputs`: The party's private input bits.
- `p_fpre`: Whether to run the preprocessing `Untrusted` or use a `TrustedDealer` (more efficient).
- `p_eval`: The party responsible for evaluating the circuit.
- `p_own`: The index of the current party executing the protocol.
- `p_out`: The indices of parties who receive the output.

**Usage Scenario**: This is a low-level functionality with both inputs and outputs being vectors of bits. The `mpc` function is used when each party participates in an actual MPC execution, but usually accompanied by higher-level functions to translate data structures to/from their bit-level representations. We provide numerous example usages in the `examples` directory, and in our simulation example, `simulate_mpc`, in the `tests` directory.