# MPC Protocol: WKR17

The **WRK17 protocol** [[WRK17]](https://eprint.iacr.org/2017/189.pdf) is an MPC protocol designed to allow collaborative computation between multiple parties while maintaining strong security guarantees. It enables multiple parties to jointly compute a function over their private inputs **without revealing those inputs** to each other. 

The WRK17 protocol is based on **garbled circuits** and **preprocessing-based MPC**, allowing efficient execution in **dishonest-majority settings**. In these settings, the privacy of the inputs is guaranteed even when up to all but one of the parties can be corrupt and collude to learn the honest parties' inputs. 

**WRK17 achieves high performance through**: 
- **Preprocessing Phase:** Correlated randomness can be generated ahead of time to speed up computation (either using an interactive preprocessing protocol or a so-called trusted dealer). 
- **Efficient Online Phase:** The computation can be efficiently executed using the preprocessed data.
- **Scalability:** Designed to handle a large number of parties.

## Functionality in Our Crate  

Our implementation of WRK17 provides a function for executing MPC computations.  

### MPC Execution

```rust
pub async fn mpc(
    channel: &mut impl Channel,
    circuit: &Circuit,
    inputs: &[bool],
    p_fpre: Preprocessor,
    p_eval: usize,
    p_own: usize,
    p_out: &[usize],
) -> Result<Vec<bool>, Error>
```

**Purpose** Executes the MPC protocol for one party and returns the computed output bits.

**Key Parameters**:
- `channel`: The communication channel for sending/receiving messages.
- `circuit`: The Boolean circuit representing the computation to be securely evaluated.
- `inputs`: The party's private input bits.
- `p_fpre`: The preprocessor, which provides correlated randomness for the MPC protocol. It is either `TrustedDealer` or `Untrusted`.
- `p_eval`: The party responsible for evaluating the circuit.
- `p_own`: The index of the current party executing the protocol.
- `p_out`: The indices of parties who receive the output.

**Usage Scenario**: Used when each party participates in an actual MPC execution. We provide numerous example usages in the `examples` directory, and in our simulation example, `simulate_mpc`.