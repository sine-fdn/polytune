# The Polytune MPC Engine

[Secure Multi-Party Computation (MPC)](https://sine.foundation/library/002-smpc) allows two or more parties to interactively perform a computation on their private inputs, without revealing any additional information about their inputs to each other, other than what the result of the computation reveals.

Our aim at SINE is to make advanced technology, such as MPC, available to as many companies as possible. We are especially keen to apply [MPC for the exchange of sustainability data](https://sine.foundation/library/sine-is-partnering-with-wbcsd-to-decarbonise-the-economy).

Polytune, our MPC engine, aims at fulfilling our vision by providing an easy-to-use framework to apply this technology wherever there is a need to share data privately, without a third-party trustee.

> ⚠️ **Note**
> Our MPC engine is being actively developed, so expect breaking changes.


## Secure Multi-Party Computation

<video width="780" src="https://github.com/user-attachments/assets/a04b5caa-2b79-40de-bf21-24f7124eb190" autoplay controls></video>

Polytune implements the multi-party [[WRK17b]](https://eprint.iacr.org/2017/189.pdf) protocol and will include optimizations from [[YWZ20]](https://eprint.iacr.org/2019/1104.pdf). This protocol is secure against malicious adversaries that can control up to all-but-one of the parties. This means that even if all but one of the parties are corrupt and together try to obtain information about the honest party's input while actively deviating from the protocol, they are unable to do so, i.e., the input of the honest party remains private.

## Documentation

We provide high-level documentation on Polytune and the examples implemented [here](./examples/) at [polytune.org](https://polytune.org/). The latest rustdoc documentation is available on [docs.rs](https://docs.rs/polytune/latest/polytune/).

## Garble and Polytune

Polytune is directly compatible with [Garble](https://github.com/sine-fdn/garble-lang), our Rust-inspired programming language that allows us to describe computations on a high level and translate them to a Boolean circuit format that is required by the [[WRK17b]](https://eprint.iacr.org/2017/189.pdf) MPC protocol.

Example of an analysis performed in Garble:
```rust
const ROWS_0: usize = PARTY_0::ROWS;
const ROWS_1: usize = PARTY_1::ROWS;
const ID_LEN: usize = max(PARTY_0::ID_LEN, PARTY_1::ID_LEN);

pub fn main(
    location: [([u8; ID_LEN], u8); ROWS_0],
    disability: [([u8; ID_LEN], u8); ROWS_1],
) -> [u16; 10] {
    let mut result: [u16; 10] = [0u16; 10];
    for joined in join_iter(location, disability) {
        let ((_, loc), (_, care_level)) = joined;
        if care_level >= 4 {
            result[loc as usize] += 1u16;
        }
    }
    result
}
```

You can see examples of using Garble and Polytune together, e.g., `benches/.join.garble.rs` or in `examples/sql-integration/.example.garble.rs`.

## Benchmarks

Polytune contains multple benchmarks in the [`benches`](./benches/) directory using [criterion](https://bheisler.github.io/criterion.rs/book/criterion_rs.html). These benchmarks require the Polytune-internal cargo feature `__bench`, which is not intended for downstream use.

You can run the benchmarks using:
```shell
cargo bench --features __bench
```

The logging output of the benchmarks can be configured using the `RUST_LOG` environment variable using an [`EnvFilter` directive](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html). For example, to see the output of the [join](./benches/join.rs) benchmark, run:
```shell
RUST_LOG=info cargo bench --features __bench 'join'
```
For the most detailed output, the logging level can be set to `trace`.

## Funded by

<p float="left">
  <img src="BMBF_Logo.jpg" alt="With funding from the: Federal Ministry of Research, Technology and Space" height="200" />
  <img src="EU_Logo.png" alt="Funded by the European Union (NextGenerationEU)" height="200" style="background: white" />
</p>
