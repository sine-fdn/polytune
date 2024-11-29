# Parlay SMPC Engine

[Secure Multi-Party Computation (SMPC)](https://sine.foundation/library/002-smpc) allows two or more parties to interactively perform a computation on their private inputs, without revealing any additional information about their inputs to each other, other than what the result of the computation reveals.

Our aim at SINE is to make advanced technology, such as SMPC, available to as many companies as possible. We are especially keen to apply  [SMPC for the exchange of sustainability data](https://sine.foundation/library/sine-is-partnering-with-wbcsd-to-decarbonise-the-economy).

Parlay, our SMPC engine, aims at fulfilling our vision by providing an easy to use framework to apply this technology wherever there is a need to share data privately, without a third-party trustee.

In parlay, we implement the multi-party [[WRK17b]](https://eprint.iacr.org/2017/189.pdf) protocol and will include optimizations from [[YWZ20]](https://eprint.iacr.org/2019/1104.pdf). This protocol achieves the highest level of security an SMPC protocol can achieve, i.e., it is secure against malicious adversaries that can control up to all-but-one of the parties. This means that even if all but one of the parties are corrupt and together try to obtain information about the honest party's input while actively deviating from the protocol, they are unable to do so, i.e., the input of the honest party remains private.

> [!NOTE]
> Our SMPC engine is being actively developed, so expect breaking changes.

Parlay is directly compatible with [Garble](https://github.com/sine-fdn/garble-lang), our programming language that allows us to describe computations on a high level and translate them to a Boolean circuit format that is required by the [[WRK17b]](https://eprint.iacr.org/2017/189.pdf) SMPC protocol.

You can see examples for the usage with examples described in Garble, e.g., `benches/.join.garble.rs` or in `examples/sql-integration/.example.garble.rs`.

## Benchmarks


You can benchmark parlay with a `join` example that allows for joining two databases with `n_records` records each by running

```
cargo bench join
```

To run the `join` benchmark once and produce a flamegraph:

```
sudo CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph --bench join
```

To run the `join` benchmark multiple times, benchmark it, then produce a flamegraph:

```
sudo CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph --bench join -- --bench
```


To run all the benchmarks you can run:

```
cargo bench
```