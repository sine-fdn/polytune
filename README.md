# Sooon MPC Engine

Sooon is an MPC engine for garbled circuits. It is being actively developed, so expect breaking changes.

## Benchmarks

To run all the benchmarks:

```
cargo bench
```

To run the `join` benchmark once and produce a flamegraph:

```
sudo CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph --bench join
```

To run the `join` benchmark multiple times, benchmark it, then produce a flamegraph:

```
sudo CARGO_PROFILE_BENCH_DEBUG=true cargo flamegraph --bench join -- --bench
```
