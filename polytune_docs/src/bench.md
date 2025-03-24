# Benchmarks

Although performance optimizations have not been the main focus so far, you can benchmark Polytune and get a feel for how it performs. We provide a benchmark for our `join` example which joins two databases with `n_records` records:

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
