# Benchmarks


You can benchmark Polytune with a `join` example that allows for joining two databases with `n_records` records each by running

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