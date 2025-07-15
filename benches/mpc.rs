use std::{fmt::Debug, time::Duration, vec};

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion,
    measurement::{Measurement, WallTime},
};
use garble_lang::circuit::{Circuit, Gate};
use polytune::{channel, mpc};
use polytune_test_utils::peak_alloc::create_instrumented_runtime;
use tokio::{runtime::Runtime, sync::oneshot};

use crate::memory_tracking::MemoryMeasurement;

pub fn mpc_benchmarks(c: &mut Criterion) {
    let rt0 = create_instrumented_runtime(0);
    let rt1 = create_instrumented_runtime(1);

    bench_and_chain(c, &rt0, &rt1);
    bench_large_input(c, &rt0, &rt1);
    // Bench memory sets up its own criterion instance
    // with a custom measurement
    bench_memory(&rt0, &rt1);
}

/// Benchmark the evaluation of a long chain of ANDs.
fn bench_and_chain(c: &mut Criterion, rt0: &Runtime, rt1: &Runtime) {
    let mut g = c.benchmark_group("mpc");
    let and_lengths = [100, 1_000, 10_000];
    for and_length in and_lengths {
        g.throughput(criterion::Throughput::Elements(and_length as u64));
        let bench_id = BenchmarkId::new("chained ANDs", and_length);
        let circ = and_chain(and_length);

        bench_circuit_two_parties(
            &mut g,
            &WallTime,
            rt0,
            rt1,
            bench_id,
            circ,
            [vec![true], vec![true]],
            |res1, res2| {
                // Output should be true because we chain a bunch of ANDs with initial inputs that are true
                assert!(res1[0]);
                assert!(res2[0]);
            },
        );
    }
}

fn bench_large_input(c: &mut Criterion, rt0: &Runtime, rt1: &Runtime) {
    let input_sizes = [100, 1_000, 10_000];
    for inputs in input_sizes {
        let mut g = c.benchmark_group("mpc");
        // Also report a "throughput" for this circuit based on the number of inputs. While this
        // circuit also has AND and output gates, the throughput allows us to easily see
        // how the execution scales with the number of inputs.
        g.throughput(criterion::Throughput::Elements(inputs as u64));
        let bench_id = BenchmarkId::new("large inputs", inputs);
        let circ = large_input_circ(inputs);

        bench_circuit_two_parties(
            &mut g,
            &WallTime,
            rt0,
            rt1,
            bench_id,
            circ,
            [vec![true; inputs / 2], vec![true; inputs / 2]],
            |res1, res2| {
                // Output should be all true because we compute ANDs of `true` inputs
                assert!(res1.iter().all(|b| *b));
                assert!(res2.iter().all(|b| *b));
            },
        );
    }
}

// Benchmark the memory consumption of party 0 and 1 for the `large_input_circ``
fn bench_memory(rt1: &Runtime, rt2: &Runtime) {
    bench_memory_for_party(rt1, rt2, 0);
    bench_memory_for_party(rt1, rt2, 1);
}

fn bench_memory_for_party(rt1: &Runtime, rt2: &Runtime, party: usize) {
    let measurement = MemoryMeasurement::new(party);
    // We need to create a new Criterion instance to change the measurement type
    let mut c = Criterion::default()
        .significance_level(0.1)
        // Sadly we can't set the sample size lower than 10, because criterion
        // enforces this as the minimum, even if it doesn't make sense for
        // custom measurements...
        .sample_size(10)
        .measurement_time(Duration::from_secs(1))
        .with_measurement(measurement)
        .warm_up_time(Duration::from_nanos(1))
        // Plots don't work for the memory measurement for some reason. Plotters fails
        // on some NaN assertion
        .without_plots()
        .configure_from_args();

    let input_sizes = [100, 1_000, 10_000];
    for inputs in input_sizes {
        let mut g = c.benchmark_group("mpc");
        let bench_id = BenchmarkId::new(format!("memory for large inputs (Party {party})"), inputs);
        let circ = large_input_circ(inputs);

        bench_circuit_two_parties(
            &mut g,
            &measurement,
            rt1,
            rt2,
            bench_id,
            circ,
            [vec![true; inputs / 2], vec![true; inputs / 2]],
            |res1, res2| {
                // Output should be all true because we compute ANDs of `true` inputs
                assert!(res1.iter().all(|b| *b));
                assert!(res2.iter().all(|b| *b));
            },
        );
    }
}

/// Benchmark the provided circuit with the criterion measurement.
///
/// Uses `rt0` for party 0 and `rt1` for party 1.
#[allow(clippy::too_many_arguments)]
fn bench_circuit_two_parties<'a, M, F>(
    g: &mut BenchmarkGroup<'a, M>,
    m: &M,
    rt0: &Runtime,
    rt1: &Runtime,
    bench_id: BenchmarkId,
    circ: Circuit,
    inputs: [Vec<bool>; 2],
    validate_output: F,
) where
    M: Measurement,
    M::Value: Default + Debug,
    F: FnMut(Vec<bool>, Vec<bool>) + Clone,
{
    g.bench_function(bench_id, move |b| {
        b.iter_custom(|iters| {
            let circ = circ.clone();
            let inputs = inputs.clone();
            let mut validate_output = validate_output.clone();
            let mut elapsed = M::Value::default();
            for _ in 0..iters {
                let [ch1, ch2] = channel::SimpleChannel::channels(2)
                    .try_into()
                    .expect("parties is 2");
                let circ1 = circ.clone();
                let circ2 = circ.clone();
                // Boh parties get the output
                let p_out = [0, 1];
                let [inputs1, inputs2] = inputs.clone();

                let now = m.start();
                // We want to spawn the mpc eval on the runtime so we actually use multiple threads. Unfortunately
                // this means that we must recreate the SimpleChannel and circ above, because the future needs to
                // be 'static for spawning.
                let fut = async move {
                    mpc(&ch1, &circ1, &inputs1, 0, 0, &p_out)
                        .await
                        .expect("mpc execution failed")
                };
                // Because we want to wait for both parties being finished
                // we use a oneshot channel for P0 which communicates that we're done.
                let (tx, rx) = oneshot::channel();
                rt0.spawn(async {
                    let res = tokio::spawn(fut).await.expect("spawn failed");
                    tx.send(res).expect("channel closed");
                });
                let fut = async move {
                    mpc(&ch2, &circ2, &inputs2, 0, 1, &p_out)
                        .await
                        .expect("mpc execution failed")
                };
                let res2 = rt1.block_on(async { tokio::spawn(fut).await.expect("spawn failed") });
                let res1 = rx.blocking_recv().expect("channel closed");
                // both futures are done and we can measure this iteration
                elapsed = m.add(&elapsed, &m.end(now));
                validate_output(res1, res2);
            }
            elapsed
        })
    });
}

/// Creates a chain of and gates where each gate is the and of the previous two.
/// One input per party for two parties.
fn and_chain(gates: usize) -> Circuit {
    let inputs = 1;
    let num_parties = 2;

    let out_idx = gates + 1;

    let gates = (2..=out_idx).map(|i| Gate::And(i - 2, i - 1)).collect();
    let output_gates = vec![out_idx];

    Circuit {
        input_gates: vec![inputs; num_parties],
        gates,
        output_gates,
    }
}

/// Creates a circuit with inputs many inputs, where for each two
/// consecutive inputs an AND is calculated, resulting in inputs / 2
/// outputs.
/// # Panics
/// If inputs is not divisible by 2.
fn large_input_circ(inputs: usize) -> Circuit {
    assert_eq!(0, inputs % 2, "inputs must be divisible by two");
    let num_parties = 2;
    let input_gates = vec![inputs / num_parties; num_parties];
    let gates = (0..inputs)
        .zip(1..)
        .step_by(2)
        .map(|(a, b)| Gate::And(a, b))
        .collect();
    let output_gates = (inputs..inputs + inputs / 2).collect();

    Circuit {
        input_gates,
        gates,
        output_gates,
    }
}
