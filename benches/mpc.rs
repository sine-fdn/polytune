use std::{
    time::{Duration, Instant},
    vec,
};

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use garble_lang::circuit::{Circuit, Gate};
use polytune::{channel, protocol::mpc};
use tokio::runtime::Runtime;

fn mpc_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    bench_and_chain(c, &rt);
    bench_large_input(c, &rt);
}

/// Benchmark the evaluation of a long chain of ANDs.
fn bench_and_chain(c: &mut Criterion, rt: &Runtime) {
    let mut g = c.benchmark_group("mpc");
    let and_lengths = [100, 1_000, 10_000];
    for and_length in and_lengths {
        g.throughput(criterion::Throughput::Elements(and_length as u64));
        let bench_id = BenchmarkId::new("chained ANDs", and_length);
        let circ = and_chain(and_length);

        bench_circuit_two_parties(
            &mut g,
            rt,
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

fn bench_large_input(c: &mut Criterion, rt: &Runtime) {
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
            rt,
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

fn bench_circuit_two_parties<'a, F>(
    g: &mut BenchmarkGroup<'a, WallTime>,
    rt: &Runtime,
    bench_id: BenchmarkId,
    circ: Circuit,
    inputs: [Vec<bool>; 2],
    validate_output: F,
) where
    F: FnMut(Vec<bool>, Vec<bool>) + Clone,
{
    g.bench_function(bench_id, move |b| {
        b.to_async(rt).iter_custom(|iters| {
            let circ = circ.clone();
            let inputs = inputs.clone();
            let mut validate_output = validate_output.clone();
            async move {
                let mut elapsed = Duration::default();
                for _ in 0..iters {
                    let [mut ch1, mut ch2] = channel::SimpleChannel::channels(2)
                        .try_into()
                        .expect("parties is 2");
                    let circ1 = circ.clone();
                    let circ2 = circ.clone();
                    // Boh parties get the output
                    let p_out = [0, 1];
                    let [inputs1, inputs2] = inputs.clone();

                    let now = Instant::now();
                    // We want to spawn the mpc eval on the runtime so we actually use multiple threads. Unfortunately
                    // this means that we must recreate the SimpleChannel and circ above, because the future needs to
                    // be 'static for spawning.
                    let jh1 =
                        tokio::spawn(
                            async move { mpc(&mut ch1, &circ1, &inputs1, 0, 0, &p_out).await },
                        );
                    let jh2 =
                        tokio::spawn(
                            async move { mpc(&mut ch2, &circ2, &inputs2, 0, 1, &p_out).await },
                        );
                    let (res1, res2) = match tokio::try_join!(jh1, jh2).expect("join failed") {
                        (_, Err(err)) | (Err(err), _) => {
                            panic!("and_chain eval failed with {err:?}")
                        }
                        (Ok(res1), Ok(res2)) => (res1, res2),
                    };
                    elapsed += now.elapsed();
                    validate_output(res1, res2);
                }
                elapsed
            }
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
/// If inputs is not divisable by 2.
fn large_input_circ(inputs: usize) -> Circuit {
    assert_eq!(0, inputs % 2, "inputs must be divisable by two");
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

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = mpc_benchmarks
}
criterion_main!(benches);
