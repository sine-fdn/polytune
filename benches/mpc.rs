use std::{
    time::{Duration, Instant},
    vec,
};

use criterion::{criterion_group, criterion_main, Criterion};
use garble_lang::circuit::{Circuit, Gate};
use polytune::{channel, protocol::mpc};
use tokio::runtime::Runtime;

fn mpc_benchmarks(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    bench_and_chain(c, &rt);
}

/// Benchmark the evaluation of a long chain of ANDs.
fn bench_and_chain(c: &mut Criterion, rt: &Runtime) {
    let and_length = 10_000;

    let mut g = c.benchmark_group("mpc");
    g.throughput(criterion::Throughput::Elements(and_length as u64));
    let bench_id = format!("{and_length} chained ANDs");

    g.bench_function(&bench_id, |b| {
        b.to_async(rt).iter_custom(|iters| {
            let circ = and_chain(and_length);

            async move {
                let mut elapsed = Duration::default();
                for _ in 0..iters {
                    let [mut ch1, mut ch2] = channel::SimpleChannel::channels(2)
                        .try_into()
                        .expect("parties is 2");
                    let circ1 = circ.clone();
                    let circ2 = circ.clone();

                    let now = Instant::now();
                    // We want to spawn the mpc eval on the runtime so we actually use multiple threads. Unfortunately
                    // this means that we must recreate the SimpleChannel and circ above, because the future needs to
                    // be 'static for spawning.
                    let jh1 =
                        tokio::spawn(
                            async move { mpc(&mut ch1, &circ1, &[true], 0, 0, &[0, 1]).await },
                        );
                    let jh2 =
                        tokio::spawn(
                            async move { mpc(&mut ch2, &circ2, &[true], 0, 1, &[0, 1]).await },
                        );
                    match tokio::try_join!(jh1, jh2).expect("join failed") {
                        (_, Err(err)) | (Err(err), _) => {
                            panic!("and_chain eval failed with {err:?}")
                        }
                        (Ok(res1), Ok(res2)) => {
                            // Output should be true because we chain a bunch of ANDs with initial inputs that are true
                            assert!(res1[0]);
                            assert!(res2[0]);
                        }
                    };
                    elapsed += now.elapsed();
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

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = mpc_benchmarks
}
criterion_main!(benches);
