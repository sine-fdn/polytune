use std::time::Instant;

use criterion::{measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion};
use polytune::{
    bench_reexports::{kos_ot_receiver, kos_ot_sender},
    channel,
};
use rand::{random, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::runtime::Runtime;

pub fn primitives_benchmark(c: &mut Criterion) {
    // Default runtime for "full" feature is multi-threaded
    let rt = Runtime::new().unwrap();

    let ot_count_exponents = [10, 13, 16];
    let mut g = c.benchmark_group("primitives");
    for exp in ot_count_exponents {
        let ot_count = 2_usize.pow(exp);
        let bench_id = BenchmarkId::new("KOS OTs", ot_count);
        g.throughput(criterion::Throughput::Elements(ot_count as u64));
        bench_ots(&mut g, &rt, bench_id, ot_count);
    }
}

fn bench_ots<'a>(
    g: &mut BenchmarkGroup<'a, WallTime>,
    rt: &Runtime,
    bench_id: BenchmarkId,
    count: usize,
) {
    g.bench_function(bench_id, |b| {
        b.to_async(rt).iter_custom(|iters| {
            // iter_custom allows us to do the setup here without impacting the tracked time
            // doing the setup in primitives_benchmark is tricky/not possible due to the
            // future capturing &mut variables
            let [ch1, ch2] = channel::SimpleChannel::channels(2)
                .try_into()
                .expect("parties is 2");
            let mut shared_rand1 = ChaCha20Rng::seed_from_u64(42);
            let mut shared_rand2 = shared_rand1.clone();
            let deltas = vec![random(); count];
            let bs = vec![random(); count];

            async move {
                let now = Instant::now();
                for _ in 0..iters {
                    tokio::try_join!(
                        kos_ot_sender(&ch1, &deltas, 1, &mut shared_rand1),
                        kos_ot_receiver(&ch2, &bs, 0, &mut shared_rand2)
                    )
                    .expect("OTs failed");
                }
                now.elapsed()
            }
        })
    });
}
