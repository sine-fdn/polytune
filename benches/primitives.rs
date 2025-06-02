use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use polytune::{
    bench_reexports::{kos_ot_receiver, kos_ot_sender},
    channel,
};
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tokio::runtime::Runtime;

fn primitives_benchmark(c: &mut Criterion) {
    let exp = 16;
    let ot_count = 2_usize.pow(exp);
    let bench_id = format!("2^{exp} OTs");
    let mut g = c.benchmark_group("OTs");
    g.throughput(criterion::Throughput::Elements(ot_count as u64));

    // Default runtime for "full" feature is multi-threaded
    let rt = Runtime::new().unwrap();

    g.bench_function(&bench_id, |b| {
        b.to_async(&rt).iter_custom(|iters| {
            // iter_custom allows us to do the setup here without impacting the tracked time
            // doing the setup in primitives_benchmark is tricky/not possible due to the
            // future capturing &mut variables
            let [mut ch1, mut ch2] = channel::SimpleChannel::channels(2)
                .try_into()
                .expect("parties is 2");
            let mut shared_rand1 = ChaCha20Rng::seed_from_u64(42);
            let mut shared_rand2 = shared_rand1.clone();
            let deltas = vec![thread_rng().r#gen(); ot_count];
            let bs = vec![thread_rng().r#gen(); ot_count];

            async move {
                let now = Instant::now();
                for _ in 0..iters {
                    tokio::try_join!(
                        kos_ot_sender(&mut ch1, &deltas, 1, &mut shared_rand1),
                        kos_ot_receiver(&mut ch2, &bs, 0, &mut shared_rand2)
                    )
                    .expect("OTs failed");
                }
                now.elapsed()
            }
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1);
    targets = primitives_benchmark
}
criterion_main!(benches);
