use std::{collections::HashMap, time::Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use garble_lang::{
    compile_with_constants,
    literal::{Literal, VariantLiteral},
    token::UnsignedNumType,
};
use parlay::protocol::simulate_mpc_async;

fn join_benchmark(c: &mut Criterion) {
    let n_records = 100;
    let code = include_str!(".join.garble.rs");

    let bench_id = format!("join {n_records} records");
    c.bench_function(&bench_id, |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let now = Instant::now();
                println!("\n\nRUNNING MPC SIMULATION FOR {n_records} RECORDS:\n");
                println!("Compiling circuit...");
                let consts = HashMap::from_iter(vec![
                    (
                        "PARTY_0".into(),
                        HashMap::from_iter(vec![(
                            "ROWS".into(),
                            Literal::NumUnsigned(n_records, UnsignedNumType::Usize),
                        )]),
                    ),
                    (
                        "PARTY_1".into(),
                        HashMap::from_iter(vec![(
                            "ROWS".into(),
                            Literal::NumUnsigned(n_records, UnsignedNumType::Usize),
                        )]),
                    ),
                ]);
                let prg = compile_with_constants(&code, consts).unwrap();
                println!("{}", prg.circuit.report_gates());
                let elapsed = now.elapsed();
                println!(
                    "Compilation took {} minute(s), {} second(s)",
                    elapsed.as_secs() / 60,
                    elapsed.as_secs() % 60,
                );

                let id = Literal::ArrayRepeat(
                    Box::new(Literal::NumUnsigned(0, UnsignedNumType::U8)),
                    20,
                );

                let screening_status = Literal::Enum(
                    "ScreeningStatus".into(),
                    "Missing".into(),
                    VariantLiteral::Unit,
                );

                let rows0 = Literal::ArrayRepeat(
                    Box::new(Literal::Tuple(vec![id.clone(), screening_status])),
                    n_records as usize,
                );

                let rows1 = Literal::ArrayRepeat(
                    Box::new(Literal::Tuple(vec![
                        id.clone(),
                        Literal::NumUnsigned(0, UnsignedNumType::U8),
                    ])),
                    n_records as usize,
                );

                let input0 = prg.literal_arg(0, rows0).unwrap().as_bits();
                let input1 = prg.literal_arg(1, rows1).unwrap().as_bits();

                let inputs = vec![input0.as_slice(), input1.as_slice()];

                simulate_mpc_async(&prg.circuit, &inputs, &[0], true)
                    .await
                    .unwrap();
                let elapsed = now.elapsed();
                println!(
                    "MPC computation took {} minute(s), {} second(s)",
                    elapsed.as_secs() / 60,
                    elapsed.as_secs() % 60,
                );
            })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = join_benchmark
}
criterion_main!(benches);
