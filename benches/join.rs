use std::{collections::HashMap, time::Instant};

use criterion::Criterion;
use garble_lang::{
    circuit::Circuit,
    compile_with_constants,
    literal::{Literal, VariantLiteral},
    token::UnsignedNumType,
};
use polytune::{
    channel,
    protocol::{mpc, Error},
};
use tracing::{error, info};

/// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
async fn simulate_mpc_async(
    circuit: &Circuit,
    inputs: &[&[bool]],
    output_parties: &[usize],
) -> Result<Vec<bool>, Error> {
    let p_eval = 0;

    let channels = channel::SimpleChannel::channels(inputs.len());

    let mut parties = channels.into_iter().zip(inputs).enumerate();
    let Some((_, (mut eval_channel, inputs))) = parties.next() else {
        return Ok(vec![]);
    };

    let mut computation: tokio::task::JoinSet<Vec<bool>> = tokio::task::JoinSet::new();
    for (p_own, (mut channel, inputs)) in parties {
        let circuit = circuit.clone();
        let inputs = inputs.to_vec();
        let output_parties = output_parties.to_vec();
        computation.spawn(async move {
            match mpc(
                &mut channel,
                &circuit,
                &inputs,
                p_eval,
                p_own,
                &output_parties,
            )
            .await
            {
                Ok(res) => {
                    info!(
                        "Party {p_own} sent {:.2}MB of messages",
                        channel.bytes_sent as f64 / 1024.0 / 1024.0
                    );
                    res
                }
                Err(e) => {
                    error!("SMPC protocol failed for party {p_own}: {:?}", e);
                    vec![]
                }
            }
        });
    }
    let eval_result = mpc(
        &mut eval_channel,
        circuit,
        inputs,
        p_eval,
        p_eval,
        output_parties,
    )
    .await;
    match eval_result {
        Err(e) => {
            error!("SMPC protocol failed for Evaluator: {:?}", e);
            Ok(vec![])
        }
        Ok(res) => {
            let mut outputs = vec![res];
            while let Some(output) = computation.join_next().await {
                if let Ok(output) = output {
                    outputs.push(output);
                }
            }
            outputs.retain(|o| !o.is_empty());
            if !outputs.windows(2).all(|w| w[0] == w[1]) {
                error!("The result does not match for all output parties: {outputs:?}");
            }
            let mb = eval_channel.bytes_sent as f64 / 1024.0 / 1024.0;
            info!("Party {p_eval} sent {mb:.2}MB of messages");
            info!("MPC simulation finished successfully!");
            Ok(outputs.pop().unwrap_or_default())
        }
    }
}

pub fn join_benchmark(c: &mut Criterion) {
    let n_records = 10;
    let code = include_str!(".join.garble.rs");

    let bench_id = format!("join {n_records} records");
    c.bench_function(&bench_id, |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let now = Instant::now();
                info!("\n\nRUNNING MPC SIMULATION FOR {n_records} RECORDS:\n");
                info!("Compiling circuit...");
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
                let prg = compile_with_constants(code, consts).unwrap();
                info!("{}", prg.circuit.report_gates());
                let elapsed = now.elapsed();
                info!(
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

                simulate_mpc_async(&prg.circuit, &inputs, &[0])
                    .await
                    .unwrap();
                let elapsed = now.elapsed();
                info!(
                    "MPC computation took {} minute(s), {} second(s)",
                    elapsed.as_secs() / 60,
                    elapsed.as_secs() % 60,
                );
            })
    });
}
