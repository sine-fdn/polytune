use anyhow::{Context, Error, anyhow, bail};
use garble_lang::{CircuitKind, CompileOptions, compile_with_options};
use polytune::{garble_lang::literal::Literal, mpc};
use polytune_test_utils::peak_alloc::scale_memory;
use reqwest::StatusCode;
use std::{
    borrow::BorrowMut,
    result::Result,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, mpsc::channel},
    time::sleep,
};
use tracing::info;

use crate::{
    ALLOCATOR,
    api::{ConstsRequest, MpcState},
    channel::HttpChannel,
    policy::Policy,
};

pub async fn execute_mpc(state: MpcState, policy: &Policy) -> Result<Option<Literal>, Error> {
    info!("executing MPC");
    let Policy {
        program,
        leader,
        participants,
        party,
        input,
        output: _output,
        constants,
    } = policy;
    let now = Instant::now();
    {
        let mut locked = state.lock().await;
        locked
            .consts
            .insert(format!("PARTY_{party}"), constants.clone());
    }
    // Now we sent around the constants to the other parties...
    let client = reqwest::Client::new();
    for p in participants.iter() {
        if p != &participants[*party] {
            info!("Sending constants to party {p}");
            let url = format!("{p}consts/{party}");
            let const_request = ConstsRequest {
                consts: constants.clone(),
            };
            let Ok(res) = client.post(&url).json(&const_request).send().await else {
                bail!("Could not reach {url}");
            };
            match res.status() {
                StatusCode::OK => {}
                code => {
                    bail!("Unexpected response while trying to send consts to {url}: {code}");
                }
            }
        }
    }
    // ...and wait for their constants:
    loop {
        sleep(Duration::from_millis(500)).await;
        let locked = state.lock().await;
        if locked.consts.len() >= participants.len() - 1 {
            break;
        } else {
            let missing = participants.len() - 1 - locked.consts.len();
            info!(
                "Constants missing from {} parties, received constants from {:?}",
                missing,
                locked.consts.keys()
            );
        }
    }
    let compile_now = Instant::now();
    ALLOCATOR.enable();
    // After receiving the constants, we can finally compile the circuit:
    let prg = {
        let locked = state.lock().await;
        info!("Compiling circuit with the following constants:");
        for (p, v) in locked.consts.iter() {
            for (k, v) in v {
                info!("{p}::{k}: {v:?}");
            }
        }
        compile_with_options(
            program,
            CompileOptions {
                circuit_kind: CircuitKind::Register,
                consts: locked.consts.clone(),
                // false reduces peak memory consumption
                optimize_duplicate_gates: false,
            },
        )
        .map_err(|e| anyhow!(e.prettify(program)))?
    };
    let memory_peak = ALLOCATOR.peak(0) as f64;
    let (denom, unit) = scale_memory(memory_peak);
    info!(
        "Trying to execute circuit with {:.2}M instructions ({:.2}M AND ops). Compilation took {:?}. Peak memory: {} {unit}",
        prg.circuit.ops() as f64 / 1000.0 / 1000.0,
        prg.circuit.ands() as f64 / 1000.0 / 1000.0,
        compile_now.elapsed(),
        memory_peak / denom
    );

    let input = prg.literal_arg(*party, input.clone())?.as_bits();

    // Now that we have our input, we can start the actual session:
    let p_out: Vec<_> = vec![*leader];
    let channel = {
        let mut locked = state.lock().await;
        let state = locked.borrow_mut();
        if !state.senders.is_empty() {
            panic!("Cannot start a new MPC execution while there are still active senders!");
        }
        let mut receivers = vec![];
        for _ in 0..policy.participants.len() {
            let (s, r) = channel(1);
            state.senders.push(s);
            receivers.push(Mutex::new(r));
        }

        #[allow(unused_mut)]
        let mut builder = reqwest::ClientBuilder::new();

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            builder = builder.tcp_user_timeout(Duration::from_secs(10 * 60));
        }

        let client = builder.build()?;

        HttpChannel {
            client,
            urls: participants.clone(),
            party: *party,
            recv: receivers,
            sync_received: Arc::clone(&state.sync_received),
            sync_requested: Arc::clone(&state.sync_requested),
        }
    };

    channel.barrier().await.context("barrier failed")?;

    // We run the computation using MPC, which might take some time...
    let output = mpc(
        &channel,
        prg.circuit.unwrap_register_ref(),
        &input,
        0,
        *party,
        &p_out,
    )
    .await?;

    // ...and now we are done and return the output (if there is any):
    state.lock().await.senders.clear();
    let elapsed = now.elapsed();
    let memory_peak = ALLOCATOR.peak(0) as f64;
    let (denom, unit) = scale_memory(memory_peak);
    info!(
        "MPC computation for party {party} took {} hour(s), {} minute(s), {} second(s). Peak memory: {} {unit}",
        elapsed.as_secs() / 60 / 60,
        (elapsed.as_secs() % (60 * 60)) / 60,
        elapsed.as_secs() % 60,
        memory_peak / denom
    );
    if output.is_empty() {
        Ok(None)
    } else {
        Ok(Some(prg.parse_output(&output)?))
    }
}
