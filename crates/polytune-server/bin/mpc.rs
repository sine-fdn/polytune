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
use tempfile::tempdir_in;
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

pub async fn execute_mpc(
    state: MpcState,
    policy: &Policy,
    channel: HttpChannel,
) -> Result<Option<Literal>, Error> {
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
    state
        .consts
        .lock()
        .await
        .insert(format!("PARTY_{party}"), constants.clone());
    // Now we sent around the constants to the other parties...
    let client = channel.client.clone();
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
        let consts = state.consts.lock().await;
        if consts.len() >= participants.len() - 1 {
            break;
        } else {
            let missing = participants.len() - 1 - consts.len();
            info!(
                "Constants missing from {} parties, received constants from {:?}",
                missing,
                consts.keys()
            );
        }
    }
    let compile_now = Instant::now();
    ALLOCATOR.enable();
    // After receiving the constants, we can finally compile the circuit:
    let prg = {
        let consts = state.consts.lock().await.clone();
        info!("Compiling circuit with the following constants:");
        for (p, v) in consts.iter() {
            for (k, v) in v {
                info!("{p}::{k}: {v:?}");
            }
        }
        compile_with_options(
            program,
            CompileOptions {
                circuit_kind: CircuitKind::Register,
                consts: consts.clone(),
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

    channel.barrier().await.context("barrier failed")?;

    // We run the computation using MPC, which might take some time...
    let output = mpc(
        &channel,
        prg.circuit.unwrap_register_ref(),
        &input,
        0,
        *party,
        &p_out,
        // create a tempdir in ./ and not /tmp because that is often backed by a tmpfs
        // and the files will be in memory and not on the disk
        Some(tempdir_in("./").context("Unable to create tempdir")?.path()),
    )
    .await?;

    // ...and now we are done and return the output (if there is any):
    state.senders.lock().await.clear();
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
