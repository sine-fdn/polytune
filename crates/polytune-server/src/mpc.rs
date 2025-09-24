use std::{sync::Arc, thread};

use futures::future::try_join_all;
use garble_lang::{CircuitKind, CompileOptions, GarbleConsts, compile_with_options};
use reqwest_middleware::ClientWithMiddleware;
use tempfile::tempdir_in;
use tokio::{
    sync::{Notify, mpsc, oneshot},
    task::JoinSet,
};
use tracing::{debug, info};

use crate::{
    api::{Policy, RunRequest},
    channel::HttpChannel,
    consts::{Consts, ConstsRequest},
};

pub(crate) struct MpcRunner {
    client: reqwest_middleware::ClientWithMiddleware,
    schedule_receiver: mpsc::Receiver<ScheduledPolicy>,
    max_concurrency: usize,
}

pub(crate) struct ScheduledPolicy {
    pub(crate) pol: Policy,
    pub(crate) channel: HttpChannel,
    pub(crate) const_receiver: oneshot::Receiver<GarbleConsts>,
}

pub(crate) enum MpcError {}

impl MpcRunner {
    pub(crate) fn new(
        client: ClientWithMiddleware,
        schedule_receiver: mpsc::Receiver<ScheduledPolicy>,
        max_concurrency: usize,
    ) -> Self {
        Self {
            client,
            schedule_receiver,
            max_concurrency,
        }
    }

    pub(crate) async fn start(mut self) -> Result<(), MpcError> {
        let mut js = JoinSet::new();
        loop {
            while js.len() < self.max_concurrency {
                let policy = match self.schedule_receiver.recv().await {
                    Some(policy) => policy,
                    None => return Ok(()),
                };
                if js.len() < self.max_concurrency {
                    // TODO use aborthandle?
                    js.spawn(Self::execute_run_request(self.client.clone(), policy));
                }
            }
            js.join_next()
                .await
                .unwrap()
                .unwrap()
                .map_err(drop)
                .unwrap();

            // spawn execution on joinset if less than max_concurrency
            // otherwise js.join_next().await
            // https://users.rust-lang.org/t/limited-concurrency-for-future-execution-tokio/87171/4
        }
    }

    pub(crate) async fn execute_run_request(
        client: ClientWithMiddleware,
        scheduled_policy: ScheduledPolicy,
    ) -> Result<(), MpcError> {
        let ScheduledPolicy {
            pol,
            channel,
            const_receiver,
        } = scheduled_policy;

        if pol.is_leader() {
            let client = client.clone();
            let run_futs = pol
                .participants
                .iter()
                .enumerate()
                .filter(|(id, _)| *id != pol.party)
                .map(async |(_, participant)| {
                    let url = participant.join("run").unwrap();
                    let run_request = RunRequest {
                        computation_id: pol.computation_id,
                    };
                    // TODO the policy request should contain the queue position at which we will schedule this
                    client.post(url).json(&run_request).send().await
                });
            // TODO: What happens if /run fails for one of the parties? We should send /cancel to the others
            try_join_all(run_futs).await.unwrap();
        }

        let const_futs = pol
            .participants
            .iter()
            .enumerate()
            .filter(|(id, _)| *id != pol.party)
            .map(async |(_, participant)| {
                let url = participant
                    .join(&format!("consts/{}/{}", pol.computation_id, pol.party))
                    .unwrap();
                let const_request = ConstsRequest {
                    consts: pol.constants.clone(),
                };
                client.post(url).json(&const_request).send().await
            });
        try_join_all(const_futs).await.unwrap();

        let consts = const_receiver.await.unwrap();
        debug!("{consts:?}");
        let program = pol.program;

        let (compiled_tx, compiled_rx) = oneshot::channel();
        thread::spawn(move || {
            let compiled = compile_with_options(
                &program,
                CompileOptions {
                    circuit_kind: CircuitKind::Register,
                    consts: consts,
                    // false reduces peak memory consumption
                    optimize_duplicate_gates: false,
                },
            );
            // ignore send error as execute_run_request has been dropped
            let _ = compiled_tx.send(compiled);
        });
        let compiled = compiled_rx.await.unwrap().unwrap();

        let input = compiled
            .literal_arg(pol.party, pol.input)
            .unwrap()
            .as_bits();
        info!("starting mpc comp");
        let output = polytune::mpc(
            &channel,
            compiled.circuit.unwrap_register_ref(),
            &input,
            0,
            pol.party,
            &vec![pol.leader],
            // create a tempdir in ./ and not /tmp because that is often backed by a tmpfs
            // and the files will be in memory and not on the disk
            Some(tempdir_in("./").unwrap().path()),
        )
        .await
        .unwrap();
        info!("finished mpc comp");

        if !output.is_empty() {
            dbg!(compiled.parse_output(&output));
        }

        Ok(())
    }
}
