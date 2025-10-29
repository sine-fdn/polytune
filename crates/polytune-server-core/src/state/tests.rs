#![allow(clippy::unwrap_used)]
use std::{fs, sync::Arc};

use garble_lang::literal::Literal;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{Level, error, trace};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

use crate::{
    ConstsError, RunError, ValidateError,
    client::{PolicyClient, PolicyClientBuilder},
    state::{MpcMsgError, OutputError, Policy, PolicyCmd, PolicyState},
};

#[derive(Clone)]
struct TestClient {
    cmd_senders: Vec<mpsc::Sender<PolicyCmd>>,
    output: mpsc::Sender<Result<Literal, OutputError>>,
}

impl PolicyClientBuilder for TestClient {
    type Client = Self;

    fn new_client(&self, policy: &Policy) -> Self::Client {
        assert_eq!(self.cmd_senders.len(), policy.participants.len());
        self.clone()
    }
}

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("validate failed")]
    Validate(#[from] ValidateError),
    #[error("run failed")]
    Run(#[from] RunError),
    #[error("consts failed")]
    Consts(#[from] ConstsError),
    #[error("msg failed")]
    Msg(#[from] MpcMsgError),
}

impl PolicyClient for TestClient {
    type Error = Error;

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn validate(&self, to: usize, req: super::ValidateRequest) -> Result<(), Self::Error> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::Validate(req, ret_tx))
            .await
            .unwrap();
        ret_rx.await.unwrap().map_err(Into::into)
    }

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn run(&self, to: usize, req: super::RunRequest) -> Result<(), Self::Error> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::Run(req, Some(ret_tx)))
            .await
            .unwrap();
        ret_rx.await.unwrap().map_err(Into::into)
    }

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
    async fn consts(&self, to: usize, req: super::ConstsRequest) -> Result<(), Self::Error> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::Consts(req, ret_tx))
            .await
            .unwrap();
        ret_rx.await.unwrap().map_err(Into::into)
    }

    #[tracing::instrument(level = Level::TRACE, skip(self))]
    async fn msg(&self, to: usize, msg: super::MpcMsg) -> Result<(), Self::Error> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::MpcMsg(msg, ret_tx))
            .await
            .unwrap();
        ret_rx.await.unwrap().map_err(Into::into)
    }

    #[tracing::instrument(level = Level::INFO, skip(self, result))]
    async fn output(
        &self,
        _to: url::Url,
        result: Result<Literal, OutputError>,
    ) -> Result<(), Self::Error> {
        if let Err(err) = &result {
            error!(%err)
        }
        self.output.send(result).await.unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn basic_test() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .try_init();

    let cb = || {
        let mut senders = vec![];
        let mut receivers = vec![];
        let (out_tx, out_rx) = mpsc::channel(1);
        for _ in 0..2 {
            let (tx, rx) = mpsc::channel(1);
            senders.push(tx);
            receivers.push(rx);
        }
        (
            TestClient {
                cmd_senders: senders,
                output: out_tx,
            },
            receivers,
            out_rx,
        )
    };
    let (cb0, mut receivers0, mut out_rx) = cb();
    let (cb1, mut receivers1, _) = cb();
    let concurrency = Arc::new(Semaphore::new(2));
    let (state0, handle0) = PolicyState::new(cb0, concurrency.clone());
    let (state1, handle1) = PolicyState::new(cb1, concurrency);
    tokio::spawn(state0.start());
    tokio::spawn(state1.start());
    let handle0_cl = handle0.clone();
    let handle1_cl = handle1.clone();
    tokio::spawn(async move {
        while let Some(cmd) = receivers0[1].recv().await {
            trace!(?cmd, "forwarding cmd to 1");
            handle1_cl.0.send(cmd).await.unwrap();
        }
    });

    tokio::spawn(async move {
        while let Some(cmd) = receivers1[0].recv().await {
            trace!(?cmd, "forwarding cmd to 0");
            handle0_cl.0.send(cmd).await.unwrap();
        }
    });

    let pol0: Policy =
        serde_json::from_str(&fs::read_to_string("policies/policy0.json").unwrap()).unwrap();
    let pol1: Policy =
        serde_json::from_str(&fs::read_to_string("policies/policy1.json").unwrap()).unwrap();
    let sched0 = handle0.schedule(pol0);
    let sched1 = handle1.schedule(pol1);
    tokio::try_join!(sched0, sched1).unwrap();
    dbg!(out_rx.recv().await.unwrap().unwrap());
}
