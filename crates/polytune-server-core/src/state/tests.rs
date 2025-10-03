use std::{convert::Infallible, fs};

use garble_lang::literal::Literal;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

use crate::{
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

impl PolicyClient for TestClient {
    type ClientError<E>
        = E
    where
        E: std::error::Error + Send + Sync;

    async fn validate(
        &self,
        to: usize,
        req: super::ValidateRequest,
    ) -> Result<(), super::ValidateError> {
        let (ret_tx, ret_rx) = oneshot::channel();
        println!("sending validate to {to}");
        self.cmd_senders[to]
            .send(PolicyCmd::Validate(req, ret_tx))
            .await
            .unwrap();
        println!("sent validate to {to}");
        ret_rx.await.unwrap().unwrap();
        println!("ret validate {to}");
        Ok(())
    }

    async fn run(&self, to: usize, req: super::RunRequest) -> Result<(), super::RunError> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::Run(req, Some(ret_tx)))
            .await
            .unwrap();
        ret_rx.await.unwrap()
    }

    async fn consts(&self, to: usize, req: super::ConstsRequest) -> Result<(), super::ConstsError> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::Consts(req, ret_tx))
            .await
            .unwrap();
        ret_rx.await.unwrap()
    }

    async fn msg(&self, to: usize, msg: super::MpcMsg) -> Result<(), MpcMsgError> {
        let (ret_tx, ret_rx) = oneshot::channel();
        self.cmd_senders[to]
            .send(PolicyCmd::MpcMsg(msg, ret_tx))
            .await
            .unwrap();
        ret_rx.await.unwrap()
    }

    async fn output(
        &self,
        _to: url::Url,
        result: Result<Literal, OutputError>,
    ) -> Result<(), Infallible> {
        self.output.send(result).await.unwrap();
        Ok(())
    }
}

#[tokio::test]
async fn basic_test() {
    let _g = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .set_default();

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
    let (cb1, mut receivers1, mut out_rx) = cb();
    let (cb2, mut receivers2, _) = cb();

    let (state1, cmd_sender1) = PolicyState::new(cb1, Semaphore::new(2));
    let (state2, cmd_sender2) = PolicyState::new(cb2, Semaphore::new(2));
    tokio::spawn(state1.start());
    tokio::spawn(state2.start());
    let cmd_sender1_cl = cmd_sender1.clone();
    let cmd_sender2_cl = cmd_sender2.clone();
    tokio::spawn(async move {
        while let Some(cmd) = receivers1[1].recv().await {
            // println!("transmitting {cmd:?}");
            cmd_sender2_cl.send(cmd).await.unwrap();
        }
    });

    tokio::spawn(async move {
        while let Some(cmd) = receivers2[0].recv().await {
            // println!("transmitting {cmd:?}");
            cmd_sender1_cl.send(cmd).await.unwrap();
        }
    });

    let pol1: Policy =
        serde_json::from_str(&fs::read_to_string("policies/policy0.json").unwrap()).unwrap();
    let pol2: Policy =
        serde_json::from_str(&fs::read_to_string("policies/policy1.json").unwrap()).unwrap();
    let (ret1_tx, ret1_rx) = oneshot::channel();
    let (ret2_tx, ret2_rx) = oneshot::channel();
    let sched1 = cmd_sender1.send(PolicyCmd::Schedule(pol1, ret1_tx));
    let sched2 = cmd_sender2.send(PolicyCmd::Schedule(pol2, ret2_tx));
    tokio::try_join!(sched1, sched2).unwrap();
    let (a, b) = tokio::try_join!(ret1_rx, ret2_rx).unwrap();
    a.unwrap();
    b.unwrap();
    dbg!(out_rx.recv().await.unwrap().unwrap());
}
