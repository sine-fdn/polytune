use std::{collections::HashMap, mem, thread};

use futures::future;
use garble_lang::{
    CircuitKind, CompileOptions, GarbleConsts, TypedProgram, compile_with_options, literal::Literal,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::info;
use url::Url;
use uuid::Uuid;

/// A policy containing everything necessary to run an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub struct Policy {
    /// The unique `computation_id` of this mpc execution. This is used to identify
    /// which `/launch/` requests belong to the same computation.
    pub computation_id: Uuid,
    /// The URLs at which we can reach the other parties. Their position in
    /// in this array needs to be identical for all parties and will correspond
    /// to their party ID (e.g. used for the leader).
    pub participants: Vec<Url>,
    /// The program as [Garble](https://garble-lang.org/) source code.
    pub program: String,
    /// The id of the leader of the computation.
    pub leader: usize,
    /// Our own party ID. Corresponds to our adress at participants[party].
    pub party: usize,
    /// The input to the Garble program as a serialized Garble `Literal` value.
    pub input: Literal,
    /// The optional output URL to which the output of the MPC computation is provided
    /// as a json serialized Garble `Literal` value.
    pub output: Option<Url>,
    /// The constants needed of this party for the MPC computation. Note that the
    /// identifier must not contain the `PARTY_{ID}::` prefix, but only the name.
    /// E.g. if the Garble program contains `const ROWS_0: usize = PARTY_0::ROWS;`
    /// this should contain e.g. `"ROWS": { "NumUnsigned": [200, "Usize"]}`.
    pub constants: HashMap<String, Literal>,
}

impl Policy {
    fn other_parties(&self) -> impl Iterator<Item = usize> + Clone {
        (0..self.participants.len()).filter(|p| *p != self.party)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct ValidateRequest {
    pub(crate) computation_id: Uuid,
    pub(crate) program_hash: String,
    pub(crate) leader: usize,
}

impl From<&Policy> for ValidateRequest {
    fn from(policy: &Policy) -> Self {
        Self {
            computation_id: policy.computation_id,
            program_hash: blake3::hash(policy.program.as_bytes()).to_string(),
            leader: policy.leader,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ValidateError;

#[derive(Clone, Debug)]
struct RunRequest {
    pub(crate) computation_id: Uuid,
}
#[derive(Debug)]
struct RunError;

pub(crate) type Consts = HashMap<String, Literal>;

#[derive(Clone, Debug)]
struct ConstsRequest {
    from: usize,
    consts: Consts,
}
#[derive(Debug)]
pub(crate) struct ConstsError;

#[derive(Debug)]
struct MpcMsg {
    from: usize,
    data: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct MpcMsgError;

#[derive(Debug)]
pub(crate) struct OutputError;

pub(crate) struct PolicyState<B, C> {
    client_builder: B,
    concurrency: Semaphore,
    state_kind: PolicyStateKind<C>,
    consts: GarbleConsts,
    cmd_rx: mpsc::Receiver<PolicyCmd>,
    cmd_tx: mpsc::Sender<PolicyCmd>,
    channel_senders: Vec<mpsc::Sender<Vec<u8>>>,
    channel_receivers: Option<Vec<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>>,
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    pub(crate) fn new(
        client_builder: B,
        concurrency: Semaphore,
    ) -> (Self, mpsc::Sender<PolicyCmd>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        let mut channel_senders = vec![];
        let mut channel_receivers = vec![];
        // TODO actual size
        for _ in 0..10 {
            // TODO buffer size?
            let (sender, receiver) = mpsc::channel(1);
            channel_senders.push(sender);
            channel_receivers.push(tokio::sync::Mutex::new(receiver));
        }
        (
            Self {
                client_builder,
                concurrency,
                state_kind: PolicyStateKind::Init,
                consts: Default::default(),
                cmd_rx,
                cmd_tx: cmd_tx.clone(),
                channel_senders,
                channel_receivers: Some(channel_receivers),
            },
            cmd_tx,
        )
    }

    pub(crate) async fn start(mut self) {
        while let Some(cmd) = self.cmd_rx.recv().await {
            println!("handling {cmd:?}");
            match cmd {
                PolicyCmd::Schedule(policy, ret) => {
                    let is_leader = policy.party == policy.leader;

                    let typed_program = garble_lang::check(&policy.program).unwrap();

                    if is_leader {
                        if !matches!(self.state_kind, PolicyStateKind::Init) {
                            ret.send(Err(ScheduleError));
                            continue;
                        }
                        let client = self.client_builder.new(policy.participants.clone());

                        dbg!("validating others");
                        let validate_req = ValidateRequest::from(&policy);
                        let validate_futs = policy
                            .other_parties()
                            .map(async |p| client.validate(p, validate_req.clone()).await);
                        future::try_join_all(validate_futs).await.unwrap();
                        dbg!("validated others");
                        ret.send(Ok(()));

                        let permit = self.concurrency.acquire().await.unwrap();
                        let run_request = RunRequest {
                            computation_id: policy.computation_id,
                        };
                        dbg!("running others");
                        let run_futs = policy
                            .other_parties()
                            .map(async |p| client.run(p, run_request.clone()).await);
                        future::try_join_all(run_futs).await;
                        dbg!("done running others");
                        self.state_kind = PolicyStateKind::Validated {
                            client,
                            policy,
                            typed_program,
                        };
                        self.cmd_tx
                            .send(PolicyCmd::Run(run_request, None))
                            .await
                            .unwrap();
                    } else {
                        let client = self.client_builder.new(policy.participants.clone());

                        match self.state_kind {
                            PolicyStateKind::Init => {
                                self.state_kind = PolicyStateKind::AwaitingValidation {
                                    client,
                                    schedule_ret: ret,
                                    policy,
                                };
                            }
                            PolicyStateKind::ValidateRequested {
                                request,
                                validate_ret,
                            } => {
                                // TODO check policy against request
                                self.state_kind = PolicyStateKind::Validated {
                                    client,
                                    policy,
                                    typed_program,
                                };
                                validate_ret.send(Ok(())).unwrap();
                            }
                            _ => panic!(),
                        }
                    }
                }
                PolicyCmd::Validate(validate_request, ret) => {
                    match self.state_kind {
                        PolicyStateKind::Init => {
                            // go to state ValidateRequested, passing along return
                            self.state_kind = PolicyStateKind::ValidateRequested {
                                request: validate_request,
                                validate_ret: ret,
                            };
                        }
                        PolicyStateKind::AwaitingValidation {
                            client,
                            schedule_ret,
                            policy,
                        } => {
                            let typed_program = garble_lang::check(&policy.program).unwrap();

                            // TODO actually validate
                            // validate and go to validated
                            self.state_kind = PolicyStateKind::Validated {
                                client,
                                policy,
                                typed_program,
                            };
                            schedule_ret.send(Ok(())).unwrap();
                            ret.send(Ok(())).unwrap();
                        }
                        _ => panic!(),
                    }
                }
                PolicyCmd::Run(run_request, opt_ret) => {
                    match mem::take(&mut self.state_kind) {
                        PolicyStateKind::Validated {
                            client,
                            policy,
                            typed_program,
                        } => {
                            self.consts.insert(
                                format!("PARTY_{}", policy.party),
                                policy.constants.clone(),
                            );
                            let cmd_sender = self.cmd_tx.clone();
                            let policy_cl = policy.clone();
                            let (client_send, client_recv) = oneshot::channel();
                            self.state_kind = PolicyStateKind::SendingConsts {
                                policy,
                                typed_program,
                                client_recv,
                            };
                            if let Some(ret) = opt_ret {
                                ret.send(Ok(())).unwrap();
                            }
                            tokio::spawn(async move {
                                let const_futs = policy_cl.other_parties().map(async |p| {
                                    let const_req = ConstsRequest {
                                        from: policy_cl.party,
                                        consts: policy_cl.constants.clone(),
                                    };
                                    client.consts(p, const_req).await
                                });
                                future::try_join_all(const_futs).await.unwrap();
                                client_send.send(client);
                                cmd_sender
                                    .send(PolicyCmd::InternalConstsSent)
                                    .await
                                    .unwrap();
                            });
                        }
                        PolicyStateKind::Running {
                            typed_program,
                            policy,
                            channel,
                        } => {
                            let (compiled_tx, compiled_rx) = oneshot::channel();
                            let program = policy.program.clone();
                            let consts = mem::take(&mut self.consts);
                            thread::spawn(move || {
                                let compiled = compile_with_options(
                                    &program,
                                    CompileOptions {
                                        circuit_kind: CircuitKind::Register,
                                        consts,
                                        // false reduces peak memory consumption
                                        optimize_duplicate_gates: false,
                                    },
                                );
                                // ignore send error as execute_run_request has been dropped
                                let _ = compiled_tx.send(compiled);
                            });
                            let compiled = compiled_rx.await.unwrap().unwrap();

                            let input = compiled
                                .literal_arg(policy.party, policy.input.clone())
                                .unwrap()
                                .as_bits();
                            info!("starting mpc comp");
                            tokio::spawn(async move {
                                let output = polytune::mpc(
                                    &channel,
                                    compiled.circuit.unwrap_register_ref(),
                                    &input,
                                    0,
                                    policy.party,
                                    &vec![policy.leader],
                                    // create a tempdir in ./ and not /tmp because that is often backed by a tmpfs
                                    // and the files will be in memory and not on the disk
                                    None,
                                )
                                .await
                                .unwrap();
                                channel
                                    .client
                                    .output(
                                        policy.output,
                                        Ok(compiled.parse_output(&output).unwrap()),
                                    )
                                    .await;
                            });
                        }
                        _ => panic!(),
                    }
                }
                PolicyCmd::Consts(consts_request, ret) => match self.state_kind {
                    state @ (PolicyStateKind::SendingConsts { .. }
                    | PolicyStateKind::Validated { .. }) => {
                        self.state_kind = state;
                        let const_prefix = format!("PARTY_{}", consts_request.from);
                        self.consts.insert(const_prefix, consts_request.consts);
                        ret.send(Ok(()));
                    }
                    PolicyStateKind::SendingConstsCompleted {
                        policy,
                        typed_program,
                        client,
                    } => {
                        let const_prefix = format!("PARTY_{}", consts_request.from);
                        self.consts.insert(const_prefix, consts_request.consts);
                        ret.send(Ok(()));
                        if self.consts.len() == typed_program.const_deps.len() {
                            let receivers = self.channel_receivers.take().unwrap();
                            let channel = Channel {
                                client,
                                receivers,
                                party: policy.party,
                            };
                            let computation_id = policy.computation_id;
                            self.state_kind = PolicyStateKind::Running {
                                channel,
                                typed_program,
                                policy,
                            };
                            self.cmd_tx
                                .send(PolicyCmd::Run(RunRequest { computation_id }, None))
                                .await
                                .unwrap();
                        } else {
                            self.state_kind = PolicyStateKind::SendingConstsCompleted {
                                policy,
                                typed_program,
                                client,
                            };
                        }
                    }
                    _ => todo!(),
                },
                PolicyCmd::InternalConstsSent => match self.state_kind {
                    PolicyStateKind::SendingConsts {
                        policy,
                        typed_program,
                        client_recv,
                    } => {
                        let client = client_recv.await.unwrap();
                        // TODO DRY this with above
                        if self.consts.len() == typed_program.const_deps.len() {
                            let receivers = self.channel_receivers.take().unwrap();
                            let channel = Channel {
                                client,
                                receivers,
                                party: policy.party,
                            };
                            let computation_id = policy.computation_id;
                            self.state_kind = PolicyStateKind::Running {
                                channel,
                                typed_program,
                                policy,
                            };
                            self.cmd_tx
                                .send(PolicyCmd::Run(RunRequest { computation_id }, None))
                                .await
                                .unwrap();
                        } else {
                            self.state_kind = PolicyStateKind::SendingConstsCompleted {
                                policy,
                                typed_program,
                                client,
                            };
                        }
                    }
                    _ => panic!(),
                },
                PolicyCmd::MpcMsg(mpc_msg, ret) => {
                    self.channel_senders[mpc_msg.from]
                        .send(mpc_msg.data)
                        .await
                        .unwrap();
                    ret.send(Ok(()));
                }
            }
        }
    }
}

pub(crate) type Ret<R> = oneshot::Sender<R>;

#[derive(Default)]
pub(crate) enum PolicyStateKind<C> {
    #[default]
    Init,
    AwaitingValidation {
        client: C,
        policy: Policy,
        schedule_ret: Ret<Result<(), ScheduleError>>,
    },
    ValidateRequested {
        request: ValidateRequest,
        validate_ret: Ret<Result<(), ValidateError>>,
    },
    Validated {
        policy: Policy,
        typed_program: TypedProgram,
        client: C,
    },
    SendingConsts {
        policy: Policy,
        typed_program: TypedProgram,
        client_recv: oneshot::Receiver<C>,
    },
    SendingConstsCompleted {
        policy: Policy,
        typed_program: TypedProgram,
        client: C,
    },
    Running {
        typed_program: TypedProgram,
        policy: Policy,
        channel: Channel<C>,
    },
}

#[derive(Debug)]
pub(crate) struct ScheduleError;

#[derive(Debug)]
pub(crate) enum PolicyCmd {
    Schedule(Policy, Ret<Result<(), ScheduleError>>),
    Validate(ValidateRequest, Ret<Result<(), ValidateError>>),
    Run(RunRequest, Option<Ret<Result<(), RunError>>>),
    Consts(ConstsRequest, Ret<Result<(), ConstsError>>),
    MpcMsg(MpcMsg, Ret<Result<(), MpcMsgError>>),
    #[doc(hidden)]
    InternalConstsSent,
}

pub(crate) trait PolicyClientBuilder {
    type Client: PolicyClient;

    fn new(&self, participants: Vec<Url>) -> Self::Client;
}

pub(crate) trait PolicyClient: Send + Sync + 'static {
    async fn validate(&self, to: usize, req: ValidateRequest) -> Result<(), ValidateError>;
    async fn run(&self, to: usize, req: RunRequest) -> Result<(), RunError>;
    fn consts(
        &self,
        to: usize,
        req: ConstsRequest,
    ) -> impl Future<Output = Result<(), ConstsError>> + Send;
    fn msg(&self, to: usize, msg: MpcMsg) -> impl Future<Output = Result<(), MpcMsgError>> + Send;
    fn output(
        &self,
        to: Option<Url>,
        result: Result<Literal, ()>,
    ) -> impl Future<Output = Result<(), OutputError>> + Send;
}

pub(crate) struct Channel<C> {
    client: C,
    party: usize,
    receivers: Vec<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl<C: PolicyClient> polytune::channel::Channel for Channel<C> {
    type SendError = ();

    type RecvError = ();

    async fn send_bytes_to(
        &self,
        party: usize,
        data: Vec<u8>,
        phase: &str,
    ) -> Result<(), Self::SendError> {
        self.client
            .msg(
                party,
                MpcMsg {
                    from: self.party,
                    data,
                },
            )
            .await
            .unwrap();
        Ok(())
    }

    async fn recv_bytes_from(&self, party: usize, phase: &str) -> Result<Vec<u8>, Self::RecvError> {
        let data = self.receivers[party].lock().await.recv().await.unwrap();
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use garble_lang::literal::Literal;
    use tokio::sync::{Semaphore, mpsc, oneshot};

    use crate::state::{
        MpcMsgError, OutputError, Policy, PolicyClient, PolicyClientBuilder, PolicyCmd, PolicyState,
    };

    #[derive(Clone)]
    struct TestClient {
        cmd_senders: Vec<mpsc::Sender<PolicyCmd>>,
        output: mpsc::Sender<Result<Literal, ()>>,
    }

    impl PolicyClientBuilder for TestClient {
        type Client = Self;

        fn new(&self, participants: Vec<url::Url>) -> Self::Client {
            assert_eq!(self.cmd_senders.len(), participants.len());
            self.clone()
        }
    }

    impl PolicyClient for TestClient {
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

        async fn consts(
            &self,
            to: usize,
            req: super::ConstsRequest,
        ) -> Result<(), super::ConstsError> {
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
            to: Option<url::Url>,
            result: Result<Literal, ()>,
        ) -> Result<(), OutputError> {
            self.output.send(result).await.unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn basic_test() {
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
                println!("transmitting {cmd:?}");
                cmd_sender2_cl.send(cmd).await.unwrap();
            }
        });

        tokio::spawn(async move {
            while let Some(cmd) = receivers2[0].recv().await {
                println!("transmitting {cmd:?}");
                cmd_sender1_cl.send(cmd).await.unwrap();
            }
        });

        let pol1: Policy =
            serde_json::from_str(&fs::read_to_string("policy0.json").unwrap()).unwrap();
        let pol2: Policy =
            serde_json::from_str(&fs::read_to_string("policy1.json").unwrap()).unwrap();
        let (ret1_tx, ret1_rx) = oneshot::channel();
        let (ret2_tx, ret2_rx) = oneshot::channel();
        let sched1 = cmd_sender1.send(PolicyCmd::Schedule(pol1, ret1_tx));
        let sched2 = cmd_sender2.send(PolicyCmd::Schedule(pol2, ret2_tx));
        tokio::try_join!(sched1, sched2).unwrap();
        let (a, b) = tokio::try_join!(ret1_rx, ret2_rx).unwrap();
        a.unwrap();
        b.unwrap();
        dbg!(out_rx.recv().await);
        todo!()
    }
}
