use std::{collections::HashMap, convert::Infallible, fmt::Debug, mem, ops::ControlFlow, thread};

use futures::future;
use garble_lang::{
    CircuitKind, CompileOptions, GarbleConsts, TypedProgram, compile_with_options, literal::Literal,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{debug, error, info};
use url::Url;
use uuid::Uuid;

use crate::api::ConstError;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

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
    fn program_hash(&self) -> String {
        blake3::hash(self.program.as_bytes()).to_string()
    }
    fn other_parties(&self) -> impl Iterator<Item = usize> + Clone {
        (0..self.participants.len()).filter(|p| *p != self.party)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ScheduleError {
    #[error(
        "unable to schedule policy {computation_id}. state must be Init for leader but is {state}"
    )]
    InvalidStateLeader { computation_id: Uuid, state: String },
    #[error(
        "unable to schedule policy {computation_id}. state must be Init or ValidateRequested but is {state}"
    )]
    InvalidStateFollower { computation_id: Uuid, state: String },
    #[error("validation of party {to} failed")]
    ValidateFailed { to: usize, source: BoxError },
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
            program_hash: policy.program_hash(),
            leader: policy.leader,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValidateError {
    #[error(
        "scheduled leader {scheduled_leader} but got validate request with leader: {requested_leader}"
    )]
    LeaderMismatch {
        scheduled_leader: usize,
        requested_leader: usize,
    },
    #[error(
        "scheduled policy with program hash {scheduled_hash} but got validate request with hash: {requested_hash}"
    )]
    ProgramHashMismatch {
        scheduled_hash: String,
        requested_hash: String,
    },
    #[error(
        "unable to validate policy {computation_id}. state must be Init or AwaitingValidation but is {state}"
    )]
    InvalidState { computation_id: Uuid, state: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct RunRequest {
    pub(crate) computation_id: Uuid,
}
#[derive(Debug, thiserror::Error)]
#[error("TODO")]
pub(crate) struct RunError;

pub(crate) type Consts = HashMap<String, Literal>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ConstsRequest {
    pub(crate) from: usize,
    pub(crate) computation_id: Uuid,
    consts: Consts,
}
#[derive(Debug, thiserror::Error)]
#[error("TODO")]
pub(crate) struct ConstsError;

pub(crate) struct MpcMsg {
    pub(crate) from: usize,
    pub(crate) data: Vec<u8>,
}

impl Debug for MpcMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcMsg")
            .field("from", &self.from)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("TODO")]
pub(crate) struct MpcMsgError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum OutputError {
    #[error("error when requesting run from followers")]
    RequestRunError { source: BoxError },
}

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
    ///
    /// # Panics
    /// - If `concurrency` [`Semaphore`] is closed.
    pub(crate) fn new(
        client_builder: B,
        concurrency: Semaphore,
    ) -> (Self, mpsc::Sender<PolicyCmd>) {
        if concurrency.is_closed() {
            panic!("concurrency semaphore must not be closed");
        }
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
            debug!("handling {cmd:?}");
            self = match self.handle_cmd(cmd).await {
                ControlFlow::Continue(this) => this,
                ControlFlow::Break(_) => return,
            }
        }
    }

    async fn handle_cmd(mut self, cmd: PolicyCmd) -> ControlFlow<(), Self> {
        match cmd {
            PolicyCmd::Schedule(policy, ret) => {
                self = self.schedule(policy, ret).await?;
            }
            PolicyCmd::Validate(request, ret) => {
                self = self.validate(request, ret).await?;
            }
            PolicyCmd::Run(request, opt_ret) => {
                self = self.run(request, opt_ret).await?;
            }
            PolicyCmd::Consts(request, ret) => {
                self = self.consts(request, ret).await?;
            }
            PolicyCmd::InternalConstsSent => {
                self = self.internal_consts_sent().await?;
            }
            PolicyCmd::MpcMsg(mpc_msg, ret) => {
                self.channel_senders[mpc_msg.from]
                    .send(mpc_msg.data)
                    .await
                    .unwrap();
                let _ = ret.send(Ok(()));
            }
        }
        ControlFlow::Continue(self)
    }

    async fn schedule(
        mut self,
        policy: Policy,
        ret: Ret<Result<(), ScheduleError>>,
    ) -> ControlFlow<(), Self> {
        let is_leader = policy.party == policy.leader;

        let typed_program = garble_lang::check(&policy.program).unwrap();

        if is_leader {
            if !matches!(self.state_kind, PolicyStateKind::Init) {
                let _ = ret.send(Err(ScheduleError::InvalidStateLeader {
                    computation_id: policy.computation_id,
                    state: format!("{:?}", self.state_kind),
                }));
                return ControlFlow::Continue(self);
            }
            let client = self.client_builder.new(&policy);

            debug!("sending validate to followers");
            let validate_req = ValidateRequest::from(&policy);
            let validate_futs = policy.other_parties().map(async |p| {
                client
                    .validate(p, validate_req.clone())
                    .await
                    .map_err(|err| (p, err))
            });
            if let Err((to, err)) = future::try_join_all(validate_futs).await {
                let _ = ret.send(Err(ScheduleError::ValidateFailed {
                    to,
                    source: Box::new(err),
                }));
                return ControlFlow::Break(());
            }
            debug!("validated followers");
            // we return from `schedule` call after validating with the the other parties
            // which means that they are reachable and a compatible policy has been scheduled
            // for these parties
            let _ = ret.send(Ok(()));

            // We currently limit the concurrency in terms of computation where a party is the leader
            let _permit = self
                .concurrency
                .acquire()
                .await
                .expect("is_closed checked in new()");
            let run_request = RunRequest {
                computation_id: policy.computation_id,
            };
            debug!("sending run to followers");
            let run_futs = policy
                .other_parties()
                .map(async |p| client.run(p, run_request.clone()).await);
            if let Err(err) = future::try_join_all(run_futs).await {
                if let Some(url) = policy.output {
                    let res = client
                        .output(
                            url.clone(),
                            Err(OutputError::RequestRunError {
                                source: Box::new(err),
                            }),
                        )
                        .await;
                    if let Err(err) = res {
                        error!(?err, "unable to notify output {url} of request run error")
                    }
                    return ControlFlow::Break(());
                }
            }
            debug!("followers are running");
            self.state_kind = PolicyStateKind::Validated {
                client,
                policy,
                typed_program,
            };
            self.cmd_tx
                .send(PolicyCmd::Run(run_request, None))
                .await
                .expect("unreachable");
        } else {
            // Schedule on  a follower
            let client = self.client_builder.new(&policy);

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
                    if request.leader != policy.leader {
                        let _ = validate_ret.send(Err(ValidateError::LeaderMismatch {
                            scheduled_leader: policy.leader,
                            requested_leader: request.leader,
                        }));
                        return ControlFlow::Break(());
                    }
                    let scheduled_hash = policy.program_hash();
                    if request.program_hash != scheduled_hash {
                        let _ = validate_ret.send(Err(ValidateError::ProgramHashMismatch {
                            scheduled_hash,
                            requested_hash: request.program_hash,
                        }));
                        return ControlFlow::Break(());
                    }
                    self.state_kind = PolicyStateKind::Validated {
                        client,
                        policy,
                        typed_program,
                    };
                    let _ = validate_ret.send(Ok(()));
                }
                state => {
                    let _ = ret.send(Err(ScheduleError::InvalidStateFollower {
                        computation_id: policy.computation_id,
                        state: format!("{state:?}"),
                    }));
                    // keep the state machine for this computation running in case
                    // of an erronous schedule
                    self.state_kind = state;
                }
            }
        }
        ControlFlow::Continue(self)
    }

    async fn validate(
        mut self,
        request: ValidateRequest,
        validate_ret: Ret<Result<(), ValidateError>>,
    ) -> ControlFlow<(), Self> {
        match self.state_kind {
            PolicyStateKind::Init => {
                // go to state ValidateRequested, passing along return
                self.state_kind = PolicyStateKind::ValidateRequested {
                    request,
                    validate_ret,
                };
            }
            PolicyStateKind::AwaitingValidation {
                client,
                schedule_ret,
                policy,
            } => {
                let typed_program = garble_lang::check(&policy.program).unwrap();

                if request.leader != policy.leader {
                    let _ = validate_ret.send(Err(ValidateError::LeaderMismatch {
                        scheduled_leader: policy.leader,
                        requested_leader: request.leader,
                    }));
                    return ControlFlow::Break(());
                }
                let scheduled_hash = policy.program_hash();
                if request.program_hash != scheduled_hash {
                    let _ = validate_ret.send(Err(ValidateError::ProgramHashMismatch {
                        scheduled_hash,
                        requested_hash: request.program_hash,
                    }));
                    return ControlFlow::Break(());
                }

                // validate and go to validated
                self.state_kind = PolicyStateKind::Validated {
                    client,
                    policy,
                    typed_program,
                };
                // TOOD is the ordering irrelevant here?
                let _ = schedule_ret.send(Ok(()));
                let _ = validate_ret.send(Ok(()));
            }
            state => {
                let _ = validate_ret.send(Err(ValidateError::InvalidState {
                    computation_id: request.computation_id,
                    state: format!("{state:?}"),
                }));
                self.state_kind = state;
            }
        }
        ControlFlow::Continue(self)
    }

    async fn run(
        mut self,
        req: RunRequest,
        opt_ret: Option<Ret<Result<(), RunError>>>,
    ) -> ControlFlow<(), Self> {
        match mem::take(&mut self.state_kind) {
            PolicyStateKind::Validated {
                client,
                policy,
                typed_program,
            } => {
                self.consts
                    .insert(format!("PARTY_{}", policy.party), policy.constants.clone());
                let cmd_sender = self.cmd_tx.clone();
                let policy_cl = policy.clone();
                let (client_send, client_recv) = oneshot::channel();
                self.state_kind = PolicyStateKind::SendingConsts {
                    policy,
                    typed_program,
                    client_recv,
                };
                if let Some(ret) = opt_ret {
                    let _ = ret.send(Ok(()));
                }
                tokio::spawn(async move {
                    let const_futs = policy_cl.other_parties().map(async |p| {
                        let const_req = ConstsRequest {
                            from: policy_cl.party,
                            consts: policy_cl.constants.clone(),
                            computation_id: policy_cl.computation_id,
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
                    if let Some(url) = policy.output {
                        if !output.is_empty() {
                            channel
                                .client
                                .output(url, Ok(compiled.parse_output(&output).unwrap()))
                                .await
                                .unwrap();
                        }
                    }
                });
            }
            _ => panic!(),
        }
        ControlFlow::Continue(self)
    }

    async fn consts(
        mut self,
        consts_request: ConstsRequest,
        ret: Ret<Result<(), ConstsError>>,
    ) -> ControlFlow<(), Self> {
        match self.state_kind {
            state @ (PolicyStateKind::SendingConsts { .. } | PolicyStateKind::Validated { .. }) => {
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
        }
        ControlFlow::Continue(self)
    }

    async fn internal_consts_sent(mut self) -> ControlFlow<(), Self> {
        match self.state_kind {
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
        }
        ControlFlow::Continue(self)
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

impl<C> Debug for PolicyStateKind<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init => write!(f, "Init"),
            Self::AwaitingValidation { .. } => write!(f, "AwaitingValidation"),
            Self::ValidateRequested { .. } => write!(f, "ValidateRequested"),
            Self::Validated { .. } => write!(f, "Validated"),
            Self::SendingConsts { .. } => write!(f, "SendingConsts"),
            Self::SendingConstsCompleted { .. } => write!(f, "SendingConstsCompleted"),
            Self::Running { .. } => write!(f, "Running"),
        }
    }
}

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

    fn new(&self, policy: &Policy) -> Self::Client;
}

pub(crate) trait PolicyClient: Send + Sync + 'static {
    type ClientError<E>: std::error::Error + Send + Sync
    where
        E: std::error::Error + Send + Sync;

    async fn validate(
        &self,
        to: usize,
        req: ValidateRequest,
    ) -> Result<(), Self::ClientError<ValidateError>>;
    async fn run(&self, to: usize, req: RunRequest) -> Result<(), Self::ClientError<RunError>>;
    fn consts(
        &self,
        to: usize,
        req: ConstsRequest,
    ) -> impl Future<Output = Result<(), Self::ClientError<ConstsError>>> + Send;
    fn msg(
        &self,
        to: usize,
        msg: MpcMsg,
    ) -> impl Future<Output = Result<(), Self::ClientError<MpcMsgError>>> + Send;
    fn output(
        &self,
        to: Url,
        result: Result<Literal, OutputError>,
    ) -> impl Future<Output = Result<(), Self::ClientError<Infallible>>> + Send;
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
    use std::{convert::Infallible, fmt::Debug, fs, time::Duration};

    use garble_lang::literal::Literal;
    use tokio::sync::{Semaphore, mpsc, oneshot};
    use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

    use crate::state::{
        MpcMsgError, OutputError, Policy, PolicyClient, PolicyClientBuilder, PolicyCmd, PolicyState,
    };

    #[derive(Clone)]
    struct TestClient {
        cmd_senders: Vec<mpsc::Sender<PolicyCmd>>,
        output: mpsc::Sender<Result<Literal, OutputError>>,
    }

    impl PolicyClientBuilder for TestClient {
        type Client = Self;

        fn new(&self, policy: &Policy) -> Self::Client {
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
