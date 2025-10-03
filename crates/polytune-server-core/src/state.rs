use std::{collections::HashMap, fmt::Debug, mem, ops::ControlFlow, thread};

use futures::future;
use garble_lang::{
    CircuitKind, CompileOptions, GarbleConsts, TypedProgram, compile_with_options, literal::Literal,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    client::{PolicyClient, PolicyClientBuilder},
    policy::Policy,
};

#[cfg(test)]
mod tests;

pub struct PolicyState<B, C> {
    client_builder: B,
    concurrency: Semaphore,
    state_kind: PolicyStateKind<C>,
    consts: GarbleConsts,
    cmd_rx: mpsc::Receiver<PolicyCmd>,
    cmd_tx: mpsc::Sender<PolicyCmd>,
    channel_senders: Vec<mpsc::Sender<Vec<u8>>>,
    channel_receivers: Option<Vec<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>>,
}

pub type Ret<R> = oneshot::Sender<R>;

#[derive(Debug)]
// TODO can/should we reduce the size of PolicyCmd?
#[allow(clippy::large_enum_variant)]
pub enum PolicyCmd {
    Schedule(Policy, Ret<Result<(), ScheduleError>>),
    Validate(ValidateRequest, Ret<Result<(), ValidateError>>),
    Run(RunRequest, Option<Ret<Result<(), RunError>>>),
    Consts(ConstsRequest, Ret<Result<(), ConstsError>>),
    MpcMsg(MpcMsg, Ret<Result<(), MpcMsgError>>),
    #[doc(hidden)]
    InternalConstsSent,
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    /// Create a new [`PolicyState`].
    ///
    /// This returns the state machine, which can be executing by awaiting
    /// [`PolicyState::start`] and controlled by sending [`PolicyCmd`] to
    /// the sender.
    ///
    /// # Panics
    /// - If `concurrency` [`Semaphore`] is closed.
    pub fn new(client_builder: B, concurrency: Semaphore) -> (Self, mpsc::Sender<PolicyCmd>) {
        if concurrency.is_closed() {
            panic!("concurrency semaphore must not be closed");
        }
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        (
            Self {
                client_builder,
                concurrency,
                state_kind: PolicyStateKind::Init,
                consts: Default::default(),
                cmd_rx,
                cmd_tx: cmd_tx.clone(),
                channel_senders: vec![],
                channel_receivers: None,
            },
            cmd_tx,
        )
    }

    pub async fn start(mut self) {
        while let Some(cmd) = self.cmd_rx.recv().await {
            debug!("handling {cmd:?}");
            self = match self.handle_cmd(cmd).await {
                ControlFlow::Continue(this) => this,
                ControlFlow::Break(_) => return,
            }
        }
    }
}

#[derive(Default)]
pub(crate) enum PolicyStateKind<C> {
    #[default]
    Init,
    AwaitingValidation {
        client: C,
        policy: Policy,
        typed_program: TypedProgram,
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
        policy: Policy,
        channel: Channel<C>,
    },
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
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
                self.msg(mpc_msg, ret).await?;
            }
        }
        ControlFlow::Continue(self)
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum ScheduleError {
    #[error("Policy contains invalid Garble program")]
    // TODO use source for garble error once they implement Error trait
    InvalidProgram { err: garble_lang::Error },
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

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error("error when requesting run from followers")]
    RequestRunError { source: BoxError },
    #[error("error when sending consts")]
    SendConstsError { source: BoxError },
    #[error("error during program compilation: {0:?}")]
    CompileError(garble_lang::Error),
    #[error("invalid input to garble program: {0:?}")]
    InvalidInput(garble_lang::eval::EvalError),
    #[error("error during mpc evaluation: {0:?}")]
    MpcError(polytune::Error),
    #[error("internal error: unable to convert polytune output to Garble Literal. {0:?}")]
    InvalidOutput(garble_lang::eval::EvalError),
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    async fn schedule(
        mut self,
        policy: Policy,
        ret: Ret<Result<(), ScheduleError>>,
    ) -> ControlFlow<(), Self> {
        let is_leader = policy.party == policy.leader;

        let typed_program = match garble_lang::check(&policy.program) {
            Ok(prg) => prg,
            Err(err) => {
                let _ = ret.send(Err(ScheduleError::InvalidProgram { err }));
                return ControlFlow::Break(());
            }
        };
        self.init_channel(&policy);

        if is_leader {
            if !matches!(self.state_kind, PolicyStateKind::Init) {
                let _ = ret.send(Err(ScheduleError::InvalidStateLeader {
                    computation_id: policy.computation_id,
                    state: format!("{:?}", self.state_kind),
                }));
                return ControlFlow::Continue(self);
            }
            let client = self.client_builder.new_client(&policy);

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
            if let Err(err) = future::try_join_all(run_futs).await
                && let Some(url) = policy.output
            {
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
            let client = self.client_builder.new_client(&policy);

            match self.state_kind {
                PolicyStateKind::Init => {
                    self.state_kind = PolicyStateKind::AwaitingValidation {
                        client,
                        schedule_ret: ret,
                        policy,
                        typed_program,
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

    fn init_channel(&mut self, policy: &Policy) {
        let mut channel_senders = vec![];
        let mut channel_receivers = vec![];
        // TODO actual size
        for _ in 0..policy.participants.len() {
            // TODO buffer size?
            let (sender, receiver) = mpsc::channel(1);
            channel_senders.push(sender);
            channel_receivers.push(tokio::sync::Mutex::new(receiver));
        }
        self.channel_senders = channel_senders;
        self.channel_receivers = Some(channel_receivers);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidateRequest {
    pub computation_id: Uuid,
    pub program_hash: String,
    pub leader: usize,
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
#[non_exhaustive]
pub enum ValidateError {
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

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
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
                typed_program,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RunRequest {
    pub computation_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RunError {
    #[error(
        "unabel to run policy {computation_id}. state must be Validated or Running but is {state}"
    )]
    InvalidState { state: String, computation_id: Uuid },
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
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
                // insert own constants
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
                // Return from run requests before sending consts, so we don't
                // hold up the leader who sent run
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
                    if let Err(err) = future::try_join_all(const_futs).await
                        && let Some(url) = policy_cl.output
                    {
                        // TODO log error
                        let _ = client
                            .output(
                                url,
                                Err(OutputError::SendConstsError {
                                    source: Box::new(err),
                                }),
                            )
                            .await;
                    }
                    // returns an error if the state machine is dropped, nothing to do
                    let _ = client_send.send(client);
                    let _ = cmd_sender.send(PolicyCmd::InternalConstsSent).await;
                });
            }
            PolicyStateKind::Running { policy, channel } => {
                let (compiled_tx, compiled_rx) = oneshot::channel();
                let program = policy.program.clone();
                let consts = mem::take(&mut self.consts);
                // We compile the program in a separate thread so we don't block the runtime
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
                // TODO, the sender should only drop if the compilation panics, should we maybe
                // catch_unwind in the thread and transmit panics?
                let compiled = match compiled_rx.await.expect("sender dropped") {
                    Ok(compiled) => compiled,
                    Err(err) => {
                        if let Some(url) = policy.output {
                            // TODO log error
                            let _ = channel
                                .client
                                .output(url, Err(OutputError::CompileError(err)))
                                .await;
                        }
                        // stop the state machine
                        return ControlFlow::Break(());
                    }
                };

                let input = match compiled.literal_arg(policy.party, policy.input.clone()) {
                    Ok(args) => args.as_bits(),
                    Err(err) => {
                        if let Some(url) = policy.output {
                            // TODO log error
                            let _ = channel
                                .client
                                .output(url, Err(OutputError::InvalidInput(err)))
                                .await;
                        }
                        // stop the state machine
                        return ControlFlow::Break(());
                    }
                };
                info!("starting mpc comp");
                // TODO this is wrong, we should check in validation which policies
                // have an output Url and collect those party IDs. The following will
                // likely break if if we have two Polcies both with output Urls, as
                // `mpc` will only be passed one id.
                let p_out = if policy.output.is_some() {
                    vec![policy.party]
                } else {
                    vec![]
                };
                // TODO what happens with the state machine if `mpc` finishes?
                // we can't return ControlFlow::Break from tokio::spawn and we also can't
                // wait here for the spawned task, as we need to continue with the state machine
                // which needs to handle the msg commands
                // maybe we could have a receiver which we concurrently with the cmd_receiver wait on
                tokio::spawn(async move {
                    let output = polytune::mpc(
                        &channel,
                        compiled.circuit.unwrap_register_ref(),
                        &input,
                        0,
                        policy.party,
                        &p_out,
                        // create a tempdir in ./ and not /tmp because that is often backed by a tmpfs
                        // and the files will be in memory and not on the disk
                        // TODO: Have configurable tmpdir
                        None,
                    )
                    .await;
                    if let Some(url) = policy.output {
                        let client = channel.client;
                        match output {
                            Ok(output) if !output.is_empty() => {
                                let _ = client
                                    .output(
                                        url,
                                        compiled
                                            .parse_output(&output)
                                            .map_err(OutputError::InvalidOutput),
                                    )
                                    .await;
                            }
                            Ok(_) => {
                                warn!("policy contained output url but party received no output");
                            }
                            Err(err) => {
                                let _ = client.output(url, Err(OutputError::MpcError(err))).await;
                            }
                        }
                    }
                });
            }
            state => {
                if let Some(ret) = opt_ret {
                    let _ = ret.send(Err(RunError::InvalidState {
                        computation_id: req.computation_id,
                        state: format!("{state:?}"),
                    }));
                }
                // TODO should in this case the state machine continue or do we want to return Break?
                self.state_kind = state;
            }
        }
        ControlFlow::Continue(self)
    }
}

pub type Consts = HashMap<String, Literal>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstsRequest {
    pub from: usize,
    pub computation_id: Uuid,
    pub consts: Consts,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConstsError {
    #[error(
        "unabel to add consts for policy {computation_id}. state must be Validate, SendingConsts or SendingConstsCompleted but is {state}"
    )]
    InvalidState { state: String, computation_id: Uuid },
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    async fn consts(
        mut self,
        consts_request: ConstsRequest,
        ret: Ret<Result<(), ConstsError>>,
    ) -> ControlFlow<(), Self> {
        match mem::take(&mut self.state_kind) {
            state @ (PolicyStateKind::Validated { .. } | PolicyStateKind::SendingConsts { .. }) => {
                self.state_kind = state;
                let const_prefix = format!("PARTY_{}", consts_request.from);
                self.consts.insert(const_prefix, consts_request.consts);
                let _ = ret.send(Ok(()));
            }
            PolicyStateKind::SendingConstsCompleted {
                policy,
                typed_program,
                client,
            } => {
                let const_prefix = format!("PARTY_{}", consts_request.from);
                self.consts.insert(const_prefix, consts_request.consts);
                let _ = ret.send(Ok(()));
                self.check_consts(client, policy, typed_program).await;
            }
            state => {
                let _ = ret.send(Err(ConstsError::InvalidState {
                    state: format!("{state:?}"),
                    computation_id: consts_request.computation_id,
                }));
                self.state_kind = state;
            }
        }
        ControlFlow::Continue(self)
    }

    async fn internal_consts_sent(mut self) -> ControlFlow<(), Self> {
        match mem::take(&mut self.state_kind) {
            PolicyStateKind::SendingConsts {
                policy,
                typed_program,
                client_recv,
            } => {
                let client = client_recv.await.unwrap();
                // TODO DRY this with above
                self.check_consts(client, policy, typed_program).await;
            }
            _ => panic!(),
        }
        ControlFlow::Continue(self)
    }

    async fn check_consts(
        &mut self,
        client: C,
        policy: Policy,
        typed_program: garble_lang::ast::Program<garble_lang::ast::Type>,
    ) {
        if self.consts.len() == typed_program.const_deps.len() {
            let receivers = self
                .channel_receivers
                .take()
                .expect("initialized in schedule");
            let channel = Channel {
                client,
                receivers,
                party: policy.party,
            };
            let computation_id = policy.computation_id;
            self.state_kind = PolicyStateKind::Running { channel, policy };
            self.cmd_tx
                .send(PolicyCmd::Run(RunRequest { computation_id }, None))
                .await
                .expect("unreachable");
        } else {
            self.state_kind = PolicyStateKind::SendingConstsCompleted {
                policy,
                typed_program,
                client,
            };
        }
    }
}

pub struct MpcMsg {
    pub from: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum MpcMsgError {
    #[error("polytune engine is unreachable")]
    Unreachable,
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    async fn msg(&self, mpc_msg: MpcMsg, ret: Ret<Result<(), MpcMsgError>>) -> ControlFlow<()> {
        match self.channel_senders[mpc_msg.from].send(mpc_msg.data).await {
            Ok(_) => {
                let _ = ret.send(Ok(()));
                ControlFlow::Continue(())
            }
            Err(_) => {
                let _ = ret.send(Err(MpcMsgError::Unreachable));
                ControlFlow::Break(())
            }
        }
    }
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

impl Debug for MpcMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcMsg")
            .field("from", &self.from)
            .field("data_len", &self.data.len())
            .finish()
    }
}

pub(crate) struct Channel<C> {
    client: C,
    party: usize,
    receivers: Vec<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("PolicyState state machine has stopped execution")]
pub(crate) struct RecvErr;

impl<C: PolicyClient> polytune::channel::Channel for Channel<C> {
    type SendError = C::ClientError<MpcMsgError>;

    type RecvError = RecvErr;

    async fn send_bytes_to(
        &self,
        party: usize,
        data: Vec<u8>,
        _phase: &str,
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
    }

    async fn recv_bytes_from(
        &self,
        party: usize,
        _phase: &str,
    ) -> Result<Vec<u8>, Self::RecvError> {
        self.receivers[party]
            .lock()
            .await
            .recv()
            .await
            .ok_or(RecvErr)
    }
}
