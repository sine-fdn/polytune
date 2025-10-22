use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    mem,
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
};

use futures::future;
use garble_lang::{
    CircuitKind, CompileOptions, GarbleConsts, TypedProgram, compile_with_options, literal::Literal,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tracing::{Instrument, Level, Span, debug, debug_span, error, field, info_span, trace, warn};
use uuid::Uuid;

use crate::{
    client::{PolicyClient, PolicyClientBuilder},
    handle::PolicyStateHandle,
    policy::Policy,
};

#[cfg(test)]
mod tests;

/// A state-machine that coordinates the secure execution of a [`Policy`].
pub struct PolicyState<B, C> {
    client_builder: B,
    concurrency: Arc<Semaphore>,
    tmp_dir_path: Option<PathBuf>,
    permit: Option<OwnedSemaphorePermit>,
    state_kind: PolicyStateKind<C>,
    consts: GarbleConsts,
    cmd_rx: mpsc::Receiver<PolicyCmd>,
    cmd_tx: mpsc::Sender<PolicyCmd>,
    channel_senders: Vec<mpsc::Sender<Vec<u8>>>,
    channel_receivers: Option<Vec<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>>,
    start_span: Option<Span>,
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    /// Create a new [`PolicyState`].
    ///
    /// This returns the state machine, which can be executing by awaiting
    /// [`PolicyState::start`] and communicated with using the [`PolicyStateHandle`].
    ///
    /// # Panics
    /// - If `concurrency` [`Semaphore`] is closed.
    pub fn new(client_builder: B, concurrency: Arc<Semaphore>) -> (Self, PolicyStateHandle) {
        if concurrency.is_closed() {
            panic!("concurrency semaphore must not be closed");
        }
        // TODO what should the buffer size be?
        let (cmd_tx, cmd_rx) = mpsc::channel(10);
        (
            Self {
                client_builder,
                concurrency,
                tmp_dir_path: None,
                permit: None,
                state_kind: PolicyStateKind::Init,
                consts: Default::default(),
                cmd_rx,
                cmd_tx: cmd_tx.clone(),
                channel_senders: vec![],
                channel_receivers: None,
                start_span: None,
            },
            PolicyStateHandle(cmd_tx),
        )
    }

    /// Set the tmp dir path passed to [`polytune::mpc()`].
    ///
    /// Please note the documentation regarding the location of path at [`polytune::mpc()`]
    /// (`/tmp` is usually not what you want).
    /// If this method is not called, `None` will be provided to the `mpc` function.
    pub fn with_tmp_dir(mut self, path: &Path) -> Self {
        self.tmp_dir_path = Some(path.to_owned());
        self
    }

    /// Executes the policy state machine.
    pub async fn start(mut self) {
        // We manually create the span with empty fields for the computation id and party so that we can store a
        // clone of the span in the policy state and record those values later once we know them
        let start_span = info_span!(target:"polytune_server_core::state", "start", computation_id = field::Empty, party = field::Empty);
        self.start_span = Some(start_span.clone());
        async {
            while let Some(cmd) = self.cmd_rx.recv().await {
                self = match self.handle_cmd(cmd).await {
                    ControlFlow::Continue(this) => this,
                    ControlFlow::Break(_) => return,
                }
            }
        }
        .instrument(start_span)
        .await
    }
}

/// Convenience type alias for a oneshot Sender which returns the result of a [`PolicyCmd`].
pub(crate) type Ret<E> = oneshot::Sender<Result<(), E>>;

/// Helper function to log error and return error via Ret sender
fn ret_err<E: Display>(ret: Ret<E>, err: E) {
    error!(%err);
    let _ = ret.send(Err(err));
}

// TODO can/should we reduce the size of PolicyCmd?
#[allow(clippy::large_enum_variant)]
pub(crate) enum PolicyCmd {
    Schedule(Policy, Ret<ScheduleError>),
    Validate(ValidateRequest, Ret<ValidateError>),
    Run(RunRequest, Option<Ret<RunError>>),
    Consts(ConstsRequest, Ret<ConstsError>),
    MpcMsg(MpcMsg, Ret<MpcMsgError>),
    InternalConstsSent,
    Stop,
}

impl Debug for PolicyCmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Schedule(arg0, ..) => f.debug_tuple("Schedule").field(arg0).finish(),
            Self::Validate(arg0, ..) => f.debug_tuple("Validate").field(arg0).finish(),
            Self::Run(arg0, ..) => f.debug_tuple("Run").field(arg0).finish(),
            Self::Consts(arg0, ..) => f.debug_tuple("Consts").field(arg0).finish(),
            Self::MpcMsg(arg0, ..) => f.debug_tuple("MpcMsg").field(arg0).finish(),
            Self::InternalConstsSent => write!(f, "InternalConstsSent"),
            Self::Stop => write!(f, "Stop"),
        }
    }
}

#[derive(Default)]
enum PolicyStateKind<C> {
    #[default]
    Init,
    AwaitingValidation {
        client: C,
        policy: Policy,
        typed_program: TypedProgram,
        schedule_ret: Ret<ScheduleError>,
    },
    ValidateRequested {
        request: ValidateRequest,
        validate_ret: Ret<ValidateError>,
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
            PolicyCmd::Stop => {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(self)
    }
}

/// Type alias for a boxed dyn Error + Send + Sync.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Error during scheduling a policy.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ScheduleError {
    #[error("Policy contains invalid Garble program\n{err}")]
    InvalidProgram { err: String },
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

/// Error that is sent via the [`PolicyClient::output`] method to the output url.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum OutputError {
    #[error("error when requesting run from followers")]
    RequestRunError { source: BoxError },
    #[error("error when sending consts")]
    SendConstsError { source: BoxError },
    #[error("error during program compilation: {0:?}")]
    CompileError(garble_lang::Error),
    #[error(
        "panic during program compilation. Please report this at https://github.com/sine-fdn/garble-lang"
    )]
    CompilePanic,
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
    #[tracing::instrument(level = Level::DEBUG, skip_all, fields(computation_id = %policy.computation_id, party = policy.party))]
    async fn schedule(mut self, policy: Policy, ret: Ret<ScheduleError>) -> ControlFlow<(), Self> {
        debug!(?policy, "scheduling policy for execution");
        let is_leader = policy.party == policy.leader;

        let typed_program = match garble_lang::check(&policy.program) {
            Ok(prg) => prg,
            Err(err) => {
                ret_err(
                    ret,
                    ScheduleError::InvalidProgram {
                        err: err.prettify(&policy.program),
                    },
                );
                return ControlFlow::Break(());
            }
        };
        self.init_channel(&policy);

        if is_leader {
            if !matches!(self.state_kind, PolicyStateKind::Init) {
                ret_err(
                    ret,
                    ScheduleError::InvalidStateLeader {
                        computation_id: policy.computation_id,
                        state: format!("{:?}", self.state_kind),
                    },
                );
                return ControlFlow::Continue(self);
            }
            record_span_fields(&self.start_span, &policy.computation_id, policy.party);
            let client = self.client_builder.new_client(&policy);

            trace!("sending validate to followers");
            let validate_req = ValidateRequest::from(&policy);
            let validate_futs = policy.other_parties().map(async |p| {
                client
                    .validate(p, validate_req.clone())
                    .await
                    .map_err(|err| (p, err))
            });
            if let Err((to, err)) = future::try_join_all(validate_futs).await {
                ret_err(
                    ret,
                    ScheduleError::ValidateFailed {
                        to,
                        source: Box::new(err),
                    },
                );
                return ControlFlow::Break(());
            }
            trace!("validated followers");
            // we return from `schedule` call after validating with the the other parties
            // which means that they are reachable and a compatible policy has been scheduled
            // for these parties
            let _ = ret.send(Ok(()));

            // We currently limit the concurrency in terms of computation where a party is the leader
            self.permit = Some(
                Arc::clone(&self.concurrency)
                    .acquire_owned()
                    .await
                    .expect("is_closed checked in new()"),
            );
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
            // Schedule on a follower
            let client = self.client_builder.new_client(&policy);

            match self.state_kind {
                PolicyStateKind::Init => {
                    record_span_fields(&self.start_span, &policy.computation_id, policy.party);
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
                    record_span_fields(&self.start_span, &policy.computation_id, policy.party);
                    if request.leader != policy.leader {
                        ret_err(
                            validate_ret,
                            ValidateError::LeaderMismatch {
                                scheduled_leader: policy.leader,
                                requested_leader: request.leader,
                            },
                        );
                        return ControlFlow::Break(());
                    }
                    let scheduled_hash = policy.program_hash();
                    if request.program_hash != scheduled_hash {
                        ret_err(
                            validate_ret,
                            ValidateError::ProgramHashMismatch {
                                scheduled_hash,
                                requested_hash: request.program_hash,
                            },
                        );
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
                    ret_err(
                        ret,
                        ScheduleError::InvalidStateFollower {
                            computation_id: policy.computation_id,
                            state: format!("{state:?}"),
                        },
                    );
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
        for _ in 0..policy.participants.len() {
            // TODO buffer size?
            let (sender, receiver) = mpsc::channel(10);
            channel_senders.push(sender);
            channel_receivers.push(tokio::sync::Mutex::new(receiver));
        }
        self.channel_senders = channel_senders;
        self.channel_receivers = Some(channel_receivers);
    }
}
fn record_span_computation_id(span: &Option<Span>, computation_id: &Uuid) {
    if let Some(span) = &span {
        span.record("computation_id", format!("{:?}", computation_id));
    }
}

fn record_span_fields(span: &Option<Span>, computation_id: &Uuid, party: usize) {
    if let Some(span) = &span {
        span.record("computation_id", format!("{:?}", computation_id));
        span.record("party", party);
    }
}

/// A request to validate a policy against a scheduled policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ValidateRequest {
    /// Computation id of the scheduled policy.
    pub computation_id: Uuid,
    /// Program hash computed by [`Policy::program_hash`].
    pub program_hash: String,
    /// Leader party.
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

/// Error occured during policy validation.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
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
    #[tracing::instrument(level = Level::DEBUG, skip(self, validate_ret))]
    async fn validate(
        mut self,
        request: ValidateRequest,
        validate_ret: Ret<ValidateError>,
    ) -> ControlFlow<(), Self> {
        match self.state_kind {
            PolicyStateKind::Init => {
                record_span_computation_id(&self.start_span, &request.computation_id);
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
                    ret_err(
                        validate_ret,
                        ValidateError::LeaderMismatch {
                            scheduled_leader: policy.leader,
                            requested_leader: request.leader,
                        },
                    );
                    return ControlFlow::Break(());
                }
                let scheduled_hash = policy.program_hash();
                if request.program_hash != scheduled_hash {
                    ret_err(
                        validate_ret,
                        ValidateError::ProgramHashMismatch {
                            scheduled_hash,
                            requested_hash: request.program_hash,
                        },
                    );
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
                ret_err(
                    validate_ret,
                    ValidateError::InvalidState {
                        computation_id: request.computation_id,
                        state: format!("{state:?}"),
                    },
                );
                self.state_kind = state;
            }
        }
        ControlFlow::Continue(self)
    }
}

/// A request to run a computation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct RunRequest {
    /// The computation Id of the policy to run.
    pub computation_id: Uuid,
}

/// Error when processing [`RunRequest`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
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
    #[tracing::instrument(level = Level::DEBUG, skip(self, run_ret))]
    async fn run(
        mut self,
        req: RunRequest,
        run_ret: Option<Ret<RunError>>,
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
                if let Some(ret) = run_ret {
                    let _ = ret.send(Ok(()));
                }
                tokio::spawn(
                    async move {
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
                    }
                    .in_current_span(),
                );
            }
            PolicyStateKind::Running { policy, channel } => {
                let (compiled_tx, compiled_rx) = oneshot::channel();
                let program = policy.program.clone();
                let consts = mem::take(&mut self.consts);
                // We compile the program in a separate thread so we don't block the runtime
                let span = Span::current();
                thread::spawn(move || {
                    let _g = span.enter();
                    let compiled = compile_with_options(
                        &program,
                        CompileOptions {
                            circuit_kind: CircuitKind::Register,
                            consts,
                            // false reduces peak memory consumption
                            optimize_duplicate_gates: false,
                        },
                    );
                    // ignore send error as run future has been dropped
                    let _ = compiled_tx.send(compiled);
                });
                let compiled = match compiled_rx.await {
                    Ok(Ok(compiled)) => compiled,
                    Ok(Err(err)) => {
                        if let Some(url) = policy.output {
                            let _ = channel
                                .client
                                .output(url, Err(OutputError::CompileError(err)))
                                .await;
                        }
                        // stop the state machine
                        return ControlFlow::Break(());
                    }
                    // sender has been dropped which means the compile thread panicked
                    Err(_) => {
                        if let Some(url) = policy.output {
                            let _ = channel
                                .client
                                .output(url, Err(OutputError::CompilePanic))
                                .await;
                        }
                        return ControlFlow::Break(());
                    }
                };

                let input = match compiled.literal_arg(policy.party, policy.input.clone()) {
                    Ok(args) => args.as_bits(),
                    Err(err) => {
                        if let Some(url) = policy.output {
                            let _ = channel
                                .client
                                .output(url, Err(OutputError::InvalidInput(err)))
                                .await;
                        }
                        // stop the state machine
                        return ControlFlow::Break(());
                    }
                };
                // TODO this is not ideal. We currently provide the mpc output to every party, even those that don't
                // specify /output in the policy. Ideally, the policy contains the set of output party ids which must
                // be equal for all policies with the same ID. If a parties id is contained in this set, the policy
                // can optionally specify the output URL.
                let p_out = policy.party_ids();
                let permit = self.permit.take();
                // We instrument the spawned future that does the acutal mpc computation so that
                // the events will be recorded in the correct span
                let span = debug_span!("polytune_mpc").or_current();
                let tmp_dir = self.tmp_dir_path.clone();
                let cmd_tx = self.cmd_tx.clone();
                let fut = async move {
                    debug!("starting mpc computation");
                    // Move permit into the async task so that its desctructor is run when the task is finished
                    let _permit = permit;
                    let output = polytune::mpc(
                        &channel,
                        compiled.circuit.unwrap_register_ref(),
                        &input,
                        0,
                        policy.party,
                        &p_out,
                        tmp_dir.as_deref(),
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
                                error!(?err);
                                let _ = client.output(url, Err(OutputError::MpcError(err))).await;
                            }
                        }
                    } else if let Err(err) = output {
                        error!(?err);
                    }
                    // This break from the `start` loop and drop the state machine
                    let _ = cmd_tx.send(PolicyCmd::Stop).await;
                };

                tokio::spawn(fut.instrument(span));
            }
            state => {
                if let Some(ret) = run_ret {
                    ret_err(
                        ret,
                        RunError::InvalidState {
                            computation_id: req.computation_id,
                            state: format!("{state:?}"),
                        },
                    );
                }
                self.state_kind = state;
            }
        }
        ControlFlow::Continue(self)
    }
}

/// Map of Garble Literals provided as constants.
pub type Consts = HashMap<String, Literal>;

/// A request that exchanges necessary consts for program compilation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstsRequest {
    /// Party this request originates from.
    pub from: usize,
    /// Computation Id of the executing policy.
    pub computation_id: Uuid,
    /// Garble constants.
    pub consts: Consts,
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
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
    #[tracing::instrument(level = Level::DEBUG, skip(self, ret))]
    async fn consts(
        mut self,
        consts_request: ConstsRequest,
        ret: Ret<ConstsError>,
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
                ret_err(
                    ret,
                    ConstsError::InvalidState {
                        state: format!("{state:?}"),
                        computation_id: consts_request.computation_id,
                    },
                );
                self.state_kind = state;
            }
        }
        ControlFlow::Continue(self)
    }

    #[tracing::instrument(level = Level::DEBUG, skip(self))]
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

/// MPC message data from one party intended for a [`polytune::channel::Channel`].
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MpcMsg {
    /// The party this message originates from.
    pub from: usize,
    /// The data for the polytune channel.
    pub data: Vec<u8>,
}

/// Error during transmission of MPC message.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum MpcMsgError {
    #[error("polytune engine is unreachable")]
    Unreachable,
}

impl<B, C> PolicyState<B, C>
where
    B: PolicyClientBuilder<Client = C>,
    C: PolicyClient,
{
    #[tracing::instrument(level = Level::TRACE, skip(self, ret))]
    async fn msg(&self, mpc_msg: MpcMsg, ret: Ret<MpcMsgError>) -> ControlFlow<()> {
        match self.channel_senders[mpc_msg.from].send(mpc_msg.data).await {
            Ok(_) => {
                let _ = ret.send(Ok(()));
                ControlFlow::Continue(())
            }
            Err(_) => {
                ret_err(ret, MpcMsgError::Unreachable);
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

struct Channel<C> {
    client: C,
    party: usize,
    receivers: Vec<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

#[derive(Debug, thiserror::Error)]
enum RecvErr {
    #[error("PolicyState state machine has stopped execution")]
    Stopped,
    #[error("Polytune request message from unknown party {0}")]
    UnknownParty(usize),
}

impl<C: PolicyClient> polytune::channel::Channel for Channel<C> {
    type SendError = C::ClientError<MpcMsgError>;

    type RecvError = RecvErr;

    #[tracing::instrument(level = Level::TRACE, skip(self, data), err)]
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

    #[tracing::instrument(level = Level::TRACE, skip(self), err)]
    async fn recv_bytes_from(
        &self,
        party: usize,
        _phase: &str,
    ) -> Result<Vec<u8>, Self::RecvError> {
        self.receivers
            .get(party)
            .ok_or(RecvErr::UnknownParty(party))?
            .lock()
            .await
            .recv()
            .await
            .ok_or(RecvErr::Stopped)
    }
}
