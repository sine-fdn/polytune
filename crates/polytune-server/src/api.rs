use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use aide::{OperationIo, axum::IntoApiResponse, openapi::OpenApi, transform::TransformOperation};
use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use futures::future::try_join_all;
use garble_lang::literal::Literal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, oneshot};
use tower_http::follow_redirect::policy;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use crate::{
    mpc::ScheduledPolicy,
    state::{PolicyCompatError, PolicyState, PolytuneState},
};

// TOOD split this into public API and mpc specific API

pub async fn serve_open_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}

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
    pub(crate) fn is_leader(&self) -> bool {
        self.party == self.leader
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            computation_id: Default::default(),
            participants: Default::default(),
            program: Default::default(),
            leader: Default::default(),
            party: Default::default(),
            input: Literal::Tuple(vec![]),
            output: Default::default(),
            constants: Default::default(),
        }
    }
}

pub fn schedule_docs(t: TransformOperation) -> TransformOperation {
    t.id("scheduleMpcSession")
        .description("Schedule a new MPC session. This needs to be called in the same order for all participants for all computations.")
}

// TODO maybe a have a /schedule endpoint?
// when does this endpoint return?
// how do the different participants decide when to schedule a computation?
// `/schedule` could be called in a different order for different parties
// #[axum::debug_handler]
pub(crate) async fn schedule(
    State(state): State<PolytuneState>,
    Json(policy): Json<Policy>,
) -> Result<(), ScheduleError> {
    let party = policy.party;
    let is_leader = party == policy.leader;
    let computation_id = policy.computation_id;

    let validate_notify = Arc::new(Notify::new());
    let pol_request = {
        let pol_request = ValidatePolicyRequest::from(&policy);
        let mut computations = state.computations.lock();
        match computations.entry(computation_id) {
            Entry::Occupied(occupied_entry) => todo!("return duplicate comp error"),
            Entry::Vacant(vacant_entry) => vacant_entry.insert(PolicyState::Scheduled(
                policy.clone(),
                Arc::clone(&validate_notify),
            )),
        };
        pol_request
    };

    let (const_sender, const_receiver) = oneshot::channel();

    // TODO only parse here, not type check, as we will probably require constants to be known for
    // type checking in the future
    let own_part_const_ident = format!("PARTY_{party}");
    let parsed_prog = garble_lang::check(&policy.program).unwrap();
    let const_count = parsed_prog
        .const_deps
        .iter()
        .filter_map(|(party, deps)| (party != &own_part_const_ident).then(|| deps.len()))
        .sum();
    let own_consts = HashMap::from_iter([(own_part_const_ident, policy.constants.clone())]);
    state
        .const_state
        .init_consts(computation_id, const_count, own_consts);
    state
        .const_state
        .insert_const_sender(computation_id, const_sender);

    if is_leader {
        let client = state.0.client.clone();
        let validate_futs = pol_request
            .participants
            .iter()
            .enumerate()
            .filter(|(id, _)| *id != party)
            .map(async |(_, participant)| {
                let url = participant.join("validate").unwrap();
                info!("validating {url}");
                // TODO the policy request should contain the queue position at which we will schedule this
                let ret = client.post(url).json(&pol_request).send().await;
                debug!("validated ret: {ret:?}");
                ret
            });
        // TODO: What happens if validate fails for one of the parties? We should send /cancel to the others
        try_join_all(validate_futs).await.unwrap();
        let channel = state
            .msg_state
            .create_channel(&policy, state.client.clone())
            .await;

        state
            .schedule_sender
            .send(ScheduledPolicy {
                pol: policy,
                channel,
                const_receiver,
            })
            .await
            .unwrap();
    } else {
        // TODO have a timeout here? If policy is not validated in reasonable time we should not schedule it
        validate_notify.notified_owned().await;
        state
            .computations
            .lock()
            .get_mut(&computation_id)
            .unwrap()
            .validated(const_receiver);
    }

    Ok(())

    // prev /launch comments:
    // each party receives /launch call in arbitrary order
    // compute ComputationId hash from Policy
    // check in state if such a computation is already running, if yes, return error
    // if not, add to state
    // if not leader, wait for notify that mpc computation is started, then return
    // if leader, send /validate requests to all other parties, retrying in case of failure
    //  for a few minutes
    // if /validate returns error for one of the parties, send /cancel to all
    // as leader: send /run to all other parties
    // when /run returns, mpc calc is scheduled, return from /launch with success
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) struct ScheduleError;

impl IntoResponse for ScheduleError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}

/// HTTP request coming from another party to start an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct ValidatePolicyRequest {
    pub(crate) computation_id: Uuid,
    /// TODO I'm not sure how much sense it makes to include the participants in here
    /// and check whether they're equal to the ones in the `Policy`. It could be the case
    /// that P1 reaches P3 under a different URL than P2 if they're running in some
    /// weird containerized environment
    /// Could there be any weird consequences or angles for attack when not checking this?
    /// I don't think so, either we reach the parties in our policy and coordinate for the
    /// provided ID or not
    pub(crate) participants: Vec<Url>,
    pub(crate) program_hash: String,
    pub(crate) leader: usize,
}

impl From<&Policy> for ValidatePolicyRequest {
    fn from(pol: &Policy) -> Self {
        Self {
            computation_id: pol.computation_id,
            participants: pol.participants.clone(),
            program_hash: blake3::hash(pol.program.as_bytes()).to_string(),
            leader: pol.leader,
        }
    }
}

pub(crate) async fn validate(
    State(state): State<PolytuneState>,
    Json(policy_request): Json<ValidatePolicyRequest>,
) -> Result<(), ValidateError> {
    let comps = state.computations.lock();
    match comps.get(&policy_request.computation_id) {
        Some(PolicyState::Scheduled(policy, notify_schedule)) => {
            // check policy against request
            notify_schedule.notify_one();
        }
        _ => return panic!(),
    };
    Ok(())
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) struct ValidateError;

impl From<PolicyCompatError> for ValidateError {
    fn from(value: PolicyCompatError) -> Self {
        todo!()
    }
}

impl IntoResponse for ValidateError {
    fn into_response(self) -> axum::response::Response {
        StatusCode::IM_A_TEAPOT.into_response()

    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RunRequest {
    pub(crate) computation_id: Uuid,
}

pub(crate) async fn run(
    State(state): State<PolytuneState>,
    Json(run_request): Json<RunRequest>,
) -> Result<(), RunError> {
    let policy_state = state
        .computations
        .lock()
        .remove(&run_request.computation_id)
        .unwrap();

    match policy_state {
        PolicyState::Validated(policy, const_receiver) => {
            let channel = state
                .msg_state
                .create_channel(&policy, state.client.clone())
                .await;
            state
                .schedule_sender
                .send(ScheduledPolicy {
                    pol: policy,
                    channel,
                    const_receiver,
                })
                .await
                .unwrap();
        }
        _ => panic!("invalid policy state"),
    }

    Ok(())

    // take HttpChannel from state
    // parse garble program so that we know how many constants we need
    // insert (const_count, HashMap::new()) into ConstState for Id
    // insert oneshot::Sender into ConstState for Id
    // send constants to other parties
    // wait on oneshot::receiver for constants
    // compile circuit
    // if error, return error from run, and also notify still ongoing
    // /launch call that compile failed (or const exchanging) so that
    // /launch can return error (TODO, if an error occurs here, should we
    // send /cancel to the other parties?)
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) struct RunError;

impl IntoResponse for RunError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub(crate) struct CancelRequest {
    pub(crate) computation_id: Uuid,
}

pub(crate) async fn cancel(
    State(state): State<PolytuneState>,
    Json(cancel_request): Json<CancelRequest>,
) -> Result<(), CancelError> {
    // if still within /launch, notify /launch so that it can return error to caller
    // TODO, what if mpc exec already started?
    todo!()
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) struct CancelError;

impl IntoResponse for CancelError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}
