use std::collections::HashMap;

use axum::{Json, extract::State};
use garble_lang::literal::Literal;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::state::PolytuneState;

struct LaunchError;

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

// TODO maybe a have a /schedule endpoint?
// when does this endpoint return?
// how do the different participants decide when to schedule a computation?
// `/schedule` could be called in a different order for different parties
pub(crate) async fn schedule(
    State(state): State<PolytuneState>,
    Json(policy): Json<Policy>,
) -> Result<(), LaunchError> {
    todo!()
} 


pub(crate) async fn launch(
    State(state): State<PolytuneState>,
    Json(policy): Json<Policy>,
) -> Result<(), LaunchError> { 
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
    todo!()
}

/// HTTP request coming from another party to start an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, JsonSchema)]
pub(crate) struct PolicyRequest {
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

struct ValidateError;

pub(crate) async fn validate(
    State(state): State<PolytuneState>,
    Json(policy_request): Json<PolicyRequest>,
) -> Result<(), ValidateError> {
    // check that policy_request matches stored policy for computation_id
    // if not matching, return error
    // create HttpChannel and store in state
    todo!()
}

struct RunError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
pub(crate) struct RunRequest {
    pub(crate) computation_id: Uuid,
}

pub(crate) async fn run(
    State(state): State<PolytuneState>,
    Json(run_request): Json<RunRequest>,
) -> Result<(), RunError> {
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
    todo!()
}

struct CancelError;

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


