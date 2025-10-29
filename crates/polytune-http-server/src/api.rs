use std::{collections::HashMap, ops::Deref, path::PathBuf, sync::Arc};

use aide::{OperationIo, axum::IntoApiResponse, openapi::OpenApi, transform::TransformOperation};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::{debug, error};
use uuid::Uuid;

use polytune_server_core::{
    ConstsRequest, HandleError, MpcMsg, Policy, PolicyState, PolicyStateHandle, RunRequest,
    ValidateRequest,
};

use crate::policy_client::HttpClientBuilder;

pub(crate) struct PolytuneStateInner {
    pub(crate) client_builder: HttpClientBuilder,
    pub(crate) concurrency: Arc<Semaphore>,
    pub(crate) state_handles: tokio::sync::RwLock<HashMap<Uuid, PolicyStateHandle>>,
    pub(crate) tmp_dir: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct PolytuneState(Arc<PolytuneStateInner>);

impl PolytuneState {
    pub(crate) fn new(state: PolytuneStateInner) -> Self {
        Self(Arc::new(state))
    }

    /// Gets or inserts a [`PolicyStateHandle`] into the state.
    ///
    /// In case there is no handle yet, this method will create a new [`PolicyState`] state machine,
    /// spawn its [`PolicyState::start`] method in a background task and return the newly created handle.
    /// The handle is removed from the state once the state machine finishes.
    async fn get_or_insert_handle(&self, computation_id: Uuid) -> PolicyStateHandle {
        let mut state_handles = self.state_handles.write().await;
        state_handles
            .entry(computation_id)
            .or_insert_with(|| {
                let (mut policy_state, state_handle) =
                    PolicyState::new(self.client_builder.clone(), Arc::clone(&self.concurrency));
                if let Some(path) = &self.tmp_dir {
                    policy_state = policy_state.with_tmp_dir(path);
                }
                let state_cl = self.clone();
                tokio::spawn(async move {
                    policy_state.start().await;
                    state_cl.state_handles.write().await.remove(&computation_id);
                    debug!(%computation_id, "policy state machine finished and handle removed from state")
                });
                state_handle
            })
            .clone()
    }
}

impl Deref for PolytuneState {
    type Target = PolytuneStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub async fn serve_open_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}

pub fn schedule_docs(t: TransformOperation) -> TransformOperation {
    t.id("scheduleMpcSession").description(
        "Schedule a new MPC session. The schedule route returns 
        once /schedule has been called on all parties and the policy has been validated.",
    )
}

pub(crate) async fn schedule(
    State(state): State<PolytuneState>,
    Json(policy): Json<Policy>,
) -> Result<(), ApiError> {
    let computation_id = policy.computation_id;
    let state_handle = state.get_or_insert_handle(computation_id).await;
    state_handle.schedule(policy).await.map_err(ApiError::from)
}

pub(crate) async fn validate(
    State(state): State<PolytuneState>,
    Json(validate_request): Json<ValidateRequest>,
) -> Result<(), ApiError> {
    let computation_id = validate_request.computation_id;
    let state_handle = state.get_or_insert_handle(computation_id).await;
    state_handle
        .validate(validate_request)
        .await
        .map_err(ApiError::from)
}

pub(crate) async fn run(
    State(state): State<PolytuneState>,
    Json(run_request): Json<RunRequest>,
) -> Result<(), ApiError> {
    let state_handles = state.state_handles.read().await;
    let handle = state_handles
        .get(&run_request.computation_id)
        .ok_or(ApiError::UnknownComputationId(run_request.computation_id))?;
    handle.run(run_request).await.map_err(ApiError::from)
}

pub(crate) async fn consts(
    State(state): State<PolytuneState>,
    Json(const_request): Json<ConstsRequest>,
) -> Result<(), ApiError> {
    let cmd_senders = state.state_handles.read().await;
    let handle = cmd_senders
        .get(&const_request.computation_id)
        .ok_or(ApiError::UnknownComputationId(const_request.computation_id))?;
    handle.consts(const_request).await.map_err(ApiError::from)
}

pub(crate) async fn msg(
    State(state): State<PolytuneState>,
    Path((computation_id, from)): Path<(Uuid, usize)>,
    body: Bytes,
) -> Result<(), ApiError> {
    let state_handles = state.state_handles.read().await;
    let handle = state_handles
        .get(&computation_id)
        .ok_or(ApiError::UnknownComputationId(computation_id))?;
    handle
        .mpc_msg(MpcMsg {
            from,
            data: body.to_vec(),
        })
        .await
        .map_err(ApiError::from)
}

#[derive(OperationIo, Serialize)]
#[serde(tag = "type", content = "details")]
#[aide(output)]
pub(crate) enum ApiError {
    #[serde(serialize_with = "crate::serialize_error_chain")]
    Schedule(polytune_server_core::ScheduleError),
    #[serde(serialize_with = "crate::serialize_error_chain")]
    Validate(polytune_server_core::ValidateError),
    #[serde(serialize_with = "crate::serialize_error_chain")]
    Run(polytune_server_core::RunError),
    #[serde(serialize_with = "crate::serialize_error_chain")]
    Consts(polytune_server_core::ConstsError),
    #[serde(serialize_with = "crate::serialize_error_chain")]
    MpcMsg(polytune_server_core::MpcMsgError),
    UnknownComputationId(Uuid),
    StateMachineStopped,
}

impl From<HandleError<polytune_server_core::ScheduleError>> for ApiError {
    fn from(err: HandleError<polytune_server_core::ScheduleError>) -> Self {
        match err {
            HandleError::StateMachineStopped => Self::StateMachineStopped,
            HandleError::PolicyStateError(err) => Self::Schedule(err),
        }
    }
}

impl From<HandleError<polytune_server_core::ValidateError>> for ApiError {
    fn from(err: HandleError<polytune_server_core::ValidateError>) -> Self {
        match err {
            HandleError::StateMachineStopped => Self::StateMachineStopped,
            HandleError::PolicyStateError(err) => Self::Validate(err),
        }
    }
}

impl From<HandleError<polytune_server_core::RunError>> for ApiError {
    fn from(err: HandleError<polytune_server_core::RunError>) -> Self {
        match err {
            HandleError::StateMachineStopped => Self::StateMachineStopped,
            HandleError::PolicyStateError(err) => Self::Run(err),
        }
    }
}

impl From<HandleError<polytune_server_core::ConstsError>> for ApiError {
    fn from(err: HandleError<polytune_server_core::ConstsError>) -> Self {
        match err {
            HandleError::StateMachineStopped => Self::StateMachineStopped,
            HandleError::PolicyStateError(err) => Self::Consts(err),
        }
    }
}

impl From<HandleError<polytune_server_core::MpcMsgError>> for ApiError {
    fn from(err: HandleError<polytune_server_core::MpcMsgError>) -> Self {
        match err {
            HandleError::StateMachineStopped => Self::StateMachineStopped,
            HandleError::PolicyStateError(err) => Self::MpcMsg(err),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let body = match serde_json::to_string_pretty(&self) {
            Ok(body) => body,
            Err(err) => {
                error!(%err, "unable to serialize error. Returning status code 500.");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "error serialization failed",
                )
                    .into_response();
            }
        };
        let status_code = match self {
            ApiError::Schedule(_)
            | ApiError::Validate(_)
            | ApiError::Run(_)
            | ApiError::Consts(_) => StatusCode::BAD_REQUEST,
            ApiError::UnknownComputationId(_) => StatusCode::NOT_FOUND,
            ApiError::MpcMsg(_) | ApiError::StateMachineStopped => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        error!(err = body, %status_code);
        (status_code, body).into_response()
    }
}
