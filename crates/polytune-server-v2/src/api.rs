use std::{
    collections::{HashMap, hash_map::Entry},
    mem,
    ops::Deref,
    sync::Arc,
};

use aide::{OperationIo, axum::IntoApiResponse, openapi::OpenApi, transform::TransformOperation};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use futures::future::try_join_all;
use garble_lang::literal::Literal;
use reqwest_middleware::ClientWithMiddleware;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};
use tower_http::follow_redirect::policy;
use tracing::{debug, info};
use url::Url;
use uuid::Uuid;

use crate::state::{
    self, ConstsRequest, MpcMsg, Policy, PolicyClient, PolicyClientBuilder, PolicyCmd, PolicyState,
    RunRequest, ValidateRequest,
};

pub(crate) struct PolytuneStateInner {
    pub(crate) client_builder: HttpClientBuilder,
    pub(crate) cmd_senders: tokio::sync::RwLock<HashMap<Uuid, mpsc::Sender<PolicyCmd>>>,
}

#[derive(Clone)]
pub(crate) struct HttpClientBuilder {
    pub(crate) client: ClientWithMiddleware,
}
impl PolicyClientBuilder for HttpClientBuilder {
    type Client = HttpClient;

    fn new(&self, policy: &Policy) -> Self::Client {
        HttpClient {
            client: self.client.clone(),
            participants: policy.participants.clone(),
            party: policy.party,
            computation_id: policy.computation_id,
        }
    }
}
pub(crate) struct HttpClient {
    client: ClientWithMiddleware,
    party: usize,
    computation_id: Uuid,
    participants: Vec<Url>,
}

impl PolicyClient for HttpClient {
    type ClientError<E>
        = E
    where
        E: std::error::Error + Send + Sync;

    async fn validate(
        &self,
        to: usize,
        req: ValidateRequest,
    ) -> Result<(), Self::ClientError<crate::state::ValidateError>> {
        let url = self.participants[to].join("validate").unwrap();
        let resp = self
            .client
            .post(url)
            .json(&req)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        Ok(())
    }

    async fn run(
        &self,
        to: usize,
        req: RunRequest,
    ) -> Result<(), Self::ClientError<state::RunError>> {
        let url = self.participants[to].join("run").unwrap();
        let resp = self
            .client
            .post(url)
            .json(&req)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        Ok(())
    }

    async fn consts(
        &self,
        to: usize,
        req: ConstsRequest,
    ) -> Result<(), Self::ClientError<state::ConstsError>> {
        let url = self.participants[to]
            .join(&format!("consts/{}/{}", req.computation_id, req.from))
            .unwrap();
        let resp = self
            .client
            .post(url)
            .json(&req)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        Ok(())
    }

    async fn msg(
        &self,
        to: usize,
        msg: MpcMsg,
    ) -> Result<(), Self::ClientError<crate::state::MpcMsgError>> {
        let url = self.participants[to]
            .join(&format!("msg/{}/{}", self.computation_id, self.party))
            .unwrap();
        let resp = self
            .client
            .post(url)
            .body(msg.data)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        Ok(())
    }

    async fn output(
        &self,
        to: Url,
        result: Result<Literal, crate::state::OutputError>,
    ) -> Result<(), Self::ClientError<std::convert::Infallible>> {
        info!(?result);
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct PolytuneState(pub(crate) Arc<PolytuneStateInner>);

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
    let (ret_tx, ret_rx) = oneshot::channel();
    let cmd_sender = {
        let mut cmd_senders = state.cmd_senders.write().await;
        cmd_senders
            .entry(policy.computation_id)
            .or_insert_with(|| {
                let (policy_state, cmd_sender) =
                    PolicyState::new(state.client_builder.clone(), Semaphore::new(2));
                tokio::spawn(policy_state.start());
                cmd_sender
            })
            .clone()
    };
    // TODO handle channel close?
    cmd_sender
        .send(PolicyCmd::Schedule(policy, ret_tx))
        .await
        .unwrap();
    match ret_rx.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(state_err)) => Err(ScheduleError::State(state_err)),
        Err(recv) => Err(ScheduleError::Internal),
    }
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) enum ScheduleError {
    State(state::ScheduleError),
    Internal,
}

impl IntoResponse for ScheduleError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}

pub(crate) async fn validate(
    State(state): State<PolytuneState>,
    Json(validate_request): Json<ValidateRequest>,
) -> Result<(), ValidateError> {
    let (ret_tx, ret_rx) = oneshot::channel();

    let cmd_sender = {
        let mut cmd_senders = state.cmd_senders.write().await;
        cmd_senders
            .entry(validate_request.computation_id)
            .or_insert_with(|| {
                let (policy_state, cmd_sender) =
                    PolicyState::new(state.client_builder.clone(), Semaphore::new(2));
                tokio::spawn(policy_state.start());
                cmd_sender
            })
            .clone()
    };
    // TODO handle channel close?
    cmd_sender
        .send(PolicyCmd::Validate(validate_request, ret_tx))
        .await
        .unwrap();
    ret_rx.await.unwrap().unwrap();
    Ok(())
}

#[derive(OperationIo, Debug)]
#[aide(output)]
pub(crate) enum ValidateError {
    PolicyStateInvalid,
}

impl IntoResponse for ValidateError {
    fn into_response(self) -> axum::response::Response {
        StatusCode::IM_A_TEAPOT.into_response()
    }
}

pub(crate) async fn run(
    State(state): State<PolytuneState>,
    Json(run_request): Json<RunRequest>,
) -> Result<(), RunError> {
    let cmd_senders = state.cmd_senders.read().await;
    let (ret_tx, ret_rx) = oneshot::channel();
    cmd_senders
        .get(&run_request.computation_id)
        .unwrap()
        .send(PolicyCmd::Run(run_request, Some(ret_tx)))
        .await
        .unwrap();

    ret_rx.await.unwrap().unwrap();
    Ok(())
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

pub(crate) async fn consts(
    State(state): State<PolytuneState>,
    Path((computation_id, from)): Path<(Uuid, u32)>,
    Json(const_request): Json<ConstsRequest>,
) -> Result<(), ConstError> {
    let cmd_senders = state.cmd_senders.read().await;
    let (ret_tx, ret_rx) = oneshot::channel();
    cmd_senders
        .get(&const_request.computation_id)
        .unwrap()
        .send(PolicyCmd::Consts(const_request, ret_tx))
        .await
        .unwrap();

    ret_rx.await.unwrap().unwrap();
    Ok(())
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) struct ConstError;

impl IntoResponse for ConstError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}

pub(crate) async fn msg(
    State(state): State<PolytuneState>,
    Path((computation_id, from)): Path<(Uuid, usize)>,
    body: Bytes,
) -> Result<(), MsgError> {
    let cmd_senders = state.cmd_senders.read().await;
    let (ret_tx, ret_rx) = oneshot::channel();
    cmd_senders
        .get(&computation_id)
        .unwrap()
        .send(PolicyCmd::MpcMsg(
            MpcMsg {
                from,
                data: body.to_vec(),
            },
            ret_tx,
        ))
        .await
        .unwrap();

    ret_rx.await.unwrap().unwrap();
    Ok(())
}

#[derive(OperationIo)]
#[aide(output)]
pub(crate) struct MsgError;

impl IntoResponse for MsgError {
    fn into_response(self) -> axum::response::Response {
        todo!()
    }
}

// pub(crate) async fn cancel(
//     State(state): State<PolytuneState>,
//     Json(cancel_request): Json<CancelRequest>,
// ) -> Result<(), CancelError> {
//     // if still within /launch, notify /launch so that it can return error to caller
//     // TODO, what if mpc exec already started?
//     todo!()
// }

// #[derive(OperationIo)]
// #[aide(output)]
// pub(crate) struct CancelError;

// impl IntoResponse for CancelError {
//     fn into_response(self) -> axum::response::Response {
//         todo!()
//     }
// }
