use aide::{axum::IntoApiResponse, openapi::OpenApi, transform::TransformOperation};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{Path, State},
};
use polytune::garble_lang::literal::Literal;
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, Notify, mpsc::Sender};
use tracing::{error, info};
use url::Url;

use crate::{mpc::execute_mpc, policy::Policy};

/// HTTP request coming from another party to start an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, JsonSchema)]
pub struct PolicyRequest {
    pub participants: Vec<Url>,
    pub program_hash: String,
    pub leader: usize,
}

/// HTTP request to transmit constants necessary to compile a program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstsRequest {
    pub consts: HashMap<String, Literal>,
}

pub struct MpcComms {
    pub policy: Option<Policy>,
    pub consts: HashMap<String, HashMap<String, Literal>>,
    pub senders: Vec<Sender<Vec<u8>>>,
    pub sync_received: Arc<Notify>,
    pub sync_requested: Arc<Notify>,
}

pub type MpcState = Arc<Mutex<MpcComms>>;

pub async fn serve_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}

pub async fn ping() -> &'static str {
    "pong"
}

pub async fn sync(State(state): State<MpcState>) {
    state.lock().await.sync_requested.notified().await;
    state.lock().await.sync_received.notify_one();
}

pub fn launch_docs(t: TransformOperation) -> TransformOperation {
    t.id("launchMpcSession")
        .description("Launch a new MPC session. This needs to be called for all contributors before it is called for the leader.")
}

// TODO Errors need to be returned to the caller of `/launch` and not only logged
pub async fn launch(State(state): State<MpcState>, Json(policy): Json<Policy>) {
    {
        let mut state = state.lock().await;
        state.policy = Some(policy.clone());
    }
    if policy.leader != policy.party {
        return;
    }
    let hash = blake3::hash(policy.program.as_bytes()).to_string();
    let client = reqwest::Client::new();
    let policy_request = PolicyRequest {
        participants: policy.participants.clone(),
        leader: policy.leader,
        program_hash: hash,
    };
    // As a leader, we first make sure that all other participants join the session:
    let mut participant_missing = false;
    for party in policy.participants.iter() {
        if party != &policy.participants[policy.party] {
            info!("Waiting for confirmation from party {party}");
            let url = format!("{party}run");
            match client.post(&url).json(&policy_request).send().await {
                Err(err) => {
                    error!("Could not reach {url}: {err}");
                    participant_missing = true;
                    continue;
                }
                Ok(res) => match res.status() {
                    StatusCode::OK => {}
                    code => {
                        error!(
                            "Unexpected response while trying to start execution for {url}: {code}"
                        );
                        participant_missing = true;
                    }
                },
            }
        }
    }
    if participant_missing {
        return error!("Some participants are missing, aborting...");
    }
    // Now we start the MPC session:
    info!("All participants have accepted the session, starting calculation now...");
    match execute_mpc(state, &policy).await {
        Ok(Some(output)) => {
            info!("MPC Output: {output}");
            if let Some(endpoint) = policy.output {
                info!("Sending {output} to {endpoint}");
                if let Err(e) = client.post(endpoint.clone()).json(&output).send().await {
                    error!("Could not send output to {endpoint}: {e}");
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            error!("Error while executing MPC: {e}")
        }
    }
}

// TODO errors should be returned to the caller of `/run` and not only logged
pub async fn run(State(state): State<MpcState>, Json(body): Json<PolicyRequest>) {
    let Some(policy) = state.lock().await.policy.clone() else {
        return error!("Trying to start MPC execution without policy");
    };
    if policy.participants != body.participants || policy.leader != body.leader {
        error!("Policy not accepted: {body:?}");
        return;
    }
    let expected = blake3::hash(policy.program.as_bytes()).to_string();
    if expected != body.program_hash {
        error!("Aborting due to different hashes for program in policy {policy:?}");
        return;
    }
    info!("Starting execution");
    tokio::spawn(async move {
        if let Err(e) = execute_mpc(state, &policy).await {
            error!("{e}");
        }
    });
}

pub async fn consts(
    State(state): State<MpcState>,
    Path(from): Path<u32>,
    Json(body): Json<ConstsRequest>,
) {
    let mut state = state.lock().await;
    state.consts.insert(format!("PARTY_{from}"), body.consts);
}

// TODO errors should be returned to the caller of `/run` and not only logged
pub async fn msg(State(state): State<MpcState>, Path(from): Path<u32>, body: Bytes) {
    let state = state.lock().await;
    if state.senders.len() > from as usize {
        state.senders[from as usize]
            .send(body.to_vec())
            .await
            .unwrap();
    } else {
        error!("No sender for party {from}");
    }
}
