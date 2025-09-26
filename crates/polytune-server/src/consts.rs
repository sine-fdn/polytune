use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json,
    extract::{Path, State},
};
use garble_lang::literal::Literal;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, oneshot};
use uuid::Uuid;

use crate::state::PolytuneState;

pub(crate) type Consts = HashMap<String, Literal>;

pub(crate) struct ConstState {
    // usize is consts count needed for this comp
    received: Mutex<HashMap<Uuid, (usize, Consts)>>,
    // senders of Consts to the /run endpoint
    const_senders: Mutex<HashMap<Uuid, oneshot::Sender<Consts>>>,
}

/// HTTP request to transmit constants necessary to compile a program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstsRequest {
    pub consts: Consts,
}

pub(crate) struct ConstError;

pub(crate) async fn consts(
    State(state): State<PolytuneState>,
    Path(computation_id): Path<Uuid>,
    Path(from): Path<u32>,
    Json(body): Json<ConstsRequest>,
) -> Result<(), ConstError> {
    // store constants in state
    // notify /run when all constants are received
    todo!()
}
