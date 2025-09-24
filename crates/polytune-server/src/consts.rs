use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use aide::OperationIo;
use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use garble_lang::{GarbleConsts, literal::Literal};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, oneshot};
use tracing::info;
use uuid::Uuid;

use crate::state::PolytuneState;

pub(crate) type Consts = HashMap<String, Literal>;

#[derive(Default)]
pub(crate) struct ConstStateInner {
    // usize is consts count needed for this comp
    pub(crate) received: Mutex<HashMap<Uuid, (usize, GarbleConsts)>>,
    // senders of Consts to the /run endpoint
    pub(crate) const_senders: Mutex<HashMap<Uuid, oneshot::Sender<GarbleConsts>>>,
}

impl ConstStateInner {
    pub(crate) fn init_consts(&self, computation_id: Uuid, const_count: usize, own_consts: GarbleConsts) {
        self.received
            .lock()
            .insert(computation_id, (const_count, own_consts));
    }

    pub(crate) fn insert_const_sender(
        &self,
        computation_id: Uuid,
        const_sender: oneshot::Sender<GarbleConsts>,
    ) {
        self.const_senders
            .lock()
            .insert(computation_id, const_sender);
    }
}

pub(crate) type ConstState = Arc<ConstStateInner>;

/// HTTP request to transmit constants necessary to compile a program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstsRequest {
    pub consts: Consts,
}

pub(crate) async fn consts(
    State(state): State<ConstState>,
    Path((computation_id, from)): Path<(Uuid, u32)>,
    Json(const_request): Json<ConstsRequest>,
) -> Result<(), ConstError> {
    let mut received = state.received.lock();
    let (count, consts) = received.get_mut(&computation_id).unwrap();
    *count = count.checked_sub(const_request.consts.len()).unwrap();
    consts.insert(format!("PARTY_{from}"), const_request.consts);

    if *count == 0 {
        let (_, completed_consts) = received.remove(&computation_id).unwrap();
        drop(received);
        state
            .const_senders
            .lock()
            .remove(&computation_id)
            .unwrap()
            .send(completed_consts)
            .unwrap();
    }
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
