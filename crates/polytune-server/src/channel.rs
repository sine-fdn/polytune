use std::{collections::HashMap, sync::mpsc::Receiver};

use axum::{
    body::Bytes,
    extract::{Path, State},
};
use tokio::sync::mpsc::Sender;
use uuid::Uuid;

use crate::state::PolytuneState;

pub(crate) struct MsgState {
    /// Senders to send to HttpChannels
    pub(crate) senders: tokio::sync::RwLock<HashMap<Uuid, Vec<Sender<Vec<u8>>>>>,
}

pub(crate) struct MsgError;

pub(crate) async fn msg(
    State(state): State<MsgState>,
    Path(computation_id): Path<Uuid>,
    Path(from): Path<u32>,
    body: Bytes,
) -> Result<(), MsgError> {
    // send data on Senders
    todo!()
}

pub(crate) struct HttpChannel {
    receivers: Vec<tokio::sync::Mutex<Receiver<Vec<u8>>>>, // and similar fields as the old channel
}
