use std::{collections::HashMap, sync::Arc};

use aide::OperationIo;
use axum::{
    body::Bytes,
    extract::{Path, State},
    response::IntoResponse,
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use url::Url;
use uuid::Uuid;

use crate::{api::Policy, state::PolytuneState};

#[derive(Default)]
pub(crate) struct MsgStateInner {
    /// Senders to send to HttpChannels
    pub(crate) senders: tokio::sync::RwLock<HashMap<Uuid, Vec<Sender<Vec<u8>>>>>,
}

pub(crate) type MsgState = Arc<MsgStateInner>;

impl MsgStateInner {
    pub(crate) async fn create_channel(
        &self,
        policy: &Policy,
        client: reqwest_middleware::ClientWithMiddleware,
    ) -> HttpChannel {
        let participants = policy.participants.clone();
        let party = policy.party;
        let computation_id = policy.computation_id;
        let mut senders = vec![];
        let mut receivers = vec![];
        for _ in 0..participants.len() {
            // TODO buffer size?
            let (sender, receiver) = mpsc::channel(1);
            senders.push(sender);
            receivers.push(tokio::sync::Mutex::new(receiver));
        }
        self.senders.write().await.insert(computation_id, senders);
        let urls = participants
            .into_iter()
            .map(|url| url.join(&format!("msg/{computation_id}/{party}")).unwrap())
            .collect();
        HttpChannel {
            client,
            receivers,
            urls,
        }
    }
}

pub(crate) async fn msg(
    State(state): State<MsgState>,
    Path((computation_id, from)): Path<(Uuid, usize)>,
    body: Bytes,
) -> Result<(), MsgError> {
    state
        .senders
        .read()
        .await
        .get(&computation_id)
        .unwrap()
        .get(from)
        .unwrap()
        .send(body.to_vec())
        .await
        .unwrap();
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

pub(crate) struct HttpChannel {
    client: reqwest_middleware::ClientWithMiddleware,
    urls: Vec<Url>,
    receivers: Vec<tokio::sync::Mutex<Receiver<Vec<u8>>>>, // and similar fields as the old channel
}

#[derive(Debug)]
pub(crate) enum HttpChannelError {}

impl polytune::channel::Channel for HttpChannel {
    type SendError = HttpChannelError;

    type RecvError = HttpChannelError;

    async fn send_bytes_to(
        &self,
        party: usize,
        data: Vec<u8>,
        phase: &str,
    ) -> Result<(), Self::SendError> {
        self.client
            .post(self.urls[party].clone())
            .body(data)
            .send()
            .await
            .unwrap();
        Ok(())
    }

    async fn recv_bytes_from(&self, party: usize, phase: &str) -> Result<Vec<u8>, Self::RecvError> {
        Ok(self.receivers[party].lock().await.recv().await.unwrap())
    }
}
