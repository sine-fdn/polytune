//! A small server that listens for requests to the `/output` url and
//! returns those via an mpsc::channel.
use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use garble_lang::literal::Literal;
use serde::Deserialize;
use tokio::sync::mpsc;
use tower_http::{classify::StatusInRangeAsFailures, trace::TraceLayer};
use uuid::Uuid;

pub(crate) async fn server(addr: SocketAddr, sender: mpsc::Sender<(Uuid, MpcResult)>) {
    let classifier = StatusInRangeAsFailures::new(400..=599).into_make_classifier();
    let log_layer = TraceLayer::new(classifier);
    let app = Router::new()
        .route("/output/{computation_id}", post(output))
        .with_state(sender)
        .layer(log_layer);

    // Run the server.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("binding to addr");
    axum::serve(listener, app)
        .await
        .expect("starting axum server");
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "details")]
#[serde(rename_all = "camelCase")]
pub(crate) enum MpcResult {
    Success(Literal),
    Error(serde_json::Value),
}

async fn output(
    State(sender): State<mpsc::Sender<(Uuid, MpcResult)>>,
    Path(computation_id): Path<Uuid>,
    Json(result): Json<MpcResult>,
) {
    sender
        .send((computation_id, result))
        .await
        .expect("receiver dropped")
}
