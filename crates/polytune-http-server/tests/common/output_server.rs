//! A small server that listens for requests to the `/output` url and
//! returns those via an mpsc::channel.
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use garble_lang::literal::Literal;
use serde::Deserialize;
use tokio::sync::mpsc;
use tower_http::{classify::StatusInRangeAsFailures, trace::TraceLayer};
use tracing::info;
use url::Url;
use uuid::Uuid;

pub(crate) async fn server(
    sender: mpsc::Sender<(Uuid, MpcResult)>,
    addr: Option<&'static str>,
) -> (Url, impl Future<Output = ()>) {
    let classifier = StatusInRangeAsFailures::new(400..=599).into_make_classifier();
    let log_layer = TraceLayer::new(classifier);
    let app = Router::new()
        .route("/output/{computation_id}", post(output))
        .with_state(sender)
        .layer(log_layer);

    // Run the server.
    let addr = addr.unwrap_or("127.0.0.1:0");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("binding to addr");
    let output_url = Url::parse(&format!(
        "http://{}/output/",
        listener.local_addr().expect("local addr")
    ))
    .expect("URL parse");
    let server = async move {
        axum::serve(listener, app)
            .await
            .expect("starting axum server");
    };
    (output_url, server)
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
    info!(?result, "mpc result");
    sender
        .send((computation_id, result))
        .await
        .expect("receiver dropped")
}
