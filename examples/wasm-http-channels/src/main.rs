use anyhow::Error;
use axum::{
    body::Bytes,
    extract::{Path, State},
    routing::post,
    Router,
};
use reqwest::StatusCode;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    result::Result,
    sync::Arc,
};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

type Msgs = Arc<Mutex<HashMap<u32, HashMap<u32, VecDeque<Vec<u8>>>>>>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let state: Msgs = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new()
        .route("/send/:from/:to", post(send))
        .route("/recv/:from/:to", post(recv))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn send(State(msgs): State<Msgs>, Path((from, to)): Path<(u32, u32)>, body: Bytes) {
    let mut msgs = msgs.lock().await;
    msgs.entry(from)
        .or_default()
        .entry(to)
        .or_default()
        .push_back(body.to_vec());
}

async fn recv(
    State(msgs): State<Msgs>,
    Path((from, to)): Path<(u32, u32)>,
) -> Result<Vec<u8>, StatusCode> {
    let mut msgs = msgs.lock().await;
    let Some(msgs) = msgs.get_mut(&from).and_then(|msgs| msgs.get_mut(&to)) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(msg) = msgs.pop_front() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    Ok(msg)
}
