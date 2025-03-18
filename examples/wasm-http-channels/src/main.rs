use anyhow::Error;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderValue, Method},
    routing::{get, post},
    Router,
};
use clap::Parser;
use http::header;
use reqwest::StatusCode;
use std::{
    collections::{HashMap, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    result::Result,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::Mutex, time::sleep};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

type Msgs = Arc<Mutex<HashMap<String, HashMap<u32, HashMap<u32, VecDeque<Vec<u8>>>>>>>;

/// A message broker for Multi-Party Computation.
#[derive(Debug, Parser)]
#[command(name = "broker")]
struct Cli {
    /// The IP address to listen on.
    #[arg(long, short)]
    addr: Option<String>,
    /// The port to listen on.
    #[arg(long, short)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let Cli { addr, port } = Cli::parse();

    let cors = CorsLayer::new()
        .allow_origin([
            "https://benchmarking.sine.dev"
                .parse::<HeaderValue>()
                .unwrap(),
            "https://verification-pilot-ui.vercel.app"
                .parse::<HeaderValue>()
                .unwrap(),
            "http://localhost:9000".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1:9000".parse::<HeaderValue>().unwrap(),
            "http://[::1]:9000".parse::<HeaderValue>().unwrap(),
            "http://[::]:9000".parse::<HeaderValue>().unwrap(),
            "http://localhost:3000".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
            "http://[::1]:3000".parse::<HeaderValue>().unwrap(),
            "http://[::]:3000".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
            Method::PATCH,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::CONTENT_LENGTH,
        ])
        .allow_credentials(true);

    let state: Msgs = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new()
        .route("/ping", get(ping))
        .route("/session/:session/send/:from/:to", post(send))
        .route("/session/:session/recv/:from/:to", post(recv))
        .with_state(state)
        .layer(cors)
        .layer(DefaultBodyLimit::max(1000 * 1024 * 1024))
        .layer(TraceLayer::new_for_http());

    let addr = if let Ok(socket_addr) = env::var("SOCKET_ADDRESS") {
        SocketAddr::from_str(&socket_addr)
            .unwrap_or_else(|_| panic!("Invalid socket address: {socket_addr}"))
    } else {
        let addr = addr.unwrap_or_else(|| "127.0.0.1".into());
        let port = port.unwrap_or(8080);
        match addr.parse::<IpAddr>() {
            Ok(addr) => SocketAddr::new(addr, port),
            Err(_) => {
                tracing::error!("Invalid IP address: {addr}, using 127.0.0.1 instead");
                SocketAddr::from(([127, 0, 0, 1], port))
            }
        }
    };
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ping() -> &'static str {
    "pong"
}

async fn send(
    State(msgs): State<Msgs>,
    Path((session, from, to)): Path<(String, u32, u32)>,
    body: Bytes,
) {
    let mut msgs = msgs.lock().await;
    if !msgs.contains_key(&session) {
        tracing::info!("Starting new session {session}");
    }
    msgs.entry(session.clone())
        .or_default()
        .entry(from)
        .or_default()
        .entry(to)
        .or_default()
        .push_back(body.to_vec());
    tracing::debug!("Stored message from {from} to {to} ({session}/send/{from}/{to})");
}

async fn recv(
    State(msgs): State<Msgs>,
    Path((session, to, from)): Path<(String, u32, u32)>,
) -> Result<Vec<u8>, StatusCode> {
    for _ in 0..100 {
        let mut msgs = msgs.lock().await;
        let Some(msgs) = msgs
            .get_mut(&session)
            .and_then(|session| session.get_mut(&from))
            .and_then(|msgs| msgs.get_mut(&to))
        else {
            tracing::debug!("No queue from {from} to {to} ({session}/recv/{to}/{from})");
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(msg) = msgs.pop_front() else {
            tracing::debug!("No message in queue from {from} to {to} ({session}/recv/{to}/{from})");
            sleep(Duration::from_millis(50)).await;
            continue;
        };
        tracing::debug!("Responding with message from {from} to {to} ({session}/recv/{to}/{from})");
        return Ok(msg);
    }
    tracing::error!("No message in queue from {from} to {to} ({session}/recv/{to}/{from})");
    return Err(StatusCode::NOT_FOUND);
}
