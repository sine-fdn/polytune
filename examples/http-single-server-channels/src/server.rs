use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use std::result::Result;
use std::{collections::HashMap, env, str::FromStr, sync::Arc};
use std::{collections::VecDeque, net::SocketAddr};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;

pub(crate) async fn serve() {
    tracing_subscriber::fmt::init();

    let sessions = Arc::new(Mutex::new(HashMap::<String, Session>::new()));

    let app = Router::new()
        .route("/join/:session/:party", put(join))
        .route("/participants/:session", get(participants))
        .route("/send/:session/:from/:to", post(send))
        .route("/recv/:session/:from/:to", post(recv))
        .with_state(sessions)
        .layer(TraceLayer::new_for_http());

    let addr = if let Ok(addr) = env::var("SOCKET_ADDRESS") {
        SocketAddr::from_str(&addr).unwrap_or_else(|_| panic!("Invalid address: {addr}"))
    } else {
        SocketAddr::from(([127, 0, 0, 1], 8000))
    };
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug, Default)]
struct Session {
    msgs: HashMap<u32, HashMap<u32, VecDeque<Vec<u8>>>>,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

async fn join(
    State(sessions): State<Sessions>,
    Path((session_id, party)): Path<(String, u32)>,
) -> Result<(), StatusCode> {
    let mut sessions = sessions.lock().await;
    let session = sessions.entry(session_id).or_default();
    session.msgs.entry(party).or_default();
    Ok(())
}

async fn participants(
    State(sessions): State<Sessions>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<u32>>, StatusCode> {
    let mut sessions = sessions.lock().await;
    let s = sessions.entry(session_id).or_default();
    let participants: Vec<u32> = s.msgs.keys().copied().collect();
    Ok(Json(participants))
}

async fn send(
    State(sessions): State<Sessions>,
    Path((session_id, from, to)): Path<(String, u32, u32)>,
    body: Bytes,
) -> Result<(), StatusCode> {
    let mut sessions = sessions.lock().await;
    let s = sessions.entry(session_id).or_default();
    let msgs = s.msgs.entry(from).or_default().entry(to).or_default();
    msgs.push_back(body.to_vec());
    Ok(())
}

async fn recv(
    State(sessions): State<Sessions>,
    Path((session_id, from, to)): Path<(String, u32, u32)>,
) -> Result<Vec<u8>, StatusCode> {
    let mut sessions = sessions.lock().await;
    let Some(s) = sessions.get_mut(&session_id) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(msgs) = s.msgs.get_mut(&from).and_then(|msgs| msgs.get_mut(&to)) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(msg) = msgs.pop_front() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    Ok(msg)
}
