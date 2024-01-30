use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::Response,
    routing::{get, post, put},
    Json, Router,
};
use std::{collections::HashMap, env, str::FromStr, sync::Arc, time::Duration};
use std::{collections::VecDeque, net::SocketAddr};
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::Span;

pub(crate) async fn serve() {
    tracing_subscriber::fmt::init();

    let sessions = Arc::new(Mutex::new(HashMap::<String, Session>::new()));

    let log_layer = TraceLayer::new_for_http()
        .on_request(|r: &Request<_>, _: &Span| tracing::info!("{} {}", r.method(), r.uri().path()))
        .on_response(
            |r: &Response<_>, latency: Duration, _: &Span| match r.status().as_u16() {
                400..=499 => tracing::warn!("{} (in {:?})", r.status(), latency),
                500..=599 => tracing::error!("{} (in {:?})", r.status(), latency),
                _ => tracing::info!("{} (in {:?})", r.status(), latency),
            },
        );

    let app = Router::new()
        .route("/join/:session/:party", put(join))
        .route("/participants/:session", get(participants))
        .route("/send/:session/:from/:to", post(send))
        .route("/recv/:session/:from/:to", post(recv))
        .route("/clear/:session/:from", post(clear))
        .with_state(sessions)
        .layer(ServiceBuilder::new().layer(log_layer));

    let addr = if let Ok(socket_addr) = env::var("SOCKET_ADDRESS") {
        SocketAddr::from_str(&socket_addr)
            .unwrap_or_else(|_| panic!("Invalid socket address: {socket_addr}"))
    } else {
        SocketAddr::from(([127, 0, 0, 1], 8000))
    };
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

struct Session {
    msgs: HashMap<u32, HashMap<u32, VecDeque<Vec<u8>>>>,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

async fn join(
    State(sessions): State<Sessions>,
    Path((session_id, party)): Path<(String, u32)>,
) -> Result<(), StatusCode> {
    let mut sessions = sessions.lock().await;
    let session = sessions.entry(session_id).or_insert(Session {
        msgs: HashMap::new(),
    });
    session.msgs.entry(party).or_default();
    Ok(())
}

async fn participants(
    State(sessions): State<Sessions>,
    Path(session_id): Path<String>,
) -> Result<Json<Vec<u32>>, StatusCode> {
    let mut sessions = sessions.lock().await;
    let session = sessions.entry(session_id).or_insert(Session {
        msgs: HashMap::new(),
    });
    let participants: Vec<u32> = session.msgs.keys().copied().collect();
    Ok(Json(participants))
}

async fn send(
    State(sessions): State<Sessions>,
    Path((session_id, from, to)): Path<(String, u32, u32)>,
    body: Bytes,
) -> Result<(), StatusCode> {
    let mut sessions = sessions.lock().await;
    let session = sessions.entry(session_id).or_insert(Session {
        msgs: HashMap::new(),
    });
    let msgs = session.msgs.entry(from).or_default().entry(to).or_default();
    msgs.push_back(body.to_vec());
    Ok(())
}

async fn recv(
    State(sessions): State<Sessions>,
    Path((session_id, from, to)): Path<(String, u32, u32)>,
) -> Result<Vec<u8>, StatusCode> {
    let mut sessions = sessions.lock().await;
    let Some(session) = sessions.get_mut(&session_id) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(msgs) = session
        .msgs
        .get_mut(&from)
        .map(|msgs| msgs.get_mut(&to))
        .flatten()
    else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Some(msg) = msgs.pop_front() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    Ok(msg)
}

async fn clear(
    State(sessions): State<Sessions>,
    Path((session_id, from)): Path<(String, u32)>,
) -> Result<(), StatusCode> {
    let mut sessions = sessions.lock().await;
    let Some(session) = sessions.get_mut(&session_id) else {
        return Ok(());
    };
    let Some(msgs) = session.msgs.get_mut(&from) else {
        return Ok(());
    };
    msgs.clear();
    if session.msgs.values().all(|v| v.is_empty()) {
        sessions.remove(&session_id);
    }
    Ok(())
}
