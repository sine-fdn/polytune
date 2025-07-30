use aide::{
    axum::{
        ApiRouter, IntoApiResponse,
        routing::{get, post},
    },
    openapi::{Info, OpenApi},
};
use anyhow::{Context, Error, anyhow, bail};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    handler::HandlerWithoutStateExt,
    http::{Request, Response},
};
use clap::Parser;
use polytune::{
    channel::Channel,
    garble_lang::{compile_with_constants, literal::Literal},
    mpc,
};
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    borrow::{BorrowMut, Cow},
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    result::Result,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, channel},
    },
    time::{sleep, timeout},
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{Span, error, info, warn};
use url::Url;

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "polytune")]
struct Cli {
    /// The IP address to listen on for connection attempts from other parties.
    #[arg(long, short)]
    addr: Option<String>,
    /// The port to listen on for connection attempts from other parties.
    #[arg(long, short)]
    port: Option<u16>,
}

/// A policy containing everything necessary to run an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
struct Policy {
    participants: Vec<Url>,
    program: String,
    leader: usize,
    party: usize,
    input: Literal,
    output: Option<String>,
    constants: HashMap<String, Literal>,
}

/// HTTP request coming from another party to start an MPC session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, JsonSchema)]
struct PolicyRequest {
    participants: Vec<Url>,
    program_hash: String,
    leader: usize,
}

/// HTTP request to transmit constants necessary to compile a program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ConstsRequest {
    consts: HashMap<String, Literal>,
}

struct MpcComms {
    policy: Option<Policy>,
    consts: HashMap<String, HashMap<String, Literal>>,
    senders: Vec<Sender<Vec<u8>>>,
}

type MpcState = Arc<Mutex<MpcComms>>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let Cli { addr, port } = Cli::parse();

    let state = Arc::new(Mutex::new(MpcComms {
        policy: None,
        consts: HashMap::new(),
        senders: vec![],
    }));

    let log_layer = TraceLayer::new_for_http()
        .on_request(|r: &Request<_>, _: &Span| tracing::info!("{} {}", r.method(), r.uri().path()))
        .on_response(
            |r: &Response<_>, latency: Duration, _: &Span| match r.status().as_u16() {
                400..=499 => tracing::warn!("{} (in {:?})", r.status(), latency),
                500..=599 => tracing::error!("{} (in {:?})", r.status(), latency),
                _ => tracing::info!("{} (in {:?})", r.status(), latency),
            },
        );

    let app = ApiRouter::new()
        // to check whether a server is running:
        .route("/ping", get(ping))
        // to start an MPC session as a leader:
        .api_route("/launch", post(launch))
        // to kick off an MPC session:
        .api_route("/run", post(run))
        // to receive constants from other parties:
        .route("/consts/{from}", axum::routing::post(consts))
        // to receive MPC messages during the execution of the core protocol:
        .route("/msg/{from}", post(msg))
        .route("/api.json", get(serve_api))
        .with_state(Arc::clone(&state))
        .layer(DefaultBodyLimit::disable())
        .layer(ServiceBuilder::new().layer(log_layer));

    let mut api = OpenApi {
        info: Info {
            title: "Polytune API Deployment".to_string(),
            description: Some(
                "An example Polytune deployment which provides an API to start MPC computations."
                    .to_string(),
            ),
            version: "0.1.0".to_string(),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    let addr = if let Ok(socket_addr) = env::var("SOCKET_ADDRESS") {
        SocketAddr::from_str(&socket_addr)
            .unwrap_or_else(|_| panic!("Invalid socket address: {socket_addr}"))
    } else {
        let addr = addr.unwrap_or_else(|| "127.0.0.1".into());
        let port = port.unwrap_or(8000);
        match addr.parse::<IpAddr>() {
            Ok(addr) => SocketAddr::new(addr, port),
            Err(_) => {
                error!("Invalid IP address: {addr}, using 127.0.0.1 instead");
                SocketAddr::from(([127, 0, 0, 1], port))
            }
        }
    };
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.finish_api(&mut api)
            .layer(Extension(api))
            .into_make_service(),
    )
    .await?;
    Ok(())
}

async fn serve_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}

async fn execute_mpc(state: MpcState, policy: &Policy) -> Result<Option<Literal>, Error> {
    let Policy {
        program,
        leader,
        participants,
        party,
        input,
        output: _output,
        constants,
    } = policy;
    let now = Instant::now();
    {
        let mut locked = state.lock().await;
        locked
            .consts
            .insert(format!("PARTY_{party}"), constants.clone());
    }
    // Now we sent around the constants to the other parties...
    let client = reqwest::Client::new();
    for p in participants.iter() {
        if p != &participants[*party] {
            info!("Sending constants to party {p}");
            let url = format!("{p}consts/{party}");
            let const_request = ConstsRequest {
                consts: constants.clone(),
            };
            let Ok(res) = client.post(&url).json(&const_request).send().await else {
                bail!("Could not reach {url}");
            };
            match res.status() {
                StatusCode::OK => {}
                code => {
                    bail!("Unexpected response while trying to send consts to {url}: {code}");
                }
            }
        }
    }
    // ...and wait for their constants:
    loop {
        sleep(Duration::from_millis(500)).await;
        let locked = state.lock().await;
        if locked.consts.len() >= participants.len() - 1 {
            break;
        } else {
            let missing = participants.len() - 1 - locked.consts.len();
            info!(
                "Constants missing from {} parties, received constants from {:?}",
                missing,
                locked.consts.keys()
            );
        }
    }

    // After receiving the constants, we can finally compile the circuit:
    let prg = {
        let locked = state.lock().await;
        info!("Compiling circuit with the following constants:");
        for (p, v) in locked.consts.iter() {
            for (k, v) in v {
                info!("{p}::{k}: {v:?}");
            }
        }
        compile_with_constants(program, locked.consts.clone())
            .map_err(|e| anyhow!(e.prettify(program)))?
    };

    info!(
        "Trying to execute circuit with {:.2}M gates ({:.2}M AND gates)",
        prg.circuit.gates.len() as f64 / 1000.0 / 1000.0,
        prg.circuit.and_gates() as f64 / 1000.0 / 1000.0
    );
    let input = prg.literal_arg(*party, input.clone())?.as_bits();

    // Now that we have our input, we can start the actual session:
    let p_out: Vec<_> = vec![*leader];
    let channel = {
        let mut locked = state.lock().await;
        let state = locked.borrow_mut();
        if !state.senders.is_empty() {
            panic!("Cannot start a new MPC execution while there are still active senders!");
        }
        let mut receivers = vec![];
        for _ in 0..policy.participants.len() {
            let (s, r) = channel(1);
            state.senders.push(s);
            receivers.push(Mutex::new(r));
        }

        HttpChannel {
            urls: participants.clone(),
            party: *party,
            recv: receivers,
        }
    };

    // We run the computation using MPC, which might take some time...
    let output = mpc(&channel, &prg.circuit, &input, 0, *party, &p_out).await?;

    // ...and now we are done and return the output (if there is any):
    state.lock().await.senders.clear();
    let elapsed = now.elapsed();
    info!(
        "MPC computation for party {party} took {} hour(s), {} minute(s), {} second(s)",
        elapsed.as_secs() / 60 / 60,
        (elapsed.as_secs() % (60 * 60)) / 60,
        elapsed.as_secs() % 60,
    );
    if output.is_empty() {
        Ok(None)
    } else {
        Ok(Some(prg.parse_output(&output)?))
    }
}

async fn ping() -> &'static str {
    "pong"
}

async fn launch(State(state): State<MpcState>, Json(policy): Json<Policy>) {
    {
        let mut state = state.lock().await;
        state.policy = Some(policy.clone());
    }
    if policy.leader != policy.party {
        return;
    }
    let hash = blake3::hash(policy.program.as_bytes()).to_string();
    let client = reqwest::Client::new();
    let policy_request = PolicyRequest {
        participants: policy.participants.clone(),
        leader: policy.leader,
        program_hash: hash,
    };
    // As a leader, we first make sure that all other participants join the session:
    let mut participant_missing = false;
    for party in policy.participants.iter() {
        if party != &policy.participants[policy.party] {
            info!("Waiting for confirmation from party {party}");
            let url = format!("{party}run");
            match client.post(&url).json(&policy_request).send().await {
                Err(err) => {
                    error!("Could not reach {url}: {err}");
                    participant_missing = true;
                    continue;
                }
                Ok(res) => match res.status() {
                    StatusCode::OK => {}
                    code => {
                        error!(
                            "Unexpected response while trying to start execution for {url}: {code}"
                        );
                        participant_missing = true;
                    }
                },
            }
        }
    }
    if participant_missing {
        return error!("Some participants are missing, aborting...");
    }
    // Now we start the MPC session:
    info!("All participants have accepted the session, starting calculation now...");
    match execute_mpc(state, &policy).await {
        Ok(Some(output)) => {
            info!("MPC Output: {output}");
            if let Some(endpoint) = policy.output {
                info!("Sending {output} to {endpoint}");
                if let Err(e) = client.post(&endpoint).json(&output).send().await {
                    error!("Could not send output to {endpoint}: {e}");
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            error!("Error while executing MPC: {e}")
        }
    }
}

async fn run(State(state): State<MpcState>, Json(body): Json<PolicyRequest>) {
    let Some(policy) = state.lock().await.policy.clone() else {
        return error!("Trying to start MPC execution without policy");
    };
    if policy.participants != body.participants || policy.leader != body.leader {
        error!("Policy not accepted: {body:?}");
        return;
    }
    let expected = blake3::hash(policy.program.as_bytes()).to_string();
    if expected != body.program_hash {
        error!("Aborting due to different hashes for program in policy {policy:?}");
        return;
    }
    info!("Starting execution");
    tokio::spawn(async move {
        if let Err(e) = execute_mpc(state, &policy).await {
            error!("{e}");
        }
    });
}

async fn consts(
    State(state): State<MpcState>,
    Path(from): Path<u32>,
    Json(body): Json<ConstsRequest>,
) {
    let mut state = state.lock().await;
    state.consts.insert(format!("PARTY_{from}"), body.consts);
}

async fn msg(State(state): State<MpcState>, Path(from): Path<u32>, body: Bytes) {
    let state = state.lock().await;
    if state.senders.len() > from as usize {
        state.senders[from as usize]
            .send(body.to_vec())
            .await
            .unwrap();
    } else {
        error!("No sender for party {from}");
    }
}

struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    recv: Vec<Mutex<Receiver<Vec<u8>>>>,
}

impl Channel for HttpChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        phase: &str,
    ) -> Result<(), Self::SendError> {
        let simulated_delay_in_ms = 300;
        let client = reqwest::Client::new();
        let url = format!("{}msg/{}", self.urls[p], self.party);
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        info!("Sending msg {phase} to party {p} ({mb:.2}MB)...");
        loop {
            sleep(Duration::from_millis(simulated_delay_in_ms)).await;
            let req = client.post(&url).body(msg.clone()).send();
            let Ok(Ok(res)) = timeout(Duration::from_secs(1), req).await else {
                warn!("  req timeout: party {}", p);
                continue;
            };
            match res.status() {
                StatusCode::OK => break Ok(()),
                StatusCode::NOT_FOUND => {
                    error!("Could not reach party {p} at {url}...");
                    sleep(Duration::from_millis(1000)).await;
                }
                status => {
                    error!("Unexpected status code: {status}");
                    anyhow::bail!("Unexpected status code: {status}")
                }
            }
        }
    }

    async fn recv_bytes_from(&self, p: usize, _phase: &str) -> Result<Vec<u8>, Self::RecvError> {
        let mut r = self.recv[p].lock().await;
        timeout(Duration::from_secs(30 * 60), r.recv())
            .await
            .context(format!("recv_bytes_from(p = {p})"))?
            .ok_or_else(|| anyhow!("Expected a message, but received `None`!"))
    }
}
