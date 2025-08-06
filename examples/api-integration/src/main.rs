use aide::{
    axum::{
        ApiRouter, IntoApiResponse,
        routing::{get, post, post_with},
    },
    openapi::{Info, OpenApi},
    swagger::Swagger,
    transform::TransformOperation,
};
use anyhow::{Error, anyhow, bail};
use axum::{
    Extension, Json,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{Request, Response},
};
use clap::Parser;
use polytune::{
    channel::Channel,
    garble_lang::{compile_with_constants, literal::Literal},
    mpc,
};
use polytune_test_utils::peak_alloc::{PeakAllocator, create_instrumented_runtime, scale_memory};
use reqwest::StatusCode;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    borrow::BorrowMut,
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    result::Result,
    str::FromStr,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tokio::{
    sync::{
        Mutex,
        mpsc::{Receiver, Sender, channel},
    },
    time::sleep,
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{Span, error, info};
use url::Url;

#[global_allocator]
static ALLOCATOR: PeakAllocator = PeakAllocator::new();

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
    /// The URLs at which we can reach the other parties. Their position in
    /// in this array needs to be identical for all parties and will correspond
    /// to their party ID (e.g. used for the leader).
    participants: Vec<Url>,
    /// The program as [Garble](https://garble-lang.org/) source code.
    program: String,
    /// The id of the leader of the computation.
    leader: usize,
    /// Our own party ID. Corresponds to our adress at participants[party].
    party: usize,
    /// The input to the Garble program as a serialized Garble `Literal` value.
    input: Literal,
    /// The optional output URL to which the output of the MPC computation is provided
    /// as a json serialized Garble `Literal` value.
    output: Option<Url>,
    /// The constants needed of this party for the MPC computation. Note that the
    /// identifier must not contain the `PARTY_{ID}::` prefix, but only the name.
    /// E.g. if the Garble program contains `const ROWS_0: usize = PARTY_0::ROWS;`
    /// this should contain e.g. `"ROWS": { "NumUnsigned": [200, "Usize"]}`.
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

fn main() -> Result<(), Error> {
    // because we actually run this example as two processes, we can just use 0 for both
    let rt = create_instrumented_runtime(0);
    thread::spawn(|| {
        loop {
            let memory_peak = ALLOCATOR.peak(0) as f64;
            let (denom, unit) = scale_memory(memory_peak);
            info!(
                "Current peak memory consumption: {} {}",
                memory_peak / denom,
                unit
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    });
    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Error> {
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
        .api_route("/launch", post_with(launch, launch_docs))
        // to kick off an MPC session:
        .route("/run", post(run))
        // to receive constants from other parties:
        .route("/consts/{from}", axum::routing::post(consts))
        // to receive MPC messages during the execution of the core protocol:
        .route("/msg/{from}", post(msg))
        .route("/swagger", Swagger::new("/api.json").axum_route())
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
    info!("executing MPC");
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
    let compile_now = Instant::now();
    ALLOCATOR.enable();
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
    let memory_peak = ALLOCATOR.peak(0) as f64;
    let (denom, unit) = scale_memory(memory_peak);
    info!(
        "Trying to execute circuit with {:.2}M gates ({:.2}M AND gates). Compilation took {:?}. Peak memory: {} {unit}",
        prg.circuit.gates.len() as f64 / 1000.0 / 1000.0,
        prg.circuit.and_gates() as f64 / 1000.0 / 1000.0,
        compile_now.elapsed(),
        memory_peak / denom
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

        let client = reqwest::ClientBuilder::new()
            .tcp_user_timeout(Duration::from_secs(10 * 60))
            .build()?;

        HttpChannel {
            client,
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
    let memory_peak = ALLOCATOR.peak(0) as f64;
    let (denom, unit) = scale_memory(memory_peak);
    info!(
        "MPC computation for party {party} took {} hour(s), {} minute(s), {} second(s). Peak memory: {} {unit}",
        elapsed.as_secs() / 60 / 60,
        (elapsed.as_secs() % (60 * 60)) / 60,
        elapsed.as_secs() % 60,
        memory_peak / denom
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

fn launch_docs(t: TransformOperation) -> TransformOperation {
    t.id("launchMpcSession")
        .description("Launch a new MPC session. This needs to be called for all contributors before it is called for the leader.")
}

// TODO Errors need to be returned to the caller of `/launch` and not only logged
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
                if let Err(e) = client.post(endpoint.clone()).json(&output).send().await {
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

// TODO errors should be returned to the caller of `/run` and not only logged
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

// TODO errors should be returned to the caller of `/run` and not only logged
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
    client: reqwest::Client,
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
        let url = format!("{}msg/{}", self.urls[p], self.party);
        let mb = msg.len() as f64 / 1024.0 / 1024.0;
        info!("Sending msg {phase} to party {p} ({mb:.2}MB)...");
        let mut retries = 0;
        loop {
            let res = self.client.post(&url).body(msg.clone()).send().await?;
            match res.status() {
                StatusCode::OK => break Ok(()),
                // retry for 10 minutes
                StatusCode::NOT_FOUND if retries < 10 * 60 => {
                    retries += 1;
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
        r.recv()
            .await
            .ok_or_else(|| anyhow!("Expected a message, but received `None`!"))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use garble_lang::token::UnsignedNumType;

    /// Create the large policies `policy0-big.json` and `policy1-big.json`.
    ///
    /// If you want to change these policies, you can adapt this test case and
    /// execute it with
    /// `cargo t --bin polytune-api-integration -- create_big_policy --include-ignored`
    #[ignore]
    #[test]
    fn create_big_policy() {
        let size1 = 1000;
        let size2 = 1000;
        let zero_id =
            Literal::ArrayRepeat(Box::new(Literal::NumUnsigned(0, UnsignedNumType::U8)), 16);
        let one_id =
            Literal::ArrayRepeat(Box::new(Literal::NumUnsigned(1, UnsignedNumType::U8)), 16);
        let dataset1 = Literal::ArrayRepeat(Box::new(zero_id.clone()), size1);
        let dataset2 = Literal::ArrayRepeat(Box::new(one_id.clone()), size2);
        let consts = |rows| {
            HashMap::from_iter([
                (
                    "ROWS".into(),
                    Literal::NumUnsigned(rows as u64, UnsignedNumType::Usize),
                ),
                (
                    "ID_LEN".into(),
                    Literal::NumUnsigned(16, UnsignedNumType::Usize),
                ),
            ])
        };
        let consts1 = consts(size1);
        let consts2 = consts(size2);
        let participants = vec![
            "http://localhost:8000".parse().unwrap(),
            "http://localhost:8001".parse().unwrap(),
        ];
        let program = include_str!("../.example.garble.rs").to_string();
        let pol0 = Policy {
            participants: participants.clone(),
            program: program.clone(),
            leader: 0,
            party: 0,
            input: dataset1,
            output: None,
            constants: consts1,
        };
        let pol1 = Policy {
            participants,
            program,
            leader: 0,
            party: 1,
            input: dataset2,
            output: None,
            constants: consts2,
        };
        serde_json::to_writer_pretty(File::create("policy0-big.json").unwrap(), &pol0).unwrap();
        serde_json::to_writer_pretty(File::create("policy1-big.json").unwrap(), &pol1).unwrap();
    }
}
