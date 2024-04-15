use anyhow::anyhow;
use anyhow::{Context, Error};
use axum::Json;
use axum::{
    body::Bytes,
    extract::{Path, State},
    routing::post,
    Router,
};
use clap::Parser;
use parlay::garble_lang::literal::Literal;
use parlay::{
    channel::Channel,
    fpre::fpre,
    garble_lang::compile,
    protocol::{mpc, Preprocessor},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;
use std::process::exit;
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf, result::Result, time::Duration};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio::{
    fs,
    sync::mpsc::{channel, Receiver, Sender},
    time::sleep,
};
use tower_http::trace::TraceLayer;
use url::Url;

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "parlay")]
struct Cli {
    /// The port to listen on for connection attempts from other parties.
    #[arg(required = true, long, short)]
    port: u16,
    /// The location of the file with the policy configuration.
    #[arg(long, short)]
    config: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct Policies {
    accepted: Vec<Policy>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
struct Policy {
    participants: Vec<Url>,
    program: PathBuf,
    leader: usize,
    party: usize,
    // TODO: replace with db connection info
    input: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct PolicyRequest {
    participants: Vec<Url>,
    program_hash: String,
    leader: usize,
}

const TIME_BETWEEN_EXECUTIONS: Duration = Duration::from_secs(5);

type MpcState = Arc<Mutex<Vec<Sender<Vec<u8>>>>>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let Cli { port, config } = Cli::parse();
    let policies = load_policies(config).await?;
    if policies.accepted.len() == 1 {
        let policy = &policies.accepted[0];
        if policy.input.is_empty() {
            println!("Running as preprocessor...");
            return run_fpre(port, policy.participants.clone()).await;
        }
    }
    tracing_subscriber::fmt::init();

    let state = Arc::new(Mutex::new(vec![]));

    let app = Router::new()
        .route("/run", post(run))
        .route("/msg/:from", post(msg))
        .with_state((policies.clone(), Arc::clone(&state)))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    println!("Found {} active policies", policies.accepted.len());
    loop {
        for policy in &policies.accepted {
            if policy.leader == policy.party {
                println!(
                    "Acting as leader (party {}) for program {}",
                    policy.leader,
                    policy.program.display()
                );
                let Ok(code) = fs::read_to_string(&policy.program).await else {
                    eprintln!("Could not load program {:?}", &policy.program);
                    continue;
                };
                let hash = blake3::hash(code.as_bytes()).to_string();
                let client = reqwest::Client::new();
                let policy_request = PolicyRequest {
                    participants: policy.participants.clone(),
                    leader: policy.leader,
                    program_hash: hash,
                };
                for party in policy.participants.iter().rev().skip(1).rev() {
                    if party != &policy.participants[policy.party] {
                        println!("Waiting for confirmation from party {party}");
                        let url = format!("{party}run");
                        match client
                            .post(&url)
                            .json(&policy_request)
                            .send()
                            .await?
                            .status()
                        {
                            StatusCode::OK => {}
                            code => {
                                eprintln!("Unexpected response while trying to trigger execution for {url}: {code}");
                            }
                        }
                    }
                }
                println!("All participants have accepted the session, starting calculation now...");
                match execute_mpc(Arc::clone(&state), code, policy).await {
                    Ok(Some(output)) => {
                        println!("Output is {output}")
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("Error while executing MPC: {e}")
                    }
                }
            }
        }
        sleep(TIME_BETWEEN_EXECUTIONS).await;
    }
}

async fn run_fpre(port: u16, urls: Vec<Url>) -> Result<(), Error> {
    let parties = urls.len() - 1;

    tracing_subscriber::fmt::init();

    let mut senders = vec![];
    let mut receivers = vec![];
    for _ in 0..parties {
        let (s, r) = channel(1);
        senders.push(s);
        receivers.push(r);
    }

    let policies = Policies { accepted: vec![] };
    let app = Router::new()
        .route("/msg/:from", post(msg))
        .with_state((policies, Arc::new(Mutex::new(senders))))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut channel = HttpChannel {
        urls,
        party: parties,
        recv: receivers,
    };
    loop {
        println!("Running FPre...");
        channel = fpre(channel, parties).await.context("FPre")?;
    }
}

async fn load_policies(path: PathBuf) -> Result<Policies, Error> {
    let Ok(policies) = fs::read_to_string(&path).await else {
        eprintln!("Could not find '{}', exiting...", path.display());
        exit(-1);
    };
    let Ok(policies) = serde_json::from_str::<Policies>(&policies) else {
        eprintln!("'{}' has an invalid format, exiting...", path.display());
        exit(-1);
    };
    Ok(policies)
}

async fn execute_mpc(
    state: MpcState,
    code: String,
    policy: &Policy,
) -> Result<Option<Literal>, Error> {
    let Policy {
        leader,
        participants,
        party,
        input,
        ..
    } = policy;
    let prg = compile(&code).map_err(|e| anyhow!(e.prettify(&code)))?;
    let input = prg.parse_arg(*party, input)?.as_bits();
    let fpre = Preprocessor::TrustedDealer(participants.len() - 1);
    let p_out: Vec<_> = vec![*leader];
    let channel = {
        let mut state = state.lock().await;
        let senders = state.borrow_mut();
        if !senders.is_empty() {
            panic!("Cannot start a new MPC execution while there are still active senders!");
        }
        let mut receivers = vec![];
        for _ in 0..policy.participants.len() {
            let (s, r) = channel(1);
            senders.push(s);
            receivers.push(r);
        }

        HttpChannel {
            urls: participants.clone(),
            party: *party,
            recv: receivers,
        }
    };
    let output = mpc(channel, &prg.circuit, &input, fpre, 0, *party, &p_out).await?;
    state.lock().await.clear();
    if output.is_empty() {
        Ok(None)
    } else {
        Ok(Some(prg.parse_output(&output)?))
    }
}

async fn run(
    State((policies, state)): State<(Policies, MpcState)>,
    Json(body): Json<PolicyRequest>,
) {
    for policy in policies.accepted {
        if policy.participants == body.participants && policy.leader == body.leader {
            let Ok(code) = fs::read_to_string(&policy.program).await else {
                eprintln!("Could not load program {:?}", &policy.program);
                return;
            };
            let expected = blake3::hash(code.as_bytes()).to_string();
            if expected != body.program_hash {
                eprintln!("Aborting due to different hashes for program in policy {policy:?}");
                return;
            }
            println!(
                "Accepted policy for {}, starting execution",
                policy.program.display()
            );
            tokio::spawn(async move {
                if let Err(e) = execute_mpc(state, code, &policy).await {
                    eprintln!("{e}");
                }
            });
            return;
        }
    }
    eprintln!("Policy not accepted: {body:?}");
}

async fn msg(State((_, state)): State<(Policies, MpcState)>, Path(from): Path<u32>, body: Bytes) {
    let senders = state.lock().await;
    if senders.len() > from as usize {
        senders[from as usize].send(body.to_vec()).await.unwrap();
    } else {
        eprintln!("No sender for party {from}");
    }
}

struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    recv: Vec<Receiver<Vec<u8>>>,
}

impl Channel for HttpChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(&mut self, p: usize, msg: Vec<u8>) -> Result<(), Self::SendError> {
        let client = reqwest::Client::new();
        let url = format!("{}msg/{}", self.urls[p], self.party);
        loop {
            match client.post(&url).body(msg.clone()).send().await?.status() {
                StatusCode::OK => return Ok(()),
                StatusCode::NOT_FOUND => {
                    println!("Could not reach party {p} at {url}...");
                    sleep(Duration::from_millis(1000)).await;
                }
                status => anyhow::bail!("Unexpected status code: {status}"),
            }
        }
    }

    async fn recv_bytes_from(&mut self, p: usize) -> Result<Vec<u8>, Self::RecvError> {
        Ok(timeout(Duration::from_secs(10), self.recv[p].recv())
            .await
            .context(format!("recv_bytes_from(p = {p})"))?
            .unwrap_or_default())
    }
}
