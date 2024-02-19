use axum::{
    body::Bytes,
    extract::{Path, State},
    routing::post,
    Router,
};
use clap::{Parser, Subcommand};
use parlay::{
    channel::Channel,
    fpre::fpre,
    garble_lang::compile,
    protocol::{mpc, Preprocessor},
};
use reqwest::StatusCode;
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    process::exit,
    result::Result,
    sync::Arc,
    time::Duration,
};
use tokio::{fs, sync::Mutex, time::sleep};
use tower_http::trace::TraceLayer;
use url::Url;

/// A cli for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "parlay")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Runs a client as a trusted dealer, responsible for correlated randomness.
    #[command(arg_required_else_help = true)]
    Pre {
        /// The endpoints of all the parties, including this one (as the last url).
        #[arg(required = true, value_delimiter = ';')]
        urls: Vec<Url>,
    },
    /// Runs a client as a party that participates with its own inputs.
    #[command(arg_required_else_help = true)]
    Party {
        /// The endpoints of all the parties, including this one (as the last url).
        #[arg(required = true, value_delimiter = ';')]
        urls: Vec<Url>,
        /// The path to the Garble program to execute.
        #[arg(long)]
        program: PathBuf,
        /// The index of the party (0 for the first participant, 1 for the second, etc).
        #[arg(long)]
        party: usize,
        /// The party's input as a Garble literal, e.g. "123u32".
        #[arg(short, long)]
        input: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Pre { urls } => {
            let parties = urls.len() - 1;
            let c = HttpChannel::new(urls, parties).await;
            fpre(c, parties).await.unwrap()
        }
        Commands::Party {
            urls,
            program,
            party,
            input,
        } => {
            let Ok(prg) = fs::read_to_string(&program).await else {
                eprintln!("Could not find '{}'", program.display());
                exit(-1);
            };
            let prg = compile(&prg).unwrap();
            let input = prg.parse_arg(party, &input).unwrap().as_bits();
            let fpre = Preprocessor::TrustedDealer(urls.len() - 1);
            let p_out: Vec<_> = (0..(urls.len() - 1)).collect();
            let c = HttpChannel::new(urls, party).await;
            let out = mpc(c, &prg.circuit, &input, fpre, 0, party, &p_out)
                .await
                .unwrap();
            if !out.is_empty() {
                println!("\nThe result is {}", prg.parse_output(&out).unwrap());
            }
        }
    }
}

type Session = Arc<Mutex<HashMap<usize, VecDeque<Vec<u8>>>>>;

async fn serve(port: u16) -> Session {
    tracing_subscriber::fmt::init();

    let state = Arc::new(Mutex::new(HashMap::new()));
    let session = Arc::clone(&state);

    let app = Router::new()
        .route("/msg/:from", post(msg))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    session
}

async fn msg(State(session): State<Session>, Path(from): Path<u32>, body: Bytes) {
    let mut session = session.lock().await;
    let msgs = session.entry(from as usize).or_default();
    msgs.push_back(body.to_vec());
}

struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    client: reqwest::Client,
    session: Session,
}

impl HttpChannel {
    async fn new(urls: Vec<Url>, party: usize) -> Self {
        let port = urls[party].port().expect("All URLs must specify a port");
        Self {
            urls,
            party,
            client: reqwest::Client::new(),
            session: serve(port).await,
        }
    }
}

impl Channel for HttpChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(&mut self, p: usize, msg: Vec<u8>) -> Result<(), Self::SendError> {
        let url = format!("{}msg/{}", self.urls[p], self.party);
        loop {
            let resp = self.client.post(&url).body(msg.clone()).send().await?;
            if resp.status().is_success() {
                return Ok(());
            } else if resp.status() == StatusCode::NOT_FOUND {
                println!("Could not reach party {p} at {url}...");
                sleep(Duration::from_millis(1000)).await;
            } else {
                anyhow::bail!("Unexpected status code: {}", resp.status());
            }
        }
    }

    async fn recv_bytes_from(&mut self, p: usize) -> Result<Vec<u8>, Self::RecvError> {
        loop {
            let mut session = self.session.lock().await;
            if let Some(msg) = session.get_mut(&p).and_then(|msgs| msgs.pop_front()) {
                return Ok(msg);
            } else {
                println!("Waiting for message from party {p}...");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
