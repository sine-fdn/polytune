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
use std::{net::SocketAddr, path::PathBuf, process::exit, result::Result, time::Duration};
use tokio::{
    fs,
    sync::mpsc::{channel, Receiver, Sender},
    time::sleep,
};
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

async fn serve(port: u16, parties: usize) -> Vec<Receiver<Vec<u8>>> {
    tracing_subscriber::fmt::init();

    let mut senders = vec![];
    let mut receivers = vec![];
    for _ in 0..parties {
        let (s, r) = channel(1);
        senders.push(s);
        receivers.push(r);
    }

    let app = Router::new()
        .route("/msg/:from", post(msg))
        .with_state(senders)
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    receivers
}

async fn msg(State(senders): State<Vec<Sender<Vec<u8>>>>, Path(from): Path<u32>, body: Bytes) {
    senders[from as usize].send(body.to_vec()).await.unwrap();
}

struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    client: reqwest::Client,
    receivers: Vec<Receiver<Vec<u8>>>,
}

impl HttpChannel {
    async fn new(urls: Vec<Url>, party: usize) -> Self {
        let port = urls[party].port().expect("All URLs must specify a port");
        let receivers = serve(port, urls.len()).await;
        Self {
            urls,
            party,
            client: reqwest::Client::new(),
            receivers,
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
            match resp.status() {
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
        Ok(self.receivers[p].recv().await.unwrap())
    }
}
