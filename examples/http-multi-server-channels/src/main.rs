use anyhow::anyhow;
use anyhow::{Context, Error};
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
use std::{net::SocketAddr, path::PathBuf, result::Result, time::Duration};
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
async fn main() -> Result<(), Error> {
    let args = Cli::parse();
    match args.command {
        Commands::Pre { urls } => {
            let parties = urls.len() - 1;
            let channel = HttpChannel::new(urls, parties).await?;
            fpre(channel, parties).await.context("FPre")
        }
        Commands::Party {
            urls,
            program,
            party,
            input,
        } => {
            let code = fs::read_to_string(&program).await?;
            let prg = compile(&code).map_err(|e| anyhow!(e.prettify(&code)))?;
            let input = prg.parse_arg(party, &input)?.as_bits();
            let fpre = Preprocessor::TrustedDealer(urls.len() - 1);
            let p_out: Vec<_> = (0..(urls.len() - 1)).collect();
            let channel = HttpChannel::new(urls, party).await?;
            let output = mpc(channel, &prg.circuit, &input, fpre, 0, party, &p_out).await?;
            if !output.is_empty() {
                println!("\nThe result is {}", prg.parse_output(&output)?);
            }
            Ok(())
        }
    }
}

async fn serve(port: u16, parties: usize) -> Result<Vec<Receiver<Vec<u8>>>, Error> {
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
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Ok(receivers)
}

async fn msg(State(senders): State<Vec<Sender<Vec<u8>>>>, Path(from): Path<u32>, body: Bytes) {
    senders[from as usize].send(body.to_vec()).await.unwrap();
}

struct HttpChannel {
    urls: Vec<Url>,
    party: usize,
    recv: Vec<Receiver<Vec<u8>>>,
}

impl HttpChannel {
    async fn new(mut urls: Vec<Url>, party: usize) -> Result<Self, Error> {
        urls.rotate_left(1);
        let port = urls[party].port().expect("All URLs must specify a port");
        let recv = serve(port, urls.len()).await?;
        Ok(Self { urls, party, recv })
    }
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
        Ok(self.recv[p].recv().await.context("recv_bytes_from({p})")?)
    }
}
