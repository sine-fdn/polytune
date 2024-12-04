use std::{path::PathBuf, process::exit, time::Duration};

use clap::{Parser, Subcommand};
use http_channel::PollingHttpChannel;
use polytune::{
    fpre::fpre,
    garble_lang::compile,
    protocol::{mpc, Preprocessor},
};
use tokio::{fs, time::sleep};
use tracing::debug;

mod http_channel;
mod server;

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "polytune")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Starts an HTTP server that relays messages between parties.
    Serve,
    /// Runs a client as a trusted dealer, responsible for correlated randomness.
    #[command(arg_required_else_help = true)]
    Pre {
        /// The endpoint of the server relaying the messages.
        #[arg(required = true)]
        url: String,
        /// A name that uniquely identifies the MPC session on the server.
        #[arg(short, long)]
        session: String,
        /// The number of parties participating in the computation.
        #[arg(short, long)]
        parties: usize,
    },
    /// Runs a client as a party that participates with its own inputs.
    #[command(arg_required_else_help = true)]
    Party {
        /// The endpoint of the server relaying the messages.
        #[arg(required = true)]
        url: String,
        /// A name that uniquely identifies the MPC session on the server.
        #[arg(short, long)]
        session: String,
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

const P_DEALER: usize = 255;

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    match args.command {
        Commands::Serve => server::serve().await,
        Commands::Pre {
            url,
            session,
            parties,
        } => {
            let mut channel = PollingHttpChannel::new(&url, &session, P_DEALER);
            channel.join().await.unwrap();
            loop {
                let joined = channel.participants().await.unwrap();
                if joined == parties + 1 {
                    break;
                } else {
                    debug!("Waiting for {} parties to join...", parties + 1 - joined);
                    sleep(Duration::from_secs(1)).await;
                }
            }
            fpre(&mut channel, parties).await.unwrap();
        }
        Commands::Party {
            url,
            session,
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
            let p_eval = 0;
            let mut channel = PollingHttpChannel::new(&url, &session, party);
            channel.join().await.unwrap();
            let parties = prg.circuit.input_gates.len();
            loop {
                let joined = channel.participants().await.unwrap();
                if joined < parties + 1 {
                    debug!("Waiting for {} parties to join...", parties + 1 - joined);
                    sleep(Duration::from_secs(1)).await;
                } else {
                    break;
                }
            }
            let fpre = Preprocessor::TrustedDealer(P_DEALER);
            let p_out: Vec<_> = (0..parties).collect();
            let output = mpc(
                &mut channel,
                &prg.circuit,
                &input,
                fpre,
                p_eval,
                party,
                &p_out,
            )
            .await
            .unwrap();
            if !output.is_empty() {
                let result = prg.parse_output(&output).unwrap();
                println!("\nThe result is {result}");
            }
        }
    }
}
