use std::{path::PathBuf, process::exit, time::Duration};

use clap::{Parser, Subcommand};
use http_channel::PollingHttpChannel;
use parlay::{channel::MsgChannel, fpre::fpre_channel, garble_lang::compile, protocol::mpc};
use tokio::{fs, time::sleep};

mod http_channel;
mod server;

/// A cli for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "parlay")]
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
        parties: u32,
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
        #[arg(long)]
        /// The path to the Garble program to execute.
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
        Commands::Serve => server::serve().await,
        Commands::Pre {
            url,
            session,
            parties,
        } => {
            let mut fpre_channels = vec![];
            for p in 0..parties {
                let session = format!("{session}-fpre-{p}");
                let channel = PollingHttpChannel::new(&url, &session, 0);
                channel.join().await.unwrap();
                fpre_channels.push(MsgChannel(channel))
            }
            loop {
                let mut joined = 0;
                for channel in fpre_channels.iter_mut() {
                    if channel.0.participants().await.unwrap() == 2 {
                        joined += 1;
                    }
                }
                if joined == parties {
                    break;
                } else {
                    println!("Waiting for {} parties to join", parties - joined);
                    sleep(Duration::from_secs(1)).await;
                }
            }
            let other_party = 1;
            fpre_channel(other_party, &mut fpre_channels).await.unwrap()
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
            let party_channel = PollingHttpChannel::new(&url, &session, party);
            party_channel.join().await.unwrap();
            let fpre_channel = PollingHttpChannel::new(&url, &format!("{session}-fpre-{party}"), 1);
            fpre_channel.join().await.unwrap();
            let parties = prg.circuit.input_gates.len();
            loop {
                let joined = party_channel.participants().await.unwrap();
                if joined < parties {
                    println!("Waiting for {} parties to join...", parties - joined);
                    sleep(Duration::from_secs(1)).await;
                } else {
                    break;
                }
            }
            let output_parties: Vec<_> = (0..parties).collect();
            let parties = MsgChannel(party_channel);
            let fpre = MsgChannel(fpre_channel);
            let output = mpc(
                &prg.circuit,
                &input,
                fpre,
                parties,
                p_eval,
                party,
                &output_parties,
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
