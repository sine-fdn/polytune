use std::time::Duration;

use clap::{Parser, Subcommand};
use http_channel::PollingHttpChannel;
use parlay::{
    channel::MsgChannel,
    fpre::fpre_channel,
    garble_lang::compile,
    protocol::{mpc, Role},
};
use tokio::time::sleep;

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
        /// The index of the party (0 for the first participant, 1 for the second, etc).
        #[arg(short, long)]
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
                let channel = PollingHttpChannel {
                    url: url.clone(),
                    session,
                    client: reqwest::Client::new(),
                    party_index: 0,
                };
                channel.join().await.unwrap();
                fpre_channels.push(MsgChannel(channel))
            }
            loop {
                let mut active_participants = 0;
                for channel in fpre_channels.iter_mut() {
                    if channel.0.participants().await.unwrap() == 2 {
                        active_participants += 1;
                    }
                }
                if active_participants == parties {
                    break;
                } else {
                    println!(
                        "Waiting for {} participants to join",
                        parties - active_participants
                    );
                    sleep(Duration::from_secs(1)).await;
                }
            }
            let other_party = 1;
            fpre_channel(other_party, &mut fpre_channels).await.unwrap()
        }
        Commands::Party {
            url,
            session,
            party,
            input,
        } => {
            let prg = compile("pub fn main(x: u32, y: u32, z: u32) -> u32 { x + y + z }").unwrap();
            let input = prg
                .parse_arg(party, &format!("{input}u32"))
                .unwrap()
                .as_bits();
            let p_eval = 0;
            let role = if party == p_eval {
                Role::PartyEval
            } else {
                Role::PartyContrib
            };
            let party_channel = PollingHttpChannel {
                url: url.clone(),
                session: session.clone(),
                client: reqwest::Client::new(),
                party_index: party,
            };
            party_channel.join().await.unwrap();
            let fpre_channel = PollingHttpChannel {
                url,
                session: format!("{session}-fpre-{party}"),
                client: reqwest::Client::new(),
                party_index: 1,
            };
            fpre_channel.join().await.unwrap();
            loop {
                let active_participants = party_channel.participants().await.unwrap();
                if active_participants < prg.circuit.input_gates.len() {
                    println!(
                        "Waiting for {} other participants to join...",
                        prg.circuit.input_gates.len() - active_participants
                    );
                    sleep(Duration::from_secs(1)).await;
                } else {
                    break;
                }
            }
            let parties = MsgChannel(party_channel);
            let fpre = MsgChannel(fpre_channel);
            let output = mpc(&prg.circuit, &input, fpre, parties, p_eval, party, role)
                .await
                .unwrap();
            if !output.is_empty() {
                let result = prg.parse_output(&output).unwrap();
                println!("\nThe result is: {result}");
            }
        }
    }
}
