use std::{net::SocketAddr, path::PathBuf, process::exit, sync::Arc, time::Duration};

use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh_channel::IrohChannel;
use iroh_net::{derp::DerpMode, key::SecretKey, MagicEndpoint, NodeAddr};
use parlay::{
    fpre::fpre,
    garble_lang::compile,
    protocol::{mpc, Preprocessor},
};
use quinn::Connection;
use serde::{Deserialize, Serialize};
use tokio::{fs, sync::Mutex, time::sleep};
use url::Url;

mod iroh_channel;

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
        /// The number of parties participating in the computation.
        #[arg(short, long)]
        parties: usize,
    },
    /// Runs a client as a party that participates with its own inputs.
    #[command(arg_required_else_help = true)]
    Party {
        /// The id of the remote node.
        #[clap(long)]
        node_id: iroh_net::NodeId,
        /// The list of direct UDP addresses for the remote node.
        #[clap(long, value_parser, num_args = 1.., value_delimiter = ';')]
        addrs: Vec<SocketAddr>,
        /// The url of the DERP server the remote node can also be reached at.
        #[clap(long)]
        derp_url: Url,
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

const ALPN: &[u8] = b"parlay/p2p/iroh";
const MAX_MSG_BYTES: usize = 1_024_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JoinMessage {
    party: usize,
    node_id: iroh_net::NodeId,
    addrs: Vec<SocketAddr>,
    derp_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Commands::Pre { parties } => {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::ERROR)
                .init();
            println!("Starting preprocessor, waiting for other parties to connect...");
            let secret_key = SecretKey::generate();

            let endpoint = MagicEndpoint::builder()
                .secret_key(secret_key)
                .alpns(vec![ALPN.to_vec()])
                .derp_mode(DerpMode::Default)
                .bind(0)
                .await?;

            let own_node_id = endpoint.node_id();

            let local_addrs = endpoint
                .local_endpoints()
                .await?
                .into_iter()
                .map(|endpoint| endpoint.addr.to_string())
                .collect::<Vec<_>>()
                .join(";");

            let derp_url = endpoint
                .my_derp()
                .expect("could not connect to a DERP server");
            println!("\nTo connect as a party run the following command, additionally specifying --party, --program and --input:");
            println!("\ncargo run -- party --node-id={own_node_id} --addrs={local_addrs} --derp-url={derp_url}");
            let mut participants: Vec<Option<(Connection, JoinMessage)>> = vec![None; parties];
            while let Some(conn) = endpoint.accept().await {
                let (_node_id, alpn, conn) = iroh_net::magic_endpoint::accept_conn(conn).await?;
                if alpn.as_bytes() != ALPN {
                    continue;
                }
                let mut recv = conn.accept_uni().await?;
                let msg = recv.read_to_end(MAX_MSG_BYTES).await?;
                let msg: JoinMessage = bincode::deserialize(&msg)?;
                let party = msg.party;
                if party < parties {
                    println!("Party {party} ({}) joined", msg.node_id);
                    participants[party] = Some((conn, msg));
                }
                if participants.iter().flatten().count() == parties {
                    break;
                }
            }
            let joined: Vec<_> = participants
                .iter()
                .flatten()
                .map(|(_, p)| p)
                .cloned()
                .collect();
            for (conn, _) in participants.iter().flatten() {
                let mut send = conn.open_uni().await?;
                send.write_all(&bincode::serialize(&joined)?).await?;
                send.finish().await?;
            }

            println!("Connected to all parties, running MPC protocol now...");
            let conns: Vec<_> = participants
                .into_iter()
                .map(|c| c.map(|(c, _)| c))
                .collect();

            let channel = IrohChannel::new(conns, MAX_MSG_BYTES);
            fpre(channel, parties).await.unwrap();
            Ok(())
        }
        Commands::Party {
            node_id,
            addrs,
            derp_url,
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
            let parties = prg.circuit.input_gates.len();

            println!("Connecting to preprocessor...");
            let secret_key = SecretKey::generate();

            let endpoint = MagicEndpoint::builder()
                .secret_key(secret_key)
                .alpns(vec![ALPN.to_vec()])
                .derp_mode(DerpMode::Default)
                .bind(0)
                .await?;

            let own_node_id = endpoint.node_id();
            let local_addrs = endpoint
                .local_endpoints()
                .await?
                .into_iter()
                .map(|endpoint| endpoint.addr)
                .collect::<Vec<_>>();

            let my_derp_url = endpoint
                .my_derp()
                .expect("could not connect to a DERP server");
            let addr = NodeAddr::from_parts(node_id, Some(derp_url), addrs);
            let pre_conn = endpoint.connect(addr, ALPN).await?;

            let mut send = pre_conn.open_uni().await?;

            let msg = JoinMessage {
                party,
                node_id: own_node_id,
                addrs: local_addrs,
                derp_url: my_derp_url,
            };
            send.write_all(&bincode::serialize(&msg)?).await?;
            send.finish().await?;

            println!("Found preprocessor, waiting for list of other parties...");
            let mut recv = pre_conn.accept_uni().await?;

            let participants: Arc<Mutex<Vec<Option<Connection>>>> =
                Arc::new(Mutex::new(vec![None; parties]));
            let joined: Vec<JoinMessage> =
                bincode::deserialize(&recv.read_to_end(MAX_MSG_BYTES).await?)?;
            let listen_endpoint = endpoint.clone();
            let listen_joined = joined.clone();
            let listen_participants = Arc::clone(&participants);
            tokio::spawn(async move {
                while let Some(conn) = listen_endpoint.accept().await {
                    let (node_id, alpn, conn) = iroh_net::magic_endpoint::accept_conn(conn).await?;
                    if alpn.as_bytes() != ALPN {
                        continue;
                    }
                    for joined in listen_joined.iter() {
                        if joined.node_id == node_id {
                            listen_participants.lock().await[joined.party] = Some(conn);
                            break;
                        }
                    }
                    if listen_participants.lock().await.iter().flatten().count() == parties {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
            for joined in joined {
                if joined.party != party {
                    println!("Connecting to party {} ({})", joined.party, joined.node_id);
                }
                if joined.party < party {
                    let addr =
                        NodeAddr::from_parts(joined.node_id, Some(joined.derp_url), joined.addrs);
                    let conn = endpoint.connect(addr, ALPN).await?;
                    participants.lock().await[joined.party] = Some(conn);
                }
            }
            while participants.lock().await.iter().flatten().count() < parties - 1 {
                sleep(Duration::from_millis(100)).await;
            }
            println!("Connected to all parties, running MPC protocol now...");
            let mut conns: Vec<_> = participants.lock().await.clone();
            conns.push(Some(pre_conn));

            let p_eval = 0;
            let fpre = Preprocessor::TrustedDealer(conns.len() - 1);
            let channel = IrohChannel::new(conns, MAX_MSG_BYTES);
            let p_out: Vec<_> = (0..parties).collect();
            let output = mpc(
                channel,
                &prg.circuit,
                &input,
                fpre,
                p_eval,
                party,
                &p_out,
                true,
            )
            .await
            .unwrap();
            if !output.is_empty() {
                let result = prg.parse_output(&output).unwrap();
                println!("\nThe result is {result}");
            }
            Ok(())
        }
    }
}
