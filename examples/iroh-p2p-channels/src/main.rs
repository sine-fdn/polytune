use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    process::exit,
    str::FromStr,
    sync::Mutex,
    time::Duration,
};

use anyhow::{bail, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use iroh::{Endpoint, NodeAddr, RelayMap, RelayMode, RelayUrl, SecretKey};
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::StreamExt;
use polytune::{
    channel::{Channel, RecvInfo, SendInfo},
    garble_lang::compile,
    protocol::mpc,
};
use serde::{Deserialize, Serialize};
use tokio::{fs, time::sleep};

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "polytune")]
struct Cli {
    /// secret key to derive our node id from.
    #[clap(long)]
    secret_key: Option<String>,
    /// Set a custom relay server. By default, the relay server hosted by n0 will be used.
    #[clap(short, long)]
    relay: Option<RelayUrl>,
    /// Set the bind port for our socket. By default, a random port will be used.
    #[clap(short, long, default_value = "0")]
    bind_port: u16,
    /// The path to the Garble program to execute.
    #[arg(long)]
    program: PathBuf,
    /// The index of the party (0 for the first participant, 1 for the second, etc).
    #[arg(long)]
    party: usize,
    /// The party's input as a Garble literal, e.g. "123u32".
    #[arg(short, long)]
    input: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start an MPC session for others to join.
    New,
    /// Join an MPC session.
    Join {
        /// The ticket, as base32 string.
        ticket: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Cli::parse();

    let Ok(prg) = fs::read_to_string(&args.program).await else {
        eprintln!("Could not find '{}'", args.program.display());
        exit(-1);
    };
    let prg = compile(&prg).unwrap();
    let input = prg.parse_arg(args.party, &args.input).unwrap().as_bits();
    let parties = prg.circuit.input_gates.len();

    // parse the cli command
    let (topic, peers) = match &args.command {
        Command::New => {
            let topic = TopicId::from_bytes(rand::random());
            println!("> opening chat room for topic {topic}");
            (topic, vec![])
        }
        Command::Join { ticket } => {
            println!("> trying to decode ticket...");
            let Ticket { topic, peers } = Ticket::from_str(ticket)?;
            println!("> joining chat room for topic {topic}");
            (topic, peers)
        }
    };

    // parse or generate our secret key
    let secret_key = match args.secret_key {
        None => SecretKey::generate(rand::rngs::OsRng),
        Some(key) => key.parse()?,
    };
    println!("> our secret key: {secret_key}");

    // configure our relay map
    let relay_mode = match args.relay {
        Some(url) => RelayMode::Custom(RelayMap::from(url)),
        None => RelayMode::Default,
    };

    // build our magic endpoint
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(relay_mode)
        .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, args.bind_port))
        .bind()
        .await?;
    println!("> our node id: {}", endpoint.node_id());

    // create the gossip protocol
    let gossip = Gossip::builder()
        .max_message_size(100 * 1024 * 1024)
        .spawn(endpoint.clone())
        .await?;

    // print a ticket that includes our own node id and endpoint addresses
    let ticket = {
        let me = endpoint.node_addr().await?;
        let peers = peers.iter().cloned().chain([me]).collect();
        Ticket { topic, peers }
    };
    if let Command::New = args.command {
        println!("> ticket to join us: {ticket}");
    }

    // setup router
    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .spawn();

    // join the gossip topic by connecting to known peers, if any
    let peer_ids = peers.iter().map(|p| p.node_id).collect();
    if peers.is_empty() {
        println!("> waiting for peers to join us...");
    } else {
        println!("> trying to connect to {} peers...", peers.len());
        // add the peer addrs from the ticket to our endpoint's addressbook so that they can be dialed
        for peer in peers.into_iter() {
            endpoint.add_node_addr(peer)?;
        }
    };
    let (sender, receiver) = gossip.subscribe_and_join(topic, peer_ids).await?.split();

    let secs = 20;
    println!("> connected, other peers have {secs} time to join before the computation starts!");

    sleep(Duration::from_secs(secs)).await;
    println!("> starting the computation...");

    let mut channel = IrohChannel {
        sender,
        receiver: tokio::sync::Mutex::new(receiver),
        received_msgs: Mutex::default(),
        party: args.party,
    };

    let p_eval = 0;
    let p_own = args.party;
    let p_out: Vec<_> = (0..parties).collect();

    let output = mpc(&mut channel, &prg.circuit, &input, p_eval, p_own, &p_out).await?;

    // shutdown
    router.shutdown().await?;

    if !output.is_empty() {
        let result = prg.parse_output(&output).unwrap();
        println!("\nThe result is {result}");
    }
    Ok(())
}

struct IrohChannel {
    sender: GossipSender,
    receiver: tokio::sync::Mutex<GossipReceiver>,
    received_msgs: Mutex<HashMap<usize, VecDeque<Vec<u8>>>>,
    party: usize,
}

impl Channel for IrohChannel {
    type SendError = anyhow::Error;
    type RecvError = anyhow::Error;

    async fn send_bytes_to(
        &self,
        p: usize,
        msg: Vec<u8>,
        _info: SendInfo,
    ) -> Result<(), Self::SendError> {
        tracing::info!("sending msg {} bytes from {} to {p}", msg.len(), self.party);
        let message = Message {
            from_party: self.party,
            to_party: p,
            data: msg,
        };
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        self.sender.broadcast(data).await?;
        Ok(())
    }

    // TODO this implementation seems really dubious to me... I'm really not sure if it behaves
    //  correctly in edge-cases
    async fn recv_bytes_from(&self, p: usize, _info: RecvInfo) -> Result<Vec<u8>, Self::RecvError> {
        tracing::info!("receiving message from {p}");
        {
            let mut msgs_lock = self.received_msgs.lock().expect("poisoned");
            if let Some(msgs) = msgs_lock.get_mut(&p) {
                if let Some(msg) = msgs.pop_front() {
                    tracing::info!("found stored message from {p}");
                    return Ok(msg);
                }
            }
        }
        tracing::info!("could not find stored message, waiting for message...");
        let mut receiver = self.receiver.lock().await;
        while let Some(event) = receiver.try_next().await? {
            if let Event::Gossip(GossipEvent::Received(msg)) = event {
                let msg: Message = postcard::from_bytes(&msg.content)?;
                if msg.to_party == self.party {
                    if msg.from_party == p {
                        tracing::info!("received {} bytes from {p}", msg.data.len());
                        return Ok(msg.data);
                    } else {
                        tracing::debug!(
                            "received {} bytes, storing message from {} for now",
                            msg.data.len(),
                            msg.from_party,
                        );
                        self.received_msgs
                            .lock()
                            .expect("poisoned")
                            .entry(msg.from_party)
                            .or_default()
                            .push_back(msg.data);
                    }
                } else {
                    tracing::debug!(
                        "Ignoring message from {} to {}",
                        msg.from_party,
                        msg.to_party
                    );
                }
            } else {
                tracing::trace!("{event:?}");
            }
        }
        bail!("Expected to receive an event!")
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    from_party: usize,
    to_party: usize,
    data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ticket {
    topic: TopicId,
    peers: Vec<NodeAddr>,
}
impl Ticket {
    /// Deserializes from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(Into::into)
    }
    /// Serializes to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }
}

/// Serializes to base32.
impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.to_bytes()[..]);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}

/// Deserializes from base32.
impl FromStr for Ticket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD.decode(s.to_ascii_uppercase().as_bytes())?;
        Self::from_bytes(&bytes)
    }
}
