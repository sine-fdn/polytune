use std::net::SocketAddr;

use clap::Parser;

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "polytune")]
pub struct Cli {
    /// The IP address to listen on for connection attempts from other parties.
    #[arg(long, short)]
    pub addr: Option<SocketAddr>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    polytune_server_v2::server::Server::start(cli.addr.unwrap())
        .await
        .map_err(drop)
        .unwrap();
}
