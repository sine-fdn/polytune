use clap::Parser;

/// A CLI for Multi-Party Computation using the Parlay engine.
#[derive(Debug, Parser)]
#[command(name = "polytune")]
pub struct Cli {
    /// The IP address to listen on for connection attempts from other parties.
    #[arg(long, short)]
    pub addr: Option<String>,
    /// The port to listen on for connection attempts from other parties.
    #[arg(long, short)]
    pub port: Option<u16>,
}
