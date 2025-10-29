//! An HTTP-based Polytune server.
use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use polytune_http_server::{Server, ServerOpts};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

/// A HTTP-based server for the Polytune secure multi-party computation engine.
///
/// Logging can be controlled with an EnvFilter via the `POLYTUNE_LOG` environment
/// variable.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The socket address to bind the server to.
    #[arg(long, short, default_value = "127.0.0.1:8123")]
    addr: SocketAddr,
    /// Number of concurrent policy evaluations this party can be the leader of.
    #[arg(long, default_value_t = 2)]
    concurrency: usize,
    /// Directory to store temporary files to reduce memory consumption. Should not be on a tmpfs.
    #[arg(long)]
    tmp_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing().context("tracing initialization")?;

    let cli = Cli::parse();
    let server = Server::new_with_opts(
        cli.addr,
        ServerOpts {
            concurrency: cli.concurrency,
            tmp_dir: cli.tmp_dir,
        },
    );
    server.start().await
}

fn init_tracing() -> anyhow::Result<()> {
    let env_filter = EnvFilter::builder()
        .with_env_var("POLYTUNE_LOG")
        .with_default_directive("polytune_http_server=info".parse()?)
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    Ok(())
}
