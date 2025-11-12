//! An HTTP-based Polytune server.
use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use jsonwebtoken::EncodingKey;
use polytune_http_server::{JwtConf, Server, ServerOpts};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

/// A HTTP-based server for the Polytune secure multi-party computation engine.
///
/// Logging can be controlled with an EnvFilter via the `POLYTUNE_LOG` environment
/// variable.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The socket address to bind the server to
    #[arg(long, short, default_value = "0.0.0.0:8000", env = "POLYTUNE_ADDR")]
    addr: SocketAddr,
    /// Number of concurrent policy evaluations this party can be the leader of
    ///
    /// This limits how many policy evaluations this instance can be the the leader of at
    /// the same time. It does not limit the total number of concurrent evaluations.
    #[arg(long, default_value_t = 2, env = "POLYTUNE_CONCURRENCY")]
    concurrency: usize,
    /// Directory to store temporary files to reduce memory consumption. Should not be on a tmpfs
    ///
    /// Polytune will create temporary files in this directory to store intermediate values.
    /// This reduces the peak memory consumption significantly. Make sure that the directory is
    /// not on a tmpfs filesystem (as /tmp usually is), as these files will be stored in memory,
    /// negating the memory benefit.
    #[arg(long, env = "POLYTUNE_TMP_DIR")]
    tmp_dir: Option<PathBuf>,
    /// Path to PEM file with an ECDSA key in PKCS#8 form for creating JWTs that are added to requests
    ///
    /// Note that these JWTs are intended to be checked by a proxy between the Polytune instances.
    /// Polytune does not itself verify the JWTs of requests it receives.
    #[arg(long, env = "POLYTUNE_JWT_KEY")]
    jwt_key: Option<PathBuf>,
    /// The JWT `iss` claim to use for signed JWTs
    #[arg(long, default_value = "polytune", env = "POLYTUNE_JWT_ISS")]
    jwt_iss: String,
    /// The JWT `exp` expiry in seconds from creation claim to use for signed JWTs.
    #[arg(long, default_value_t = 300, env = "POLYTUNE_JWT_EXP")]
    jwt_exp: u64,
    /// Additional claims to add to the signed JWTs. Needs to be a json object
    ///
    /// If this is set, --jwt-key is required.
    ///
    /// Examples:
    ///
    /// POLYTUNE_JWT_CLAIMS='{"roles": ["TEST_ROLE"]}' polytune-http-server
    #[arg(long, requires = "jwt_key", env = "POLYTUNE_JWT_CLAIMS")]
    jwt_claims: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing().context("tracing initialization")?;

    let cli = Cli::parse();
    let jwt_conf = match cli.jwt_key {
        Some(path) => {
            let key = fs::read(path).context("unable to read JWT key file")?;
            let key = EncodingKey::from_ec_pem(&key)
                .context("JWT key is not a valid ECDSA PEM PKCS#8 key")?;
            Some(JwtConf {
                key,
                claims: cli.jwt_claims,
                iss: cli.jwt_iss,
                exp: cli.jwt_exp,
            })
        }
        None => None,
    };
    let server = Server::new_with_opts(
        cli.addr,
        ServerOpts {
            concurrency: cli.concurrency,
            tmp_dir: cli.tmp_dir,
            jwt_conf,
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
