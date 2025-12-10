//! An HTTP-based Polytune server.
use std::{env, fs, net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use jsonwebtoken::EncodingKey;
use polytune_http_server::{Cancel, JwtConf, Server, ServerOpts};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

// x86_64-unknown-linux-gnu is the only tier 1 platform for tikv_jemalloc
// so we only use it on that.
// See https://github.com/tikv/jemallocator?tab=readme-ov-file#platform-support
// On that platform, we log the memory consumption at the debug level every
// second.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
#[global_allocator]
static ALLOACTOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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
    jwt_claims: Option<serde_json::Map<String, serde_json::Value>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing().context("tracing initialization")?;

    let cli = Cli::parse();
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    memory_tracking::log_memory_consumption();

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
    let cancel = Cancel::new();
    let server = Server::new_with_opts(
        cli.addr,
        ServerOpts {
            concurrency: cli.concurrency,
            tmp_dir: cli.tmp_dir,
            jwt_conf,
            cancel: Some(cancel.clone()),
        },
    );
    let jh = tokio::spawn(server.start());
    #[cfg(unix)]
    {
        tokio::select! {
            res = jh => {
                return res.context("unable to join server future")?
            }
            _ = sigterm::handle_sigterm(cancel) => {
                return Ok(())
            }
        }
    }
    #[cfg(not(unix))]
    jh.await.context("unable to join server future")?
}

fn init_tracing() -> anyhow::Result<()> {
    let env_var = "POLYTUNE_LOG";
    let env_filter = if env::var(env_var).is_ok() {
        EnvFilter::builder().with_env_var(env_var).from_env_lossy()
    } else {
        "polytune_http_server=info,polytune-server-core=info,polytune=info".parse()?
    };

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    Ok(())
}

#[cfg(unix)]
mod sigterm {
    use std::future;

    use polytune_http_server::Cancel;
    use tokio::signal::unix::{SignalKind, signal};
    use tracing::warn;

    pub(super) async fn handle_sigterm(cancel: Cancel) {
        let mut signal = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(err) => {
                warn!(%err, "unable to install SIGTERM signal");
                // await pending future that never resolves as returning would exit server
                future::pending().await
            }
        };
        signal.recv().await;
        cancel.cancel().await;
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
mod memory_tracking {
    use std::{ops::ControlFlow, time::Duration};

    use tikv_jemalloc_ctl::{
        epoch,
        stats::{self, active_mib, allocated_mib, resident_mib},
    };
    use tracing::{debug, warn};

    // Small extension trait for tikv_jemalloc_ctl::Result to reduce boilerplate
    // from logging allocation stats errors
    trait JemallocCtrlErrorCtx<T> {
        fn log_warning(self, context: &str) -> ControlFlow<(), T>;
    }

    impl<T> JemallocCtrlErrorCtx<T> for tikv_jemalloc_ctl::Result<T> {
        fn log_warning(self, context: &str) -> ControlFlow<(), T> {
            match self {
                Ok(val) => ControlFlow::Continue(val),
                Err(err) => {
                    warn!(%err, context);
                    ControlFlow::Break(())
                }
            }
        }
    }

    pub(super) fn log_memory_consumption() {
        tokio::spawn(async {
            let ControlFlow::Continue(mibs) = log_memory_init() else {
                return;
            };
            loop {
                // We ignore intermittent errors in memory reporting
                let _ = log_memory_loop_body(mibs);
                tokio::time::sleep(Duration::from_secs(1)).await
            }
        });
    }

    fn log_memory_init() -> ControlFlow<(), (allocated_mib, active_mib, resident_mib)> {
        let allocated = stats::allocated::mib().log_warning("unable to get allocated MiB")?;
        let active = stats::active::mib().log_warning("unable to get active MiB")?;
        let resident = stats::resident::mib().log_warning("unable to get resident MiB")?;
        ControlFlow::Continue((allocated, active, resident))
    }

    fn log_memory_loop_body(
        (allocated, active, resident): (allocated_mib, active_mib, resident_mib),
    ) -> ControlFlow<()> {
        epoch::advance().log_warning("unable to advance jemalloc epoch")?;

        // Number of actually allocated bytes.
        let allocated = allocated
            .read()
            .log_warning("unable to get allocated value")?;
        // Number of bytes in active pages.
        let active = active.read().log_warning("unable to get active value")?;
        // Number of bytes of data pages mapped by the allocator.
        let resident = resident
            .read()
            .log_warning("unable to get resident value")?;
        // Calculates memory overhead percentage. This can give an indication of memory fragmentation if
        // the percentage is high.
        let overhead = resident as f64 / allocated as f64 - 1.0;
        debug!(
            allocated = scale_memory(allocated),
            active = scale_memory(active),
            resident = scale_memory(resident),
            overhead,
            "current memory consumption"
        );
        ControlFlow::Continue(())
    }

    fn scale_memory(bytes: usize) -> String {
        let bytes = bytes as f64;
        let (denom, unit) = if bytes < 1_000.0 {
            (1.0, "B")
        } else if bytes < 1_000.0_f64.powi(2) {
            (1_000.0, "KB")
        } else if bytes < 1_000.0_f64.powi(3) {
            (1_000.0_f64.powi(2), "MB")
        } else {
            (1_000.0_f64.powi(3), "GB")
        };
        let scaled = bytes / denom;
        format!("{scaled} {unit}")
    }
}
