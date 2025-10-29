use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use aide::openapi::{Info, OpenApi};
use anyhow::Context;
use axum::{Extension, routing::IntoMakeService};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use tokio::sync::Semaphore;
use tracing::info;

use crate::{
    api::{PolytuneState, PolytuneStateInner},
    policy_client::HttpClientBuilder,
    router,
};

/// An HTTP-based Polytune server.
pub struct Server {
    addr: SocketAddr,
    opts: ServerOpts,
}

/// Configuration options for a [`Server`].
#[derive(Default)]
pub struct ServerOpts {
    /// Maximum number of policies this party can concurrently evaluate as a leader.
    pub concurrency: usize,
    /// Temporary directory to store intermediate files during [`polytune::mpc`] evaluation.
    pub tmp_dir: Option<PathBuf>,
}

impl Server {
    /// Create a new server for the provided address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            opts: ServerOpts::default(),
        }
    }

    /// Create a new server for the provided address with options.
    pub fn new_with_opts(addr: SocketAddr, opts: ServerOpts) -> Self {
        Self { addr, opts }
    }

    /// Start the server.
    pub async fn start(self) -> anyhow::Result<()> {
        info!("starting polytune server on {}", self.addr);
        let listener = tokio::net::TcpListener::bind(&self.addr)
            .await
            .context("unable to bind to socket")?;
        axum::serve(listener, service(self.opts)?)
            .await
            .context("axum server error")?;
        Ok(())
    }
}

fn client() -> anyhow::Result<HttpClientBuilder> {
    #[allow(unused_mut)]
    let mut builder = reqwest::ClientBuilder::new();

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        builder = builder.tcp_user_timeout(Duration::from_secs(10 * 60));
    }

    let reqwest_client = builder.build().context("unable to build HTTP client")?;

    let retry_policy =
        ExponentialBackoff::builder().build_with_total_retry_duration(Duration::from_secs(10 * 60));
    let client_builder = reqwest_middleware::ClientBuilder::new(reqwest_client)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy));
    let client = client_builder.build();
    Ok(HttpClientBuilder { client })
}

fn service(opts: ServerOpts) -> anyhow::Result<IntoMakeService<axum::Router>> {
    let mut api = OpenApi {
        info: Info {
            title: "Polytune HTTP Server".to_string(),
            description: Some(
                "An HTTP server exposing Polytune. The service can be used to schedule 
                policies which contain computation parties, inputs, output destination, etc. 
                which is needed to evaluation an MPC program. "
                    .to_string(),
            ),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Info::default()
        },
        ..OpenApi::default()
    };
    let client_builder = client()?;
    let state = PolytuneState::new(PolytuneStateInner {
        client_builder,
        state_handles: Default::default(),
        concurrency: Arc::new(Semaphore::new(opts.concurrency)),
        tmp_dir: opts.tmp_dir,
    });

    let router = router::router(state);

    Ok(router
        .finish_api(&mut api)
        .layer(Extension(api))
        .into_make_service())
}
