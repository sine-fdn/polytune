use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use aide::openapi::{Info, OpenApi};
use anyhow::Context;
use axum::{Extension, routing::IntoMakeService};
use jsonwebtoken::EncodingKey;
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use tokio::{
    net::TcpListener,
    sync::{Notify, Semaphore},
};
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
    listener: Option<TcpListener>,
}

/// Configuration options for a [`Server`].
#[derive(Clone)]
pub struct ServerOpts {
    /// Maximum number of policies this party can concurrently evaluate as a leader.
    pub concurrency: usize,
    /// Temporary directory to store intermediate files during [`polytune::mpc`] evaluation.
    pub tmp_dir: Option<PathBuf>,
    /// JWT configuration for requests made to other Polytune instances..
    pub jwt_conf: Option<JwtConf>,
    /// An optional [`Cancel`] that can be used to gracefully shut down the server.
    ///
    /// If `cancel()` is called, all ongoing and scheduled policy evaluations
    /// are canceled and, if possible, an error is sent to the URL specified in the Policy `output`
    /// field.
    pub cancel: Option<Cancel>,
}

impl Default for ServerOpts {
    fn default() -> Self {
        Self {
            concurrency: 1,
            tmp_dir: None,
            jwt_conf: None,
            cancel: None,
        }
    }
}

/// JWT configuration options for a [`Server`].
#[derive(Clone)]
pub struct JwtConf {
    /// PEM encoded ECDSA key in PKCS#8 form for creating JWTs that are added to requests.
    pub key: EncodingKey,
    /// Additional claims to add to the signed JWTs encoded as json object.
    pub claims: Option<serde_json::Map<String, serde_json::Value>>,
    /// The JWT `iss` claim to use for signed JWTs
    pub iss: String,
    /// The JWT `exp` expiry in seconds from creation claim to use for signed JWTs.
    pub exp: u64,
}

/// A [`Cancel`] is used to cancel all running and scheduled [`Policies`] on a [`Server`].
///
/// [`Policies`]: polytune_server_core::Policy
#[derive(Clone, Default)]
pub struct Cancel {
    cancel_requested: Arc<Notify>,
    cancelled: Arc<Notify>,
}

impl Server {
    /// Create a new server for the provided address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            opts: ServerOpts::default(),
            listener: None,
        }
    }

    /// Create a new server for the provided address with options.
    pub fn new_with_opts(addr: SocketAddr, opts: ServerOpts) -> Self {
        Self {
            addr,
            opts,
            listener: None,
        }
    }

    /// Explicitly bind socket so provided address and return bound address.
    ///
    /// This is useful if the [`SocketAddr`] provided to [`Server::new`] had a port
    /// of `0`. The return address of this function will include the randomly chosen
    /// port by the OS.
    pub async fn bind_socket(&mut self) -> anyhow::Result<SocketAddr> {
        let listener = TcpListener::bind(&self.addr)
            .await
            .context("unable to bind to socket")?;
        let addr = listener
            .local_addr()
            .context("unable to get local addr of socket")?;
        self.listener = Some(listener);
        Ok(addr)
    }

    /// Start the server.
    pub async fn start(self) -> anyhow::Result<()> {
        info!("starting polytune server on {}", self.addr);
        let listener = match self.listener {
            Some(listener) => listener,
            None => TcpListener::bind(&self.addr)
                .await
                .context("unable to bind to socket")?,
        };
        axum::serve(listener, service(self.opts)?)
            .await
            .context("axum server error")?;
        Ok(())
    }
}

fn client(jwt_conf: Option<JwtConf>) -> anyhow::Result<HttpClientBuilder> {
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
    Ok(HttpClientBuilder { client, jwt_conf })
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
    let client_builder = client(opts.jwt_conf)?;
    let state = PolytuneState::new(PolytuneStateInner {
        client_builder,
        state_handles: Default::default(),
        concurrency: Arc::new(Semaphore::new(opts.concurrency)),
        tmp_dir: opts.tmp_dir,
    });

    if let Some(cancel) = opts.cancel {
        let state = state.clone();
        tokio::spawn(async move {
            cancel.cancel_requested.notified().await;
            state.cancel_all().await;
            cancel.cancelled.notify_one();
        });
    }

    let router = router::router(state);

    Ok(router
        .finish_api(&mut api)
        .layer(Extension(api))
        .into_make_service())
}

impl Cancel {
    /// Create a [`Cancel`] to cancel ongoing and scheduled computations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel ongoing and scheduled computations.
    ///
    /// This will return once all computations are cancelled, which potentially includes
    /// notifying the output destination specified in the policy.
    pub async fn cancel(&self) {
        self.cancel_requested.notify_one();
        self.cancelled.notified().await
    }
}
