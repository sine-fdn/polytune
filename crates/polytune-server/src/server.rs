use std::{net::SocketAddr, sync::Arc, time::Duration};

use aide::openapi::{Info, OpenApi};
use axum::{Extension, routing::IntoMakeService};
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use tracing::info;

use crate::{
    mpc::MpcRunner,
    router,
    state::{PolytuneState, PolytuneStateInner},
};

pub struct Server {}

pub enum ServerError {}

impl Server {
    pub async fn start(addr: SocketAddr) -> Result<(), ServerError> {
        info!("listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, service()).await.unwrap();
        Ok(())
    }
}

fn client() -> ClientWithMiddleware {
    #[allow(unused_mut)]
    let mut builder = reqwest::ClientBuilder::new();

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    {
        builder = builder.tcp_user_timeout(Duration::from_secs(10 * 60));
    }

    let reqwest_client = builder.build().unwrap();

    let retry_policy =
        ExponentialBackoff::builder().build_with_total_retry_duration(Duration::from_secs(10 * 60));
    let client_builder = reqwest_middleware::ClientBuilder::new(reqwest_client)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy));
    client_builder.build()
}

fn service() -> IntoMakeService<axum::Router> {
    let mut api = OpenApi {
        info: Info {
            title: "Polytune API Deployment".to_string(),
            description: Some(
                "An example Polytune deployment which provides an API to start MPC computations."
                    .to_string(),
            ),
            version: "0.1.0".to_string(),
            ..Info::default()
        },
        ..OpenApi::default()
    };
    let client = client();
    let (state, schedule_receiver) = PolytuneState::new(2, client.clone());
    let mpc_runner = MpcRunner::new(client, schedule_receiver, 2);
    tokio::spawn(mpc_runner.start());

    let router = router::router(state);

    router
        .finish_api(&mut api)
        .layer(Extension(api))
        .into_make_service()
}
