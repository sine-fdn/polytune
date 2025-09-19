use aide::{
    axum::{
        ApiRouter,
        routing::{get, post, post_with},
    },
    openapi::{Info, OpenApi},
    swagger::Swagger,
};
use anyhow::Error;
use axum::{
    Extension,
    extract::DefaultBodyLimit,
    http::{Request, Response},
};
use clap::Parser;
use polytune_test_utils::peak_alloc::{PeakAllocator, create_instrumented_runtime, scale_memory};
use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    result::Result,
    str::FromStr,
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::sync::{Mutex, Notify};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{Span, error, info};

use crate::{
    api::{MpcComms, consts, launch, launch_docs, msg, ping, run, serve_api, sync},
    cli::Cli,
};

mod api;
mod channel;
mod cli;
mod mpc;
mod policy;

#[global_allocator]
pub static ALLOCATOR: PeakAllocator = PeakAllocator::new();

fn main() -> Result<(), Error> {
    // because we actually run this example as two processes, we can just use 0 for both
    let rt = create_instrumented_runtime(0);
    thread::spawn(|| {
        loop {
            let memory_peak = ALLOCATOR.peak(0) as f64;
            let (denom, unit) = scale_memory(memory_peak);
            info!(
                "Current peak memory consumption: {} {}",
                memory_peak / denom,
                unit
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    });
    rt.block_on(async_main())
}

async fn async_main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let Cli { addr, port } = Cli::parse();
    let sync_received = Arc::new(Notify::new());
    let sync_requested = Arc::new(Notify::new());

    let state = Arc::new(Mutex::new(MpcComms {
        policy: None,
        consts: HashMap::new(),
        senders: vec![],
        sync_received,
        sync_requested,
    }));

    let log_layer = TraceLayer::new_for_http()
        .on_request(|r: &Request<_>, _: &Span| tracing::info!("{} {}", r.method(), r.uri().path()))
        .on_response(
            |r: &Response<_>, latency: Duration, _: &Span| match r.status().as_u16() {
                400..=499 => tracing::warn!("{} (in {:?})", r.status(), latency),
                500..=599 => tracing::error!("{} (in {:?})", r.status(), latency),
                _ => tracing::info!("{} (in {:?})", r.status(), latency),
            },
        );

    let app = ApiRouter::new()
        // to check whether a server is running:
        .route("/ping", get(ping))
        .route("/sync", axum::routing::post(sync))
        // to start an MPC session as a leader:
        .api_route("/launch", post_with(launch, launch_docs))
        // to kick off an MPC session:
        .route("/run", post(run))
        // to receive constants from other parties:
        .route("/consts/{from}", axum::routing::post(consts))
        // to receive MPC messages during the execution of the core protocol:
        .route("/msg/{from}", post(msg))
        .route("/swagger", Swagger::new("/api.json").axum_route())
        .route("/api.json", get(serve_api))
        .with_state(Arc::clone(&state))
        .layer(DefaultBodyLimit::disable())
        .layer(ServiceBuilder::new().layer(log_layer));

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

    let addr = if let Ok(socket_addr) = env::var("SOCKET_ADDRESS") {
        SocketAddr::from_str(&socket_addr)
            .unwrap_or_else(|_| panic!("Invalid socket address: {socket_addr}"))
    } else {
        let addr = addr.unwrap_or_else(|| "127.0.0.1".into());
        let port = port.unwrap_or(8000);
        match addr.parse::<IpAddr>() {
            Ok(addr) => SocketAddr::new(addr, port),
            Err(_) => {
                error!("Invalid IP address: {addr}, using 127.0.0.1 instead");
                SocketAddr::from(([127, 0, 0, 1], port))
            }
        }
    };
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.finish_api(&mut api)
            .layer(Extension(api))
            .into_make_service(),
    )
    .await?;
    Ok(())
}
