use std::{sync::Arc, time::Duration};

use aide::{
    axum::{
        ApiRouter,
        routing::{get, post, post_with},
    },
    swagger::Swagger,
};
use axum::{
    extract::DefaultBodyLimit,
    http::{Request, Response},
};
use tower::ServiceBuilder;
use tower_http::{catch_panic::CatchPanicLayer, trace::TraceLayer};
use tracing::Span;

use crate::{api, api::PolytuneState};

pub(crate) fn router(state: PolytuneState) -> ApiRouter {
    let log_layer = TraceLayer::new_for_http();
    // .on_request(|r: &Request<_>, _: &Span| tracing::info!("{} {}", r.method(), r.uri().path()))
    // .on_response(
    //     |r: &Response<_>, latency: Duration, _: &Span| match r.status().as_u16() {
    //         400..=499 => tracing::warn!("{} (in {:?})",  r.status(), latency),
    //         500..=599 => tracing::error!("{} (in {:?})", r.status(), latency),
    //         _ => tracing::info!("{} (in {:?})", r.status(), latency),
    //     },
    // );

    ApiRouter::new()
        // to start an MPC session as a leader:
        .api_route("/schedule", post_with(api::schedule, api::schedule_docs))
        .route("/validate", axum::routing::post(api::validate))
        // to kick off an MPC session:
        .route("/run", axum::routing::post(api::run))
        // to receive constants from other parties:
        .route(
            "/consts/{computation_id}/{from}",
            axum::routing::post(api::consts),
        )
        // to receive MPC messages during the execution of the core protocol:
        .route(
            "/msg/{computation_id}/{from}",
            axum::routing::post(api::msg),
        )
        .route("/swagger", Swagger::new("/api.json").axum_route())
        .route("/api.json", get(api::serve_open_api))
        .with_state(state)
        .layer(CatchPanicLayer::new())
        .layer(DefaultBodyLimit::disable())
        .layer(ServiceBuilder::new().layer(log_layer))
}
