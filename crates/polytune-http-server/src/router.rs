use aide::{
    axum::{
        ApiRouter,
        routing::{get, get_with, post_with},
    },
    swagger::Swagger,
};
use axum::extract::DefaultBodyLimit;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer, classify::StatusInRangeAsFailures, trace::TraceLayer,
};

use crate::{api, api::PolytuneState};

pub(crate) fn router(state: PolytuneState) -> ApiRouter {
    // 400..=599 status response codes will be logged as errors
    let classifier = StatusInRangeAsFailures::new(400..=599).into_make_classifier();
    let log_layer = TraceLayer::new(classifier);
    ApiRouter::new()
        // to start an MPC session as a leader:
        .api_route("/schedule", post_with(api::schedule, api::schedule_docs))
        .api_route("/health", get_with(api::health, api::health_docs))
        .route("/validate", axum::routing::post(api::validate))
        // to kick off an MPC session:
        .route("/run", axum::routing::post(api::run))
        // to receive constants from other parties:
        .route("/consts", axum::routing::post(api::consts))
        // to receive MPC messages during the execution of the core protocol:
        .route(
            "/msg/{computation_id}/{from}",
            axum::routing::post(api::msg),
        )
        .route("/swagger", Swagger::new("/api.json").axum_route())
        .route("/api.json", get(api::serve_open_api))
        .with_state(state)
        // panics will result in 500 status code responses instead of bringing down the server
        .layer(CatchPanicLayer::new())
        .layer(DefaultBodyLimit::disable())
        .layer(ServiceBuilder::new().layer(log_layer))
}
