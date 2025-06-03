use criterion::Criterion;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

mod join;
mod mpc;
mod primitives;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let mut c = Criterion::default()
        .significance_level(0.1)
        .sample_size(10)
        .configure_from_args();

    join::join_benchmark(&mut c);
    primitives::primitives_benchmark(&mut c);
    mpc::mpc_benchmarks(&mut c);

    c.final_summary();
}
