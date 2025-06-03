use criterion::Criterion;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

use crate::memory_tracking::PeakAllocator;

mod join;
mod memory_tracking;
mod mpc;
mod primitives;

#[global_allocator]
// The PeakAllocator is by default disabled and only has
// one atomic bool load overhead over the normal System
// allocator. This does not impact the other benchmarks.
static ALLOCATOR: PeakAllocator = PeakAllocator::new();

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    // This is the expanded form of the criterion macros. I find this much clearer.
    let mut c = Criterion::default()
        .significance_level(0.1)
        .sample_size(10)
        .configure_from_args();

    join::join_benchmark(&mut c);
    primitives::primitives_benchmark(&mut c);
    mpc::mpc_benchmarks(&mut c);

    c.final_summary();
}
