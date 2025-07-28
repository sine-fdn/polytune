use criterion::measurement::{Measurement, ValueFormatter};
use polytune_test_utils::peak_alloc::{MAX_PARTIES, scale_memory};

use crate::ALLOCATOR;

/// Criterion [`Measurement`] to use with [`polytune_test_utils::peak_alloc::PeakAllocator`]
/// and [`polytune_test_utils::peak_alloc::create_instrumented_runtime`].
#[derive(Copy, Clone, Debug)]
pub struct MemoryMeasurement {
    party: usize,
}

impl MemoryMeasurement {
    pub fn new(party: usize) -> Self {
        assert!(party < MAX_PARTIES, "Only {MAX_PARTIES} are supported.");
        Self { party }
    }
}

impl Measurement for MemoryMeasurement {
    type Intermediate = usize;

    type Value = usize;

    fn start(&self) -> Self::Intermediate {
        ALLOCATOR.reset();
        ALLOCATOR.enable();
        ALLOCATOR.peak(self.party)
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        ALLOCATOR.disable();
        ALLOCATOR.peak(self.party) - i
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1 + v2
    }

    fn zero(&self) -> Self::Value {
        0
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value as f64
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        &MemoryFormatter
    }
}

pub struct MemoryFormatter;

// Implementation based on `DurationFormatter` in criterion.
impl ValueFormatter for MemoryFormatter {
    fn scale_values(&self, typical_value: f64, values: &mut [f64]) -> &'static str {
        let (denom, unit) = scale_memory(typical_value);

        for val in values.iter_mut() {
            *val /= denom;
        }

        unit
    }

    fn scale_throughputs(
        &self,
        _typical_value: f64,
        _throughput: &criterion::Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        unimplemented!("Throughput makes no sense for peak memory")
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        // Don't scale
        " B"
    }
}
