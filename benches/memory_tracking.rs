use std::{
    alloc::{GlobalAlloc, System},
    cell::Cell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use criterion::measurement::{Measurement, ValueFormatter};
use tokio::runtime::Runtime;

use crate::ALLOCATOR;

/// Maximum number of parties the [`PeakAllocator`] can track.
pub const MAX_PARTIES: usize = 16;

thread_local! {
    /// The current id of the party executing on this thread.
    ///
    /// This is set by [`create_instrumented_runtime`] and used by the [`PeakAllocator`].
    static PARTY_IDX: Cell<usize> = const { Cell::new(MAX_PARTIES) };
}

/// A [`GlobalAlloc`] that tracks the peak memory allocation of multiple parties.
///
/// For this to work, the futures executed by the parties need to be executed on
/// a Criterion [`Runtime`] created by [`create_instrumented_runtime`]. The instrumented
/// Runtime can be used in combination with the criterion [`MemoryMeasurement`].
pub struct PeakAllocator {
    enabled: AtomicBool,
    // we allocate + 1 slot for allocations not associated with a party (id == MAX_PARTIES)
    current: [AtomicUsize; MAX_PARTIES + 1],
    peak: [AtomicUsize; MAX_PARTIES + 1],
}

impl PeakAllocator {
    /// Returns a new disabled [`PeakAllocator`].
    pub const fn new() -> Self {
        PeakAllocator {
            enabled: AtomicBool::new(false),
            current: [const { AtomicUsize::new(0) }; MAX_PARTIES + 1],
            peak: [const { AtomicUsize::new(0) }; MAX_PARTIES + 1],
        }
    }

    /// Enable the peak memory tracking.
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// Disable the peak memory tracking.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    /// Whether the peak memory tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Resets the current and peak memory allocation trackers.
    pub fn reset(&self) {
        for val in &self.current {
            val.store(0, Ordering::Relaxed);
        }
        for val in &self.peak {
            val.store(0, Ordering::Relaxed);
        }
    }

    /// Get the peak memory consumption for `party`.
    pub fn peak(&self, party: usize) -> usize {
        self.peak[party].load(Ordering::Relaxed)
    }
}

/// Delegate allocations to the [`System`] allocator while tracking peak allocation for each party.
unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        // Safety: We forward the layout to the system allocator. The requirements are guaranteed by our caller.
        let ret = unsafe { System.alloc(layout) };
        if !ret.is_null() && self.is_enabled() {
            let party_idx = PARTY_IDX.get();
            let prev = self.current[party_idx].fetch_add(layout.size(), Ordering::Relaxed);
            self.peak[party_idx].fetch_max(prev + layout.size(), Ordering::Relaxed);
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // Safety: We simply forward ptr and layout to the System allocator
        unsafe {
            System.dealloc(ptr, layout);
        }
        if self.is_enabled() {
            let party_idx = PARTY_IDX.get();

            self.current[party_idx]
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                    Some(val.saturating_sub(layout.size()))
                })
                .expect("unreachable because we don't return None");
        }
    }
}

/// Create a tokio [`Runtime`] set up for memory tracking with the [`PeakAllocator`].
pub fn create_instrumented_runtime(party_idx: usize) -> Runtime {
    assert!(
        party_idx < MAX_PARTIES,
        "party_idx must be less than MAX_PARTIES: {MAX_PARTIES}"
    );
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .on_thread_start(move || {
            PARTY_IDX.set(party_idx);
        })
        .build()
        .expect("runtime create")
}

/// Criterion [`Measurement`] to use with [`PeakAllocator`] and [`create_instrumented_runtime`].
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
        let (denom, unit) = if typical_value < 1_000.0 {
            (1.0, " B")
        } else if typical_value < 1_000.0_f64.powi(2) {
            (1_000.0, " KB")
        } else if typical_value < 1_000.0_f64.powi(3) {
            (1_000.0_f64.powi(2), " MB")
        } else {
            (1_000.0_f64.powi(3), " GB")
        };

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
