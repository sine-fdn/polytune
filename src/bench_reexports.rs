//! Reexports of private internals for benchmarking - DO NOT USE!
//!
//! This module requires the internal `__bench` feature to be enabled.
//! We use it to reexport some otherwise private functions as public,
//! in order to benchmark them with criterion. Criterion can currently
//! only benchmark public functions, as it is used from a `benches/` file
//! which are compiled as separate crates.
//!
//! If you're a user of polytune, do not enable the `__bench` feature or use
//! these APIs exposed here.
use crate::block::Block;
use rand_chacha::ChaCha20Rng;

use crate::{channel::Channel, faand::Error, ot};

pub async fn kos_ot_sender(
    channel: &mut impl Channel,
    deltas: &[Block],
    p_to: usize,
    shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<u128>, Error> {
    ot::kos_ot_sender(channel, deltas, p_to, shared_rand).await
}

pub async fn kos_ot_receiver(
    channel: &mut impl Channel,
    bs: &[bool],
    p_to: usize,
    shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<u128>, Error> {
    ot::kos_ot_receiver(channel, bs, p_to, shared_rand).await
}
