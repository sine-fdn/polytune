//! Implementation of a simple two-party coin tossing protocol using a PRG as a
//! commitment.
//!
//! On input `seed`, the sender computes `r := PRG(seed)` and sends `r` to the
//! receiver. It then receives `seed_` from the receiver and outputs `seed ⊕
//! seed_`. Likewise, on input `seed`, the receiver gets `r`, sends `seed` to
//! the sender, and then receives `seed_`, checking that `PRG(seed_) = r`.

use crate::{
    channel::{recv_from, send_to, Channel},
    faand::Error,
};

use rand::{RngCore, SeedableRng};
use scuttlebutt::{AesRng, Block};

/// Coin tossing sender.
#[inline]
pub async fn send<C: Channel>(
    channel: &mut C,
    seeds: &[Block],
    p_to: usize,
) -> Result<Vec<Block>, Error> {
    let mut out = Vec::with_capacity(seeds.len());
    for seed in seeds.iter() {
        let mut rng = AesRng::from_seed(*seed);
        let mut com = Block::default();
        rng.fill_bytes(com.as_mut());
        send_to(channel, p_to, "com", &[com]).await?;
    }
    for seed in seeds.iter() {
        let seed_: Block = recv_from(channel, p_to, "seed_")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        out.push(*seed ^ seed_);
    }
    for seed in seeds.iter() {
        send_to(channel, p_to, "seed", &[seed]).await?;
    }
    Ok(out)
}

/// Coin tossing receiver.
#[inline]
pub async fn receive<C: Channel>(
    channel: &mut C,
    seeds: &[Block],
    p_to: usize,
) -> Result<Vec<Block>, Error> {
    let mut coms = Vec::with_capacity(seeds.len());
    let mut out = Vec::with_capacity(seeds.len());
    for _ in 0..seeds.len() {
        let com: Block = recv_from(channel, p_to, "com")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        coms.push(com);
    }
    for seed in seeds.iter() {
        send_to(channel, p_to, "seed_", &[seed]).await?;
    }
    for (seed, com) in seeds.iter().zip(coms.into_iter()) {
        let seed_: Block = recv_from(channel, p_to, "seed")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        let mut rng_ = AesRng::from_seed(seed_);
        let mut check = Block::default();
        rng_.fill_bytes(check.as_mut());
        if check != com {
            return Err(Error::ConsistencyCheckFailed);
        }
        out.push(*seed ^ seed_)
    }
    Ok(out)
}
