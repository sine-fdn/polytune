//! KOS OT extension implementation.
use crate::swankyot::{self, CorrelatedReceiver, CorrelatedSender, Error, Receiver, Sender};

use crate::channel::Channel;

use maybe_async::maybe_async;
use rand_chacha::ChaCha20Rng;
use scuttlebutt::{AesRng, Block};

/// Transform Block to u128
pub(crate) fn block_to_u128(inp: Block) -> u128 {
    let array: [u8; 16] = inp.into();
    let mut value = 0;
    for &byte in array.iter() {
        value = (value << 8) | byte as u128;
    }
    value
}

#[maybe_async(AFIT)]
#[hax_lib::opaque]
pub(crate) async fn kos_ot_sender(
    channel: &mut impl Channel,
    delta: u128,
    lprime: usize,
    p_to: usize,
    shared_rand: &ChaCha20Rng,
) -> Result<(Vec<u128>, ChaCha20Rng), Error> {
    let deltas = vec![Block::from(delta.to_be_bytes()); lprime];

    let mut rng = AesRng::new();
    let mut rand = shared_rand.clone();
    let mut ot = swankyot::KosSender::init(channel, &mut rng, p_to, &mut rand).await?;

    let sender_out_block = ot
        .send_correlated(channel, &deltas, &mut rng, p_to, &mut rand)
        .await?;
    let mut sender_out = vec![];
    for (i, _) in sender_out_block.iter() {
        sender_out.push(block_to_u128(*i));
    }
    Ok((sender_out, rand))
}

#[maybe_async(AFIT)]
#[hax_lib::opaque]
pub(crate) async fn kos_ot_receiver(
    channel: &mut impl Channel,
    bs: &[bool],
    p_to: usize,
    shared_rand: &ChaCha20Rng,
) -> Result<(Vec<u128>, ChaCha20Rng), Error> {
    let mut rng = AesRng::new();
    let mut rand = shared_rand.clone();
    let mut ot = swankyot::KosReceiver::init(channel, &mut rng, p_to, &mut rand).await?;

    let recver_out_block = ot
        .recv_correlated(channel, bs, &mut rng, p_to, &mut rand)
        .await?;
    let mut recver_out = vec![];
    //let rand = shared_rand.clone();
    for i in recver_out_block.iter() {
        recver_out.push(block_to_u128(*i));
    }
    Ok((recver_out, rand))
}
