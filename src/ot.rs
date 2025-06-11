//! KOS OT extension implementation.
use crate::swankyot::{self, CorrelatedReceiver, CorrelatedSender, Receiver, Sender};

use crate::{channel::Channel, faand::Error};

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

pub(crate) async fn kos_ot_sender(
    channel: &mut impl Channel,
    deltas: &[Block],
    p_to: usize,
    shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<u128>, Error> {
    let mut rng = AesRng::new();
    let mut ot = swankyot::KosSender::init(channel, &mut rng, p_to, shared_rand).await?;

    let sender_out_block = ot
        .send_correlated(channel, deltas, &mut rng, p_to, shared_rand)
        .await?;
    let mut sender_out = vec![];
    for (i, _) in sender_out_block.iter() {
        sender_out.push(block_to_u128(*i));
    }
    Ok(sender_out)
}

pub(crate) async fn kos_ot_receiver(
    channel: &mut impl Channel,
    bs: &[bool],
    p_to: usize,
    shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<u128>, Error> {
    let mut rng = AesRng::new();
    let mut ot = swankyot::KosReceiver::init(channel, &mut rng, p_to, shared_rand).await?;

    let recver_out_block = ot
        .recv_correlated(channel, bs, &mut rng, p_to, shared_rand)
        .await?;
    let mut recver_out = vec![];
    for i in recver_out_block.iter() {
        recver_out.push(block_to_u128(*i));
    }
    Ok(recver_out)
}
