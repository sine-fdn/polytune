//! KOS OT extension implementation.
use crate::swankyot::{self, CorrelatedReceiver, CorrelatedSender, Receiver, Sender};

use crate::{channel::Channel, faand::Error};

use scuttlebutt::{AesRng, Block};

/// Transform Block to u128
pub fn block_to_u128(inp: Block) -> u128 {
    let array: [u8; 16] = inp.into();
    let mut value = 0;
    for &byte in array.iter() {
        value = (value << 8) | byte as u128;
    }
    value
}

/// Transform u128 to Block
pub fn u128_to_block(inp: u128) -> Block {
    let mut array = [0; 16];
    let mut value = inp;
    for byte in array.iter_mut().rev() {
        *byte = (value & 0xff) as u8;
        value >>= 8;
    }
    Block::from(array)
}

pub(crate) async fn kos_ot_sender(
    channel: &mut impl Channel,
    deltas: Vec<Block>,
    p_own: usize,
    p_to: usize,
) -> Result<Vec<(u128, u128)>, Error> {
    let mut rng = AesRng::new();
    let mut ot = swankyot::KosSender::init(channel, &mut rng, p_own, p_to).await?;

    let sender_out_block = ot
        .send_correlated(channel, &deltas, &mut rng, p_own, p_to)
        .await?;
    let mut sender_out = vec![];
    for (i, j) in sender_out_block.iter() {
        sender_out.push((block_to_u128(*i), block_to_u128(*j)));
    }
    Ok(sender_out)
}

pub(crate) async fn kos_ot_receiver(
    channel: &mut impl Channel,
    bs: Vec<bool>,
    p_own: usize,
    p_to: usize,
) -> Result<Vec<u128>, Error> {
    let mut rng = AesRng::new();
    let mut ot = swankyot::KosReceiver::init(channel, &mut rng, p_own, p_to).await?;

    let recver_out_block = ot
        .recv_correlated(channel, &bs, &mut rng, p_own, p_to)
        .await?;
    let mut recver_out = vec![];
    for i in recver_out_block.iter() {
        recver_out.push(block_to_u128(*i));
    }
    Ok(recver_out)
}
