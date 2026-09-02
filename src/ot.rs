//! KOS OT extension implementation.
use crate::ot_core::{self, CorrelatedReceiver, CorrelatedSender, Receiver, Sender};

use crate::{block::Block, channel::Channel, crypto::AesRng, mpc::faand::Error};

use rand_chacha::ChaCha20Rng;

pub(crate) async fn kos_ot_sender(
    channel: &impl Channel,
    deltas: &[Block],
    p_to: usize,
    shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<Block>, Error> {
    let mut rng = AesRng::new();
    let mut ot = ot_core::KosSender::init(channel, &mut rng, p_to, shared_rand).await?;

    let sender_out_block = ot
        .send_correlated(channel, deltas, &mut rng, p_to, shared_rand)
        .await?;
    let mut sender_out = vec![];
    for (i, _) in sender_out_block.into_iter() {
        sender_out.push(i);
    }
    Ok(sender_out)
}

pub(crate) async fn kos_ot_receiver(
    channel: &impl Channel,
    bs: &[bool],
    p_to: usize,
    shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<Block>, Error> {
    let mut rng = AesRng::new();
    let mut ot = ot_core::KosReceiver::init(channel, &mut rng, p_to, shared_rand).await?;

    let recver_out = ot
        .recv_correlated(channel, bs, &mut rng, p_to, shared_rand)
        .await?;
    Ok(recver_out)
}
