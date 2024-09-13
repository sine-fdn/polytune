//! KOS OT implementation from the Swanky framework
use ocelot::ot::{self, CorrelatedReceiver, CorrelatedSender, Receiver, Sender};

use std::{
    io::{BufReader, BufWriter},
    os::unix::net::UnixStream,
};

use scuttlebutt::{AesRng, Block, Channel};

/// Transform Block to u128
pub fn block_to_u128(inp: Block) -> u128 {
    let array: [u8; 16] = inp.into();
    let mut value: u128 = 0;
    for &byte in array.iter() {
        value = (value << 8) | byte as u128;
    }
    value
}

/// Transform u128 to Block
pub fn u128_to_block(inp: u128) -> Block {
    let mut array: [u8; 16] = [0; 16];
    let mut value = inp;
    for byte in array.iter_mut().rev() {
        *byte = (value & 0xff) as u8;
        value >>= 8;
    }
    Block::from(array)
}

pub(crate) fn kos_ot_sender(sender: UnixStream, deltas: Vec<Block>) -> Vec<(Block, Block)> {
    let mut rng = AesRng::new();
    let reader = BufReader::new(sender.try_clone().unwrap());
    let writer = BufWriter::new(sender);
    let mut channel = Channel::new(reader, writer);
    let mut ot = ot::KosSender::init(&mut channel, &mut rng).unwrap();

    ot.send_correlated(&mut channel, &deltas, &mut rng).unwrap()
}

pub(crate) fn kos_ot_receiver(receiver: UnixStream, bs: Vec<bool>) -> Vec<Block> {
    let mut rng = AesRng::new();
    let reader = BufReader::new(receiver.try_clone().unwrap());
    let writer = BufWriter::new(receiver);
    let mut channel = Channel::new(reader, writer);
    let mut ot = ot::KosReceiver::init(&mut channel, &mut rng).unwrap();

    ot.receive_correlated(&mut channel, &bs, &mut rng).unwrap()
}

pub(crate) fn generate_kosots(deltas: Vec<Block>, bs: Vec<bool>) -> (Vec<(u128, u128)>, Vec<u128>) {
    let (sender, receiver) = UnixStream::pair().unwrap();

    let sender_task = std::thread::spawn(move || kos_ot_sender(sender, deltas));

    let recver_out_block = kos_ot_receiver(receiver, bs.clone());
    let sender_out_block = sender_task.join().unwrap();

    let mut recver_out: Vec<u128> = vec![];
    for i in recver_out_block.iter() {
        recver_out.push(block_to_u128(*i));
    }
    let mut sender_out: Vec<(u128, u128)> = vec![];
    for (i, j) in sender_out_block.iter() {
        sender_out.push((block_to_u128(*i), block_to_u128(*j)));
    }
    (sender_out, recver_out)
}

#[cfg(test)]
mod tests {
    use crate::faand::Error;

    use std::{os::unix::net::UnixStream, time::Instant};

    use scuttlebutt::Block;

    use crate::ot::{kos_ot_receiver, kos_ot_sender};

    #[test]
    fn test_kos() -> Result<(), Error> {
        let now = Instant::now();

        let num_ots: usize = 10000;

        let deltas: Vec<Block> = (0..num_ots).map(|_| rand::random::<Block>()).collect();
        let bs: Vec<bool> = (0..num_ots).map(|_| rand::random::<bool>()).collect();

        let (sender, receiver) = UnixStream::pair().unwrap();

        let sender_task = std::thread::spawn(move || kos_ot_sender(sender, deltas));

        let recver_out = kos_ot_receiver(receiver, bs.clone());
        let sender_out = sender_task.join().unwrap();

        for i in 0..num_ots {
            if bs[i] {
                assert_eq!(recver_out[i], sender_out[i].1);
            } else {
                assert_eq!(recver_out[i], sender_out[i].0);
            }
        }
        println!("Time: {:?}", now.elapsed());

        Ok(())
    }
}
