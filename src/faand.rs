//! F_aAND protocol from WRK17b.

use rand::random;

use crate::{
    channel::{self, Channel, MsgChannel},
    fpre::{Delta, Key, Mac},
};

/// A custom error type.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}

/// Performs F_abit.
pub async fn fabit(
    channel: impl Channel,
    p_own: usize,
    p_max: usize,
    length: usize,
) -> Result<(), Error> {
    let delta: Delta = Delta(random());

    let vec_len = length + 2 * 128;
    let mut bits: Vec<bool> = vec![];
    for _ in 0..vec_len {
        bits.push(random());
    }
    let mut channel = MsgChannel(channel);
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "bits", &bits).await?;
    }
    let mut others_vec: Vec<Vec<bool>> = vec![vec![]; p_max];
    let mut keys: Vec<Vec<Key>> = vec![vec![]; p_max];
    let mut macs: Vec<Vec<Mac>> = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        others_vec[p] = channel.recv_from(p, "bits").await?;
        for i in 0..others_vec[p].len() {
            let rand = random();
            keys[p].push(Key(rand));
            macs[p].push(Mac(rand ^ ((others_vec[p][i] as u128) * delta.0)));
        }
    }

    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "macs", &macs[p]).await?;
    }
    let mut macs_for_my_bits: Vec<Vec<Mac>> = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        macs_for_my_bits[p] = channel.recv_from(p, "macs").await?;
    }
    //let result: (Vec<bool>, Vec<Vec<Mac>>, Delta, Vec<Vec<Key>>) =
    //    (bits, macs_for_my_bits, delta, keys);
    //println!("{:?}", result);

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::{Error, SimpleChannel},
        faand::fabit,
    };

    #[tokio::test]
    async fn test_fabit() -> Result<(), Error> {
        let parties = 3;
        let length = 32;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<tokio::task::JoinHandle<Result<(), crate::faand::Error>>> = vec![];
        for i in 0..parties {
            handles.push(tokio::spawn(fabit(
                channels.pop().unwrap(),
                parties - i - 1,
                parties,
                length,
            )));
        }
        for i in handles {
            let out = i.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok(()) => {}
            }
        }
        Ok(())
    }
}
