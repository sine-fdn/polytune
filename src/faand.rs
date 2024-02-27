//! F_aAND protocol from WRK17b.

use rand::random;

use crate::{
    channel::{self, Channel, MsgChannel},
    fpre::Delta,
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
pub(crate) async fn fabit(
    channel: &mut MsgChannel<impl Channel>,
    p_to: usize,
    delta: Delta,
    xbits: &Vec<bool>,
    role: bool,
) -> Result<Vec<u128>, Error> {
    match role {
        true => {
            channel.send_to(p_to, "bits", &xbits).await?;
            let macs: Vec<u128> = channel.recv_from(p_to, "macs").await?;
            Ok(macs)
        }
        false => {
            let mut keys: Vec<u128> = vec![];
            let mut macs: Vec<u128> = vec![];
            let other_xbits: Vec<bool> = channel.recv_from(p_to, "bits").await?;
            for bit in other_xbits {
                let rand: u128 = random();
                keys.push(rand);
                macs.push(rand ^ ((bit as u128) * delta.0));
            }
            channel.send_to(p_to, "macs", &macs).await?;
            Ok(keys)
        }
    }
}

/// Performs F_aAND.
pub async fn faand(
    channel: impl Channel,
    p_own: usize,
    p_max: usize,
    length: usize,
) -> Result<(), Error> {
    let delta: Delta = Delta(random());
    let mut channel = MsgChannel(channel);

    let lenshare = length + 128;

    // Protocol Pi_aBit^n
    // Step 1 initialize random bitstring
    let vec_len = lenshare + 2 * 128;
    let mut bits: Vec<bool> = (0..vec_len).map(|_| random()).collect();

    // Steps 2 running Pi_aBit^2 for each pair of parties
    let mut keys: Vec<Vec<u128>> = vec![vec![]; p_max];
    let mut macs: Vec<Vec<u128>> = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        let macvec: Vec<u128>;
        let keyvec: Vec<u128>;
        if p_own < p {
            macvec = fabit(&mut channel, p, delta, &bits, true).await?;
            keyvec = fabit(&mut channel, p, delta, &bits, false).await?;
        } else {
            keyvec = fabit(&mut channel, p, delta, &bits, false).await?;
            macvec = fabit(&mut channel, p, delta, &bits, true).await?;
        }
        macs[p] = macvec;
        keys[p] = keyvec;
    }
    //println!("{:?}\n{:?}\n{:?}\n{:?}", bits, macs, keys, delta);

    // Steps 3 including verification of macs and keys
    // TODO FIX THE CHECK HERE, ALSO FIGURE OUT HOW Pk calculates with same rm as Pi in the check
    // PERFORM 2SIGMA TIMES

    let randbits: Vec<bool> = (0..vec_len).map(|_| random()).collect();
    let mut xj = false;
    for (&xb, &rb) in bits.iter().zip(&randbits) {
        xj ^= xb & rb;
        //broadcast xj TODO
    }

    for p in (0..p_max).filter(|p| *p != p_own) {
        let mut macint: u128 = 0;
        let mut keyint: u128 = 0;
        for (i, rbit) in randbits.iter().enumerate().take(vec_len) {
            if *rbit {
                macint ^= macs[p][i];
            }
        }
        channel
            .send_to(p, "mac", &(macint, randbits.clone()))
            .await?;
        let (macp, randbitsp): (u128, Vec<bool>) = channel.recv_from(p, "mac").await?;

        for (i, rbit) in randbitsp.iter().enumerate().take(vec_len) {
            if *rbit {
                keyint ^= keys[p][i];
            }
        }
        if macp != keyint ^ delta.0 && macp != keyint && macp != keyint ^ ((xj as u128) * delta.0) {
            println!(
                "Problem\n {:?}\n {:?}\n {:?}!",
                macp,
                keyint ^ delta.0,
                keyint
            );
        }
    }

    // Step 4 return first l objects
    bits.truncate(lenshare);
    for p in (0..p_max).filter(|p| *p != p_own) {
        keys[p].truncate(lenshare);
        macs[p].truncate(lenshare);
    }
    //println!("{:?}\n{:?}\n{:?}\n{:?}", bits, macs, keys, delta);

    // Protocol Pi_aShare

    // Protocol Pi_HaAND

    // Protocol Pi_LaAND

    // Protocol Pi_aAND

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::{Error, SimpleChannel},
        faand::faand,
    };

    #[tokio::test]
    async fn test_faand() -> Result<(), Error> {
        let parties = 3;
        let length = 3;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<tokio::task::JoinHandle<Result<(), crate::faand::Error>>> = vec![];
        for i in 0..parties {
            handles.push(tokio::spawn(faand(
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
