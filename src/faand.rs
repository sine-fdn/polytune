//! F_aAND protocol from WRK17b.

use blake3::Hasher;
use rand::random;
use serde::{Deserialize, Serialize};

use crate::{
    channel::{self, Channel, MsgChannel},
    //fpre::{Auth, Delta, Key, Mac, Share},
    fpre::Delta,
};

/// A custom error type.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
    /// The MAC is not the correct one in aBit.
    ABitMacMisMatch,
    /// A calculated bit value is not 0 or 1.
    BitNotBit,
    /// The xor of MACs is not equal to the XOR of corresponding keys or that XOR delta.
    AShareMacsMismatch,
    /// A commitment could not be opened.
    CommitmentCouldNotBeOpened,
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Commitment(pub(crate) [u8; 32]);

// Commit to a u128 value using BLAKE3 hash function
fn commit(value: &[u8]) -> Commitment {
    let mut hasher = Hasher::new();
    hasher.update(value);
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(result.as_bytes());
    Commitment(commitment)
}

// Open the commitment and reveal the original value
fn open_commitment(commitment: &Commitment, value: &[u8]) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(value);
    let result = hasher.finalize();
    &commitment.0 == result.as_bytes()
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
    const RHO: usize = 1;
    let delta: Delta = Delta(random());
    let mut channel = MsgChannel(channel);

    let len_ashare = length + RHO;

    // Protocol Pi_aBit^n
    // Step 1 initialize random bitstring
    let len_abit = len_ashare + 2 * RHO;
    let mut x: Vec<bool> = (0..len_abit).map(|_| random()).collect();

    // Steps 2 running Pi_aBit^2 for each pair of parties
    let mut xkeys: Vec<Vec<u128>> = vec![vec![]; p_max];
    let mut xmacs: Vec<Vec<u128>> = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        let macvec: Vec<u128>;
        let keyvec: Vec<u128>;
        if p_own < p {
            macvec = fabit(&mut channel, p, delta, &x, true).await?;
            keyvec = fabit(&mut channel, p, delta, &x, false).await?;
        } else {
            keyvec = fabit(&mut channel, p, delta, &x, false).await?;
            macvec = fabit(&mut channel, p, delta, &x, true).await?;
        }
        xmacs[p] = macvec;
        xkeys[p] = keyvec;
    }
    //println!("{:?}\n{:?}\n{:?}\n{:?}", bits, macs, keys, delta);

    // Steps 3 including verification of macs and keys
    // TODO FIGURE OUT HOW Pk calculates with same rm as Pi in the check
    for _ in 0..2 * RHO {
        let randbits: Vec<bool> = (0..len_abit).map(|_| random()).collect();
        let mut xj = false;
        for (&xb, &rb) in x.iter().zip(&randbits) {
            xj ^= xb & rb;
        }

        for p in (0..p_max).filter(|p| *p != p_own) {
            let mut xjp: Vec<bool> = vec![false; p_max];
            channel.send_to(p, "xj", &xj).await?;
            xjp[p] = channel.recv_from(p, "xj").await?;

            let mut macint: u128 = 0;
            let mut keyint: u128 = 0;
            for (i, rbit) in randbits.iter().enumerate().take(len_abit) {
                if *rbit {
                    macint ^= xmacs[p][i];
                }
            }
            channel
                .send_to(p, "mac", &(macint, randbits.clone()))
                .await?;
            let (macp, randbitsp): (u128, Vec<bool>) = channel.recv_from(p, "mac").await?;

            for (i, rbit) in randbitsp.iter().enumerate().take(len_abit) {
                if *rbit {
                    keyint ^= xkeys[p][i];
                }
            }
            if macp != keyint ^ ((xjp[p] as u128) * delta.0) {
                return Err(Error::ABitMacMisMatch);
            }
        }
    }

    // Step 4 return first l objects
    x.truncate(len_ashare);
    for p in (0..p_max).filter(|p| *p != p_own) {
        xkeys[p].truncate(len_ashare);
        xmacs[p].truncate(len_ashare);
    }
    //println!("{:?}\n{:?}\n{:?}\n{:?}", bits, macs, keys, delta);

    // Protocol Pi_aShare
    // Input: bits of len_ashare length, authenticated bits
    // Step 3
    let mut d0: Vec<u128> = vec![0; RHO]; // xorkeys
    let mut d1: Vec<u128> = vec![0; RHO]; // xorkeysdelta
    let mut dm: Vec<Vec<u8>> = vec![vec![]; RHO]; // multiple macs
    let mut c0: Vec<Commitment> = vec![]; // commitment to d0
    let mut c1: Vec<Commitment> = vec![]; // commitment to d1
    let mut cm: Vec<Commitment> = vec![]; // commitment to dm

    // 3/(a)
    for r in 0..RHO {
        dm[r].push(x[length + r] as u8);
        for p in 0..p_max {
            if p != p_own {
                d0[r] ^= xkeys[p][length + r];
                let macbytes = xmacs[p][length + r].to_be_bytes().to_vec(); // 16 bytes
                dm[r].extend(macbytes);
            } else {
                dm[r].extend(vec![0; 16]);
            }
        }
        d1[r] = d0[r] ^ delta.0;
        c0.push(commit(&d0[r].to_be_bytes()));
        c1.push(commit(&d1[r].to_be_bytes()));
        cm.push(commit(&dm[r]));
    }
    let mut commitments: Vec<(Vec<Commitment>, Vec<Commitment>, Vec<Commitment>)> =
        vec![(vec![], vec![], vec![]); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "commit", &(&c0, &c1, &cm)).await?;
        let result: (Vec<Commitment>, Vec<Commitment>, Vec<Commitment>) =
            channel.recv_from(p, "commit").await?;
        commitments[p] = result;
    }

    // 3/(b) After receiving all commitments, Pi broadcasts decommitment for macs
    let mut dmp: Vec<Vec<Vec<u8>>> = vec![vec![vec![]; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "verify", &dm).await?;
        dmp[p] = channel.recv_from(p, "verify").await?;
    }
    dmp[p_own] = dm;

    // 3/(c) bit
    let mut combit: Vec<u8> = vec![0; RHO];
    let mut xorkeysbit: Vec<u128> = vec![0; RHO];
    for r in 0..RHO {
        for p in (0..p_max).filter(|p| *p != p_own) {
            combit[r] ^= dmp[p][r][0];
        }
        if combit[r] == 0 {
            xorkeysbit[r] = d0[r];
        } else if combit[r] == 1 {
            xorkeysbit[r] = d1[r];
        } else {
            return Err(Error::BitNotBit);
        }
    }
    let mut xorkeysbitp: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "bitcom", &xorkeysbit).await?;
        xorkeysbitp[p] = channel.recv_from(p, "bitcom").await?;
    }

    // 3/(d) consistency check
    let mut xormacs: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for r in 0..RHO {
        for (p, pitem) in dmp.iter().enumerate().take(p_max) {
            for pp in (0..p_max).filter(|pp| *pp != p) {
                if !pitem[r].is_empty() {
                    let b: u128 = u128::from_be_bytes(
                        pitem[r][(1 + pp * 16)..(17 + pp * 16)].try_into().unwrap(),
                    );
                    xormacs[pp][r] ^= b;
                }
            }
        }
    }

    for r in 0..RHO {
        for p in (0..p_max).filter(|p| *p != p_own) {
            if open_commitment(&commitments[p].0[r], &xorkeysbitp[p][r].to_be_bytes())
                || open_commitment(&commitments[p].1[r], &xorkeysbitp[p][r].to_be_bytes())
            {
                if !xormacs[p][r] == xorkeysbitp[p][r] {
                    return Err(Error::AShareMacsMismatch);
                }
            } else {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
        }
    }

    // Step 4
    x.truncate(length);
    for p in (0..p_max).filter(|p| *p != p_own) {
        xkeys[p].truncate(length);
        xmacs[p].truncate(length);
    }

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
