//! The FPre preprocessor as a (semi-)trusted party, providing correlated randomness.

use maybe_async::maybe_async;
use rand::random;
use smallvec::smallvec;

use crate::{
    channel::{self, recv_from, send_to, Channel},
    data_types::{Auth, Delta, Key, Mac, Share},
};

/// Errors that can occur while executing FPre as a trusted dealer.
#[derive(Debug)]
pub(crate) enum Error {
    /// One of the parties tried to cheat.
    CheatingDetected,
    /// The parties expect a different number of random shares.
    RandomSharesMismatch(u32, u32),
    /// The parties expect a different number of AND shares.
    AndSharesMismatch(usize, usize),
    /// An error occurred while trying to communicate over the channel.
    Channel(channel::Error),
    /// A message was sent, but it contained no data.
    EmptyMsg,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CheatingDetected => f.write_str("Cheating detected"),
            Error::RandomSharesMismatch(a, b) => write!(f, "Unequal number of shares: {a} vs {b}"),
            Error::AndSharesMismatch(a, b) => write!(f, "Unequal number of AND shares: {a} vs {b}"),
            Error::Channel(e) => write!(f, "Channel error: {e:?}"),
            Error::EmptyMsg => f.write_str("The message sent by the other party was empty"),
        }
    }
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Error::Channel(e)
    }
}

/// Runs FPre as a trusted dealer, communicating with all other parties.
#[maybe_async(AFIT)]
pub(crate) async fn fpre(channel: &mut (impl Channel + Send), parties: usize) -> Result<(), Error> {
    for p in 0..parties {
        recv_from::<()>(channel, p, "delta (fpre)").await?;
    }
    let mut deltas = vec![];
    for p in 0..parties {
        let delta = Delta(random());
        send_to(channel, p, "delta (fpre)", &[delta]).await?;
        deltas.push(delta);
    }

    let mut num_shares = 0;
    for p in 0..parties {
        let r: u32 = recv_from(channel, p, "random shares (fpre)")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        if num_shares > 0 && num_shares != r {
            let e = Error::RandomSharesMismatch(num_shares, r);
            for p in 0..parties {
                send_to(channel, p, "error", &[format!("{e:?}")]).await?;
            }
            return Err(e);
        }
        num_shares = r;
    }
    let num_shares = num_shares as usize;
    let mut random_shares = vec![vec![]; parties];
    for _ in 0..num_shares {
        let mut bits = vec![];
        let mut keys = vec![];
        for i in 0..parties {
            bits.push(random());
            keys.push(vec![Key(0); parties]);
            for j in 0..parties {
                if i != j {
                    keys[i][j] = Key(random());
                }
            }
        }
        for i in 0..parties {
            let mut mac_and_key = smallvec![(Mac(0), Key(0)); parties];
            for j in 0..parties {
                if i != j {
                    let mac = keys[j][i] ^ (bits[i] & deltas[j]);
                    let key = keys[i][j];
                    mac_and_key[j] = (mac, key);
                }
            }
            random_shares[i].push(Share(bits[i], Auth(mac_and_key)));
        }
    }
    for (p, shares) in random_shares.into_iter().enumerate() {
        send_to(channel, p, "random shares (fpre)", &shares).await?;
    }

    let mut num_shares = None;
    let mut shares = vec![];
    for p in 0..parties {
        let and_shares: Vec<(Share, Share)> = recv_from(channel, p, "AND shares (fpre)").await?;
        if let Some(num_shares) = num_shares {
            if num_shares != and_shares.len() {
                let e = Error::AndSharesMismatch(num_shares, and_shares.len());
                for p in 0..parties {
                    send_to(channel, p, "error", &[format!("{e:?}")]).await?;
                }
                return Err(e);
            }
        } else {
            for _ in 0..and_shares.len() {
                shares.push(vec![]);
            }
        }
        num_shares = Some(and_shares.len());
        for (s, (a, b)) in and_shares.into_iter().enumerate() {
            shares[s].push((a, b))
        }
    }
    let mut has_cheated = false;
    for share in shares.iter() {
        for (i, (a, b)) in share.iter().enumerate() {
            for (Share(bit, Auth(macs_i)), round) in [(a, 0), (b, 1)] {
                for (j, (mac_i, _)) in macs_i.iter().enumerate() {
                    if *mac_i != Mac(0) {
                        // Added when removed Option
                        let (a, b) = &share[j];
                        let Share(_, Auth(keys_j)) = if round == 0 { a } else { b };
                        let (_, key_j) = keys_j[i];
                        if *mac_i != key_j ^ (*bit & deltas[j]) {
                            has_cheated = true;
                        }
                    }
                }
            }
        }
    }
    if has_cheated {
        let e = Error::CheatingDetected;
        for p in 0..parties {
            send_to(channel, p, "error", &[format!("{e:?}")]).await?;
        }
        return Err(e);
    }
    let mut and_shares = vec![vec![]; parties];
    for share in shares {
        let mut a = false;
        let mut b = false;
        for (Share(a_i, _), Share(b_i, _)) in share {
            a ^= a_i;
            b ^= b_i;
        }
        let c = a & b;
        let mut current_share = false;
        let mut bits = vec![false; parties];
        let mut keys = vec![];
        for i in 0..parties {
            bits[i] = if i == parties - 1 {
                current_share != c
            } else {
                let share: bool = random();
                current_share ^= share;
                share
            };
            keys.push(vec![Key(0); parties]);
            for j in 0..parties {
                if i != j {
                    keys[i][j] = Key(random());
                }
            }
        }
        for i in 0..parties {
            let mut mac_and_key = smallvec![(Mac(0), Key(0)); parties];
            for j in 0..parties {
                if i != j {
                    let mac = keys[j][i] ^ (bits[i] & deltas[j]);
                    let key = keys[i][j];
                    mac_and_key[j] = (mac, key);
                }
            }
            and_shares[i].push(Share(bits[i], Auth(mac_and_key)));
        }
    }
    for (p, and_shares) in and_shares.into_iter().enumerate() {
        send_to(channel, p, "AND shares (fpre)", &and_shares).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::{recv_from, recv_vec_from, send_to, SimpleChannel},
        fpre::{fpre, Auth, Delta, Error, Key, Mac, Share},
    };
    use smallvec::smallvec;

    #[tokio::test]
    async fn xor_homomorphic_mac() -> Result<(), Error> {
        let parties = 2;
        let mut channels = SimpleChannel::channels(parties + 1);
        let mut channel = channels.pop().unwrap();
        tokio::spawn(async move { fpre(&mut channel, parties).await });
        let fpre_party = parties;
        let mut b = channels.pop().unwrap();
        let mut a = channels.pop().unwrap();

        // init:
        send_to::<()>(&mut a, fpre_party, "delta", &[]).await?;
        send_to::<()>(&mut b, fpre_party, "delta", &[]).await?;
        let delta_a: Delta = recv_from(&mut a, fpre_party, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        let delta_b: Delta = recv_from(&mut b, fpre_party, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;

        // random r1, r2, s1, s2:
        send_to(&mut a, fpre_party, "random shares", &[2_u32]).await?;
        send_to(&mut b, fpre_party, "random shares", &[2_u32]).await?;

        let mut r = recv_vec_from(&mut a, fpre_party, "random shares", 2)
            .await?
            .into_iter();
        let mut s = recv_vec_from(&mut b, fpre_party, "random shares", 2)
            .await?
            .into_iter();

        let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
        let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
        let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, Auth(mac_r2_key_s2))) = (auth_r1, auth_r2);
        let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, Auth(mac_s2_key_r2))) = (auth_s1, auth_s2);
        let (mac_r1, key_s1) = mac_r1_key_s1[1];
        let (mac_r2, key_s2) = mac_r2_key_s2[1];
        let (mac_s1, key_r1) = mac_s1_key_r1[0];
        let (mac_s2, key_r2) = mac_s2_key_r2[0];

        let (r3, mac_r3, key_s3) = {
            let r3 = r1 ^ r2;
            let mac_r3 = mac_r1 ^ mac_r2;
            let key_s3 = key_s1 ^ key_s2;
            (r3, mac_r3, key_s3)
        };
        let (s3, mac_s3, key_r3) = {
            let s3 = s1 ^ s2;
            let mac_s3 = mac_s1 ^ mac_s2;
            let key_r3 = key_r1 ^ key_r2;
            (s3, mac_s3, key_r3)
        };
        // verify that the MAC is XOR-homomorphic:
        assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
        assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_and_shares() -> Result<(), Error> {
        for i in 0..3 {
            let parties = 2;
            let mut channels = SimpleChannel::channels(parties + 1);
            let mut channel = channels.pop().unwrap();
            tokio::spawn(async move { fpre(&mut channel, parties).await });
            let fpre_party = parties;
            let mut b = channels.pop().unwrap();
            let mut a = channels.pop().unwrap();

            // init:
            send_to::<()>(&mut a, fpre_party, "delta", &[]).await?;
            send_to::<()>(&mut b, fpre_party, "delta", &[]).await?;
            let delta_a: Delta = recv_from(&mut a, fpre_party, "delta")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;
            let delta_b: Delta = recv_from(&mut b, fpre_party, "delta")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;

            // random r1, r2, s1, s2:
            send_to(&mut a, fpre_party, "random shares", &[2_u32]).await?;
            send_to(&mut b, fpre_party, "random shares", &[2_u32]).await?;

            let mut r = recv_vec_from::<Share>(&mut a, fpre_party, "random shares", 2)
                .await?
                .into_iter();
            let mut s = recv_vec_from::<Share>(&mut b, fpre_party, "random shares", 2)
                .await?
                .into_iter();

            let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
            let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
            let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, _)) = (auth_r1.clone(), auth_r2.clone());
            let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, _)) = (auth_s1.clone(), auth_s2.clone());
            let (mac_r1, key_s1) = mac_r1_key_s1[1];
            let (_, key_r1) = mac_s1_key_r1[0];

            if i == 0 {
                // uncorrupted authenticated (r1 XOR s1) AND (r2 XOR s2):
                send_to(&mut a, fpre_party, "AND shares", &[(auth_r1, auth_r2)]).await?;
                send_to(&mut b, fpre_party, "AND shares", &[(auth_s1, auth_s2)]).await?;
                let Share(r3, Auth(mac_r3_key_s3)) =
                    recv_from::<Share>(&mut a, fpre_party, "AND shares")
                        .await?
                        .pop()
                        .unwrap();
                let Share(s3, Auth(mac_s3_key_r3)) =
                    recv_from::<Share>(&mut b, fpre_party, "AND shares")
                        .await?
                        .pop()
                        .unwrap();
                let (mac_r3, key_s3) = mac_r3_key_s3[1];
                let (mac_s3, key_r3) = mac_s3_key_r3[0];
                assert_eq!(r3 ^ s3, (r1 ^ s1) & (r2 ^ s2));
                assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
                assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
            } else if i == 1 {
                // corrupted (r1 XOR s1) AND (r2 XOR s2):
                let auth_r1_corrupted =
                    Share(!r1, Auth(smallvec![(Mac(0), Key(0)), (mac_r1, key_s1)]));
                send_to(
                    &mut a,
                    fpre_party,
                    "AND shares",
                    &[(auth_r1_corrupted, auth_r2)],
                )
                .await?;
                send_to(&mut b, fpre_party, "AND shares", &[(auth_s1, auth_s2)]).await?;
                assert_eq!(
                    recv_from::<String>(&mut a, fpre_party, "AND shares").await?,
                    vec!["CheatingDetected".to_string()]
                );
                assert_eq!(
                    recv_from::<String>(&mut b, fpre_party, "AND shares").await?,
                    vec!["CheatingDetected".to_string()]
                );
            } else if i == 2 {
                // A would need knowledge of B's key and delta to corrupt the shared secret:
                let mac_r1_corrupted = key_r1 ^ (!r1 & delta_b);
                let auth_r1_corrupted = Share(
                    !r1,
                    Auth(smallvec![(Mac(0), Key(0)), (mac_r1_corrupted, key_s1)]),
                );
                send_to(
                    &mut a,
                    fpre_party,
                    "AND shares",
                    &[(auth_r1_corrupted, auth_r2)],
                )
                .await?;
                send_to(&mut b, fpre_party, "AND shares", &[(auth_s1, auth_s2)]).await?;
                assert_eq!(
                    recv_from::<Share>(&mut a, fpre_party, "AND shares")
                        .await?
                        .len(),
                    1
                );
                assert_eq!(
                    recv_from::<Share>(&mut b, fpre_party, "AND shares")
                        .await?
                        .len(),
                    1
                );
            }
        }
        Ok(())
    }
}
