//! An implementation of the FPre ideal functionality from the paper
//! [Authenticated Garbling and Efficient Maliciously Secure Two-Party Computation](https://acmccs.github.io/papers/p21-wangA.pdf)
//! as a third party that communicates with two parties over channels.

use std::ops::{BitAnd, BitXor};

use rand::random;
use serde::{Deserialize, Serialize};
use tokio::task;

use crate::channel::{self, Channel, MsgChannel, SimpleChannel};

/// Implements FPre as a trusted dealer.
///
/// Returns communication channels for N parties that can send/receive messages to/from FPre.
pub(crate) async fn f_pre(parties: usize) -> Vec<MsgChannel<SimpleChannel>> {
    let mut party_channels = vec![];
    let mut fpre_channels = vec![];
    for _ in 0..parties {
        let mut channels = SimpleChannel::channels(2).into_iter();
        fpre_channels.push(channels.next().unwrap());
        party_channels.push(channels.next().unwrap());
    }
    task::spawn(async move {
        let other_party = 1;
        if let Err(e) = fpre_channel(other_party, &mut fpre_channels).await {
            for fpre in fpre_channels.iter_mut() {
                if let Err(e) = fpre.send_to(other_party, "error", &format!("{e:?}")).await {
                    eprintln!("{e:?}");
                }
            }
            eprintln!("{e:?}");
        }
    });
    party_channels
}

#[derive(Debug)]
enum Error {
    CheatingDetected,
    RandomSharesMismatch(u32, u32),
    AndSharesMismatch(usize, usize),
    Channel(channel::Error),
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Error::Channel(e)
    }
}

async fn fpre_channel<C: Channel>(
    other_party: usize,
    fpre_channels: &mut Vec<MsgChannel<C>>,
) -> Result<(), Error> {
    for fpre in fpre_channels.iter_mut() {
        fpre.recv_from(other_party, "delta (fpre)").await?;
    }
    let mut deltas = vec![];
    for fpre in fpre_channels.iter_mut() {
        let delta = Delta(random());
        fpre.send_to(other_party, "delta (fpre)", &delta).await?;
        deltas.push(delta);
    }

    let mut num_shares = None;
    for fpre in fpre_channels.iter_mut() {
        let r: u32 = fpre.recv_from(other_party, "random shares (fpre)").await?;
        if let Some(random_shares) = num_shares {
            if random_shares != r {
                return Err(Error::RandomSharesMismatch(random_shares, r));
            }
        }
        num_shares = Some(r);
    }
    let num_shares = num_shares.unwrap() as usize;
    let mut random_shares = vec![vec![]; fpre_channels.len()];
    for _ in 0..num_shares {
        let mut bits = vec![];
        let mut keys = vec![];
        for i in 0..fpre_channels.len() {
            bits.push(random());
            keys.push(vec![None; fpre_channels.len()]);
            for j in 0..fpre_channels.len() {
                if i != j {
                    keys[i][j] = Some(Key(random()));
                }
            }
        }
        for i in 0..fpre_channels.len() {
            let mut mac_and_key = vec![None; fpre_channels.len()];
            for j in 0..fpre_channels.len() {
                if i != j {
                    let mac = keys[j][i].unwrap() ^ (bits[i] & deltas[j]);
                    let key = keys[i][j].unwrap();
                    mac_and_key[j] = Some((mac, key));
                }
            }
            random_shares[i].push(Share(bits[i], Auth(mac_and_key)));
        }
    }
    for (fpre, random_shares) in fpre_channels.iter_mut().zip(random_shares.into_iter()) {
        fpre.send_to(other_party, "random shares (fpre)", &random_shares)
            .await?;
    }

    let mut num_shares = None;
    let mut shares = vec![];
    for fpre in fpre_channels.iter_mut() {
        let and_shares: Vec<(Share, Share)> =
            fpre.recv_from(other_party, "AND shares (fpre)").await?;
        if let Some(num_shares) = num_shares {
            if num_shares != and_shares.len() {
                return Err(Error::AndSharesMismatch(num_shares, and_shares.len()));
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
                for (j, macs_i) in macs_i.iter().enumerate() {
                    if let Some((mac_i, _)) = macs_i {
                        let (a, b) = &share[j];
                        let Share(_, Auth(keys_j)) = if round == 0 { a } else { b };
                        let (_, key_j) = keys_j[i].unwrap();
                        if *mac_i != key_j ^ (*bit & deltas[j]) {
                            has_cheated = true;
                        }
                    }
                }
            }
        }
    }
    if has_cheated {
        return Err(Error::CheatingDetected);
    }
    let mut and_shares = vec![vec![]; fpre_channels.len()];
    for share in shares {
        let mut a = false;
        let mut b = false;
        for (Share(a_i, _), Share(b_i, _)) in share {
            a ^= a_i;
            b ^= b_i;
        }
        let c = a & b;
        let mut current_share = false;
        let mut bits = vec![false; fpre_channels.len()];
        let mut keys = vec![];
        for i in 0..fpre_channels.len() {
            bits[i] = if i == fpre_channels.len() - 1 {
                current_share != c
            } else {
                let share: bool = random();
                current_share ^= share;
                share
            };
            keys.push(vec![None; fpre_channels.len()]);
            for j in 0..fpre_channels.len() {
                if i != j {
                    keys[i][j] = Some(Key(random()));
                }
            }
        }
        for i in 0..fpre_channels.len() {
            let mut mac_and_key = vec![None; fpre_channels.len()];
            for j in 0..fpre_channels.len() {
                if i != j {
                    let mac = keys[j][i].unwrap() ^ (bits[i] & deltas[j]);
                    let key = keys[i][j].unwrap();
                    mac_and_key[j] = Some((mac, key));
                }
            }
            and_shares[i].push(Share(bits[i], Auth(mac_and_key)));
        }
    }
    for (fpre, and_shares) in fpre_channels.iter_mut().zip(and_shares.into_iter()) {
        fpre.send_to(other_party, "AND shares (fpre)", &and_shares)
            .await?;
    }
    Ok(())
}

/// The global key known only to a single party that is used to authenticate bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Delta(pub(crate) u128);

impl BitAnd<Delta> for bool {
    type Output = Delta;

    fn bitand(self, rhs: Delta) -> Self::Output {
        if self {
            rhs
        } else {
            Delta(0)
        }
    }
}

/// A message authentication code held by a party together with an authenticated bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mac(pub(crate) u128);

impl BitXor<Delta> for Mac {
    type Output = Key;

    fn bitxor(self, rhs: Delta) -> Self::Output {
        Key(self.0 ^ rhs.0)
    }
}

impl BitXor for Mac {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Mac(self.0 ^ rhs.0)
    }
}

/// A key used to authenticate (together with the [Delta] global key) a bit for the other party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Key(pub(crate) u128);

impl BitXor<Delta> for Key {
    type Output = Mac;

    fn bitxor(self, rhs: Delta) -> Self::Output {
        Mac(self.0 ^ rhs.0)
    }
}

impl BitXor for Key {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Key(self.0 ^ rhs.0)
    }
}

/// One half of a shared secret consisting of 2 XORed bits `r` and `s`.
///
/// Party A holds (`r`, [Mac]_r, [Key]_s) and party B holds (`s`, [Mac]_s, [Key]_r), so that each
/// party holds bit + MAC, with the other holding key + global key for the corresponding half of the
/// bit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Share(pub(crate) bool, pub(crate) Auth);

impl BitXor for &Share {
    type Output = Share;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let Share(bit0, auth0) = self;
        let Share(bit1, auth1) = rhs;
        Share(bit0 ^ bit1, auth0 ^ auth1)
    }
}

impl Share {
    pub(crate) fn bit(&self) -> bool {
        self.0
    }

    pub(crate) fn macs(&self) -> Vec<Option<Mac>> {
        self.1.macs()
    }

    pub(crate) fn xor_keys(&self) -> Key {
        self.1.xor_keys()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Auth(pub(crate) Vec<Option<(Mac, Key)>>);

impl BitXor for &Auth {
    type Output = Auth;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let Auth(auth0) = self;
        let Auth(auth1) = rhs;
        let mut xor = vec![];
        for (a, b) in auth0.iter().zip(auth1.iter()) {
            xor.push(match (a, b) {
                (Some((mac1, key1)), Some((mac2, key2))) => Some((*mac1 ^ *mac2, *key1 ^ *key2)),
                (None, None) => None,
                (a, b) => panic!("Invalid AuthBits: {a:?} vs {b:?}"),
            });
        }
        Auth(xor)
    }
}

impl Auth {
    pub(crate) fn macs(&self) -> Vec<Option<Mac>> {
        self.0.iter().map(|s| s.map(|(mac, _)| mac)).collect()
    }

    pub(crate) fn xor_keys(&self) -> Key {
        let mut k = 0;
        for (_, key) in self.0.iter().flatten() {
            k ^= key.0;
        }
        Key(k)
    }

    pub(crate) fn xor_key(mut self, i: usize, delta: Delta) -> Auth {
        for (j, share) in self.0.iter_mut().enumerate() {
            if i == j {
                let share = share.as_mut().unwrap();
                share.1 .0 ^= delta.0
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::Error,
        fpre::{f_pre, Auth, Delta, Share},
    };

    #[tokio::test]
    async fn xor_homomorphic_mac() -> Result<(), Error> {
        let fpre_party = 0;
        let mut channels = f_pre(2).await.into_iter();
        let mut a = channels.next().unwrap();
        let mut b = channels.next().unwrap();

        // init:
        a.send_to(fpre_party, "delta", &()).await?;
        b.send_to(fpre_party, "delta", &()).await?;
        let delta_a: Delta = a.recv_from(fpre_party, "delta").await?;
        let delta_b: Delta = b.recv_from(fpre_party, "delta").await?;

        // random r1, r2, s1, s2:
        a.send_to(fpre_party, "random shares", &2_u32).await?;
        b.send_to(fpre_party, "random shares", &2_u32).await?;

        let mut r = a
            .recv_vec_from(fpre_party, "random shares", 2)
            .await?
            .into_iter();
        let mut s = b
            .recv_vec_from(fpre_party, "random shares", 2)
            .await?
            .into_iter();

        let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
        let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
        let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, Auth(mac_r2_key_s2))) = (auth_r1, auth_r2);
        let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, Auth(mac_s2_key_r2))) = (auth_s1, auth_s2);
        let (mac_r1, key_s1) = mac_r1_key_s1[1].unwrap();
        let (mac_r2, key_s2) = mac_r2_key_s2[1].unwrap();
        let (mac_s1, key_r1) = mac_s1_key_r1[0].unwrap();
        let (mac_s2, key_r2) = mac_s2_key_r2[0].unwrap();

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
            let fpre_party = 0;
            let mut channels = f_pre(2).await.into_iter();
            let mut a = channels.next().unwrap();
            let mut b = channels.next().unwrap();

            // init:
            a.send_to(fpre_party, "delta", &()).await?;
            b.send_to(fpre_party, "delta", &()).await?;
            let delta_a: Delta = a.recv_from(fpre_party, "delta").await?;
            let delta_b: Delta = b.recv_from(fpre_party, "delta").await?;

            // random r1, r2, s1, s2:
            a.send_to(fpre_party, "random shares", &2_u32).await?;
            b.send_to(fpre_party, "random shares", &2_u32).await?;

            let mut r = a
                .recv_vec_from::<Share>(fpre_party, "random shares", 2)
                .await?
                .into_iter();
            let mut s = b
                .recv_vec_from::<Share>(fpre_party, "random shares", 2)
                .await?
                .into_iter();

            let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
            let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
            let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, _)) = (auth_r1.clone(), auth_r2.clone());
            let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, _)) = (auth_s1.clone(), auth_s2.clone());
            let (mac_r1, key_s1) = mac_r1_key_s1[1].unwrap();
            let (_, key_r1) = mac_s1_key_r1[0].unwrap();

            if i == 0 {
                // uncorrupted authenticated (r1 XOR s1) AND (r2 XOR s2):
                a.send_to(fpre_party, "AND shares", &vec![(auth_r1, auth_r2)])
                    .await?;
                b.send_to(fpre_party, "AND shares", &vec![(auth_s1, auth_s2)])
                    .await?;
                let Share(r3, Auth(mac_r3_key_s3)) = a
                    .recv_from::<Vec<Share>>(fpre_party, "AND shares")
                    .await?
                    .pop()
                    .unwrap();
                let Share(s3, Auth(mac_s3_key_r3)) = b
                    .recv_from::<Vec<Share>>(fpre_party, "AND shares")
                    .await?
                    .pop()
                    .unwrap();
                let (mac_r3, key_s3) = mac_r3_key_s3[1].unwrap();
                let (mac_s3, key_r3) = mac_s3_key_r3[0].unwrap();
                assert_eq!(r3 ^ s3, (r1 ^ s1) & (r2 ^ s2));
                assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
                assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
            } else if i == 1 {
                // corrupted (r1 XOR s1) AND (r2 XOR s2):
                let auth_r1_corrupted = Share(!r1, Auth(vec![None, Some((mac_r1, key_s1))]));
                a.send_to(
                    fpre_party,
                    "AND shares",
                    &vec![(auth_r1_corrupted, auth_r2)],
                )
                .await?;
                b.send_to(fpre_party, "AND shares", &vec![(auth_s1, auth_s2)])
                    .await?;
                assert_eq!(
                    a.recv_from::<String>(fpre_party, "AND shares").await?,
                    "CheatingDetected"
                );
                assert_eq!(
                    b.recv_from::<String>(fpre_party, "AND shares").await?,
                    "CheatingDetected"
                );
            } else if i == 2 {
                // A would need knowledge of B's key and delta to corrupt the shared secret:
                let mac_r1_corrupted = key_r1 ^ (!r1 & delta_b);
                let auth_r1_corrupted =
                    Share(!r1, Auth(vec![None, Some((mac_r1_corrupted, key_s1))]));
                a.send_to(
                    fpre_party,
                    "AND shares",
                    &vec![(auth_r1_corrupted, auth_r2)],
                )
                .await?;
                b.send_to(fpre_party, "AND shares", &vec![(auth_s1, auth_s2)])
                    .await?;
                assert_eq!(
                    a.recv_from::<Vec<Share>>(fpre_party, "AND shares")
                        .await?
                        .len(),
                    1
                );
                assert_eq!(
                    b.recv_from::<Vec<Share>>(fpre_party, "AND shares")
                        .await?
                        .len(),
                    1
                );
            }
        }
        Ok(())
    }
}
