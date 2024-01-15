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
/// Returns communication channels for the parties A and B that can be used to send and receive
/// messages to and from FPre.
pub(crate) async fn f_pre() -> (MsgChannel<SimpleChannel>, MsgChannel<SimpleChannel>) {
    let (a, mut fpre_a) = SimpleChannel::channels();
    let (b, mut fpre_b) = SimpleChannel::channels();
    task::spawn(async move {
        if let Err(e) = fpre_channel(&mut fpre_a, &mut fpre_b).await {
            if let Err(e) = fpre_a.send("error", &format!("{e:?}")).await {
                eprintln!("{e:?}");
            }
            if let Err(e) = fpre_b.send("error", &format!("{e:?}")).await {
                eprintln!("{e:?}");
            }
            eprintln!("{e:?}");
        }
    });
    (a, b)
}

#[derive(Debug)]
enum Error {
    CheatingDetected,
    RandomSharesMismatch(u32, u32),
    AndSharesMismatch(usize, usize),
    ChannelError(channel::Error),
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Error::ChannelError(e)
    }
}

async fn fpre_channel<C: Channel>(
    fpre_a: &mut MsgChannel<C>,
    fpre_b: &mut MsgChannel<C>,
) -> Result<(), Error> {
    let _: () = fpre_a.recv("delta (fpre)").await?;
    let _: () = fpre_b.recv("delta (fpre)").await?;
    let delta_a = Delta(random());
    let delta_b = Delta(random());
    fpre_a.send("delta (fpre)", &delta_a).await?;
    fpre_b.send("delta (fpre)", &delta_b).await?;

    let random_a: u32 = fpre_a.recv("random shares (fpre)").await?;
    let random_b: u32 = fpre_b.recv("random shares (fpre)").await?;
    if random_a != random_b {
        return Err(Error::RandomSharesMismatch(random_a, random_b));
    }
    let mut random_shares_a = vec![];
    let mut random_shares_b = vec![];
    for _ in 0..random_a {
        let r: bool = random();
        let mac_r = Mac(random());
        let key_s = Key(random());
        random_shares_a.push(AuthBit(r, mac_r, key_s));
        let s: bool = random();
        let key_r = mac_r ^ (r & delta_b);
        let mac_s = key_s ^ (s & delta_a);
        random_shares_b.push(AuthBit(s, mac_s, key_r));
    }
    fpre_a
        .send("random shares (fpre)", &random_shares_a)
        .await?;
    fpre_b
        .send("random shares (fpre)", &random_shares_b)
        .await?;

    let shares_a: Vec<(AuthBit, AuthBit)> = fpre_a.recv("AND shares (fpre)").await?;
    let shares_b: Vec<(AuthBit, AuthBit)> = fpre_b.recv("AND shares (fpre)").await?;
    if shares_a.len() != shares_b.len() {
        return Err(Error::AndSharesMismatch(shares_a.len(), shares_b.len()));
    }
    let mut and_shares_a = vec![];
    let mut and_shares_b = vec![];
    for ((a1, a2), (b1, b2)) in shares_a.into_iter().zip(shares_b.into_iter()) {
        let mut has_cheated = false;
        for (a, b) in [(a1, b1), (a2, b2)] {
            let AuthBit(r, mac_r, key_s) = a;
            let AuthBit(s, mac_s, key_r) = b;
            let r_verified = mac_r == key_r ^ (r & delta_b);
            let s_verified = mac_s == key_s ^ (s & delta_a);
            if !r_verified || !s_verified {
                has_cheated = true;
                break;
            }
        }
        if has_cheated {
            return Err(Error::CheatingDetected);
        } else {
            let AuthBit(r1, _, _) = a1;
            let AuthBit(r2, _, _) = a2;
            let AuthBit(r3, mac_r3, key_s3) = AuthBit(random(), Mac(random()), Key(random()));
            let AuthBit(s1, _, _) = b1;
            let AuthBit(s2, _, _) = b2;
            let s3 = r3 ^ ((r1 ^ s1) & (r2 ^ s2));
            let mac_s3 = key_s3 ^ (s3 & delta_a);
            let key_r3 = mac_r3 ^ (r3 & delta_b);
            and_shares_a.push(AuthBit(r3, mac_r3, key_s3));
            and_shares_b.push(AuthBit(s3, mac_s3, key_r3));
        }
    }
    fpre_a.send("AND shares (fpre)", &and_shares_a).await?;
    fpre_b.send("AND shares (fpre)", &and_shares_b).await?;
    Ok(())
}

/// The global key known only to a single party that is used to authenticate bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta(pub u128);

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
pub struct Mac(pub u128);

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
pub struct Key(pub u128);

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
/// Party A holds (`r`, [MAC]_r, [Key]_s) and party B holds (`s`, [MAC]_s, [Key]_r), so that each
/// party holds bit + MAC, with the other holding key + global key for the corresponding half of the
/// bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthBit(pub bool, pub Mac, pub Key);

impl BitXor for AuthBit {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        AuthBit(self.0 ^ rhs.0, self.1 ^ rhs.1, self.2 ^ rhs.2)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::Error,
        fpre::{f_pre, AuthBit, Delta},
    };

    #[tokio::test]
    async fn xor_homomorphic_mac() -> Result<(), Error> {
        let (mut a, mut b) = f_pre().await;

        // init:
        a.send("delta", &()).await?;
        b.send("delta", &()).await?;
        let delta_a: Delta = a.recv("delta").await?;
        let delta_b: Delta = b.recv("delta").await?;

        // random r1, r2, s1, s2:
        a.send("random shares", &(2 as u32)).await?;
        b.send("random shares", &(2 as u32)).await?;

        let r: Vec<AuthBit> = a.recv("random shares").await?;
        let s: Vec<AuthBit> = b.recv("random shares").await?;

        let (AuthBit(r1, mac_r1, key_s1), AuthBit(r2, mac_r2, key_s2)) = (r[0], r[1]);
        let (AuthBit(s1, mac_s1, key_r1), AuthBit(s2, mac_s2, key_r2)) = (s[0], s[1]);

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
            let (mut a, mut b) = f_pre().await;

            // init:
            a.send("delta", &()).await?;
            b.send("delta", &()).await?;
            let delta_a: Delta = a.recv("delta").await?;
            let delta_b: Delta = b.recv("delta").await?;

            // random r1, r2, s1, s2:
            a.send("random shares", &(2 as u32)).await?;
            b.send("random shares", &(2 as u32)).await?;

            let r: Vec<AuthBit> = a.recv("random shares").await?;
            let s: Vec<AuthBit> = b.recv("random shares").await?;

            let (auth_r1, auth_r2) = (r[0], r[1]);
            let (auth_s1, auth_s2) = (s[0], s[1]);

            let AuthBit(r1, mac_r1, key_s1) = auth_r1;
            let AuthBit(s1, _, key_r1) = auth_s1;
            let AuthBit(r2, _, _) = auth_r2;
            let AuthBit(s2, _, _) = auth_s2;

            if i == 0 {
                // uncorrupted authenticated (r1 XOR s1) AND (r2 XOR s2):
                a.send("AND shares", &vec![(auth_r1, auth_r2)]).await?;
                b.send("AND shares", &vec![(auth_s1, auth_s2)]).await?;
                let AuthBit(r3, mac_r3, key_s3) = a.recv::<Vec<AuthBit>>("AND shares").await?[0];
                let AuthBit(s3, mac_s3, key_r3) = b.recv::<Vec<AuthBit>>("AND shares").await?[0];
                assert_eq!(r3 ^ s3, (r1 ^ s1) & (r2 ^ s2));
                assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
                assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
            } else if i == 1 {
                // corrupted (r1 XOR s1) AND (r2 XOR s2):
                let auth_r1_corrupted = AuthBit(!r1, mac_r1, key_s1);
                a.send("AND shares", &vec![(auth_r1_corrupted, auth_r2)])
                    .await?;
                b.send("AND shares", &vec![(auth_s1, auth_s2)]).await?;
                assert_eq!(a.recv::<String>("AND shares").await?, "CheatingDetected");
                assert_eq!(b.recv::<String>("AND shares").await?, "CheatingDetected");
            } else if i == 2 {
                // A would need knowledge of B's key and delta to corrupt the shared secret:
                let mac_r1_corrupted = key_r1 ^ (!r1 & delta_b);
                let auth_r1_corrupted = AuthBit(!r1, mac_r1_corrupted, key_s1);
                a.send("AND shares", &vec![(auth_r1_corrupted, auth_r2)])
                    .await?;
                b.send("AND shares", &vec![(auth_s1, auth_s2)]).await?;
                assert_eq!(a.recv::<Vec<AuthBit>>("AND shares").await?.len(), 1);
                assert_eq!(b.recv::<Vec<AuthBit>>("AND shares").await?.len(), 1);
            }
        }
        Ok(())
    }
}
