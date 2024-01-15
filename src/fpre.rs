//! An implementation of the FPre ideal functionality from the paper
//! [Authenticated Garbling and Efficient Maliciously Secure Two-Party Computation](https://acmccs.github.io/papers/p21-wangA.pdf)
//! as a third party that communicates with two parties over channels.

use std::{
    ops::{BitAnd, BitXor},
    thread,
};

use rand::random;
use serde::{Deserialize, Serialize};

use crate::channel::{self, Channel, SyncChannel};

/// Implements FPre as a trusted dealer.
///
/// Returns communication channels for the parties A and B that can be used to send and receive
/// messages to and from FPre.
pub fn f_pre() -> (SyncChannel, SyncChannel) {
    let (a, fpre_a) = SyncChannel::channels();
    let (b, fpre_b) = SyncChannel::channels();
    thread::spawn(move || {
        if let Err(e) = fpre_channel(&fpre_a, &fpre_b) {
            let _ = fpre_a.send("error", &format!("{e:?}"));
            let _ = fpre_b.send("error", &format!("{e:?}"));
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

fn fpre_channel(fpre_a: &SyncChannel, fpre_b: &SyncChannel) -> Result<(), Error> {
    let _: () = fpre_a.recv("delta (fpre)")?;
    let _: () = fpre_b.recv("delta (fpre)")?;
    let delta_a = Delta(random());
    let delta_b = Delta(random());
    fpre_a.send("delta (fpre)", &delta_a)?;
    fpre_b.send("delta (fpre)", &delta_b)?;

    let random_a: u32 = fpre_a.recv("random shares (fpre)")?;
    let random_b: u32 = fpre_b.recv("random shares (fpre)")?;
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
    fpre_a.send("random shares (fpre)", &random_shares_a)?;
    fpre_b.send("random shares (fpre)", &random_shares_b)?;

    let shares_a: Vec<(AuthBit, AuthBit)> = fpre_a.recv("AND shares (fpre)")?;
    let shares_b: Vec<(AuthBit, AuthBit)> = fpre_b.recv("AND shares (fpre)")?;
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
    fpre_a.send("AND shares (fpre)", &and_shares_a)?;
    fpre_b.send("AND shares (fpre)", &and_shares_b)?;
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
