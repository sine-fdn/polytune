//! Data types used across difference parts of the SMPC engine.

use std::ops::{BitAnd, BitXor};

use serde::{Deserialize, Serialize};

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

    pub(crate) fn macs(&self) -> Vec<Mac> {
        self.1.macs()
    }

    pub(crate) fn xor_keys(&self) -> Key {
        self.1.xor_keys()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Auth(pub(crate) Vec<(Mac, Key)>);

impl BitXor for &Auth {
    type Output = Auth;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let Auth(auth0) = self;
        let Auth(auth1) = rhs;
        let mut xor = Vec::with_capacity(auth0.len());
        for ((mac1, key1), (mac2, key2)) in auth0.iter().zip(auth1.iter()) {
            xor.push((*mac1 ^ *mac2, *key1 ^ *key2));
        }
        Auth(xor)
    }
}

impl Auth {
    pub(crate) fn macs(&self) -> Vec<Mac> {
        self.0.iter().map(|(mac, _)| *mac).collect()
    }

    pub(crate) fn xor_keys(&self) -> Key {
        let mut k = 0;
        for (_, key) in &self.0 {
            k ^= key.0;
        }
        Key(k)
    }

    pub(crate) fn xor_key(mut self, i: usize, delta: Delta) -> Auth {
        for (j, (_, key)) in self.0.iter_mut().enumerate() {
            if i == j {
                key.0 ^= delta.0;
            }
        }
        self
    }
}

/// Preprocessed AND gates that need to be sent to the circuit evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GarbledGate(pub(crate) [Vec<u8>; 4]);

/// A label for a particular wire in the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Label(pub(crate) u128);

impl BitXor for Label {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<Delta> for Label {
    type Output = Self;

    fn bitxor(self, rhs: Delta) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<Mac> for Label {
    type Output = Self;

    fn bitxor(self, rhs: Mac) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<Key> for Label {
    type Output = Self;

    fn bitxor(self, rhs: Key) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}
