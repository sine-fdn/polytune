use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand::rngs::OsRng;

use crate::otext::constants::{ALICE, BOB};
use crate::channel::{MsgChannel, Channel};
use crate::otext::block::Block;
use crate::otext::utils::kdf;

use super::block::ZERO_BLOCK;

// Chou-Orlandi OT
pub struct OTCO{}

impl OTCO {
    pub async fn send(&mut self, channel: &mut MsgChannel<impl Channel>, data0: & Vec<Block>, data1: & Vec<Block>, length: usize) {
        let mut rng = OsRng;
        let a = Scalar::random(&mut rng);
        let aa = RISTRETTO_BASEPOINT_POINT * a;
        let aa_inv = aa * -a;

        let mut b = Vec::with_capacity(length);
        let mut ba = Vec::with_capacity(length);


        channel.send_to(ALICE, "asend", &aa).await.unwrap(); //NOT SURE WHICH PARTY IT IS HERE

        for i in 0..length {
            b[i] = channel.recv_from(ALICE, "bsend").await.unwrap();
            b[i] = b[i] * a;
            ba[i] = b[i] + aa_inv;
        }

        let mut res: [Block; 2] = [ZERO_BLOCK; 2];
        for i in 0..length {
            res[0] = kdf(&b[i], i) ^ data0[i];
            res[1] = kdf(&ba[i], i) ^ data1[i];
            channel.send_to(ALICE, "res", &res).await.unwrap();
        }
    }

    pub async fn recv(&mut self, channel: &mut MsgChannel<impl Channel>, data: &mut Vec<Block>, b: Vec<bool>, length: usize) {
        let mut rng = OsRng;

        let mut bb = Vec::with_capacity(length);
        for _ in 0..length {
            bb.push(Scalar::random(&mut rng));
        }

        let a: RistrettoPoint = channel.recv_from(BOB, "asend").await.unwrap();
        let mut bigb = Vec::with_capacity(length);
        let mut a_s = Vec::with_capacity(length);

        for i in 0..length {
            bigb[i] = RISTRETTO_BASEPOINT_POINT * bb[i];
            if b[i] {
                bigb[i] += a;
            }
            channel.send_to(BOB, "bsend", &bigb[i]).await.unwrap();
        }

        for i in 0..length {
            a_s[i] = a * bb[i];
        }

        for i in 0..length {
            let res: [Block; 2] = channel.recv_from(BOB, "res").await.unwrap();
            let kdf_result = kdf(&a_s[i], i);
            if b[i] {
                data[i] = kdf_result ^ res[1];
            } else {
                data[i] = kdf_result ^ res[0];
            }
        }
    }
}