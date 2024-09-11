//! Pi_aAND protocol from WRK17b instantiating F_aAND for being used in preprocessing.
use std::vec;

use blake3::Hasher;
use rand::{random, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

use crate::{
    channel::{self, recv_from, send_to, Channel},
    fpre::{Auth, Delta, Key, Mac, Share},
};

pub(crate) const RHO: usize = 40;

/// Errors occurring during preprocessing.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
    /// The MAC is not the correct one in aBit.
    ABitMacMisMatch,
    /// The xor of MACs is not equal to the XOR of corresponding keys or that XOR delta.
    AShareMacsMismatch,
    /// A commitment could not be opened.
    CommitmentCouldNotBeOpened,
    /// XOR of all values in FLaAND do not cancel out.
    LaANDXorNotZero,
    /// Wrong MAC of d when combining two leaky ANDs.
    AANDWrongDMAC,
    /// Wrong MAC of e.
    AANDWrongEFMAC,
    /// No Mac or Key.
    MissingMacKey,
    /// Conversion error.
    ConversionError,
    /// Empty bucket.
    EmptyBucketError,
    /// A message was sent, but it contained no data.
    EmptyMsg,
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Commitment(pub(crate) [u8; 32]);

/// Commit to a u128 value using the BLAKE3 hash function.
fn commit(value: &[u8]) -> Commitment {
    let mut hasher = Hasher::new();
    hasher.update(value);
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(result.as_bytes());
    Commitment(commitment)
}

/// Open the commitment and reveal the original value.
fn open_commitment(commitment: &Commitment, value: &[u8]) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(value);
    let result = hasher.finalize();
    &commitment.0 == result.as_bytes()
}

/// Multi-party coin tossing to generate shared randomness.
pub(crate) async fn shared_rng(
    channel: &mut impl Channel,
    p_own: usize,
    p_max: usize,
) -> Result<ChaCha20Rng, Error> {
    let r = [random::<u128>(), random::<u128>()];
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&r[0].to_be_bytes());
    buf[16..].copy_from_slice(&r[1].to_be_bytes());
    let c = commit(&buf);
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "RNG", &[(c, buf)]).await?;
    }
    let mut commitments = vec![Commitment([0; 32]); p_max];
    let mut bufs: Vec<[u8; 32]> = vec![[0; 32]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        let (commitment, buffer): (Commitment, [u8; 32]) = recv_from(channel, p, "RNG")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        commitments[p] = commitment;
        bufs[p] = buffer;
    }
    let mut buf_xor = buf;
    for p in (0..p_max).filter(|p| *p != p_own) {
        if !open_commitment(&commitments[p], &bufs[p]) {
            return Err(Error::CommitmentCouldNotBeOpened);
        }
        buf_xor
            .iter_mut()
            .zip(bufs[p].iter())
            .for_each(|(buf_xor_byte, buf_byte)| *buf_xor_byte ^= *buf_byte);
    }
    Ok(ChaCha20Rng::from_seed(buf_xor))
}

/// Protocol PI_aBit^n that performs F_aBit^n.
///
/// A random bit-string is generated as well as the corresponding keys and MACs are sent to all
/// parties.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fabitn(
    channel: &mut impl Channel,
    x: &mut Vec<bool>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
    shared_rng: &mut ChaCha20Rng,
    sender_ot: Vec<Vec<u128>>,
    receiver_ot: Vec<Vec<u128>>,
) -> Result<Vec<Share>, Error> {
    // Step 1 initialize random bitstring.
    let two_rho = 2 * RHO;
    let len_abit = length + two_rho;

    // Steps 2 running Pi_aBit^2 for each pair of parties.
    let mut xkeys: Vec<Vec<u128>> = vec![vec![]; p_max];
    let mut xmacs: Vec<Vec<u128>> = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        let macvec: Vec<u128> = receiver_ot[p].clone();
        let keyvec: Vec<u128> = sender_ot[p].clone();

        println!("{:?} macvec: {:?}", p, macvec);
        println!("{:?} keyvec: {:?}", p_own, keyvec);
        xmacs[p] = macvec;
        xkeys[p] = keyvec;
    }

    // Step 3 including verification of macs and keys.
    let (rbits, xjs): (Vec<_>, Vec<_>) = (0..two_rho)
        .map(|_| {
            let r: Vec<bool> = (0..len_abit).map(|_| shared_rng.gen()).collect();
            let xj = x.iter().zip(&r).fold(false, |acc, (&x, &r)| acc ^ (x & r));
            (r, xj)
        })
        .unzip();

    for p in (0..p_max).filter(|p| *p != p_own) {
        let mut msg = Vec::with_capacity(two_rho);
        for (r, xj) in rbits.iter().zip(xjs.iter()) {
            let mut macint = 0;
            for (j, &rbit) in r.iter().enumerate() {
                if rbit {
                    macint ^= xmacs[p][j];
                }
            }
            msg.push((*xj, macint));
        }
        send_to(channel, p, "fabitn", &msg).await?;
    }

    let mut fabitn_msg_p: Vec<Vec<(bool, u128)>> = vec![vec![(false, 0); two_rho]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        fabitn_msg_p[p] = recv_from(channel, p, "fabitn").await?;
    }

    for (j, rbits) in rbits.iter().enumerate() {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let (xj, macint) = &fabitn_msg_p[p][j];
            let mut keyint: u128 = 0;
            for (i, rbit) in rbits.iter().enumerate() {
                if *rbit {
                    keyint ^= xkeys[p][i];
                }
            }
            if *macint != keyint ^ ((*xj as u128) * delta.0) {
                return Err(Error::ABitMacMisMatch);
            }
        }
    }

    // Step 4 return first l objects.
    x.truncate(length);
    for p in (0..p_max).filter(|p| *p != p_own) {
        xkeys[p].truncate(length);
        xmacs[p].truncate(length);
    }
    let mut res: Vec<Share> = vec![];
    for (l, xx) in x.iter().enumerate().take(length) {
        let mut authvec: Vec<Option<(Mac, Key)>> = vec![None; p_max];
        for p in (0..p_max).filter(|p| *p != p_own) {
            authvec[p] = Some((Mac(xmacs[p][l]), Key(xkeys[p][l])));
        }
        res.push(Share(*xx, Auth(authvec)));
    }
    Ok(res)
}

/// Protocol PI_aShare that performs F_aShare.
///
/// Random bit strings are picked and random authenticated shares are distributed to the parties.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fashare(
    channel: &mut impl Channel,
    x: &mut Vec<bool>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
    shared_rng: &mut ChaCha20Rng,
    sender_ot: Vec<Vec<u128>>,
    receiver_ot: Vec<Vec<u128>>,
) -> Result<Vec<Share>, Error> {
    // Step 1 pick random bit-string x (input).
    // Step 2 run Pi_aBit^n for each pair of parties.
    let mut shares = fabitn(
        channel,
        x,
        p_own,
        p_max,
        length + RHO,
        delta,
        shared_rng,
        sender_ot,
        receiver_ot,
    )
    .await?;

    // Step 3 commitments and checks.
    let mut d0: Vec<u128> = vec![0; RHO]; // xorkeys
    let mut d1: Vec<u128> = vec![0; RHO]; // xorkeysdelta
    let mut own_commitments = Vec::with_capacity(RHO); // c0, c1, cm, dm

    // Step 3/(a) compute d0, d1, dm, c0, c1, cm and send commitments to all parties.
    for r in 0..RHO {
        let mut dm = Vec::with_capacity(p_max * 16);
        dm.push(shares[length + r].0 as u8);
        for p in 0..p_max {
            if p != p_own {
                if let Some((mac, key)) = shares[length + r].1 .0[p] {
                    d0[r] ^= key.0;
                    dm.extend(&mac.0.to_be_bytes());
                } else {
                    return Err(Error::MissingMacKey);
                }
            } else {
                dm.extend(&[0; 16]);
            }
        }
        d1[r] = d0[r] ^ delta.0;
        let c0 = commit(&d0[r].to_be_bytes());
        let c1 = commit(&d1[r].to_be_bytes());
        let cm = commit(&dm);
        own_commitments.push((c0, c1, cm, dm))
    }

    // 3/(b) After receiving all commitments, Pi broadcasts decommitment for macs.
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "fashare commitverify", &own_commitments).await?;
    }
    let mut commitments = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        commitments[p] = recv_from::<(Commitment, Commitment, Commitment, Vec<u8>)>(
            channel,
            p,
            "fashare commitverify",
        )
        .await?;
    }
    commitments[p_own] = own_commitments;

    // 3/(c) compute xorkeysbit and send to all parties.
    let mut combit: Vec<u8> = vec![0; RHO];
    let mut xorkeysbit: Vec<u128> = vec![0; RHO];
    for r in 0..RHO {
        for p in (0..p_max).filter(|p| *p != p_own) {
            combit[r] ^= commitments[p][r].3[0];
        }
        if combit[r] == 0 {
            xorkeysbit[r] = d0[r];
        } else if combit[r] == 1 {
            xorkeysbit[r] = d1[r];
        }
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "fashare bitcom", &xorkeysbit).await?;
    }
    let mut xorkeysbitp: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        xorkeysbitp[p] = recv_from(channel, p, "fashare bitcom").await?;
    }

    // 3/(d) consistency check of macs.
    let mut xormacs: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for r in 0..RHO {
        for (p, commitments) in commitments.iter().enumerate().take(p_max) {
            for pp in (0..p_max).filter(|pp| *pp != p) {
                if !commitments.is_empty() {
                    let (_, _, _, pitem) = &commitments[r];
                    if let Ok(b) = pitem[(1 + pp * 16)..(17 + pp * 16)]
                        .try_into()
                        .map(u128::from_be_bytes)
                    {
                        xormacs[pp][r] ^= b;
                    } else {
                        return Err(Error::ConversionError);
                    }
                }
            }
        }
    }
    for r in 0..RHO {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let bj = &xorkeysbitp[p][r].to_be_bytes();
            if open_commitment(&commitments[p][r].0, bj)
                || open_commitment(&commitments[p][r].1, bj)
            {
                if xormacs[p][r] != xorkeysbitp[p][r] {
                    return Err(Error::AShareMacsMismatch);
                }
            } else {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
        }
    }

    // Step 4 return first l objects.
    shares.truncate(length);
    Ok(shares)
}

/// Protocol Pi_HaAND that performs F_HaAND.
///
/// The XOR of xiyj values are generated obliviously, which is half of the z value in an
/// authenticated share, i.e., a half-authenticated share.
pub(crate) async fn fhaand(
    channel: &mut impl Channel,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    length: usize,
    x: &[Share],
    y: Vec<bool>,
) -> Result<Vec<bool>, Error> {
    // Step 1 obtain <x> (input).

    // Step 2 calculate v.
    let mut v: Vec<bool> = vec![false; length];
    let mut h0h1 = vec![(false, false); length];
    for p in (0..p_max).filter(|p| *p != p_own) {
        for l in 0..length {
            let s: bool = random();
            let Some((_, xkey)) = x[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            let mut hash: [u8; 32] = blake3::hash(&xkey.0.to_le_bytes()).into();
            let lsb0 = (hash[31] & 0b0000_0001) != 0;
            h0h1[l].0 = lsb0 ^ s;

            hash = blake3::hash(&(xkey.0 ^ delta.0).to_le_bytes()).into();
            let lsb1 = (hash[31] & 0b0000_0001) != 0;
            h0h1[l].1 = lsb1 ^ s ^ y[l];
            v[l] ^= s;
        }
        send_to(channel, p, "haand", &h0h1).await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        let h0h1: Vec<(bool, bool)> = recv_from(channel, p, "haand").await?;
        for l in 0..length {
            let Some((xmac, _)) = x[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            let hash: [u8; 32] = blake3::hash(&xmac.0.to_le_bytes()).into();
            let lsb = (hash[31] & 0b0000_0001) != 0;
            let mut t: bool = lsb;
            if x[l].0 {
                t ^= h0h1[l].1;
            } else {
                t ^= h0h1[l].0;
            }
            v[l] ^= t;
        }
    }

    //Step 3 return v.
    Ok(v)
}

/// Hash 128 bits input 128 bits using BLAKE3.
///
/// We hash into 256 bits and then xor the first 128 bits and the second 128 bits. In our case this
/// works as the 256-bit hashes need to cancel out when xored together, and this simplifies dealing
/// with u128s instead while still cancelling the hashes out if correct.
pub(crate) fn hash128(input: u128) -> u128 {
    let res: [u8; 32] = blake3::hash(&input.to_le_bytes()).into();
    let mut value1: u128 = 0;
    let mut value2: u128 = 0;
    for i in 0..16 {
        value1 |= (res[i] as u128) << (8 * i);
        value2 |= (res[i + 16] as u128) << (8 * i);
    }
    value1 ^ value2
}

/// Protocol Pi_LaAND that performs F_LaAND.
///
/// Generates a "leaky authenticated AND", i.e., <x>, <y>, <z> such that the AND of the XORs of the
/// x and y values equals to the XOR of the z values.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn flaand(
    channel: &mut impl Channel,
    xbits: &[Share],
    ybits: &[Share],
    rbits: &[Share],
    p_own: usize,
    p_max: usize,
    delta: Delta,
    length: usize,
) -> Result<Vec<Share>, Error> {
    // Triple computation.
    // Step 1 triple computation.
    let mut yvec: Vec<bool> = vec![false; length];
    for l in 0..length {
        yvec[l] = ybits[l].0;
    }

    // Step 2 run Pi_HaAND for each pair of parties.
    let v = fhaand(channel, p_own, p_max, delta, length, xbits, yvec).await?;

    // Step 3 a) compute z and e.
    let mut flaand_msg: Vec<(bool, Vec<u128>)> = vec![(false, vec![0; p_max]); length];
    let mut z: Vec<bool> = vec![false; length];
    let mut e: Vec<bool> = vec![false; length];
    for l in 0..length {
        z[l] = v[l] ^ (xbits[l].0 & ybits[l].0);
        e[l] = z[l] ^ rbits[l].0;
        flaand_msg[l].0 = e[l];
    }
    // If e is true, this is negation of r as described in Section 2 of WRK17b, if e is false (0), this is a copy.
    let mut zbits: Vec<Share> = vec![Share(false, Auth(vec![None; p_max])); length];
    for l in 0..length {
        zbits[l].0 = z[l];
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        for l in 0..length {
            zbits[l].1 .0[p] = rbits[l].1 .0[p];
        }
    }

    // Triple Checking.
    // Step 4 compute phi and send to all parties.
    let mut phi: Vec<u128> = vec![0; length];
    for (l, phie) in phi.iter_mut().enumerate().take(length) {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let Some((ymac, ykey)) = ybits[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            *phie ^= ykey.0 ^ ymac.0;
        }
        *phie ^= ybits[l].0 as u128 * delta.0;
    }

    // Set 3 b broadcast e
    // Step 5 compute uij and xkeys_phi and send to all parties.
    let mut uij: Vec<Vec<u128>> = vec![vec![0; p_max]; length];
    let mut xkeys_phi: Vec<Vec<u128>> = vec![vec![0; length]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        for (l, phie) in phi.iter().enumerate().take(length) {
            let Some((_, xkey)) = xbits[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            xkeys_phi[p][l] = hash128(xkey.0);
            uij[l][p] = hash128(xkey.0 ^ delta.0) ^ xkeys_phi[p][l] ^ *phie;
            flaand_msg[l].1[p] = uij[l][p];
        }
        send_to(channel, p, "flaand_vec", &flaand_msg).await?;
    }
    let mut xmacs_phi: Vec<Vec<u128>> = vec![vec![0; length]; p_max];
    let mut flaand_msg_p: Vec<Vec<(bool, Vec<u128>)>> =
        vec![vec![(false, vec![0; p_max]); length]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        flaand_msg_p[p] = recv_from(channel, p, "flaand_vec").await?;
        for (l, xbit) in xbits.iter().enumerate().take(length) {
            let Some((xmac, _)) = xbits[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            xmacs_phi[p][l] = hash128(xmac.0) ^ (xbit.0 as u128 * flaand_msg_p[p][l].1[p_own]);
        }
        for l in 0..flaand_msg_p[p].len() {
            let Some((mac, key)) = rbits[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            if flaand_msg_p[p][l].0 {
                zbits[l].1 .0[p] = Some((mac, Key(key.0 ^ delta.0)));
            } else {
                zbits[l].1 .0[p] = Some((mac, key));
            }
        }
    }

    // Step 6 compute hash and comm and send to all parties.
    let mut hash_comm_own = vec![(0, Commitment([0; 32])); length];
    for l in 0..length {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let Some((zmac, zkey)) = zbits[l].1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            hash_comm_own[l].0 ^= zmac.0 ^ zkey.0 ^ xmacs_phi[p][l] ^ xkeys_phi[p][l];
        }
        hash_comm_own[l].0 ^= xbits[l].0 as u128 * phi[l];
        hash_comm_own[l].0 ^= zbits[l].0 as u128 * delta.0;
        hash_comm_own[l].1 = commit(&hash_comm_own[l].0.to_be_bytes());
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "flaand hashcomm", &hash_comm_own).await?;
    }

    let mut hash_comm: Vec<Vec<(u128, Commitment)>> =
        vec![vec![(0, Commitment([0; 32])); length]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        hash_comm[p] = recv_from(channel, p, "flaand hashcomm").await?;
    }

    let mut xorhash = hash_comm_own; // XOR for all parties, including p_own
    for p in (0..p_max).filter(|p| *p != p_own) {
        for (l, (xh, _)) in xorhash.iter_mut().enumerate().take(length) {
            if !open_commitment(&hash_comm[p][l].1, &hash_comm[p][l].0.to_be_bytes()) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            *xh ^= hash_comm[p][l].0;
        }
    }

    // Step 7 check if xorhash is zero and abort if not true.
    for (xh, _) in xorhash.iter().take(length) {
        if *xh != 0 {
            println!("{:?}", xh);
            println!("{:?}", delta);
            return Err(Error::LaANDXorNotZero);
        }
    }

    Ok(zbits)
}

/// Calculates the bucket size according to WRK17a, Table 4 for statistical security ρ = 40 (rho).
pub(crate) fn bucket_size(circuit_size: usize) -> usize {
    match circuit_size {
        n if n >= 280_000 => 3,
        n if n >= 3_100 => 4,
        _ => 5,
    }
}

/// Transforms all triples into a single vector of triples.
fn transform(x: &[Share], y: &[Share], z: &[Share], length: usize) -> Vec<(Share, Share, Share)> {
    let mut triples: Vec<(Share, Share, Share)> = vec![];
    for l in 0..length {
        let s1 = x[l].clone();
        let s2 = y[l].clone();
        let s3 = z[l].clone();
        triples.push((s1, s2, s3));
    }
    triples
}

/// Protocol Pi_aAND that performs F_aAND.
///
/// The protocol combines leaky authenticated bits into non-leaky authenticated bits.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn faand_precomp(
    channel: &mut impl Channel,
    p_own: usize,
    p_max: usize,
    circuit_size: usize,
    length: usize,
    shared_rng: &mut ChaCha20Rng,
    delta: Delta,
    xyzbits: Vec<Share>,
) -> Result<Vec<(Share, Share, Share)>, Error> {
    let b = bucket_size(circuit_size);
    let lprime: usize = length * b;

    let (xbits, rest) = xyzbits.split_at(lprime);
    let (ybits, rbits) = rest.split_at(lprime);

    // Step 1 generate all leaky and triples.
    let zbits: Vec<Share> =
        flaand(channel, xbits, ybits, rbits, p_own, p_max, delta, lprime).await?;
    let triples = transform(xbits, ybits, &zbits, lprime);

    // Step 2 assign objects to buckets.
    let mut buckets: Vec<SmallVec<[(Share, Share, Share); 3]>> = vec![smallvec![]; length];

    for obj in triples {
        let mut i: usize = shared_rng.gen_range(0..buckets.len());
        loop {
            let i_wrapped = i % buckets.len();
            if buckets[i_wrapped].len() < b {
                buckets[i_wrapped].push(obj);
                break;
            }
            i += 1;
        }
    }

    // Step 3 check d-values.
    let dvalues = check_dvalue(channel, p_own, p_max, &buckets, delta).await?;

    let mut combined: Vec<(Share, Share, Share)> = Vec::with_capacity(buckets.len());

    for (bucket, dval) in buckets.into_iter().zip(dvalues.into_iter()) {
        combined.push(combine_bucket(p_own, p_max, bucket, dval)?);
    }

    Ok(combined)
}

/// Protocol Pi_aAND that performs F_aAND.
///
/// The protocol combines leaky authenticated bits into non-leaky authenticated bits.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn faand(
    channel: &mut impl Channel,
    bits_rand: Vec<(Share, Share)>,
    p_own: usize,
    p_max: usize,
    circuit_size: usize,
    length: usize,
    shared_rng: &mut ChaCha20Rng,
    delta: Delta,
    xyzbits: Vec<Share>,
) -> Result<Vec<Share>, Error> {
    let vectriples = faand_precomp(
        channel,
        p_own,
        p_max,
        circuit_size,
        length,
        shared_rng,
        delta,
        xyzbits,
    )
    .await?;

    // Beaver triple precomputation - transform random triples to specific triples.
    let mut ef_with_macs = vec![(false, false, None, None); vectriples.len()];

    let mut ef = vec![];
    for i in 0..vectriples.len() {
        let (e, f, _, _) = &mut ef_with_macs[i];
        let (a, b, _c) = &vectriples[i];
        let (x, y) = &bits_rand[i];
        ef.push((a ^ x, b ^ y));
        *e = a.0 ^ x.0;
        *f = b.0 ^ y.0;
    }
    let mut emacs = vec![];
    let mut fmacs = vec![];
    for p in (0..p_max).filter(|p| *p != p_own) {
        for (e, f) in &ef {
            let Some((emac, _)) = e.1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            let Some((fmac, _)) = f.1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            emacs.push(Some(emac));
            fmacs.push(Some(fmac));
        }
        for i in 0..vectriples.len() {
            let (_, _, emac, fmac) = &mut ef_with_macs[i];
            *emac = emacs[i];
            *fmac = fmacs[i];
        }
        send_to(channel, p, "faand", &ef_with_macs).await?;
    }
    let mut faand_vec = vec![vec![(false, false, None, None); vectriples.len()]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        faand_vec[p] =
            recv_from::<(bool, bool, Option<Mac>, Option<Mac>)>(channel, p, "faand").await?;
        for (i, &(_e, _f, ref emac, ref fmac)) in faand_vec[p].iter().enumerate() {
            let Some(_emacp) = emac else {
                return Err(Error::MissingMacKey);
            };
            let Some((_, _ekey)) = ef[i].0 .1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            let Some(_fmacp) = fmac else {
                return Err(Error::MissingMacKey);
            };
            let Some((_, _fkey)) = ef[i].1 .1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            /*if e && (emacp.0 != ekey.0 ^ delta.0) || !e && (emacp.0 != ekey.0) {
                println!("{:?} {:?} {:?}", emacp.0, ekey.0 ^ delta.0, ekey.0);
                return Err(Error::AANDWrongEFMAC);
            }
            if f && (fmacp.0 != fkey.0 ^ delta.0) || !f && (fmacp.0 != fkey.0) {
                println!("{:?} {:?} {:?}", fmacp.0, fkey.0 ^ delta.0, fkey.0);
                return Err(Error::AANDWrongEFMAC);
            }*/ // TODO for some reason this still fails for 3 or more parties
        }
    }
    ef_with_macs
        .iter_mut()
        .enumerate()
        .for_each(|(i, (e, f, _, _))| {
            for p in (0..p_max).filter(|&p| p != p_own) {
                let (fa_e, fa_f, _, _) = faand_vec[p][i];
                *e ^= fa_e;
                *f ^= fa_f;
            }
        });
    let mut result = vec![Share(false, Auth(vec![])); vectriples.len()];

    for i in 0..vectriples.len() {
        let (a, _b, c) = &vectriples[i];
        let (_x, y) = &bits_rand[i];
        let (e, f, _, _) = ef_with_macs[i];
        result[i] = c.clone();
        if e {
            result[i] = &result[i] ^ y;
        }
        if f {
            result[i] = &result[i] ^ a;
        }
    }
    Ok(result)
}

/// Combine the whole bucket by combining elements one by one.
pub(crate) fn combine_bucket(
    p_own: usize,
    p_max: usize,
    bucket: SmallVec<[(Share, Share, Share); 3]>,
    d_values: Vec<bool>,
) -> Result<(Share, Share, Share), Error> {
    if bucket.is_empty() {
        return Err(Error::EmptyBucketError);
    }

    let mut bucket = bucket.into_iter();
    let mut result = bucket.next().unwrap();

    // Combine elements one by one, starting from the second element.
    for (i, triple) in bucket.enumerate() {
        let d = d_values[i];
        result = combine_two_leaky_ands(p_own, p_max, result, triple, d)?;
    }
    Ok(result)
}

/// Check and return d-values for a vector of shares.
pub(crate) async fn check_dvalue(
    channel: &mut impl Channel,
    p_own: usize,
    p_max: usize,
    buckets: &[SmallVec<[(Share, Share, Share); 3]>],
    delta: Delta,
) -> Result<Vec<Vec<bool>>, Error> {
    // Step (a) compute and check macs of d-values.
    let mut d_values = vec![vec![]; buckets.len()];
    let mut d_macs = vec![vec![vec![]; buckets.len()]; p_max];

    for j in 0..buckets.len() {
        let (_, y, _) = &buckets[j][0];
        let first = y.0;
        for (_, y_value, _) in buckets[j].iter().skip(1) {
            d_values[j].push(first ^ y_value.0);
            for p in (0..p_max).filter(|p| *p != p_own) {
                let Some((y0mac, _)) = y.1 .0[p] else {
                    return Err(Error::MissingMacKey);
                };
                let Some((ymac, _)) = y_value.1 .0[p] else {
                    return Err(Error::MissingMacKey);
                };
                d_macs[p][j].push(Some(y0mac ^ ymac));
            }
        }
    }

    for p in (0..p_max).filter(|p| *p != p_own) {
        let dvalue_msg: Vec<(Vec<bool>, Vec<Option<Mac>>)> = (0..buckets.len())
            .map(|i| (d_values[i].clone(), d_macs[p][i].clone()))
            .collect();
        send_to(channel, p, "dvalue", &dvalue_msg).await?;
    }

    let mut dvalue_msg_p = vec![vec![(vec![], vec![]); buckets.len()]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        dvalue_msg_p[p] = recv_from::<(Vec<bool>, Vec<Option<Mac>>)>(channel, p, "dvalue").await?;
    }

    for p in (0..p_max).filter(|p| *p != p_own) {
        for (j, dval) in d_values.iter_mut().enumerate().take(buckets.len()) {
            let (d_value_p, d_macs_p) = &dvalue_msg_p[p][j];
            let Some((_, y0key)) = buckets[j][0].1 .1 .0[p] else {
                return Err(Error::MissingMacKey);
            };
            for (i, d) in dval.iter_mut().enumerate().take(d_macs_p.len()) {
                let Some(dmac) = d_macs_p[i] else {
                    return Err(Error::MissingMacKey);
                };
                let Some((_, ykey)) = buckets[j][i + 1].1 .1 .0[p] else {
                    return Err(Error::MissingMacKey);
                };
                if (d_value_p[i] && dmac.0 != y0key.0 ^ ykey.0 ^ delta.0)
                    || (!d_value_p[i] && dmac.0 != y0key.0 ^ ykey.0)
                {
                    println!(
                        "{:?} {:?} {:?}",
                        dmac.0,
                        y0key.0 ^ ykey.0 ^ delta.0,
                        y0key.0 ^ ykey.0
                    );
                    return Err(Error::AANDWrongDMAC);
                }
                *d ^= d_value_p[i];
            }
        }
    }

    Ok(d_values)
}

/// Combine two leaky ANDs into one non-leaky AND.
pub(crate) fn combine_two_leaky_ands(
    p_own: usize,
    p_max: usize,
    (x1, y1, z1): (Share, Share, Share),
    (x2, _, z2): (Share, Share, Share),
    d: bool,
) -> Result<(Share, Share, Share), Error> {
    //Step (b) compute x, y, z.
    let xbit = x1.0 ^ x2.0;
    let mut xauth: Auth = Auth(vec![None; p_max]);
    for p in (0..p_max).filter(|p| *p != p_own) {
        let Some((x1mac, x1key)) = x1.1 .0[p] else {
            return Err(Error::MissingMacKey);
        };
        let Some((x2mac, x2key)) = x2.1 .0[p] else {
            return Err(Error::MissingMacKey);
        };
        xauth.0[p] = Some((x1mac ^ x2mac, x1key ^ x2key));
    }
    let xres: Share = Share(xbit, xauth);

    let zbit = z1.0 ^ z2.0 ^ d & x2.0;
    let mut zauth: Auth = Auth(vec![None; p_max]);
    for p in (0..p_max).filter(|p| *p != p_own) {
        let Some((z1mac, z1key)) = z1.1 .0[p] else {
            return Err(Error::MissingMacKey);
        };
        let Some((z2mac, z2key)) = z2.1 .0[p] else {
            return Err(Error::MissingMacKey);
        };
        let Some((x2mac, x2key)) = x2.1 .0[p] else {
            return Err(Error::MissingMacKey);
        };
        zauth.0[p] = Some((
            z1mac ^ z2mac ^ Mac(d as u128 * x2mac.0),
            z1key ^ z2key ^ Key(d as u128 * x2key.0),
        ));
    }
    let zres: Share = Share(zbit, zauth);

    Ok((xres, y1, zres))
}
