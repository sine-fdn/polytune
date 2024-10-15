//! Pi_aAND protocol from WRK17b instantiating F_aAND for being used in preprocessing.
use std::vec;

use blake3::Hasher;
use rand::{random, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

use crate::{
    channel::{self, recv_from, recv_vec_from, send_to, Channel},
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
    /// Invalid array length.
    InvalidLength,
    /// Invalid data in OT.
    InvalidOTData,
    /// KOS consistency check failed.
    ConsistencyCheckFailed,
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
    i: usize,
    n: usize,
) -> Result<ChaCha20Rng, Error> {
    let r = [random::<u128>(), random::<u128>()];
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&r[0].to_be_bytes());
    buf[16..].copy_from_slice(&r[1].to_be_bytes());
    let c = commit(&buf);
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "RNG comm", &[c]).await?;
    }
    let mut commitments = vec![Commitment([0; 32]); n];
    for k in (0..n).filter(|k| *k != i) {
        let commitment = recv_from::<Commitment>(channel, k, "RNG comm")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        commitments[k] = commitment;
    }
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "RNG ver", &[buf]).await?;
    }
    let mut bufs = vec![[0; 32]; n];
    for k in (0..n).filter(|k| *k != i) {
        let buffer = recv_from::<[u8; 32]>(channel, k, "RNG ver")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        bufs[k] = buffer;
    }
    let mut buf_xor = buf;
    for k in (0..n).filter(|k| *k != i) {
        if !open_commitment(&commitments[k], &bufs[k]) {
            return Err(Error::CommitmentCouldNotBeOpened);
        }
        buf_xor
            .iter_mut()
            .zip(bufs[k].iter())
            .for_each(|(buf_xor_byte, buf_byte)| *buf_xor_byte ^= *buf_byte);
    }
    Ok(ChaCha20Rng::from_seed(buf_xor))
}

/// Protocol PI_aBit^n that performs F_aBit^n.
///
/// A random bit-string is generated as well as the corresponding keys and MACs are sent to all
/// parties.
pub(crate) async fn fabitn(
    (channel, delta): (&mut impl Channel, Delta),
    x: &mut Vec<bool>,
    i: usize,
    n: usize,
    l: usize,
    shared_rng: &mut ChaCha20Rng,
    (sender_ot, receiver_ot): (Vec<Vec<u128>>, Vec<Vec<u128>>),
) -> Result<Vec<Share>, Error> {
    // Step 1) Pick random bit-string x (input) of length lprime.
    let two_rho = 2 * RHO;
    let lprime = l + two_rho;

    // Steps 2) Use the output of the oblivious transfers between each pair of parties to generate keys and macs.
    let mut kk = vec![vec![]; n];
    let mut mm = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        mm[k] = receiver_ot[k].clone();
        kk[k] = sender_ot[k].clone();
    }

    // Step 3) Verification of macs and keys.
    // Step 3 a) Sample 2*RHO random l'-bit strings r.
    let r: Vec<Vec<bool>> = (0..two_rho)
        .map(|_| (0..lprime).map(|_| shared_rng.gen()).collect())
        .collect();

    // Step 3 b) Compute xj and xjmac for each party, broadcast xj.
    // Broadcast includes sending xjmac as well, as from Step 3 d).
    if x.len() < lprime {
        return Err(Error::InvalidLength);
    }

    let mut xj = Vec::with_capacity(two_rho);
    for rbits in &r {
        let mut xm = false;
        for (xi, ri) in x.iter().zip(rbits) {
            xm ^= xi & ri;
        }
        xj.push(xm);
    }

    for k in (0..n).filter(|k| *k != i) {
        let mut xj_xjmac = Vec::with_capacity(two_rho);
        for (r, xj) in r.iter().zip(xj.iter()) {
            let mut xjmac = 0;
            for (j, &rbit) in r.iter().enumerate() {
                if rbit {
                    xjmac ^= mm[k][j];
                }
            }
            xj_xjmac.push((*xj, xjmac));
        }
        send_to(channel, k, "fabitn", &xj_xjmac).await?;
    }

    let mut xj_xjmac_k = vec![vec![(false, 0); two_rho]; n];
    for k in (0..n).filter(|k| *k != i) {
        xj_xjmac_k[k] = recv_vec_from(channel, k, "fabitn", two_rho).await?;
    }

    // Step 3 c) Compute keys.
    for (j, rbits) in r.iter().enumerate() {
        for k in (0..n).filter(|k| *k != i) {
            let (xj, xjmac) = &xj_xjmac_k[k][j];
            let mut xjkey = 0;
            for (i, rbit) in rbits.iter().enumerate() {
                if *rbit {
                    xjkey ^= kk[k][i];
                }
            }
            // Step 3 d) Validity check of macs.
            if *xjmac != xjkey ^ ((*xj as u128) * delta.0) {
                return Err(Error::ABitMacMisMatch);
            }
        }
    }

    // Step 4) Return first l objects.
    x.truncate(l);
    for k in (0..n).filter(|k| *k != i) {
        kk[k].truncate(l);
        mm[k].truncate(l);
    }
    let mut res = Vec::with_capacity(l);
    for (l, xi) in x.iter().enumerate().take(l) {
        let mut authvec = smallvec![None; n];
        for k in (0..n).filter(|k| *k != i) {
            authvec[k] = Some((Mac(mm[k][l]), Key(kk[k][l])));
        }
        res.push(Share(*xi, Auth(authvec)));
    }
    Ok(res)
}

/// Protocol PI_aShare that performs F_aShare.
///
/// Random bit strings are picked and random authenticated shares are distributed to the parties.
pub(crate) async fn fashare(
    (channel, delta): (&mut impl Channel, Delta),
    x: &mut Vec<bool>,
    i: usize,
    n: usize,
    l: usize,
    shared_rng: &mut ChaCha20Rng,
    (sender_ot, receiver_ot): (Vec<Vec<u128>>, Vec<Vec<u128>>),
) -> Result<Vec<Share>, Error> {
    // Step 1) Pick random bit-string x (input).

    // Step 2) Run Pi_aBit^n to compute shares.
    let mut xishares = fabitn(
        (channel, delta),
        x,
        i,
        n,
        l + RHO,
        shared_rng,
        (sender_ot, receiver_ot),
    )
    .await?;

    // Step 3) Compute commitments and verify consistency.
    // Step 3 a) Compute d0, d1, dm, c0, c1, cm and send commitments to all parties.
    let mut d0 = vec![0; RHO];
    let mut d1 = vec![0; RHO];
    let mut c0_c1_cm = Vec::with_capacity(RHO); // c0, c1, cm
    let mut dmvec = Vec::with_capacity(RHO);

    for r in 0..RHO {
        let xishare = &xishares[l + r];
        let mut dm = Vec::with_capacity(n * 16);
        dm.push(xishare.0 as u8);
        for k in 0..n {
            if k != i {
                if let Some((mac, key)) = xishare.1 .0[k] {
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

        c0_c1_cm.push((c0, c1, cm));
        dmvec.push(dm.clone());
    }

    // 3 b) After receiving all commitments, Pi broadcasts decommitment for macs.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "fashare comm", &c0_c1_cm).await?;
    }
    let mut c0_c1_cm_k = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        c0_c1_cm_k[k] =
            recv_vec_from::<(Commitment, Commitment, Commitment)>(channel, k, "fashare comm", RHO)
                .await?;
    }
    c0_c1_cm_k[i] = c0_c1_cm;

    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "fashare ver", &dmvec).await?;
    }
    let mut dm_k = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        dm_k[k] = recv_vec_from::<Vec<u8>>(channel, k, "fashare ver", RHO).await?;
    }
    dm_k[i] = dmvec;

    // 3 c) Compute di_bi and send to all parties.
    let mut bi = [0; RHO];
    let mut di_bi = vec![0; RHO];
    for r in 0..RHO {
        for k in (0..n).filter(|k| *k != i) {
            bi[r] ^= dm_k[k][r][0];
        }
        if bi[r] == 0 {
            di_bi[r] = d0[r];
        } else if bi[r] == 1 {
            di_bi[r] = d1[r];
        }
    }
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "fashare di_bi", &di_bi).await?;
    }
    let mut di_bi_k = vec![vec![0; RHO]; n];
    for k in (0..n).filter(|k| *k != i) {
        di_bi_k[k] = recv_vec_from::<u128>(channel, k, "fashare di_bi", RHO).await?;
    }

    // 3 d) Consistency check of macs.
    let mut xor_xk_macs = vec![vec![0; RHO]; n];
    for r in 0..RHO {
        for (k, dm) in dm_k.iter().enumerate().take(n) {
            for kk in (0..n).filter(|pp| *pp != k) {
                if !dm.is_empty() {
                    let dm = &dm[r];
                    if let Ok(b) = dm[(1 + kk * 16)..(17 + kk * 16)]
                        .try_into()
                        .map(u128::from_be_bytes)
                    {
                        xor_xk_macs[kk][r] ^= b;
                    } else {
                        return Err(Error::ConversionError);
                    }
                }
            }
        }
        for k in (0..n).filter(|k| *k != i) {
            let bj = &di_bi_k[k][r].to_be_bytes();
            if open_commitment(&c0_c1_cm_k[k][r].0, bj) || open_commitment(&c0_c1_cm_k[k][r].1, bj)
            {
                if xor_xk_macs[k][r] != di_bi_k[k][r] {
                    return Err(Error::AShareMacsMismatch);
                }
            } else {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
        }
    }

    // Step 4) Return first l objects.
    xishares.truncate(l);
    Ok(xishares)
}

/// Protocol Pi_HaAND that performs F_HaAND.
///
/// The XOR of xiyj values are generated obliviously, which is half of the z value in an
/// authenticated share, i.e., a half-authenticated share.
pub(crate) async fn fhaand(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    xshares: &[Share],
    yi: Vec<bool>,
) -> Result<Vec<bool>, Error> {
    // Step 1) Obtain x shares (input).

    // Step 2) Calculate v.
    let mut vi = vec![false; l];
    let mut h0h1 = vec![(false, false); l];
    // Step 2 a) Pick random sj, compute h0, h1 for all j != i, and send to the respective party.
    for j in (0..n).filter(|j| *j != i) {
        for ll in 0..l {
            let sj: bool = random();
            let Some((_, kixj)) = xshares[ll].1 .0[j] else {
                return Err(Error::MissingMacKey);
            };
            let hash_kixj: [u8; 32] = blake3::hash(&kixj.0.to_le_bytes()).into();
            let lsb0 = (hash_kixj[31] & 0b0000_0001) != 0;
            h0h1[ll].0 = lsb0 ^ sj;

            let hash_kixj_delta: [u8; 32] = blake3::hash(&(kixj.0 ^ delta.0).to_le_bytes()).into();
            let lsb1 = (hash_kixj_delta[31] & 0b0000_0001) != 0;
            h0h1[ll].1 = lsb1 ^ sj ^ yi[ll];
            vi[ll] ^= sj;
        }
        send_to(channel, j, "haand", &h0h1).await?;
    }
    // Step 2 b) Receive h0, h1 from all parties and compute t.
    for j in (0..n).filter(|j| *j != i) {
        let h0h1_j = recv_vec_from::<(bool, bool)>(channel, j, "haand", l).await?;
        for ll in 0..l {
            let Some((mixj, _)) = xshares[ll].1 .0[j] else {
                return Err(Error::MissingMacKey);
            };
            let hash_mixj: [u8; 32] = blake3::hash(&mixj.0.to_le_bytes()).into();
            let mut t = (hash_mixj[31] & 0b0000_0001) != 0;
            if xshares[ll].0 {
                t ^= h0h1_j[ll].1;
            } else {
                t ^= h0h1_j[ll].0;
            }
            vi[ll] ^= t;
        }
    }

    // Step 3) Return v.
    Ok(vi)
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
pub(crate) async fn flaand(
    (channel, delta): (&mut impl Channel, Delta),
    (xshares, yshares, rshares): (&[Share], &[Share], &[Share]),
    i: usize,
    n: usize,
    l: usize,
) -> Result<Vec<Share>, Error> {
    // Triple computation.
    // Step 1) Triple computation (inputs).

    // Step 2) Run Pi_HaAND to get back some v.
    let y = yshares.iter().take(l).map(|share| share.0).collect();
    let v = fhaand((channel, delta), i, n, l, xshares, y).await?;

    // Step 3) Compute z and e AND shares.
    let mut z = vec![false; l];
    let mut e = vec![false; l];
    for ll in 0..l {
        z[ll] = v[ll] ^ (xshares[ll].0 & yshares[ll].0);
        e[ll] = z[ll] ^ rshares[ll].0;
    }
    let mut zshares = vec![Share(false, Auth(smallvec![None; n])); l];
    for ll in 0..l {
        zshares[ll].0 = z[ll];
    }
    for k in (0..n).filter(|k| *k != i) {
        for ll in 0..l {
            zshares[ll].1 .0[k] = rshares[ll].1 .0[k];
        }
    }
    drop(v);
    drop(z);

    // Triple Checking.
    // Step 4) Compute phi.
    let mut phi = vec![0; l];
    for (ll, phi_l) in phi.iter_mut().enumerate().take(l) {
        for k in (0..n).filter(|k| *k != i) {
            let Some((mk_yi, ki_yk)) = yshares[ll].1 .0[k] else {
                return Err(Error::MissingMacKey);
            };
            *phi_l ^= ki_yk.0 ^ mk_yi.0;
        }
        *phi_l ^= yshares[ll].0 as u128 * delta.0;
    }

    // Step 5) Compute uij and send to all parties along with e from Step 3).
    // Receive uij from all parties and compute mi_xj_phi.
    let mut ki_xj_phi = vec![vec![0; l]; n];
    for j in (0..n).filter(|j| *j != i) {
        let mut ei_uij = Vec::with_capacity(l);
        for (ll, phi_l) in phi.iter().enumerate().take(l) {
            let Some((_, ki_xj)) = xshares[ll].1 .0[j] else {
                return Err(Error::MissingMacKey);
            };
            ki_xj_phi[j][ll] = hash128(ki_xj.0);
            let uij = hash128(ki_xj.0 ^ delta.0) ^ ki_xj_phi[j][ll] ^ *phi_l;
            ei_uij.push((e[ll], uij));
        }
        send_to(channel, j, "flaand", &ei_uij).await?;
    }
    for j in (0..n).filter(|j| *j != i) {
        let ei_hi_dhi_k = recv_vec_from::<(bool, u128)>(channel, j, "flaand", l).await?;
        for (ll, xbit) in xshares.iter().enumerate().take(l) {
            let Some((mi_xj, _)) = xshares[ll].1 .0[j] else {
                return Err(Error::MissingMacKey);
            };
            ki_xj_phi[j][ll] ^= hash128(mi_xj.0) ^ (xbit.0 as u128 * ei_hi_dhi_k[ll].1);
            // mi_xj_phi added here
        }
        for ll in 0..ei_hi_dhi_k.len() {
            let Some((mac, key)) = rshares[ll].1 .0[j] else {
                return Err(Error::MissingMacKey);
            };
            // Part of Step 3) If e is true, this is negation of r as described in WRK17b, if e is false, this is a copy.
            if ei_hi_dhi_k[ll].0 {
                zshares[ll].1 .0[j] = Some((mac, Key(key.0 ^ delta.0)));
            } else {
                zshares[ll].1 .0[j] = Some((mac, key));
            }
        }
    }

    // Step 6) Compute hash and comm and send to all parties.
    let mut hi = vec![0; l];
    {
        let mut commhi = Vec::with_capacity(l);
        for ll in 0..l {
            for k in (0..n).filter(|k| *k != i) {
                let Some((mk_zi, ki_zk)) = zshares[ll].1 .0[k] else {
                    return Err(Error::MissingMacKey);
                };
                hi[ll] ^= mk_zi.0 ^ ki_zk.0 ^ ki_xj_phi[k][ll];
            }
            hi[ll] ^= xshares[ll].0 as u128 * phi[ll];
            hi[ll] ^= zshares[ll].0 as u128 * delta.0;
            commhi.push(commit(&hi[ll].to_be_bytes()));
        }
        for k in (0..n).filter(|k| *k != i) {
            send_to(channel, k, "flaand comm", &commhi).await?;
        }
    }
    drop(phi);
    drop(ki_xj_phi);

    let mut commhi_k = Vec::with_capacity(n);
    for k in 0..n {
        if k == i {
            commhi_k.push(vec![]);
        } else {
            commhi_k.push(recv_vec_from::<Commitment>(channel, k, "flaand comm", l).await?);
        }
    }

    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "flaand hash", &hi).await?;
    }

    let mut xor_all_hi = hi; // XOR for all parties, including p_own
    for k in (0..n).filter(|k| *k != i) {
        let hi_k = recv_vec_from::<u128>(channel, k, "flaand hash", l).await?;
        for (ll, (xh, hi_k)) in xor_all_hi
            .iter_mut()
            .zip(hi_k.into_iter())
            .enumerate()
            .take(l)
        {
            if !open_commitment(&commhi_k[k][ll], &hi_k.to_be_bytes()) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            *xh ^= hi_k;
        }
    }

    // Step 7) Check that the xor of all his is zero.
    for xh in xor_all_hi.iter().take(l) {
        if *xh != 0 {
            return Err(Error::LaANDXorNotZero);
        }
    }

    Ok(zshares)
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
fn transform<'a>(
    x: &'a [Share],
    y: &'a [Share],
    z: &'a [Share],
    length: usize,
) -> Vec<(&'a Share, &'a Share, &'a Share)> {
    let mut triples = Vec::with_capacity(length);
    for l in 0..length {
        triples.push((&x[l], &y[l], &z[l]));
    }
    triples
}

type Bucket<'a> = SmallVec<[(&'a Share, &'a Share, &'a Share); 3]>;

/// Protocol Pi_aAND that performs F_aAND.
///
/// The protocol combines leaky authenticated bits into non-leaky authenticated bits.
pub(crate) async fn faand(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    shared_rng: &mut ChaCha20Rng,
    xyz_shares: Vec<Share>,
) -> Result<Vec<(Share, Share, Share)>, Error> {
    let b = bucket_size(l);
    let lprime = l * b;

    let (xshares, rest) = xyz_shares.split_at(lprime);
    let (yshares, rshares) = rest.split_at(lprime);

    // Step 1) Generate all leaky AND triples.
    let zshares = flaand((channel, delta), (xshares, yshares, rshares), i, n, lprime).await?;
    let triples = transform(xshares, yshares, &zshares, lprime);

    // Step 2) Randomly partition all objects into l buckets, each with b objects.
    let mut buckets: Vec<Bucket> = vec![smallvec![]; l];

    for obj in triples {
        let mut j = shared_rng.gen_range(0..buckets.len());
        while buckets[j].len() >= b {
            j = (j + 1) % buckets.len();
        }
        buckets[j].push(obj);
    }

    // Step 3) For each bucket, combine b leaky ANDs into a single non-leaky AND.
    let d_values = check_dvalue((channel, delta), i, n, &buckets).await?;

    let mut aand_triples = Vec::with_capacity(buckets.len());
    for (bucket, d) in buckets.into_iter().zip(d_values.into_iter()) {
        aand_triples.push(combine_bucket(i, n, bucket, d)?);
    }

    Ok(aand_triples)
}

/// Protocol that transforms precomputed AND triples to specific triples using Beaver's method.
pub(crate) async fn beaver_aand(
    (channel, delta): (&mut impl Channel, Delta),
    and_shares: Vec<(Share, Share)>,
    i: usize,
    n: usize,
    l: usize, //circuit_size
    shared_rng: &mut ChaCha20Rng,
    xyz_shares: Vec<Share>,
) -> Result<Vec<Share>, Error> {
    let rand_triples = faand((channel, delta), i, n, l, shared_rng, xyz_shares).await?;
    let len = rand_triples.len();

    // Beaver triple precomputation - transform random triples to specific triples.
    let mut e_f_emac_fmac = vec![(false, false, None, None); len];

    let mut ef_shares = vec![];
    for j in 0..len {
        let (e, f, _, _) = &mut e_f_emac_fmac[j];
        let (a, b, _c) = &rand_triples[j];
        let (x, y) = &and_shares[j];
        ef_shares.push((a ^ x, b ^ y));
        *e = a.0 ^ x.0;
        *f = b.0 ^ y.0;
    }
    for k in (0..n).filter(|k| *k != i) {
        for j in 0..len {
            let (eshare, fshare) = &ef_shares[j];
            let (_, _, eemac, ffmac) = &mut e_f_emac_fmac[j];
            let Some((emac, _)) = eshare.1 .0[k] else {
                return Err(Error::MissingMacKey);
            };
            let Some((fmac, _)) = fshare.1 .0[k] else {
                return Err(Error::MissingMacKey);
            };
            *eemac = Some(emac);
            *ffmac = Some(fmac);
        }
        send_to(channel, k, "faand", &e_f_emac_fmac).await?;
    }
    let mut e_f_emac_fmac_k = vec![vec![(false, false, None, None); len]; n];
    for k in (0..n).filter(|k| *k != i) {
        e_f_emac_fmac_k[k] =
            recv_vec_from::<(bool, bool, Option<Mac>, Option<Mac>)>(channel, k, "faand", len)
                .await?;
    }
    for k in (0..n).filter(|k| *k != i) {
        for (j, &(e, f, ref emac, ref fmac)) in e_f_emac_fmac_k[k].iter().enumerate() {
            let Some(emacp) = emac else {
                return Err(Error::MissingMacKey);
            };
            let Some((_, ekey)) = ef_shares[j].0 .1 .0[k] else {
                return Err(Error::MissingMacKey);
            };
            let Some(fmacp) = fmac else {
                return Err(Error::MissingMacKey);
            };
            let Some((_, fkey)) = ef_shares[j].1 .1 .0[k] else {
                return Err(Error::MissingMacKey);
            };
            if (e && emacp.0 != ekey.0 ^ delta.0) || (!e && emacp.0 != ekey.0) {
                return Err(Error::AANDWrongEFMAC);
            }
            if (f && fmacp.0 != fkey.0 ^ delta.0) || (!f && fmacp.0 != fkey.0) {
                return Err(Error::AANDWrongEFMAC);
            }
        }
    }
    e_f_emac_fmac
        .iter_mut()
        .enumerate()
        .for_each(|(j, (e, f, _, _))| {
            for k in (0..n).filter(|&k| k != i) {
                let (fa_e, fa_f, _, _) = e_f_emac_fmac_k[k][j];
                *e ^= fa_e;
                *f ^= fa_f;
            }
        });
    let mut and_share = vec![Share(false, Auth(smallvec![])); len];

    for j in 0..len {
        let (a, _b, c) = &rand_triples[j];
        let (_x, y) = &and_shares[j];
        let (e, f, _, _) = e_f_emac_fmac[j];
        and_share[j] = c.clone();
        if e {
            and_share[j] = &and_share[j] ^ y;
        }
        if f {
            and_share[j] = &and_share[j] ^ a;
        }
    }
    Ok(and_share)
}

/// Check and return d-values for a vector of shares.
pub(crate) async fn check_dvalue(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    buckets: &[Bucket<'_>],
) -> Result<Vec<Vec<bool>>, Error> {
    // Step (a) compute and check macs of d-values.
    let len = buckets.len();
    let mut d_values = vec![vec![]; len];
    let mut d_macs = vec![vec![vec![]; len]; n];

    for j in 0..len {
        let (_, y, _) = &buckets[j][0];
        let first = y.0;
        for (_, y_next, _) in buckets[j].iter().skip(1) {
            d_values[j].push(first ^ y_next.0);
            for k in (0..n).filter(|k| *k != i) {
                let Some((y0mac, _)) = y.1 .0[k] else {
                    return Err(Error::MissingMacKey);
                };
                let Some((ymac, _)) = y_next.1 .0[k] else {
                    return Err(Error::MissingMacKey);
                };
                d_macs[k][j].push(Some(y0mac ^ ymac));
            }
        }
    }

    for k in (0..n).filter(|k| *k != i) {
        let dvalues_macs: Vec<(Vec<bool>, Vec<Option<Mac>>)> = (0..len)
            .map(|i| (d_values[i].clone(), d_macs[k][i].clone()))
            .collect();
        send_to(channel, k, "dvalue", &dvalues_macs).await?;
    }

    for k in (0..n).filter(|k| *k != i) {
        let dvalues_macs_k =
            recv_vec_from::<(Vec<bool>, Vec<Option<Mac>>)>(channel, k, "dvalue", len).await?;
        for (j, dval) in d_values.iter_mut().enumerate().take(len) {
            let (d_value_p, d_macs_p) = &dvalues_macs_k[j];
            let Some((_, y0key)) = buckets[j][0].1 .1 .0[k] else {
                return Err(Error::MissingMacKey);
            };
            for (m, d) in dval.iter_mut().enumerate().take(d_macs_p.len()) {
                let Some(dmac) = d_macs_p[m] else {
                    return Err(Error::MissingMacKey);
                };
                let Some((_, ykey)) = buckets[j][m + 1].1 .1 .0[k] else {
                    return Err(Error::MissingMacKey);
                };
                if (d_value_p[m] && dmac.0 != y0key.0 ^ ykey.0 ^ delta.0)
                    || (!d_value_p[m] && dmac.0 != y0key.0 ^ ykey.0)
                {
                    return Err(Error::AANDWrongDMAC);
                }
                *d ^= d_value_p[m];
            }
        }
    }

    Ok(d_values)
}

/// Combine the whole bucket by combining elements one by one.
pub(crate) fn combine_bucket(
    i: usize,
    n: usize,
    bucket: SmallVec<[(&Share, &Share, &Share); 3]>,
    d_vec: Vec<bool>,
) -> Result<(Share, Share, Share), Error> {
    if bucket.is_empty() {
        return Err(Error::EmptyBucketError);
    }

    let mut bucket = bucket.into_iter();
    let (x, y, z) = bucket.next().unwrap();
    let mut result = (x.clone(), y.clone(), z.clone());

    // Combine elements one by one, starting from the second element.
    for (triple, d) in bucket.zip(d_vec.into_iter()) {
        result = combine_two_leaky_ands(i, n, result, triple, d)?;
    }
    Ok(result)
}

/// Combine two leaky ANDs into one non-leaky AND.
pub(crate) fn combine_two_leaky_ands(
    i: usize,
    n: usize,
    (x1, y1, z1): (Share, Share, Share),
    (x2, _, z2): (&Share, &Share, &Share),
    d: bool,
) -> Result<(Share, Share, Share), Error> {
    //Step (b) compute x, y, z.
    let xbit = x1.0 ^ x2.0;
    let mut xauth = Auth(smallvec![None; n]);
    for k in (0..n).filter(|k| *k != i) {
        let Some((mk_x1, ki_x1)) = x1.1 .0[k] else {
            return Err(Error::MissingMacKey);
        };
        let Some((mk_x2, ki_x2)) = x2.1 .0[k] else {
            return Err(Error::MissingMacKey);
        };
        xauth.0[k] = Some((mk_x1 ^ mk_x2, ki_x1 ^ ki_x2));
    }
    let xshare = Share(xbit, xauth);

    let zbit = z1.0 ^ z2.0 ^ d & x2.0;
    let mut zauth = Auth(smallvec![None; n]);
    for k in (0..n).filter(|k| *k != i) {
        let Some((mk_z1, ki_z1)) = z1.1 .0[k] else {
            return Err(Error::MissingMacKey);
        };
        let Some((mk_z2, ki_z2)) = z2.1 .0[k] else {
            return Err(Error::MissingMacKey);
        };
        let Some((mk_x2, ki_x2)) = x2.1 .0[k] else {
            return Err(Error::MissingMacKey);
        };
        zauth.0[k] = Some((
            mk_z1 ^ mk_z2 ^ Mac(d as u128 * mk_x2.0),
            ki_z1 ^ ki_z2 ^ Key(d as u128 * ki_x2.0),
        ));
    }
    let zshare = Share(zbit, zauth);

    Ok((xshare, y1, zshare))
}
