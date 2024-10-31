//! Preprocessing protocol generating authenticated triples for secure multi-party computation.
use std::vec;

use blake3;
use rand::{random, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

use crate::{
    channel::{self, recv_from, recv_vec_from, send_to, Channel},
    fpre::{Auth, Delta, Key, Mac, Share},
    ot::{kos_ot_receiver, kos_ot_sender, u128_to_block},
};

/// The statistical security parameter `RHO` used for cryptographic operations.
const RHO: usize = 40;

/// Errors occurring during preprocessing.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
    /// The MAC is not the correct one in aBit.
    ABitMacMisMatch,
    /// The value of bi is not 0 or 1.
    InvalidBiValue,
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
    /// Empty vector.
    EmptyVector,
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

/// Converts a `channel::Error` into a custom `Error` type.
impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}

/// Represents a cryptographic commitment as a fixed-size 32-byte array (a BLAKE3 hash).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Commitment(pub(crate) [u8; 32]);

/// Commits to a value using the BLAKE3 cryptographic hash function.
fn commit(value: &[u8]) -> Commitment {
    let result = blake3::hash(value).into();
    Commitment(result)
}

/// Verifies if a given value matches a previously generated commitment.
fn open_commitment(commitment: &Commitment, value: &[u8]) -> bool {
    blake3::hash(value).as_bytes() == &commitment.0
}

/// Multi-party coin tossing to generate shared randomness in a secure, distributed manner.
///
/// This function generates a shared random number generator (RNG) using multi-party
/// coin tossing in a secure multi-party computation (MPC) setting. Each participant contributes
/// to the randomness generation, and all contributions are combined securely to generate
/// a final shared random seed. This shared seed is then used to create a `ChaCha20Rng`, a
/// cryptographically secure random number generator.
pub(crate) async fn shared_rng(
    channel: &mut impl Channel,
    i: usize,
    indices: Vec<usize>,
) -> Result<ChaCha20Rng, Error> {
    let r = [random::<u128>(), random::<u128>()];
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&r[0].to_be_bytes());
    buf[16..].copy_from_slice(&r[1].to_be_bytes());
    let commitment = commit(&buf);

    let valid_indices: Vec<usize> = indices.iter().filter(|&&k| k != i).copied().collect();

    for &k in &valid_indices {
        send_to(channel, k, "RNG comm", &[commitment]).await?;
    }
    let mut commitments = Vec::with_capacity(valid_indices.len());
    for &k in &valid_indices {
        let commitment = recv_from::<Commitment>(channel, k, "RNG comm")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        commitments.push(commitment);
    }
    for &k in &valid_indices {
        send_to(channel, k, "RNG ver", &[buf]).await?;
    }
    let mut bufs = Vec::with_capacity(valid_indices.len());
    for &k in &valid_indices {
        let buffer = recv_from::<[u8; 32]>(channel, k, "RNG ver")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        bufs.push(buffer);
    }
    let mut buf_xor = buf;
    for (j, &_) in valid_indices.iter().enumerate() {
        if !open_commitment(&commitments[j], &bufs[j]) {
            return Err(Error::CommitmentCouldNotBeOpened);
        }
        buf_xor
            .iter_mut()
            .zip(&bufs[j])
            .for_each(|(buf_xor_byte, buf_byte)| *buf_xor_byte ^= *buf_byte);
    }
    Ok(ChaCha20Rng::from_seed(buf_xor))
}

/// Protocol PI_aBit^n that performs F_aBit^n.
///
/// A random bit-string is generated as well as the corresponding keys and MACs are sent to all
/// parties.
async fn fabitn(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    shared_rng: &mut ChaCha20Rng,
) -> Result<Vec<Share>, Error> {
    // Step 1) Pick random bit-string x of length lprime.
    let two_rho = 2 * RHO;
    let lprime = l + two_rho;

    let mut x: Vec<bool> = (0..lprime).map(|_| random()).collect();

    // Steps 2) Use the output of the oblivious transfers between each pair of parties to generate keys and macs.
    let mut keys = vec![vec![0; lprime]; n];
    let mut macs = vec![vec![0; lprime]; n];

    let deltas = vec![u128_to_block(delta.0); lprime];
    for p in (0..n).filter(|p| *p != i) {
        if i < p {
            keys[p] = kos_ot_sender(channel, &deltas, i, p).await?;
            macs[p] = kos_ot_receiver(channel, &x, i, p).await?;
        } else {
            macs[p] = kos_ot_receiver(channel, &x, i, p).await?;
            keys[p] = kos_ot_sender(channel, &deltas, i, p).await?;
        }
    }
    drop(deltas);

    // Step 2) Run 2-party OTs to compute keys and MACs [input parameters mm and kk].

    // Step 3) Verification of MACs and keys.
    // Step 3 a) Sample 2*RHO random l'-bit strings r.
    let r: Vec<Vec<bool>> = vec![vec![shared_rng.gen(); lprime]; two_rho];

    // Step 3 b) Compute xj and xjmac for each party, broadcast xj.
    // We batch messages and send xjmac with xj as well, as from Step 3 d).
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
        for (rbits, xj) in r.iter().zip(xj.iter()) {
            let mut xjmac = 0;
            for (j, &rbit) in rbits.iter().enumerate() {
                if rbit {
                    xjmac ^= macs[k][j];
                }
            }
            xj_xjmac.push((*xj, xjmac));
        }
        send_to(channel, k, "fabitn", &xj_xjmac).await?;
    }

    let mut xj_xjmac_k: Vec<Vec<(bool, u128)>> = vec![vec![]; n];
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
                    xjkey ^= keys[k][i];
                }
            }
            // Step 3 d) Validity check of macs.
            if (*xj && *xjmac != xjkey ^ delta.0) || (!*xj && *xjmac != xjkey) {
                return Err(Error::ABitMacMisMatch);
            }
        }
    }
    drop(r);

    // Step 4) Return first l objects.
    x.truncate(l);
    for k in (0..n).filter(|k| *k != i) {
        keys[k].truncate(l);
        macs[k].truncate(l);
    }
    let mut res = Vec::with_capacity(l);
    for (l, xi) in x.iter().enumerate().take(l) {
        let mut authvec = smallvec![(Mac(0), Key(0)); n];
        for k in (0..n).filter(|k| *k != i) {
            authvec[k] = (Mac(macs[k][l]), Key(keys[k][l]));
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
    i: usize,
    n: usize,
    l: usize,
    shared_rng: &mut ChaCha20Rng,
) -> Result<Vec<Share>, Error> {
    // Step 1) Pick random bit-string x (input).

    // Step 2) Run Pi_aBit^n to compute shares.
    let mut xishares = fabitn((channel, delta), i, n, l + RHO, shared_rng).await?;

    // Step 3) Compute commitments and verify consistency.
    // Step 3 a) Compute d0, d1, dm, c0, c1, cm and broadcast commitments to all parties.
    let mut d0 = vec![0; RHO];
    let mut d1 = vec![0; RHO];
    let mut c0_c1_cm = Vec::with_capacity(RHO); // c0, c1, cm
    let mut dmvec = Vec::with_capacity(RHO);

    for r in 0..RHO {
        let xishare = &xishares[l + r];
        let mut dm = Vec::with_capacity(n * 16);
        dm.push(xishare.0 as u8);
        for k in (0..n).filter(|k| *k != i) {
            let (mac, key) = xishare.1 .0[k];
            d0[r] ^= key.0;
            dm.extend(&mac.0.to_be_bytes());
        }
        d1[r] = d0[r] ^ delta.0;
        let c0 = commit(&d0[r].to_be_bytes());
        let c1 = commit(&d1[r].to_be_bytes());
        let cm = commit(&dm);

        c0_c1_cm.push((c0, c1, cm));
        dmvec.push(dm);
    }

    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "fashare comm", &c0_c1_cm).await?;
    }

    // 3 b) Receiving all commitments.
    let mut c0_c1_cm_k = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        c0_c1_cm_k[k] =
            recv_vec_from::<(Commitment, Commitment, Commitment)>(channel, k, "fashare comm", RHO)
                .await?;
    }
    c0_c1_cm_k[i] = c0_c1_cm;

    // 3 b) Pi broadcasts decommitment for macs.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "fashare ver", &dmvec).await?;
    }
    let mut dm_k = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        dm_k[k] = recv_vec_from::<Vec<u8>>(channel, k, "fashare ver", RHO).await?;
    }
    dm_k[i] = dmvec;

    // 3 c) Compute bi to determine di_bi and send to all parties.
    let mut bi = [false; RHO];
    let mut di_bi = vec![0; RHO];
    for r in 0..RHO {
        for k in (0..n).filter(|k| *k != i) {
            if dm_k[k][r][0] > 1 {
                return Err(Error::InvalidBiValue);
            }
            bi[r] ^= dm_k[k][r][0] != 0;
        }
        di_bi[r] = if bi[r] { d1[r] } else { d0[r] };
    }
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "fashare di_bi", &di_bi).await?;
    }
    let mut di_bi_k = vec![vec![0; RHO]; n];
    for k in (0..n).filter(|k| *k != i) {
        di_bi_k[k] = recv_vec_from::<u128>(channel, k, "fashare di_bi", RHO).await?;
    }

    // 3 d) Consistency check of macs: open commitment of xor of keys and check if it equals to the xor of all macs.
    let mut xor_xk_macs = vec![vec![0; RHO]; n];
    for r in 0..RHO {
        for (k, dmv) in dm_k.iter().enumerate().take(n) {
            for kk in (0..n).filter(|pp| *pp != k) {
                if dmv.is_empty() {
                    return Err(Error::EmptyVector);
                }
                let dm = &dmv[r];
                let start = if kk > k {
                    // here we compensate for not sending anything for own index
                    1 + (kk - 1) * 16
                } else {
                    1 + kk * 16
                };
                let end = start + 16;
                if let Ok(mac) = dm[start..end].try_into().map(u128::from_be_bytes) {
                    xor_xk_macs[kk][r] ^= mac;
                } else {
                    return Err(Error::ConversionError);
                }
            }
        }
        for k in (0..n).filter(|k| *k != i) {
            let d_bj = &di_bi_k[k][r].to_be_bytes();
            let commitments = &c0_c1_cm_k[k][r];
            if !open_commitment(&commitments.0, d_bj) && !open_commitment(&commitments.1, d_bj) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            if xor_xk_macs[k][r] != di_bi_k[k][r] {
                return Err(Error::AShareMacsMismatch);
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
async fn fhaand(
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
            let (_, kixj) = xshares[ll].1 .0[j];
            let hash_kixj = blake3::hash(&kixj.0.to_le_bytes());
            let hash_kixj_delta = blake3::hash(&(kixj.0 ^ delta.0).to_le_bytes());
            h0h1[ll].0 = (hash_kixj.as_bytes()[31] & 1 != 0) ^ sj;
            h0h1[ll].1 = (hash_kixj_delta.as_bytes()[31] & 1 != 0) ^ sj ^ yi[ll];
            vi[ll] ^= sj;
        }
        send_to(channel, j, "haand", &h0h1).await?;
    }
    // Step 2 b) Receive h0, h1 from all parties and compute t.
    for j in (0..n).filter(|j| *j != i) {
        let h0h1_j = recv_vec_from::<(bool, bool)>(channel, j, "haand", l).await?;
        for ll in 0..l {
            let (mixj, _) = xshares[ll].1 .0[j];
            let hash_mixj = blake3::hash(&mixj.0.to_le_bytes());
            let mut t = hash_mixj.as_bytes()[31] & 1 != 0;
            t ^= if xshares[ll].0 {
                h0h1_j[ll].1
            } else {
                h0h1_j[ll].0
            };
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
fn hash128(input: u128) -> u128 {
    let res: [u8; 32] = blake3::hash(&input.to_le_bytes()).into();
    let value1 = u128::from_le_bytes(res[0..16].try_into().unwrap());
    let value2 = u128::from_le_bytes(res[16..32].try_into().unwrap());
    value1 ^ value2
}

/// Protocol Pi_LaAND that performs F_LaAND.
///
/// Generates a "leaky authenticated AND", i.e., <x>, <y>, <z> such that the AND of the XORs of the
/// x and y values equals to the XOR of the z values.
async fn flaand(
    (channel, delta): (&mut impl Channel, Delta),
    (xshares, yshares, rshares): (&[Share], &[Share], &[Share]),
    i: usize,
    n: usize,
    l: usize,
) -> Result<Vec<Share>, Error> {
    // Triple computation.
    // Step 1) Triple computation [random authenticated shares as input parameters xshares, yshares, rshares].

    // Step 2) Run Pi_HaAND to get back some v.
    let y = yshares.iter().take(l).map(|share| share.0).collect();
    let v = fhaand((channel, delta), i, n, l, xshares, y).await?;

    // Step 3) Compute z and e AND shares.
    let mut z = vec![false; l];
    let mut e = vec![false; l];
    let mut zshares = vec![Share(false, Auth(smallvec![(Mac(0), Key(0)); n])); l];

    for ll in 0..l {
        z[ll] = v[ll] ^ (xshares[ll].0 & yshares[ll].0);
        e[ll] = z[ll] ^ rshares[ll].0;
        zshares[ll].0 = z[ll];
    }
    drop(v);
    drop(z);

    // Triple Checking.
    // Step 4) Compute phi.
    let mut phi = vec![0; l];
    for (ll, phi_l) in phi.iter_mut().enumerate().take(l) {
        for k in (0..n).filter(|k| *k != i) {
            let (mk_yi, ki_yk) = yshares[ll].1 .0[k];
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
            let (_, ki_xj) = xshares[ll].1 .0[j];
            ki_xj_phi[j][ll] = hash128(ki_xj.0);
            let uij = hash128(ki_xj.0 ^ delta.0) ^ ki_xj_phi[j][ll] ^ *phi_l;
            ei_uij.push((e[ll], uij));
        }
        send_to(channel, j, "flaand", &ei_uij).await?;
    }
    for j in (0..n).filter(|j| *j != i) {
        let ei_uij_k = recv_vec_from::<(bool, u128)>(channel, j, "flaand", l).await?;
        for (ll, xbit) in xshares.iter().enumerate().take(l) {
            let (mi_xj, _) = xshares[ll].1 .0[j];
            ki_xj_phi[j][ll] ^= hash128(mi_xj.0) ^ (xbit.0 as u128 * ei_uij_k[ll].1);
            // mi_xj_phi added here
            // Part of Step 3) If e is true, this is negation of r as described in WRK17b, if e is false, this is a copy.
            let (mac, key) = rshares[ll].1 .0[j];
            if ei_uij_k[ll].0 {
                zshares[ll].1 .0[j] = (mac, Key(key.0 ^ delta.0));
            } else {
                zshares[ll].1 .0[j] = (mac, key);
            }
        }
    }

    // Step 6) Compute hash and comm and send to all parties.
    let mut hi = vec![0; l];
    let mut commhi = Vec::with_capacity(l);
    for ll in 0..l {
        for k in (0..n).filter(|k| *k != i) {
            let (mk_zi, ki_zk) = zshares[ll].1 .0[k];
            hi[ll] ^= mk_zi.0 ^ ki_zk.0 ^ ki_xj_phi[k][ll];
        }
        hi[ll] ^= (xshares[ll].0 as u128 * phi[ll]) ^ (zshares[ll].0 as u128 * delta.0);
        commhi.push(commit(&hi[ll].to_be_bytes()));
    }
    drop(phi);
    drop(ki_xj_phi);

    // All parties first broadcast the commitment of Hi.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "flaand comm", &commhi).await?;
    }
    let mut commhi_k: Vec<Vec<Commitment>> = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        commhi_k[k] = recv_vec_from::<Commitment>(channel, k, "flaand comm", l).await?;
    }

    // Then all parties broadcast Hi.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "flaand hash", &hi).await?;
    }
    let mut xor_all_hi = hi; // XOR for all parties, including p_own
    for k in (0..n).filter(|k| *k != i) {
        let hi_k = recv_vec_from::<u128>(channel, k, "flaand hash", l).await?;
        for (ll, (xh, hi_k)) in xor_all_hi.iter_mut().zip(hi_k).enumerate() {
            if !open_commitment(&commhi_k[k][ll], &hi_k.to_be_bytes()) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            *xh ^= hi_k;
        }
    }

    // Step 7) Check that the xor of all his is zero.
    if xor_all_hi.iter().take(l).any(|&xh| xh != 0) {
        return Err(Error::LaANDXorNotZero);
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

type Bucket<'a> = SmallVec<[(&'a Share, &'a Share, &'a Share); 3]>;

/// Protocol Pi_aAND that performs F_aAND.
///
/// The protocol combines leaky authenticated bits into non-leaky authenticated bits.
async fn faand(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize, //num_and_gates
    shared_rng: &mut ChaCha20Rng,
    xyr_shares: Vec<Share>,
) -> Result<Vec<(Share, Share, Share)>, Error> {
    let b = bucket_size(l);
    let lprime = l * b;

    let (xshares, rest) = xyr_shares.split_at(lprime);
    let (yshares, rshares) = rest.split_at(lprime);

    // Step 1) Generate all leaky AND triples.
    let zshares = flaand((channel, delta), (xshares, yshares, rshares), i, n, lprime).await?;
    let triples: Vec<(&Share, &Share, &Share)> = (0..lprime)
        .map(|l| (&xshares[l], &yshares[l], &zshares[l]))
        .collect();

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
    alpha_beta_shares: Vec<(Share, Share)>,
    i: usize,
    n: usize,
    l: usize, //num_and_gates
    shared_rng: &mut ChaCha20Rng,
    abc_shares: Vec<Share>,
) -> Result<Vec<Share>, Error> {
    let abc_triples = faand((channel, delta), i, n, l, shared_rng, abc_shares).await?;
    let len = abc_triples.len();

    // Beaver triple precomputation - transform random triples to specific triples.
    // Steps 1 and 2) of https://securecomputation.org/docs/pragmaticmpc.pdf#section.3.4: compute blinded shares d and e and
    // send to all parties with corresponding macs.
    let mut d_e_dmac_emac = Vec::with_capacity(len);
    let mut de_shares = Vec::with_capacity(len);

    for j in 0..len {
        let (a, b, _) = &abc_triples[j];
        let (alpha, beta) = &alpha_beta_shares[j];

        de_shares.push((a ^ alpha, b ^ beta));
        d_e_dmac_emac.push((a.0 ^ alpha.0, b.0 ^ beta.0, Mac(0), Mac(0)));
    }
    for k in (0..n).filter(|k| *k != i) {
        for j in 0..len {
            let (dshare, eshare) = &de_shares[j];
            let (_, _, dmac, emac) = &mut d_e_dmac_emac[j];
            *dmac = dshare.1 .0[k].0;
            *emac = eshare.1 .0[k].0;
        }
        send_to(channel, k, "faand", &d_e_dmac_emac).await?;
    }
    let mut d_e_dmac_emac_k = vec![vec![(false, false, Mac(0), Mac(0)); len]; n];
    for k in (0..n).filter(|k| *k != i) {
        d_e_dmac_emac_k[k] =
            recv_vec_from::<(bool, bool, Mac, Mac)>(channel, k, "faand", len).await?;
    }
    for k in (0..n).filter(|k| *k != i) {
        for (j, &(d, e, ref dmac, ref emac)) in d_e_dmac_emac_k[k].iter().enumerate() {
            let (_, dkey) = de_shares[j].0 .1 .0[k];
            let (_, ekey) = de_shares[j].1 .1 .0[k];
            if (d && dmac.0 != dkey.0 ^ delta.0)
                || (!d && dmac.0 != dkey.0)
                || (e && emac.0 != ekey.0 ^ delta.0)
                || (!e && emac.0 != ekey.0)
            {
                return Err(Error::AANDWrongEFMAC);
            }
        }
    }
    for (j, (d, e, _, _)) in d_e_dmac_emac.iter_mut().enumerate() {
        for k in (0..n).filter(|&k| k != i) {
            let (d_k, e_k, _, _) = d_e_dmac_emac_k[k][j];
            *d ^= d_k;
            *e ^= e_k;
        }
    }
    let mut alpha_and_beta = Vec::with_capacity(len);

    // Step 3) of https://securecomputation.org/docs/pragmaticmpc.pdf#section.3.4: compute and return the final shares.
    for j in 0..len {
        let (a, _, c) = &abc_triples[j];
        let (_, beta) = &alpha_beta_shares[j];
        let (d, e, _, _) = d_e_dmac_emac[j];
        let mut and_share = c.clone();
        if d {
            and_share = &and_share ^ beta;
        }
        if e {
            and_share = &and_share ^ a;
        }
        alpha_and_beta.push(and_share);
    }
    Ok(alpha_and_beta)
}

/// Check and return d-values for a vector of shares.
async fn check_dvalue(
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
                let (y0mac, _) = y.1 .0[k];
                let (ymac, _) = y_next.1 .0[k];
                d_macs[k][j].push(y0mac ^ ymac);
            }
        }
    }

    for k in (0..n).filter(|k| *k != i) {
        let dvalues_macs: Vec<(Vec<bool>, Vec<Mac>)> = (0..len)
            .map(|i| (d_values[i].clone(), d_macs[k][i].clone()))
            .collect();
        send_to(channel, k, "dvalue", &dvalues_macs).await?;
    }

    for k in (0..n).filter(|k| *k != i) {
        let dvalues_macs_k =
            recv_vec_from::<(Vec<bool>, Vec<Mac>)>(channel, k, "dvalue", len).await?;
        for (j, dval) in d_values.iter_mut().enumerate().take(len) {
            let (d_value_p, d_macs_p) = &dvalues_macs_k[j];
            let (_, y0key) = buckets[j][0].1 .1 .0[k];
            for (m, d) in dval.iter_mut().enumerate().take(d_macs_p.len()) {
                let dmac = d_macs_p[m];
                let (_, ykey) = buckets[j][m + 1].1 .1 .0[k];
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
fn combine_bucket(
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
fn combine_two_leaky_ands(
    i: usize,
    n: usize,
    (x1, y1, z1): (Share, Share, Share),
    (x2, _, z2): (&Share, &Share, &Share),
    d: bool,
) -> Result<(Share, Share, Share), Error> {
    //Step (b) compute x, y, z.
    let xbit = x1.0 ^ x2.0;
    let mut xauth = Auth(smallvec![(Mac(0), Key(0)); n]);
    for k in (0..n).filter(|k| *k != i) {
        let (mk_x1, ki_x1) = x1.1 .0[k];
        let (mk_x2, ki_x2) = x2.1 .0[k];
        xauth.0[k] = (mk_x1 ^ mk_x2, ki_x1 ^ ki_x2);
    }
    let xshare = Share(xbit, xauth);

    let zbit = z1.0 ^ z2.0 ^ d & x2.0;
    let mut zauth = Auth(smallvec![(Mac(0), Key(0)); n]);
    for k in (0..n).filter(|k| *k != i) {
        let (mk_z1, ki_z1) = z1.1 .0[k];
        let (mk_z2, ki_z2) = z2.1 .0[k];
        let (mk_x2, ki_x2) = x2.1 .0[k];
        zauth.0[k] = (
            mk_z1 ^ mk_z2 ^ Mac(d as u128 * mk_x2.0),
            ki_z1 ^ ki_z2 ^ Key(d as u128 * ki_x2.0),
        );
    }
    let zshare = Share(zbit, zauth);

    Ok((xshare, y1, zshare))
}
