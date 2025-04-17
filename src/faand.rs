//! Preprocessing protocol generating authenticated triples for secure multi-party computation.
use std::vec;

use maybe_async::maybe_async;
use rand::{random, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use scuttlebutt::Block;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};

use crate::{
    channel::{self, recv_from, recv_vec_from, send_to, Channel},
    data_types::{Auth, Delta, Key, Mac, Share},
    ot::{kos_ot_receiver, kos_ot_sender},
};

/// The statistical security parameter `RHO` used for cryptographic operations.
const RHO: usize = 40;

/// Errors occurring during preprocessing.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelErr(channel::Error),
    /// The value of bi is not 0 or 1.
    InvalidBitValue,
    /// A commitment could not be opened.
    CommitmentCouldNotBeOpened,
    /// Empty vector.
    EmptyVector,
    /// Conversion error.
    ConversionErr,
    /// Empty bucket.
    EmptyBucket,
    /// A message was sent, but it contained no data.
    EmptyMsg,
    /// Invalid array length.
    InvalidLength,
    /// Broadcast not consistent.
    InconsistentBroadcast,
    /// KOS consistency check failed.
    KOSConsistencyCheckFailed,
    /// The MAC is not the correct one in aBit.
    ABitWrongMAC,
    /// The xor of MACs is not equal to the XOR of corresponding keys or that XOR delta.
    AShareWrongMAC,
    /// XOR of all values in FLaAND do not cancel out.
    LaANDXorNotZero,
    /// Wrong MAC of d when combining two leaky ANDs.
    AANDWrongMAC,
    /// Wrong MAC of e.
    BeaverWrongMAC,
    /// Too short hash for statistical security parameter.
    InvalidHashLength,
}

/// Converts a `channel::Error` into a custom `Error` type.
impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelErr(e)
    }
}

/// Represents a cryptographic commitment as a fixed-size 32-byte array (a BLAKE3 hash).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
struct Commitment(pub(crate) [u8; 32]);

/// Commits to a value using the BLAKE3 cryptographic hash function.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
fn commit(value: &[u8]) -> Commitment {
    Commitment(blake3::hash(value).into())
}

/// Verifies if a given value matches a previously generated commitment.
/// This is not a general-purpose commitment scheme, the input value is assumed to have high entropy.
fn open_commitment(commitment: &Commitment, value: &[u8]) -> bool {
    blake3::hash(value).as_bytes() == &commitment.0
}

/// Hashes a Vec<T> using blake3 and returns the resulting hash as `u128`.
///
/// The hash is truncated to 128 bits to match the input size. Due to the truncation, the security
/// guarantees of the hash function are reduced to 64-bit collision resistance and 128-bit preimage
/// resistance. This is sufficient for the purposes of the protocol if RHO <= 64, which we expect
/// to be the case in all real-world usages of our protocol.
pub(crate) fn hash_vec<T: Serialize>(data: &Vec<T>) -> Result<u128, Error> {
    if data.is_empty() {
        return Err(Error::EmptyVector);
    }
    let serialized_data = bincode::serialize(data).map_err(|_| Error::ConversionErr)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&serialized_data);

    let mut binding = hasher.finalize_xof();
    if RHO > 64 {
        return Err(Error::InvalidHashLength);
    }
    let mut buf = [0u8; 16];
    binding.fill(&mut buf);
    let hash = u128::from_le_bytes(buf);

    Ok(hash)
}

/// Implements the verification step of broadcast with abort based on Goldwasser and Lindell's protocol.
#[maybe_async(AFIT)]
pub(crate) async fn broadcast_verification<
    T: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
>(
    channel: &mut impl Channel,
    i: usize,
    n: usize,
    phase: &str,
    vec: &[Vec<T>],
) -> Result<(), Error> {
    if n == 2 {
        return Ok(());
    }
    if vec.is_empty() {
        return Err(Error::EmptyVector);
    }
    let mut hash_vecs: Vec<u128> = vec![0; n];
    for k in (0..n).filter(|k| *k != i) {
        if let Ok(hash) = hash_vec(&vec[k]) {
            hash_vecs[k] = hash;
        } else {
            return Err(Error::EmptyVector);
        }
    }
    // Step 1: Send the vector to all parties that does not included its already sent value
    // (for index i) and the value it received from the party it is sending to (index k).
    for k in (0..n).filter(|k| *k != i) {
        let mut modified_vec: Vec<Option<u128>> = vec![None; n];
        for j in (0..n).filter(|j| *j != i && *j != k) {
            if vec[j].is_empty() {
                return Err(Error::EmptyVector);
            }
            modified_vec[j] = Some(hash_vecs[j]);
        }
        send_to(channel, k, phase, &modified_vec).await?;
    }

    // Step 2: Receive and verify the vectors from all parties, that for index j the value is
    // the same for all parties.
    for k in (0..n).filter(|k| *k != i) {
        let vec_k: Vec<Option<u128>> = recv_vec_from(channel, k, phase, n).await?;
        for j in (0..n).filter(|j| *j != i && *j != k) {
            if vec_k[j].is_none() {
                return Err(Error::EmptyVector);
            } else if vec_k[j] != Some(hash_vecs[j]) {
                return Err(Error::InconsistentBroadcast);
            }
        }
    }

    Ok(())
}

/// Implements broadcast with abort based on Goldwasser and Lindell's protocol
/// for all parties at once, where each party sends its vector to all others.
/// The function returns the vector received and verified by broadcast.
#[maybe_async(AFIT)]
pub(crate) async fn broadcast<
    T: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
>(
    channel: &mut impl Channel,
    i: usize,
    n: usize,
    phase: &str,
    vec: &[T],
    len: usize,
) -> Result<Vec<Vec<T>>, Error> {
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, phase, vec).await?;
    }

    // 3 b) Receiving all commitments.
    let mut res_vec = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        res_vec[k] = recv_vec_from::<T>(channel, k, phase, len).await?;
    }
    let string = "broadcast ";
    broadcast_verification(channel, i, n, &(string.to_owned() + phase), &res_vec).await?;
    Ok(res_vec)
}

/// Implements same broadcast with abort as broadcast, but only the first element of the tuple in
/// the vector is broadcasted, the second element is simply sent to all parties.
#[maybe_async(AFIT)]
pub(crate) async fn broadcast_first_send_second<
    T: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
    S: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
>(
    channel: &mut impl Channel,
    i: usize,
    n: usize,
    phase: &str,
    vec: &[Vec<(T, S)>],
    len: usize,
) -> Result<Vec<Vec<(T, S)>>, Error> {
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, phase, &vec[k]).await?;
    }

    // 3 b) Receiving all commitments.
    let mut recv_vec = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        recv_vec[k] = recv_vec_from::<(T, S)>(channel, k, phase, len).await?;
    }
    let first_vec: Vec<Vec<T>> = recv_vec
        .iter()
        .map(|inner_vec| inner_vec.iter().map(|(a, _)| a.clone()).collect())
        .collect();
    let string = "broadcast ";
    broadcast_verification(channel, i, n, &(string.to_owned() + phase), &first_vec).await?;
    Ok(recv_vec)
}

/// Multi-party coin tossing to generate shared randomness in a secure, distributed manner.
///
/// This function generates a shared random number generator (RNG) using multi-party
/// coin tossing in a secure multi-party computation (MPC) setting. Each participant contributes
/// to the randomness generation, and all contributions are combined securely to generate
/// a final shared random seed. This shared seed is then used to create a `ChaCha20Rng`, a
/// cryptographically secure random number generator.
#[maybe_async(AFIT)]
pub(crate) async fn shared_rng(
    channel: &mut impl Channel,
    i: usize,
    n: usize,
) -> Result<ChaCha20Rng, Error> {
    // Step 1 Generate a random 256-bit seed for multi-party cointossing and commit to it.
    let buf = random::<[u8; 32]>();
    let mut buf_id = [0u8; 34]; // with 16 bits for the id
    buf_id[..32].copy_from_slice(&buf);
    // Set the last two bytes to the party ID to ensure unique commitments.
    let id_bytes = (i as u16).to_be_bytes();
    buf_id[32..].copy_from_slice(&id_bytes);
    let commitment = commit(&buf_id);

    // Step 2) a) Send the commitments to all parties for multi-party cointossing.
    // Broadcast multi-party commitments.
    let comm = vec![commitment];
    let commitments = broadcast(channel, i, n, "RNG comm", &comm, 1).await?;

    // Step 3) Send the decommitments to all parties for multi-party cointossing.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "RNG ver", &[buf]).await?;
    }
    let mut bufs = vec![[0; 32]; n];
    let mut bufs_id = vec![[0; 34]; n];
    for k in (0..n).filter(|k| *k != i) {
        bufs[k] = recv_from::<[u8; 32]>(channel, k, "RNG ver")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        bufs_id[k][..32].copy_from_slice(&bufs[k]);
        let id_bytes = (k as u16).to_be_bytes();
        bufs_id[k][32..].copy_from_slice(&id_bytes);
    }

    // Step 4) Verify the decommitments and calculate multi-party seed.
    let mut buf_xor = buf;
    for k in (0..n).filter(|k| *k != i) {
        if !open_commitment(&commitments[k][0], &bufs_id[k]) {
            return Err(Error::CommitmentCouldNotBeOpened);
        }
        buf_xor
            .iter_mut()
            .zip(&bufs[k])
            .for_each(|(buf_xor_byte, buf_byte)| *buf_xor_byte ^= *buf_byte);
    }

    Ok(ChaCha20Rng::from_seed(buf_xor))
}

/// Pairwise two-party coin tossing to generate shared randomness in a secure, distributed manner.
///
/// This function generates a shared random number generator (RNG) between every two parties using
/// two-party coin tossing for the two-party KOS OT protocol.
#[maybe_async(AFIT)]
pub(crate) async fn shared_rng_pairwise(
    channel: &mut impl Channel,
    i: usize,
    n: usize,
) -> Result<Vec<Vec<Option<ChaCha20Rng>>>, Error> {
    // Step 1 b) Generate a random 256-bit seed for every other party for the pairwise
    // cointossing and commit to it.
    let bufvec: Vec<[u8; 32]> = (0..n).map(|_| random::<[u8; 32]>()).collect();
    let mut bufvec_id: Vec<[u8; 34]> = vec![[0; 34]; n];
    let mut commitment_vec = vec![Commitment([0; 32]); n];
    for k in (0..n).filter(|k| *k != i) {
        bufvec_id[k][..32].copy_from_slice(&bufvec[k]);
        let id_bytes = (i as u16).to_be_bytes();
        bufvec_id[k][32..].copy_from_slice(&id_bytes);
        commitment_vec[k] = commit(&bufvec_id[k]);
    }

    // Step 2) Send the commitments to all parties for pairwise cointossing.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "RNG comm", &[commitment_vec[k]]).await?;
    }
    let mut commitments = vec![Commitment([0; 32]); n];
    for k in (0..n).filter(|k| *k != i) {
        commitments[k] = recv_from::<Commitment>(channel, k, "RNG comm")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
    }

    // Step 3) Send the decommitments to all parties for pairwise cointossing.
    for k in (0..n).filter(|k| *k != i) {
        send_to(channel, k, "RNG ver", &[bufvec[k]]).await?;
    }
    let mut bufs = vec![[0; 32]; n];
    let mut bufs_id = vec![[0; 34]; n];
    for k in (0..n).filter(|k| *k != i) {
        bufs[k] = recv_from::<[u8; 32]>(channel, k, "RNG ver")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        bufs_id[k][..32].copy_from_slice(&bufs[k]);
        let id_bytes = (k as u16).to_be_bytes();
        bufs_id[k][32..].copy_from_slice(&id_bytes);
    }

    // Step 4) Verify the decommitments.
    for k in (0..n).filter(|k| *k != i) {
        if !open_commitment(&commitments[k], &bufs_id[k]) {
            return Err(Error::CommitmentCouldNotBeOpened);
        }
    }

    // Step 5) Set up shared RNGs for pairwise cointossing
    let mut shared_two_by_two: Vec<Vec<Option<ChaCha20Rng>>> = vec![vec![None; n]; n];
    for k in (0..n).filter(|&k| k != i) {
        let (a, b) = if i < k { (i, k) } else { (k, i) };
        shared_two_by_two[a][b] = Some(ChaCha20Rng::from_seed(std::array::from_fn(|i| {
            bufvec[k][i] ^ bufs[k][i]
        })));
    }

    Ok(shared_two_by_two)
}

/// Protocol PI_aBit^n that performs F_aBit^n from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// This function implements a secure multi-party computation protocol to generate a random
/// bit-string and the corresponding keys and MACs (the latter are sent to the other parties),
/// i.e., shares of random authenticated bits.
/// The two main steps of the protocol are running two-party oblivious transfers (OTs) for
/// each pair of parties and then checking the validity of the MACs and keys by checking the XOR
/// of a linear combination of the bits, keys and the MACs and then removing 2 * RHO objects,
/// where RHO is the statistical security parameter.
#[maybe_async(AFIT)]
async fn fabitn(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    mut shared_two_by_two: Vec<Vec<Option<ChaCha20Rng>>>,
) -> Result<(Vec<Share>, ChaCha20Rng), Error> {
    // Step 1) Pick random bit-string x of length lprime.
    let three_rho = 3 * RHO;
    let lprime = l + three_rho;

    let mut x: Vec<bool> = (0..lprime).map(|_| random()).collect();

    // Steps 2) Use the output of the oblivious transfers between each pair of parties to generate keys and macs.
    let mut keys = vec![vec![0; lprime]; n];
    let mut macs = vec![vec![0; lprime]; n];

    let deltas = vec![Block::from(delta.0.to_be_bytes()); lprime];

    // Step 2: Use the shared RNGs for key and MAC generation
    if !(shared_two_by_two.len() == n && shared_two_by_two.iter().all(|row| row.len() == n)) {
        return Err(Error::InvalidLength);
    }

    for k in (0..n).filter(|&k| k != i) {
        let (a, b) = if i < k { (i, k) } else { (k, i) };

        if let Some(shared) = shared_two_by_two[a][b].as_mut() {
            if i < k {
                keys[k] = kos_ot_sender(channel, &deltas, k, shared).await?;
                macs[k] = kos_ot_receiver(channel, &x, k, shared).await?;
            } else {
                macs[k] = kos_ot_receiver(channel, &x, k, shared).await?;
                keys[k] = kos_ot_sender(channel, &deltas, k, shared).await?;
            }
        } else {
            return Err(Error::EmptyVector);
        }
    }
    drop(deltas);

    // Step 2) Run 2-party OTs to compute keys and MACs [input parameters mm and kk].

    // Step 3) Verification of MACs and keys.
    // Step 3 a) Sample 2 * RHO random l'-bit strings r.
    let mut multi_shared_rand = shared_rng(channel, i, n).await?;
    let r: Vec<Vec<bool>> = (0..three_rho)
        .map(|_| (0..lprime).map(|_| multi_shared_rand.gen()).collect())
        .collect();

    // Step 3 b) Compute xj and xjmac for each party, broadcast xj.
    // We batch messages and send xjmac with xj as well, as from Step 3 d).
    let mut xj = Vec::with_capacity(three_rho);
    for rbits in &r {
        let mut xm = false;
        for (xi, ri) in x.iter().zip(rbits) {
            xm ^= xi & ri;
        }
        xj.push(xm);
    }

    // Step 3 b continued) Send xj and its corresponding MACs to all parties except self.
    let mut xj_xjmac = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        for (rbits, xj) in r.iter().zip(xj.iter()) {
            let mut xjmac = 0;
            for (j, &rbit) in rbits.iter().enumerate() {
                if rbit {
                    xjmac ^= macs[k][j];
                }
            }
            xj_xjmac[k].push((*xj, xjmac));
        }
    }

    let xj_xjmac_k =
        broadcast_first_send_second(channel, i, n, "fabitn", &xj_xjmac, three_rho).await?;

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
                return Err(Error::ABitWrongMAC);
            }
        }
    }
    drop(r);

    // Step 4) Return the first l objects.
    x.truncate(l);
    for k in (0..n).filter(|k| *k != i) {
        keys[k].truncate(l);
        macs[k].truncate(l);
    }
    let mut res = Vec::with_capacity(l);
    for (l, xi) in x.iter().enumerate().take(l) {
        let mut authvec = vec![(Mac(0), Key(0)); n];
        for k in (0..n).filter(|k| *k != i) {
            authvec[k] = (Mac(macs[k][l]), Key(keys[k][l]));
        }
        res.push(Share(*xi, Auth(authvec)));
    }
    Ok((res, multi_shared_rand))
}

/// Protocol PI_aShare that performs F_aShare from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// This protocol allows parties to generate and distribute authenticated random shares securely.
/// It consists of the following steps:
///
/// 1. **Random Bit String Generation**: Each party picks a random bit string of a specified length.
/// 2. **Autenticated Bit Generation**: The parties generate random authenticated bit shares.
/// 3. **Commitment and Verification**:
///    - The parties compute commitments based on a subset of their shares and broadcast these to ensure consistency.
///    - They then verify these commitments by performing decommitments and checking the validity of the
///      MACs against the commitments.
/// 4. **Return Shares**: Finally, the function returns the first `l` authenticated bit shares.
#[maybe_async(AFIT)]
pub(crate) async fn fashare(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    shared_two_by_two: Vec<Vec<Option<ChaCha20Rng>>>,
) -> Result<(Vec<Share>, ChaCha20Rng), Error> {
    // Step 1) Pick random bit-string x (input).

    // Step 2) Run Pi_aBit^n to compute shares.
    let (mut xishares, multi_shared_rand) =
        fabitn((channel, delta), i, n, l + RHO, shared_two_by_two).await?;

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

    let mut c0_c1_cm_k = broadcast(channel, i, n, "fashare comm", &c0_c1_cm, RHO).await?;

    c0_c1_cm_k[i] = c0_c1_cm;

    // 3 b) Pi broadcasts decommitment for macs.
    let mut dm_k = broadcast(channel, i, n, "fashare ver", &dmvec, RHO).await?;
    dm_k[i] = dmvec;

    // 3 c) Compute bi to determine di_bi and send to all parties.
    let mut bi = [false; RHO];
    let mut di_bi = vec![0; RHO];
    for r in 0..RHO {
        for k in (0..n).filter(|k| *k != i) {
            if dm_k[k][r][0] > 1 {
                return Err(Error::InvalidBitValue);
            }
            bi[r] ^= dm_k[k][r][0] != 0;
        }
        di_bi[r] = if bi[r] { d1[r] } else { d0[r] };
    }

    let di_bi_k = broadcast(channel, i, n, "fashare di_bi", &di_bi, RHO).await?;

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
                    return Err(Error::ConversionErr);
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
                return Err(Error::AShareWrongMAC);
            }
        }
    }

    // Step 4) Return first l objects.
    xishares.truncate(l);
    Ok((xishares, multi_shared_rand))
}

/// Protocol Pi_HaAND that performs F_HaAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// This protocol computes the half-authenticated AND of two bit strings.
/// The XOR of xiyj values are generated obliviously, which is half of the z value in an
/// authenticated share, i.e., a half-authenticated share.
#[maybe_async(AFIT)]
async fn fhaand(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    xshares: &[Share],
    yi: Vec<bool>,
) -> Result<Vec<bool>, Error> {
    // Step 1) Obtain x shares (input).
    if xshares.len() != l {
        return Err(Error::InvalidLength);
    }

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

/// This function takes a 128-bit unsigned integer (`u128`) as input and produces a 128-bit hash value.
///
/// We use the BLAKE3 cryptographic hash function to hash the input value and return the resulting hash.
/// The hash is truncated to 128 bits to match the input size. Due to the truncation, the security
/// guarantees of the hash function are reduced to 64-bit collision resistance and 128-bit preimage
/// resistance. This is sufficient for the purposes of the protocol if RHO <= 64, which we expect
/// to be the case in all real-world usages of our protocol.
fn hash128(input: u128) -> Result<u128, Error> {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(&input.to_le_bytes());
    let mut xof = hasher.finalize_xof();
    if RHO > 64 {
        return Err(Error::InvalidHashLength);
    }
    let mut buf = [0u8; 16];
    xof.fill(&mut buf);
    Ok(u128::from_le_bytes(buf))
}

/// Protocol Pi_LaAND that performs F_LaAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// This asynchronous function implements the "leaky authenticated AND" protocol. It computes
/// shares <x>, <y>, and <z> such that the AND of the XORs of the input values x and y equals
/// the XOR of the output values z.
#[maybe_async(AFIT)]
async fn flaand(
    (channel, delta): (&mut impl Channel, Delta),
    (xshares, yshares, rshares): (&[Share], &[Share], &[Share]),
    i: usize,
    n: usize,
    l: usize,
) -> Result<Vec<Share>, Error> {
    // Triple computation.
    // Step 1) Triple computation [random authenticated shares as input parameters xshares, yshares, rshares].
    if xshares.len() != l || yshares.len() != l || rshares.len() != l {
        return Err(Error::InvalidLength);
    }

    // Step 2) Run Pi_HaAND to get back some v.
    let y = yshares.iter().take(l).map(|share| share.0).collect();
    let v = fhaand((channel, delta), i, n, l, xshares, y).await?;

    // Step 3) Compute z and e AND shares.
    let mut z = vec![false; l];
    let mut e = vec![false; l];
    let mut zshares = vec![Share(false, Auth(vec![(Mac(0), Key(0)); n])); l];

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
    let mut ei_uij = vec![vec![]; n];
    for j in (0..n).filter(|j| *j != i) {
        for (ll, phi_l) in phi.iter().enumerate().take(l) {
            let (_, ki_xj) = xshares[ll].1 .0[j];
            ki_xj_phi[j][ll] = hash128(ki_xj.0)?;
            let uij = hash128(ki_xj.0 ^ delta.0)? ^ ki_xj_phi[j][ll] ^ *phi_l;
            ei_uij[j].push((e[ll], uij));
        }
    }

    let ei_uij_k = broadcast_first_send_second(channel, i, n, "flaand", &ei_uij, l).await?;

    for j in (0..n).filter(|j| *j != i) {
        for (ll, xbit) in xshares.iter().enumerate().take(l) {
            let (mi_xj, _) = xshares[ll].1 .0[j];
            ki_xj_phi[j][ll] ^= hash128(mi_xj.0)? ^ (xbit.0 as u128 * ei_uij_k[j][ll].1);
            // mi_xj_phi added here
            // Part of Step 3) If e is true, this is negation of r as described in WRK17b, if e is false, this is a copy.
            let (mac, key) = rshares[ll].1 .0[j];
            if ei_uij_k[j][ll].0 {
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
    let commhi_k = broadcast(channel, i, n, "flaand comm", &commhi, l).await?;

    // Then all parties broadcast Hi.
    let hi_k = broadcast(channel, i, n, "flaand hash", &hi, l).await?;

    let mut xor_all_hi = hi; // XOR for all parties, including p_own
    for k in (0..n).filter(|k| *k != i) {
        for (ll, (xh, hi_k)) in xor_all_hi.iter_mut().zip(hi_k[k].clone()).enumerate() {
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

/// Protocol Pi_aAND that performs F_aAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// The protocol combines leaky authenticated bits into non-leaky authenticated bits.
#[maybe_async(AFIT)]
async fn faand(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize, //num_and_gates
    shared_rand: &mut ChaCha20Rng,
    xyr_shares: Vec<Share>,
) -> Result<Vec<(Share, Share, Share)>, Error> {
    let b = bucket_size(l);
    let lprime = l * b;
    if xyr_shares.len() != 3 * lprime {
        return Err(Error::InvalidLength);
    }

    let (xshares, rest) = xyr_shares.split_at(lprime);
    let (yshares, rshares) = rest.split_at(lprime);

    // Step 1) Generate all leaky AND triples by calling flaand l' times.
    let zshares = flaand((channel, delta), (xshares, yshares, rshares), i, n, lprime).await?;
    let triples: Vec<(&Share, &Share, &Share)> = (0..lprime)
        .map(|l| (&xshares[l], &yshares[l], &zshares[l]))
        .collect();

    // Step 2) Randomly partition all objects into l buckets, each with b objects.
    let mut buckets: Vec<Bucket> = vec![smallvec![]; l];

    for obj in triples {
        let mut j = shared_rand.gen_range(0..l);
        while buckets[j].len() >= b {
            j = (j + 1) % l;
        }
        buckets[j].push(obj);
    }

    // Step 3) For each bucket, combine b leaky ANDs into a single non-leaky AND.
    let d_values = check_dvalue((channel, delta), i, n, &buckets).await?;
    if d_values.len() != buckets.len() {
        //=l
        return Err(Error::InvalidLength);
    }

    let mut aand_triples = Vec::with_capacity(buckets.len());
    for (bucket, d) in buckets.into_iter().zip(d_values.into_iter()) {
        aand_triples.push(combine_bucket(i, n, bucket, d)?);
    }

    Ok(aand_triples)
}

/// Protocol that transforms precomputed AND triples to specific triples using Beaver's method.
#[maybe_async(AFIT)]
pub(crate) async fn beaver_aand(
    (channel, delta): (&mut impl Channel, Delta),
    alpha_beta_shares: Vec<(Share, Share)>,
    i: usize,
    n: usize,
    l: usize, //num_and_gates
    shared_rand: &mut ChaCha20Rng,
    abc_shares: Vec<Share>,
) -> Result<Vec<Share>, Error> {
    if alpha_beta_shares.len() != l {
        //abc_shares length is checked in function faand
        return Err(Error::InvalidLength);
    }

    let abc_triples = faand((channel, delta), i, n, l, shared_rand, abc_shares).await?;
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
        for (j, (dshare, eshare)) in de_shares.iter().enumerate() {
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

            let expected_dmac = dkey.0 ^ if d { delta.0 } else { 0 };
            let expected_emac = ekey.0 ^ if e { delta.0 } else { 0 };
            if dmac.0 != expected_dmac || emac.0 != expected_emac {
                return Err(Error::BeaverWrongMAC);
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
#[maybe_async(AFIT)]
async fn check_dvalue(
    (channel, delta): (&mut impl Channel, Delta),
    i: usize,
    n: usize,
    buckets: &[Bucket<'_>],
) -> Result<Vec<Vec<bool>>, Error> {
    // Step (a) compute and check macs of d-values.
    let len = buckets.len();
    let mut d_values: Vec<Vec<bool>> = vec![vec![]; len];
    if len == 0 {
        return Err(Error::EmptyVector);
    }

    for (j, bucket) in buckets.iter().enumerate() {
        let (_, y, _) = &bucket[0];
        for (_, y_next, _) in bucket.iter().skip(1) {
            d_values[j].push(y.0 ^ y_next.0);
        }
    }

    for k in (0..n).filter(|&k| k != i) {
        let mut dvalues_macs = vec![(vec![], vec![]); len];
        for (j, bucket) in buckets.iter().enumerate() {
            let (_, y, _) = &bucket[0];
            for (_, y_next, _) in bucket.iter().skip(1) {
                let (y0mac, _) = y.1 .0[k];
                let (ymac, _) = y_next.1 .0[k];
                dvalues_macs[j].1.push(y0mac ^ ymac);
            }
            dvalues_macs[j].0 = d_values[j].to_vec();
        }
        send_to(channel, k, "dvalue", &dvalues_macs).await?;
        drop(dvalues_macs);
    }

    for k in (0..n).filter(|k| *k != i) {
        let dvalues_macs_k =
            recv_vec_from::<(Vec<bool>, Vec<Mac>)>(channel, k, "dvalue", len).await?;
        for (j, dval) in d_values.iter_mut().enumerate().take(len) {
            let (d_value_p, d_macs_p) = &dvalues_macs_k[j];
            let (_, y0key) = buckets[j][0].1 .1 .0[k];
            for (m, (d, dmac)) in dval.iter_mut().zip(d_macs_p).enumerate() {
                let (_, ykey) = buckets[j][m + 1].1 .1 .0[k];
                let expected_mac = y0key.0 ^ ykey.0 ^ if d_value_p[m] { delta.0 } else { 0 };
                if dmac.0 != expected_mac {
                    return Err(Error::AANDWrongMAC);
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
    let mut bucket = bucket.into_iter();
    let (x, y, z) = match bucket.next() {
        Some(item) => item,
        None => return Err(Error::EmptyBucket),
    };
    let mut result = (x.clone(), y.clone(), z.clone());

    // Combine elements one by one, starting from the second element.
    for (triple, d) in bucket.zip(d_vec.into_iter()) {
        result =
            combine_two_leaky_ands(i, n, x.clone(), y.clone(), z.clone(), triple.0, triple.2, d)?;
    }
    Ok(result)
}

/// Combine two leaky ANDs into one non-leaky AND.
fn combine_two_leaky_ands(
    i: usize,
    n: usize,
    x1: Share,
    y1: Share,
    z1: Share,
    x2: &Share,
    z2: &Share,
    d: bool,
) -> Result<(Share, Share, Share), Error> {
    //Step (b) compute x, y, z.
    let xbit = x1.0 ^ x2.0;
    let mut xauth = Auth(vec![(Mac(0), Key(0)); n]);
    for k in 0..n {
        if k == i {
            continue;
        }
        let (mk_x1, ki_x1) = x1.1 .0[k];
        let (mk_x2, ki_x2) = x2.1 .0[k];
        xauth.0[k] = (mk_x1 ^ mk_x2, ki_x1 ^ ki_x2);
    }
    let xshare = Share(xbit, xauth);

    let zbit = z1.0 ^ z2.0 ^ d & x2.0;
    let mut zauth = Auth(vec![(Mac(0), Key(0)); n]);
    for k in 0..n {
        if k == i {
            continue;
        }
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
