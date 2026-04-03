//! Preprocessing protocol generating authenticated triples for secure multi-party computation.
//!
//! This module implements the preprocessing phase of the [WRK17b](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979)
//! protocol, which generates the cryptographic material needed for maliciously-secure MPC. The
//! preprocessing has a function-independent and function-dependent phase.
//! The authenticated shares and multiplication triples computed in the function-independent preprocessing
//! can be used for any boolean circuit of appropriate size. The function-dependent preprocessing uses
//! multiplication triples to compute the AND of the input authenticated shares to each AND gate.
//!
//! The preprocessing phase generates shares of **authenticated multiplication triples** (x, y, z) where z = x ∧ y:
//! Each share consists of:
//! - A share x_i of a secret bit value x held by party i
//! - MACs of x_i authenticated by all other parties j != i
//! - The Keys of party i for the MACs of the shared bits x_j held by the other parties j != i
//!
//! The authentication structure and protocols ensure that malicious parties cannot deviate from the protocol
//! without being detected with overwhelming probability depending on the statistical security
//! parameter RHO = 40 (this means that any cheating attempt is detected with probability
//! at least `1 - 2^-40`).
//!
//! The preprocessing consists of several layered protocols, each building on the previous:
//!
//! ## 1. Randomness Generation
//! - [`shared_rng`]: Multi-party coin-tossing to generate shared randomness across all parties
//! - [`shared_rng_pairwise`]: Pairwise coin-tossing for party-to-party OT operations
//!   These ensure that no single party can bias the random values used throughout preprocessing.
//!
//! ## 2. Authenticated Bit Generation
//! - [`fabitn`]: Generates random authenticated bits using oblivious transfer (OT) between each
//!   pair of parties, with statistical verification to detect malicious behavior
//!
//! ## 3. Authenticated Share Generation
//! - [`fashare`]: Builds on `fabitn` with additional commitment-based verification to generate
//!   authenticated random shares
//!
//! ## 4. AND Triple Generation
//! The core preprocessing output is authenticated AND triples (x, y, z) where z = x ∧ y:
//! - [`fhaand`]: Computes authenticated x of the triple and unauthenticated cross terms of x ∧ y
//!   (half authenticated AND)
//! - [`flaand`]: Combines half-authenticated ANDs into "leaky" authenticated AND triples
//! - [`faand`]: Uses bucketing to combine multiple leaky ANDs into fully secure AND triples
//!
//! ## 5. Function-dependent preprocessing
//! - [`beaver_aand`]: Uses authenticated AND triples to multiply randomly sampled authenticated
//!   input shares of AND gates to compute output share.
use std::{fmt, vec};

use futures_util::future::try_join_all;
use rand::{Rng, SeedableRng, random, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{Level, debug, instrument};

use crate::{
    block::Block,
    channel::{self, Channel, recv_vec_from, scatter, send_to, unverified_broadcast},
    crypto::AesRng,
    mpc::data_types::{Auth, Delta, Key, Mac, Share},
    ot::{kos_ot_receiver, kos_ot_sender},
    utils::{serialize, xor_inplace},
};

/// The statistical security parameter `RHO` used for cryptographic operations.
const RHO: usize = 40;

/// A custom error type for MPC precomputation. All errors in this module represent protocol aborts.
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ChannelErr(e) => write!(f, "Channel error: {e:?}"),
            Error::InvalidBitValue => write!(f, "Invalid bit value (expected 0 or 1)"),
            Error::CommitmentCouldNotBeOpened => write!(f, "Commitment could not be opened"),
            Error::EmptyVector => write!(f, "Empty vector"),
            Error::ConversionErr => write!(f, "Conversion error"),
            Error::EmptyBucket => write!(f, "Empty bucket"),
            Error::EmptyMsg => write!(f, "Empty message"),
            Error::InvalidLength => write!(f, "Invalid array length"),
            Error::InconsistentBroadcast => write!(f, "Inconsistent broadcast"),
            Error::KOSConsistencyCheckFailed => write!(f, "KOS OT consistency check failed"),
            Error::ABitWrongMAC => write!(f, "Wrong MAC in aBit"),
            Error::AShareWrongMAC => write!(f, "Wrong MAC in aShare"),
            Error::LaANDXorNotZero => write!(f, "XOR of values in LaAND not zero"),
            Error::AANDWrongMAC => write!(f, "Wrong MAC of d in leaky AND combination"),
            Error::BeaverWrongMAC => write!(f, "Wrong MAC of e (Beaver triple)"),
            Error::InvalidHashLength => {
                write!(f, "Too short hash for statistical security parameter")
            }
        }
    }
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelErr(e)
    }
}

/// Represents a cryptographic commitment as a fixed-size 32-byte array (a BLAKE3 hash).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
struct Commitment([u8; 32]);

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

/// Hashes a Vec<T> using BLAKE3 and returns the resulting hash as `u128`.
///
/// The hash is truncated to 128 bits to match the input size. Due to the truncation, the security
/// guarantees of the hash function are reduced to 64-bit collision resistance and 128-bit preimage
/// resistance. This is sufficient for the purposes of the protocol if RHO <= 64, which we expect
/// to be the case in all real-world usages of our protocol.
///
/// This function is used for broadcast consistency checks.
fn hash_vec<T: Serialize>(data: &Vec<T>) -> Result<u128, Error> {
    // Empty vectors would always serialize to the same byte sequence, producing a
    // fixed hash.
    if data.is_empty() {
        return Err(Error::EmptyVector);
    }
    let serialized_data = serialize(data).map_err(|_| Error::ConversionErr)?;

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

/// Performs the verification step of *broadcast with abort* following the
/// Goldwasser–Lindell protocol[^broadcast].
///
/// This function checks the correctness of a broadcast performed via
/// `unverified_broadcast` by ensuring that *all parties* report *consistent
/// hashes* of the values they claim to have received.
///
/// Each party `i`:
/// - Computes a hash of every vector it received from other parties.
/// - Sends these hashes (except its own and the recipient’s) in a modified
///   vector via `scatter`.
/// - Receives similar modified vectors from all other parties.
/// - Verifies that every party reports the same hash for the value coming
///   from index `j`.
///
/// # Note
/// If `n == 2`, broadcast verification is skipped because consistency is
/// trivially guaranteed in the two-party case.
///
/// [^broadcast]: [Secure Multi-Party Computation Without Agreement](https://eprint.iacr.org/2002/040.pdf)
///     p. 16, Protocol 1 using hashes of values instead of actual values.
async fn broadcast_verification<
    T: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
>(
    channel: &impl Channel,
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
    let mut modified_vecs = vec![vec![None; n]; n];
    for k in (0..n).filter(|k| *k != i) {
        for j in (0..n).filter(|j| *j != i && *j != k) {
            if vec[j].is_empty() {
                return Err(Error::EmptyVector);
            }
            modified_vecs[k][j] = Some(hash_vecs[j]);
        }
    }

    let received_vecs = scatter(channel, i, phase, &modified_vecs).await?;

    // Step 2.1: Verify the vectors from all parties, that for index j the value is
    // the same for all parties.
    for k in (0..n).filter(|k| *k != i) {
        let vec_k = &received_vecs[k];
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

/// Implements broadcast with abort among all parties using the Goldwasser–Lindell
/// protocol.
///
/// This function:
/// 1. Performs an unverified broadcast of the local vector.
/// 2. Runs broadcast verification to ensure all parties received
///    consistent values.
/// 3. Returns the verified matrix of broadcasted values.
pub(crate) async fn broadcast<
    T: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
>(
    channel: &impl Channel,
    i: usize,
    n: usize,
    phase: &str,
    vec: &[T],
) -> Result<Vec<Vec<T>>, Error> {
    let res_vec = unverified_broadcast(channel, i, n, phase, vec).await?;
    let string = "broadcast ";
    broadcast_verification(channel, i, n, &(string.to_owned() + phase), &res_vec).await?;
    Ok(res_vec)
}

/// Performs a *combined* verified broadcast and scatter.
///
/// Each party provides a vector of tuples `(T, S)`.  
/// - `T` must be *identical across all parties* at each position `k`.
/// - `S` may differ and is scattered normally.
///
/// The protocol:
/// 1. **Scatters** the full `(T, S)` tuples (unverified broadcast of `T`,
///    scatter of `S`).  
/// 2. Collects all first components `T`.
/// 3. Performs **broadcast verification** on the collected `T` to ensure
///    consistency.  
///
/// If verification succeeds, the function returns all received tuples;
/// otherwise it aborts.
///
/// # Correctness Requirement
/// The following must hold, otherwise broadcast verification will detect the
/// disagreement and abort:
/// ```ignore
/// for each i,j in {0,..,n}^2:
///     for k in {0,.., data[0].len()}:
///         data[i].0[k] == data[j].0[k]
///
/// ```
///
/// # Note
/// This function was added as an optimization of the protocol rounds. By scattering
/// together multiple independent elements and performing the broadcast verification
/// only on one of them, we reduce the number of communication rounds needed.
async fn broadcast_first_scatter_second<
    T: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
    S: Clone + Serialize + DeserializeOwned + std::fmt::Debug + PartialEq,
>(
    channel: &impl Channel,
    i: usize,
    n: usize,
    phase: &str,
    data: &[Vec<(T, S)>],
) -> Result<Vec<Vec<(T, S)>>, Error> {
    // First we scatter the data, as the second elements of the tuple with type `S`
    // might be different. This effectively `unverified_broadcasts`s the first elements
    let recv_vec = scatter(channel, i, phase, data).await?;
    // Now we extract those first elements of the tuples which we scattered which
    // should have been equal
    let first_vec: Vec<Vec<T>> = recv_vec
        .iter()
        .map(|inner_vec| inner_vec.iter().map(|(a, _)| a.clone()).collect())
        .collect();
    let string = "broadcast ";
    // And verify that the first elements of the tuples were indeed broadcasted correctly
    broadcast_verification(channel, i, n, &(string.to_owned() + phase), &first_vec).await?;
    // As a result, we have broadcasted the first elements of the vec and scattered the second
    Ok(recv_vec)
}

/// Multi-party coin tossing to derive a *shared* cryptographically secure RNG.
///
/// This function implements standard MPC coin tossing:
/// - Each party samples a random 256-bit seed.
/// - Commits to it and broadcasts the commitment.
/// - Broadcasts the seed (decommitment).
/// - Verifies every other party’s commitment.
/// - XORs all revealed seeds together to obtain a joint random seed.
///
/// The resulting seed is used to instantiate a `ChaCha20Rng` that is **identical
/// for all honest parties** and unpredictable to any adversary unless it
/// corrupts *all* parties.
#[instrument(level=Level::DEBUG, skip_all, err)]
pub(crate) async fn shared_rng(
    channel: &impl Channel,
    i: usize,
    n: usize,
) -> Result<ChaCha20Rng, Error> {
    debug!(party_id = i, num_parties = n, "Multi-party RNG generation");
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
    let commitments = broadcast(channel, i, n, "RNG comm", &comm).await?;

    // Step 3) Send and receive decommitments concurrently for multi-party cointossing.
    let bufs_vec = unverified_broadcast(channel, i, n, "RNG ver", &buf).await?;
    let bufs: Vec<[u8; 32]> = bufs_vec
        .into_iter()
        .enumerate()
        .map(|(k, v)| {
            if k != i {
                v.try_into()
                    .expect("len 32 checked by unverified_broadcast")
            } else {
                [0; 32]
            }
        })
        .collect();

    let mut bufs_id = vec![[0; 34]; n];
    for k in (0..n).filter(|k| *k != i) {
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

/// Pairwise two-party coin tossing for generating shared RNGs between
/// every pair of parties.
///
/// This is used by protocols that require pairwise shared randomness, such as the
/// two-party KOS Oblivious Transfer extension protocol (see `ot_core/kos.rs`).
///
/// For each ordered pair `(i, k)`:
/// - Both parties generate random 256-bit seeds.
/// - Exchange commitments, then seeds.
/// - Verify commitments.
/// - XOR the two seeds to obtain a shared 256-bit value.
/// - Use that to create a `ChaCha20Rng`.
#[instrument(level=Level::DEBUG, skip_all, err)]
pub(crate) async fn shared_rng_pairwise(
    channel: &impl Channel,
    i: usize,
    n: usize,
) -> Result<Vec<Vec<Option<ChaCha20Rng>>>, Error> {
    debug!(party_id = i, num_parties = n, "Pairwise RNG generation");
    // Step 1 b) Generate a random 256-bit seed for every other party for the pairwise
    // cointossing and commit to it.
    let bufvec: Vec<Vec<u8>> = (0..n).map(|_| random::<[u8; 32]>().to_vec()).collect();
    let mut bufvec_id: Vec<[u8; 34]> = vec![[0; 34]; n];
    let mut commitment_vec = vec![vec![Commitment([0; 32])]; n];
    for k in (0..n).filter(|k| *k != i) {
        bufvec_id[k][..32].copy_from_slice(&bufvec[k]);
        let id_bytes = (i as u16).to_be_bytes();
        bufvec_id[k][32..].copy_from_slice(&id_bytes);
        commitment_vec[k][0] = commit(&bufvec_id[k]);
    }

    // Step 2) Send and receive commitments concurrently for pairwise cointossing.

    let commitments = scatter(channel, i, "RNG comm", &commitment_vec).await?;

    // Step 3) Send and receive decommitments concurrently for pairwise cointossing.
    let bufs = scatter(channel, i, "RNG ver", &bufvec).await?;

    let mut bufs_id = vec![[0; 34]; n];
    for k in (0..n).filter(|k| *k != i) {
        bufs_id[k][..32].copy_from_slice(&bufs[k]);
        let id_bytes = (k as u16).to_be_bytes();
        bufs_id[k][32..].copy_from_slice(&id_bytes);
    }

    // Step 4) Verify the decommitments.
    for k in (0..n).filter(|k| *k != i) {
        if !open_commitment(&commitments[k][0], &bufs_id[k]) {
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

/// Implements protocol PI_aBit^n from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// This protocol realizes the ideal functionality F_aBit^n, generating:
///   - a random bit-string `x` of length `l`, and  
///   - for each party pair `(i, k)`, correlated keys and MACs authenticating
///     the bits of `x`.
///
/// The protocol consists of three main phases:
///
/// 1. Random-bit generation
/// Each party samples a local random bit-string `x` of length `l' = l + 3*RHO`,
/// where RHO is the statistical security parameter.  
/// The last `3*RHO` bits are used only for MAC/key verification and are
/// discarded at the end.
///
///
/// 2. Pairwise OTs to construct keys and MACs
/// For every party pair `(i, k)`, the parties run two KOS OT extensions
/// using their pairwise shared RNG (`shared_two_by_two`):
///   • Sender role produces keys  
///   • Receiver role produces MACs for its chosen bits `x`  
///
/// 3. Global MAC consistency check
/// The parties jointly sample `3*RHO` random challenge vectors `r` using the shared
/// multi-party RNG `multi_shared_rand`, and if any check fails, the protocol aborts.
///
///
/// 4. Output truncation
/// Only the first `l` bits, keys, and MACs are kept.  
#[instrument(level=Level::DEBUG, skip_all, fields(
    num_auth_bits = l,
), err)]
async fn fabitn(
    (channel, delta): (&impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    shared_two_by_two: &mut [Vec<Option<ChaCha20Rng>>],
    multi_shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<Share>, Error> {
    debug!("PI_aBit^n protocol of WRK17b");
    // Step 1) Pick random bit-string x of length lprime.
    // (!) Different from the paper: we generate 3*RHO extra bits instead of 2*RHO bits as
    // specified in theorem B.1 on page 26 of [WRK17b]. The proof in the paper is erroneous
    // and only holds for 3*RHO bits.
    let three_rho = 3 * RHO;
    let lprime = l + three_rho;
    let mut x: Vec<bool> = (0..lprime).map(|_| random()).collect();
    debug!("Generated local bitstring x of length {}", lprime);

    // Steps 2) Use the output of the oblivious transfers between each pair of parties to generate keys and macs.
    let deltas = vec![Block::from(delta.0.to_be_bytes()); lprime];

    // Step 2: Use the shared RNGs for key and MAC generation
    if !(shared_two_by_two.len() == n && shared_two_by_two.iter().all(|row| row.len() == n)) {
        return Err(Error::InvalidLength);
    }

    let shared_rngs = (0..n).map(|k| {
        let (a, b) = if i < k { (i, k) } else { (k, i) };
        shared_two_by_two[a][b].clone()
    });

    let ot_futs = shared_rngs.enumerate().map(async |(k, mut rng)| {
        if k == i {
            return Ok((vec![], vec![]));
        }
        // TODO unfortunately we can't do pairwise OT sending/receiving in parallel due to limitations in the
        //  Channel implementation. If we execute
        // ```
        // join(
        //     kos_ot_sender(channel, &delta, k, shared)
        //     kos_ot_receiver(channel, &x, k, shared)
        // )
        // ```
        // the channel implementation can't distinguish between the messages intended for the ot
        // sender and for the ot receiver. We would likely need a notion of sub-channels over
        // an existing channel for this.
        debug!("Starting pairwise OT with party {}", k);
        if let Some(shared) = &mut rng {
            if i < k {
                let keys = kos_ot_sender(channel, &deltas, k, shared).await?;
                let macs = kos_ot_receiver(channel, &x, k, shared).await?;
                Ok((keys, macs))
            } else {
                let macs = kos_ot_receiver(channel, &x, k, shared).await?;
                let keys = kos_ot_sender(channel, &deltas, k, shared).await?;
                Ok((keys, macs))
            }
        } else {
            Err(Error::EmptyVector)
        }
    });

    // TODO having keys and macs as Blocks will likely further increase performance as then
    // explicit sse2 instructions are used (whe available) (robinhundt 2.9.25)
    let (mut keys, mut macs): (Vec<_>, Vec<_>) = try_join_all(ot_futs).await?.into_iter().unzip();

    drop(deltas);

    // Step 2) Run 2-party OTs to compute keys and MACs [input parameters mm and kk].

    // Seed a faster AesRng from the shared chacha rng
    let mut aes_rand = AesRng::from_seed(multi_shared_rand.random());
    // Step 3) Verification of MACs and keys.
    // Step 3 a) Sample 3 * RHO random l'-bit strings r.
    // We sample whole Blocks as this requires less memory and is faster than sampling
    // individual bools.
    let blocks = lprime.div_ceil(Block::BITS);
    let r: Vec<Vec<Block>> = (0..three_rho)
        .map(|_| (0..blocks).map(|_| aes_rand.random()).collect())
        .collect();

    // Step 3 b) Compute xj and xjmac for each party, broadcast xj.
    // (!) Different from paper: We batch messages and send xjmac with xj as well, as from
    // Step 3 d).
    let mut xj = Vec::with_capacity(three_rho);
    for rbits in &r {
        let mut xm = false;
        chunked_update_with_rbits(&x, rbits, |xi, rbit| {
            let ri = rbit != 0;
            xm ^= xi & ri;
        });
        xj.push(xm);
    }

    let mut xj_xjmac = vec![vec![]; n];
    for k in (0..n).filter(|k| *k != i) {
        let macs = &macs[k];
        for (rbits, xj) in r.iter().zip(xj.iter()) {
            let mut xjmac = 0;
            chunked_update_with_rbits(macs, rbits, |mac, rbit| {
                let mask = (-(rbit as i128)) as u128;
                xjmac ^= mac & mask;
            });
            xj_xjmac[k].push((*xj, xjmac));
        }
    }

    // Step 3 b continued) Send xj and its corresponding MACs to all parties except self.
    let xj_xjmac_k = broadcast_first_scatter_second(channel, i, n, "fabitn", &xj_xjmac).await?;

    // Step 3 c) Compute keys.
    for (j, rbits) in r.iter().enumerate() {
        for k in (0..n).filter(|k| *k != i) {
            let (xj, xjmac) = &xj_xjmac_k[k][j];
            let mut xjkey = 0;

            chunked_update_with_rbits(&keys[k], rbits, |key, rbit| {
                let mask = (-(rbit as i128)) as u128;
                xjkey ^= key & mask;
            });

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
    Ok(res)
}

// A helper function that calls the update function with each element of x and a u64 where
// the lowest bit is the random bit for this element x_i.
// This function applies the update function to chunks of x to make use of automatic loop
// unrolling and efficiently transform the rbits Blocks into individual bits.
// This function is generic as it is called with T = bool and T = u128
fn chunked_update_with_rbits<T>(x: &[T], rbits: &[Block], mut update: impl FnMut(&T, u64)) {
    // Blocks are 128 bits, so we split x into 128 bit chunks
    let (chunks, remainder) = x.as_chunks::<128>();
    let mut r_bits = rbits.iter();
    for (chunk, r_chunk) in chunks.iter().zip(r_bits.by_ref()) {
        // We can't efficiently iterate over all bits a Block, so we split it into
        // the low and high 64 bits over which we iterate by ANDing 1 and shifting
        let mut lower_r = r_chunk.low();
        for xi in &chunk[..64] {
            update(xi, lower_r & 1);
            lower_r >>= 1;
        }

        let mut upper_r = r_chunk.high();
        for xi in &chunk[64..] {
            update(xi, upper_r & 1);
            upper_r >>= 1;
        }
    }

    if remainder.is_empty() {
        return;
    }
    // handle the remainder
    let r_chunk = r_bits.next().expect("Insufficient random bits");
    let mut lower_r = r_chunk.low();
    for xi in remainder.iter().take(64) {
        update(xi, lower_r & 1);
        lower_r >>= 1;
    }
    let mut upper_r = r_chunk.high();
    for xi in remainder.iter().skip(64) {
        update(xi, upper_r & 1);
        upper_r >>= 1;
    }
}

/// Protocol PI_aShare that performs F_aShare from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// We closely follow the description in the paper.
///
/// This protocol allows parties to generate and distribute authenticated random shares securely.
/// It consists of the following steps:
///
/// a. **Autenticated Bit Generation**: The parties generate random authenticated bit shares.
/// b. **Commitment and Verification**:
///    - The parties compute commitments based on a subset of their shares and broadcast these to ensure consistency.
///    - They then verify these commitments by performing decommitments and checking the validity of the
///      MACs against the commitments.
/// c. **Return Shares**: Finally, the function returns the first `l` authenticated bit shares.
#[instrument(level=Level::DEBUG, skip_all, fields(
    num_auth_shares = l,
), err)]
pub(crate) async fn fashare(
    (channel, delta): (&impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    shared_two_by_two: &mut [Vec<Option<ChaCha20Rng>>],
    multi_shared_rand: &mut ChaCha20Rng,
) -> Result<Vec<Share>, Error> {
    // Step 1) Pick random bit-string x (input). This is done inside fabitn.
    // Step 2) Run Pi_aBit^n to to obtain l + RHO authenticated bits. The last RHO bits are
    // reserved exclusively for consistency checking and will be discarded.
    debug!("PI_aShare protocol of WRK17b");
    let mut xishares = fabitn(
        (channel, delta),
        i,
        n,
        l + RHO,
        shared_two_by_two,
        multi_shared_rand,
    )
    .await?;

    // Step 3) Compute commitments and verify consistency:
    // 3 a) Compute d0, d1, dm, c0, c1, cm and broadcast commitments to all parties.
    // For each of the last ρ authenticated bits, we compute:
    //   • d0  = XOR of all keys,
    //   • d1  = d0 XOR delta,
    //   • dm  = local bit and all MACs (concatenated),
    // and commit to all three values.
    let mut d0 = vec![0; RHO];
    let mut d1 = vec![0; RHO];
    let mut c0_c1_cm = Vec::with_capacity(RHO); // c0, c1, cm
    let mut dmvec = Vec::with_capacity(RHO);

    for r in 0..RHO {
        let xishare = &xishares[l + r];
        let mut dm = Vec::with_capacity(n * 16);
        // First byte is the local bit
        dm.push(xishare.0 as u8);
        // Collect MACs and XOR keys
        for k in (0..n).filter(|k| *k != i) {
            let (mac, key) = xishare.1.0[k];
            d0[r] ^= key.0;
            dm.extend(&mac.0.to_be_bytes());
        }
        // Alternative key value for bit = 1
        d1[r] = d0[r] ^ delta.0;
        // Commit to both possibilities and the MAC vector
        let c0 = commit(&d0[r].to_be_bytes());
        let c1 = commit(&d1[r].to_be_bytes());
        let cm = commit(&dm);

        c0_c1_cm.push((c0, c1, cm));
        dmvec.push(dm);
    }

    // Broadcast commitments
    let mut c0_c1_cm_k = broadcast(channel, i, n, "fashare comm", &c0_c1_cm).await?;

    c0_c1_cm_k[i] = c0_c1_cm;

    // 3 b) Pi broadcasts decommitment for macs.
    let mut dm_k = broadcast(channel, i, n, "fashare ver", &dmvec).await?;
    dm_k[i] = dmvec;

    // Step 4) Determine the effective bit b_i for each check index
    // and broadcast the corresponding di_bi.
    let mut bi = [false; RHO];
    let mut di_bi = vec![0; RHO];
    for r in 0..RHO {
        // Reconstruct b_i by XORing all revealed bit values
        for k in (0..n).filter(|k| *k != i) {
            if dm_k[k][r][0] > 1 {
                return Err(Error::InvalidBitValue);
            }
            bi[r] ^= dm_k[k][r][0] != 0;
        }
        // Select d0 or d1 depending on b_i
        di_bi[r] = if bi[r] { d1[r] } else { d0[r] };
    }

    let di_bi_k = broadcast(channel, i, n, "fashare di_bi", &di_bi).await?;

    // 3 d) Consistency check of macs: open commitment of xor of keys and check if it equals
    // to the xor of all macs.
    let mut xor_xk_macs = vec![vec![0; RHO]; n];
    for r in 0..RHO {
        // Reconstruct XOR of MACs from all parties
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
        // Check commitment openings and MAC equality
        for k in (0..n).filter(|k| *k != i) {
            let d_bj = &di_bi_k[k][r].to_be_bytes();
            let (c0, c1, _) = &c0_c1_cm_k[k][r];
            if !open_commitment(c0, d_bj) && !open_commitment(c1, d_bj) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            if xor_xk_macs[k][r] != di_bi_k[k][r] {
                return Err(Error::AShareWrongMAC);
            }
        }
    }

    // Step 4) Return first l objects.
    xishares.truncate(l);
    debug!("Returning first {} authenticated shares", l);
    Ok(xishares)
}

/// Protocol Pi_HaAND that performs F_HaAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
/// We closely follow the description in the paper.
///
/// This protocol computes the half-authenticated AND of two bit strings.
/// The XOR of xiyj values are generated obliviously, which is half of the z value in an
/// authenticated share, i.e., a half-authenticated share.
/// - `x` is provided as authenticated shares as input to the protocol (slight difference from paper),
/// - `y` is provided as a local cleartext bit vector.
///
/// The output is a vector `v` such that, for each position `i`:
///
/// ```text
/// v[i] = XOR_j (x_j[i] ∧ y_i[i])
/// ```
/// where the XOR ranges over all parties’ contributions. This value corresponds
/// to the unauthenticated cross terms of x ∧ y.
///
///
/// # High-level idea
///
/// Each party masks its contribution with random bits and uses
/// hash-based correlation checks (derived from MAC keys) so that:
/// - no party learns the other parties’ inputs,
/// - correctness is guaranteed assuming the MACs are valid,
/// - the result can later be completed into a fully authenticated AND.
///
/// This protocol performs no MAC verification itself; correctness relies on the
/// validity of the input authenticated shares. The output must be combined with
/// additional steps to obtain a fully authenticated AND.
#[instrument(level=Level::DEBUG, skip_all, err)]
async fn fhaand(
    (channel, delta): (&impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize,
    xshares: &[Share],
    yi: Vec<bool>,
) -> Result<Vec<bool>, Error> {
    debug!("PI_HaAND protocol of WRK17b");
    // Step 1) Obtain x shares (input).
    if xshares.len() != l {
        return Err(Error::InvalidLength);
    }

    // Step 2) Oblivious computation of masked AND contributions for each party.
    //
    // Each party j not i:
    //   - samples random masks s_j,
    //   - derives hash-based correlations from MAC keys,
    //   - sends masked values (h0, h1) to party j,
    //   - accumulates its local contribution to v.
    let send_all = try_join_all((0..n).filter(|j| *j != i).map(async |j| {
        let mut vi = vec![false; l];
        // Step 2 a) For each bit, sample s_j and compute h0, h1.
        let mut h0h1_for_j = vec![(false, false); l];
        for ll in 0..l {
            let sj: bool = random();
            let (_, kixj) = xshares[ll].1.0[j];
            // Hash MAC keys to derive pseudorandom bits
            let hash_kixj = blake3::hash(&kixj.0.to_le_bytes());
            let hash_kixj_delta = blake3::hash(&(kixj.0 ^ delta.0).to_le_bytes());
            h0h1_for_j[ll].0 = (hash_kixj.as_bytes()[31] & 1 != 0) ^ sj;
            h0h1_for_j[ll].1 = (hash_kixj_delta.as_bytes()[31] & 1 != 0) ^ sj ^ yi[ll];
            // Accumulate masked local contribution
            vi[ll] ^= sj;
        }
        // Send masked values to party j
        send_to(channel, j, "haand", &h0h1_for_j)
            .await
            .map_err(Error::from)?;
        Ok(vi)
    }));

    // Step 2 b) Receive masked values (h0, h1) from all other parties.
    let recv_all = try_join_all((0..n).map(async |j| {
        if j != i {
            recv_vec_from::<(bool, bool)>(channel, j, "haand", l)
                .await
                .map_err(Error::from)
        } else {
            Ok(vec![])
        }
    }));

    let (vi_all, received_h0h1) = futures_util::try_join!(send_all, recv_all)?;

    // Finish step 2) Calculate v by combining all random masks.
    let mut vi = vi_all.iter().fold(vec![false; l], |mut vi, el| {
        xor_inplace(&mut vi, el);
        vi
    });

    // Use received h0, h1 values and authenticated x-shares to compute
    // the final masked AND result v.
    for j in (0..n).filter(|j| *j != i) {
        let h0h1_j = &received_h0h1[j];
        for ll in 0..l {
            let (mixj, _) = xshares[ll].1.0[j];
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

    // Step 3) Return v, the half-authenticated AND shares.
    Ok(vi)
}

/// This function takes a 128-bit unsigned integer (`u128`) as input and produces a 128-bit hash value.
///
/// We use the BLAKE3 cryptographic hash function to hash the input value and return the resulting hash.
///
/// # Security Note
/// The hash is truncated to 128 bits to match the input size. Due to the truncation, the security
/// guarantees of the hash function are reduced to 64-bit collision resistance and 128-bit preimage
/// resistance. This is sufficient for the purposes of the protocol if RHO <= 64, which we expect
/// to be the case in all real-world usages of our protocol.
fn hash128(input: u128) -> Result<u128, Error> {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(&input.to_le_bytes());
    let mut xof = hasher.finalize_xof();
    // Enforce that truncation provides sufficient security
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
/// This function implements the "leaky authenticated AND" protocol. It computes
/// shares <x>, <y>, and <z> such that the AND of the XORs of the input values x and y equals
/// the XOR of the output values z. TODO: I don't think it is right that the "XOR of input values equals output value".
///
/// # Notes
/// This protocol is leaky by design and must be combined with bucketing
/// (as described in WRK17b) to obtain fully secure authenticated AND gates.
#[instrument(level=Level::DEBUG, skip_all, fields(
    num_leaky_auth_ands = l,
), err)]
async fn flaand(
    (channel, delta): (&impl Channel, Delta),
    (xshares, yshares, rshares): (&[Share], &[Share], &[Share]),
    i: usize,
    n: usize,
    l: usize,
) -> Result<Vec<Share>, Error> {
    debug!("PI_LaAND protocol of WRK17b");
    // Triple computation.
    // Step 1) Triple computation [random authenticated shares as input parameters xshares, yshares, rshares].
    if xshares.len() != l || yshares.len() != l || rshares.len() != l {
        return Err(Error::InvalidLength);
    }

    // Step 2) Half-authenticated AND: Run Pi_HaAND to compute masked AND contributions v.
    let y = yshares.iter().take(l).map(|share| share.0).collect();
    let v = fhaand((channel, delta), i, n, l, xshares, y).await?;

    // Step 3) Local computation of z and masking with r.
    // z = v XOR (x AND y)
    // e = z XOR r
    //
    // e will be revealed later in a controlled way.
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
    // Step 4) Compute phi values used for MAC consistency checking.
    let mut phi = vec![0; l];
    for (ll, phi_l) in phi.iter_mut().enumerate().take(l) {
        for k in (0..n).filter(|k| *k != i) {
            let (mk_yi, ki_yk) = yshares[ll].1.0[k];
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
            let (_, ki_xj) = xshares[ll].1.0[j];
            ki_xj_phi[j][ll] = hash128(ki_xj.0)?;
            let uij = hash128(ki_xj.0 ^ delta.0)? ^ ki_xj_phi[j][ll] ^ *phi_l;
            ei_uij[j].push((e[ll], uij));
        }
    }

    // (!) Different from the paper: We send e and uij together to reduce the number of
    // communication rounds. The e values are not used until this point so we can safely postpone
    // their sending until this step in the protocol (in the paper they are broadcast in Step 3).
    let ei_uij_k = broadcast_first_scatter_second(channel, i, n, "flaand", &ei_uij).await?;

    // Compute ki_xj_phi and finalize zshares from Step 3).
    for j in (0..n).filter(|j| *j != i) {
        for (ll, xbit) in xshares.iter().enumerate().take(l) {
            let (mi_xj, _) = xshares[ll].1.0[j];
            // (!) Different from the paper: This step should only compute mi_xj_phi as per Step 5), which
            // is then added to ki_xj_phi later. We do this here to reduce the number of loops over l and
            // improve performance.
            ki_xj_phi[j][ll] ^= hash128(mi_xj.0)? ^ (xbit.0 as u128 * ei_uij_k[j][ll].1);
            // (!) Different from the paper: Since the e values were sent here, we finalize MACs for z depending
            // on mask e only in this step. This completes Step 3).
            // Note: If e is true, this is negation of r as described in WRK17b, if e is false, this is a copy.
            let (mac, key) = rshares[ll].1.0[j];
            if ei_uij_k[j][ll].0 {
                zshares[ll].1.0[j] = (mac, Key(key.0 ^ delta.0));
            } else {
                zshares[ll].1.0[j] = (mac, key);
            }
        }
    }

    // Step 6) Commitment-based global consistency check.
    // Each party computes h_i and commits to it, then opens it. The XOR of all h_i
    // must equal zero for correctness.
    let mut hi = vec![0; l];
    let mut commhi = Vec::with_capacity(l);
    for ll in 0..l {
        for k in (0..n).filter(|k| *k != i) {
            let (mk_zi, ki_zk) = zshares[ll].1.0[k];
            hi[ll] ^= mk_zi.0 ^ ki_zk.0 ^ ki_xj_phi[k][ll];
        }
        hi[ll] ^= (xshares[ll].0 as u128 * phi[ll]) ^ (zshares[ll].0 as u128 * delta.0);
        commhi.push(commit(&hi[ll].to_be_bytes()));
    }
    drop(phi);
    drop(ki_xj_phi);

    // All parties first broadcast the commitment of Hi.
    let commhi_k = broadcast(channel, i, n, "flaand comm", &commhi).await?;

    // Then all parties broadcast Hi.
    let hi_k = broadcast(channel, i, n, "flaand hash", &hi).await?;

    // Step 7) Open commitments and verify global XOR is zero.
    let mut xor_all_hi = hi; // XOR for all parties, including p_own
    for k in (0..n).filter(|k| *k != i) {
        for (ll, (xh, hi_k)) in xor_all_hi.iter_mut().zip(hi_k[k].clone()).enumerate() {
            if !open_commitment(&commhi_k[k][ll], &hi_k.to_be_bytes()) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            *xh ^= hi_k;
        }
    }

    if xor_all_hi.iter().take(l).any(|&xh| xh != 0) {
        return Err(Error::LaANDXorNotZero);
    }
    Ok(zshares)
}

/// Calculates the bucket size according to the paper WRK17a [Authenticated Garbling and Efficient
/// Maliciously Secure Two-Party Computation](https://acmccs.github.io/papers/p21-wangA.pdf),
/// Table 4 for statistical security ρ = 40 (rho).
pub(crate) fn bucket_size(circuit_size: usize) -> usize {
    const {
        if RHO != 40 {
            panic!("RHO must be 40 for the bucket sizes of the WRK17a paper");
        }
    };
    match circuit_size {
        n if n >= 280_000 => 3,
        n if n >= 3_100 => 4,
        _ => 5,
    }
}

type Bucket<'a> = Vec<(&'a Share, &'a Share, &'a Share)>;

/// Protocol Pi_aAND that performs F_aAND from the paper
/// [Global-Scale Secure Multiparty Computation](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979).
///
/// This protocol converts *random authenticated shares* into
/// *fully authenticated AND triples* using bucketing and consistency checks.
///
/// Each output triple `(⟨x⟩, ⟨y⟩, ⟨z⟩)` satisfies:
///
/// ```text
/// XOR_i z_i = (XOR_i x_i) ∧ (XOR_i y_i)
/// ```
/// with full authentication and negligible leakage.
///
/// The protocol consists of the following steps:
/// 1. Generate `lb` leaky AND triples using [Pi_LaAND].
/// 2. Randomly permute and partition the triples into `l` buckets of size `b`.
/// 3. For each bucket, perform a consistency check and combine the
///    `b` leaky triples into a single non-leaky authenticated AND triple.
///
/// # Notes
/// The bucket size `b` is chosen according to [WRK17a]. Bucketing removes the leakage introduced by
/// [Pi_LaAND] at the cost of additional preprocessing. The resulting triples are safe to use
/// in the online MPC phase.
///
/// [Pi_LaAND]: `flaand`
#[instrument(level=Level::DEBUG, skip_all, fields(
    num_auth_ands = l,
), err)]
async fn faand(
    (channel, delta): (&impl Channel, Delta),
    i: usize,
    n: usize,
    l: usize, //num_and_gates
    shared_rand: &mut ChaCha20Rng,
    xyr_shares: &[Share],
) -> Result<Vec<(Share, Share, Share)>, Error> {
    debug!("PI_aAND protocol of WRK17b");
    // Determine bucket size b and total number of leaky triples.
    let b = bucket_size(l);
    let lprime = l * b;
    // Expect x, y, and r shares for all lprime triples.
    if xyr_shares.len() != 3 * lprime {
        return Err(Error::InvalidLength);
    }

    // Split inputs into x, y, and r shares.
    let (xshares, rest) = xyr_shares.split_at(lprime);
    let (yshares, rshares) = rest.split_at(lprime);

    // Step 1) Generate all leaky authenticated AND triples by calling flaand l' times.
    // This produces l' the missing <z> shares of the triples (⟨x⟩, ⟨y⟩, ⟨z⟩) with controlled leakage.
    let zshares = flaand((channel, delta), (xshares, yshares, rshares), i, n, lprime).await?;

    // Step 2) Randomly bucketing.
    // Randomly partition all objects into l buckets, each with b objects.
    // Use SliceRandom::shuffle for unbiased random permutation
    let mut indices: Vec<usize> = (0..lprime).collect();
    indices.shuffle(shared_rand);

    // Distribute shuffled indices into buckets using chunks
    // Since indices.len() == lprime == l * b, chunks_exact(b) gives us exactly l chunks of size b.
    let buckets: Vec<Bucket> = indices
        .chunks_exact(b)
        .map(|chunk| {
            chunk
                .iter()
                .map(|&idx| (&xshares[idx], &yshares[idx], &zshares[idx]))
                .collect()
        })
        .collect();

    debug!(
        "Distributed shares into {} buckets of size {}",
        buckets.len(),
        b
    );

    // Step 3) Bucket verification and combination.
    // For each bucket, combine b leaky ANDs into a single non-leaky authenticated AND triple.
    // (!) Different from the paper: We first check all d-values for all buckets
    // and only if all are valid, we proceed to combine the buckets.
    // This is done to optimize performance by reducing the number of communication rounds.
    let d_values = check_dvalue((channel, delta), i, n, &buckets).await?;
    if d_values.len() != buckets.len() {
        return Err(Error::InvalidLength);
    }

    let mut aand_triples = Vec::with_capacity(buckets.len());
    for (bucket, d) in buckets.into_iter().zip(d_values) {
        aand_triples.push(combine_bucket(i, n, bucket, d)?);
    }

    // Return the final authenticated AND triples.
    Ok(aand_triples)
}

/// Uses authenticated AND to compute AND of pairs of shares.
///
/// This uses Beaver’s method (https://securecomputation.org/docs/pragmaticmpc.pdf#section.3.4)
/// to compute the output share <α ∧ β> of and AND gate with inputs α and β.
///
/// This protocol takes:
/// - precomputed *random* authenticated AND triples,
/// - authenticated input shares for specific values alpha and beta,
/// and produces authenticated shares of α ∧ β (inputs to AND gates)
///
/// The transformation follows Beaver’s method:
/// 1. Parties locally compute blinded differences d and e.
/// 2. Parties broadcast d and e together with MACs and verify correctness.
/// 3. Using the public d and e values, parties locally derive the final AND share.
///
/// The resulting shares are fully authenticated and can be used as inputs
/// to MPC computations.
#[instrument(level=Level::DEBUG, skip_all, fields(
    num_auth_ands = l,
), err)]
pub(crate) async fn beaver_aand(
    (channel, delta): (&impl Channel, Delta),
    alpha_beta_shares: &[(Share, Share)],
    i: usize,
    n: usize,
    l: usize, //num_and_gates
    shared_rand: &mut ChaCha20Rng,
    abc_shares: &[Share],
) -> Result<Vec<Share>, Error> {
    debug!(
        "Protocol for transforming precomputed AND triples using Beaver's method for {} triples",
        l
    );
    if alpha_beta_shares.len() != l {
        //abc_shares length is checked in function faand
        return Err(Error::InvalidLength);
    }

    // Obtain random authenticated AND triples using Pi_aAND.
    let abc_triples = faand((channel, delta), i, n, l, shared_rand, abc_shares).await?;
    debug!("Received {} AND triples from faand", abc_triples.len());
    let len = abc_triples.len();

    // Beaver triple precomputation - transform random triples to specific triples.
    // Steps 1 and 2) of https://securecomputation.org/docs/pragmaticmpc.pdf#section.3.4:
    // compute blinded difference shares for d and e and prepare their macs for verification.
    let mut d_e_dmac_emac = Vec::with_capacity(len);
    let mut de_shares = Vec::with_capacity(len);

    for j in 0..len {
        let (a, b, _) = &abc_triples[j];
        let (alpha, beta) = &alpha_beta_shares[j];

        de_shares.push((a ^ alpha, b ^ beta));
        d_e_dmac_emac.push((a.0 ^ alpha.0, b.0 ^ beta.0, Mac(0), Mac(0)));
    }

    // Scatter d and e together with their MACs to all parties.
    let scatter_data: Vec<Vec<(bool, bool, Mac, Mac)>> = (0..n)
        .map(|k| {
            if k != i {
                let mut d_e_dmac_emac_for_k = d_e_dmac_emac.clone();
                for (j, (dshare, eshare)) in de_shares.iter().enumerate() {
                    let (_, _, dmac, emac) = &mut d_e_dmac_emac_for_k[j];
                    *dmac = dshare.1.0[k].0;
                    *emac = eshare.1.0[k].0;
                }
                d_e_dmac_emac_for_k
            } else {
                vec![]
            }
        })
        .collect();

    // Verify correctness of MACs for d and e.
    let d_e_dmac_emac_k: Vec<Vec<(bool, bool, Mac, Mac)>> =
        scatter(channel, i, "faand", &scatter_data).await?;
    for k in (0..n).filter(|k| *k != i) {
        for (j, &(d, e, ref dmac, ref emac)) in d_e_dmac_emac_k[k].iter().enumerate() {
            let (_, dkey) = de_shares[j].0.1.0[k];
            let (_, ekey) = de_shares[j].1.1.0[k];

            let expected_dmac = dkey.0 ^ if d { delta.0 } else { 0 };
            let expected_emac = ekey.0 ^ if e { delta.0 } else { 0 };
            if dmac.0 != expected_dmac || emac.0 != expected_emac {
                return Err(Error::BeaverWrongMAC);
            }
        }
    }
    // Aggregate all parties' contributions to obtain the final d and e values.
    for (j, (d, e, _, _)) in d_e_dmac_emac.iter_mut().enumerate() {
        for k in (0..n).filter(|&k| k != i) {
            let (d_k, e_k, _, _) = d_e_dmac_emac_k[k][j];
            *d ^= d_k;
            *e ^= e_k;
        }
    }
    let mut alpha_and_beta = Vec::with_capacity(len);

    // Step 3) of https://securecomputation.org/docs/pragmaticmpc.pdf#section.3.4:
    // compute and return the final shares.
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

/// Computes and verifies the d-values used for bucket combination in Pi_aAND.
///
/// For each bucket of leaky AND triples, this function:
/// 1. Computes local `d`-values as XORs of the `y`-shares within the bucket.
/// 2. Collects corresponding MACs from all parties.
/// 3. Verifies that the MACs are consistent with the global MAC key delta.
/// 4. Aggregates all parties' contributions to obtain the final d-values.
///
/// These d-values are used to safely combine leaky AND triples into a single
/// non-leaky authenticated AND.
#[instrument(level=Level::DEBUG, skip_all, err)]
async fn check_dvalue(
    (channel, delta): (&impl Channel, Delta),
    i: usize,
    n: usize,
    buckets: &[Bucket<'_>],
) -> Result<Vec<Vec<bool>>, Error> {
    // Step (a) Compute and verify d-values for each bucket.
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

    // Collect MACs for the d-values and scatter them to all parties.
    let scatter_data: Vec<Vec<(Vec<bool>, Vec<Mac>)>> = (0..n)
        .map(|k| {
            if k != i {
                let mut dvalues_macs = vec![(vec![], vec![]); len];
                for (j, bucket) in buckets.iter().enumerate() {
                    let (_, y, _) = &bucket[0];
                    for (_, y_next, _) in bucket.iter().skip(1) {
                        let (y0mac, _) = y.1.0[k];
                        let (ymac, _) = y_next.1.0[k];
                        dvalues_macs[j].1.push(y0mac ^ ymac);
                    }
                    dvalues_macs[j].0 = d_values[j].to_vec();
                }
                dvalues_macs
            } else {
                vec![]
            }
        })
        .collect();

    let dvalues_macs_all = scatter(channel, i, "dvalue", &scatter_data).await?;

    // Verify MAC correctness and aggregate d-values across parties.
    for k in (0..n).filter(|k| *k != i) {
        let dvalues_macs_k = &dvalues_macs_all[k];
        for (j, dval) in d_values.iter_mut().enumerate().take(len) {
            let (d_value_p, d_macs_p) = &dvalues_macs_k[j];
            let (_, y0key) = buckets[j][0].1.1.0[k];
            for (m, (d, dmac)) in dval.iter_mut().zip(d_macs_p).enumerate() {
                let (_, ykey) = buckets[j][m + 1].1.1.0[k];
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

/// Combines all leaky AND triples in a bucket into a single authenticated AND.
///
/// The bucket is reduced sequentially by repeatedly combining two leaky ANDs
/// using the corresponding `d`-values.
fn combine_bucket(
    i: usize,
    n: usize,
    bucket: Vec<(&Share, &Share, &Share)>,
    d_vec: Vec<bool>,
) -> Result<(Share, Share, Share), Error> {
    // Take the first triple as the initial accumulator.
    let mut bucket = bucket.into_iter();
    let (x, y, z) = match bucket.next() {
        Some(item) => item,
        None => return Err(Error::EmptyBucket),
    };
    let mut result = (x.clone(), y.clone(), z.clone());

    // Combine elements one by one, starting from the second element.
    for (triple, d) in bucket.zip(d_vec.into_iter()) {
        result = combine_two_leaky_ands(i, n, result, triple, d)?;
    }
    Ok(result)
}

/// Combines two leaky authenticated AND triples into one non-leaky authenticated AND.
///
/// Given two leaky AND triples and a corresponding `d`-value, this function produces a
/// new non-leaky authenticated AND triple.
fn combine_two_leaky_ands(
    i: usize,
    n: usize,
    (x1, y1, z1): (Share, Share, Share),
    (x2, _, z2): (&Share, &Share, &Share),
    d: bool,
) -> Result<(Share, Share, Share), Error> {
    //Step (b) compute x, y, z.
    let xbit = x1.0 ^ x2.0;
    let mut xauth = Auth(vec![(Mac(0), Key(0)); n]);
    for k in (0..n).filter(|k| *k != i) {
        let (mk_x1, ki_x1) = x1.1.0[k];
        let (mk_x2, ki_x2) = x2.1.0[k];
        xauth.0[k] = (mk_x1 ^ mk_x2, ki_x1 ^ ki_x2);
    }
    let xshare = Share(xbit, xauth);

    // Combine z-shares using the d-value term.
    let zbit = z1.0 ^ z2.0 ^ d & x2.0;
    let mut zauth = Auth(vec![(Mac(0), Key(0)); n]);
    for k in (0..n).filter(|k| *k != i) {
        let (mk_z1, ki_z1) = z1.1.0[k];
        let (mk_z2, ki_z2) = z2.1.0[k];
        let (mk_x2, ki_x2) = x2.1.0[k];
        zauth.0[k] = (
            mk_z1 ^ mk_z2 ^ Mac(d as u128 * mk_x2.0),
            ki_z1 ^ ki_z2 ^ Key(d as u128 * ki_x2.0),
        );
    }
    let zshare = Share(zbit, zauth);

    Ok((xshare, y1, zshare))
}
