//! Pi_aAND protocol from WRK17b instantiating F_aAND for being used in preprocessing.

use std::vec;

use blake3::Hasher;
use rand::{random, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{
    channel::{self, Channel, MsgChannel},
    //fpre::{Auth, Delta, Key, Mac, Share},
    fpre::Delta,
};

const RHO: usize = 128;

/// A custom error type.
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
    /// The check if the XOR fo all hashes is zero failed.
    HashNotZero,
    /// Wrong MAC of d when combining two leaky ANDs.
    WrongDMAC,
    /// XOR of all values in FLaAND do not cancel out.
    XorNotZero,
    /// Commitment of sent hash is wrong in FLaAND.
    CommitmentNotMatching,
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Commitment(pub(crate) [u8; 32]);

/// Authenticated bits with the bits, keys (for other's bits) and macs (for own bit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABits {
    bits: Vec<bool>,
    keys: Vec<Vec<u128>>,
    macs: Vec<Vec<u128>>,
}

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
async fn shared_rng(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
) -> Result<ChaCha20Rng, Error> {
    let r = [random::<u128>(), random::<u128>()];
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(&r[0].to_be_bytes());
    buf[16..].copy_from_slice(&r[1].to_be_bytes());
    let c = commit(&buf);
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "commit RNG", &c).await?;
    }
    let mut commitments = vec![Commitment([0; 32]); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        let commitment: Commitment = channel.recv_from(p, "commit RNG").await?;
        commitments[p] = commitment
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "open RNG", &buf).await?;
    }
    let mut buf_xor = buf;
    for p in (0..p_max).filter(|p| *p != p_own) {
        let buf: [u8; 32] = channel.recv_from(p, "open RNG").await?;
        if !open_commitment(&commitments[p], &buf) {
            return Err(Error::CommitmentCouldNotBeOpened);
        }
        for i in 0..32 {
            buf_xor[i] ^= buf[i];
        }
    }
    Ok(ChaCha20Rng::from_seed(buf_xor))
}

/// Performs an insecure F_abit, practically the ideal functionality of correlated OT.
/// The sender sends bit x, the receiver inputs delta, and the receiver receives a random key,
/// whereas the sender receives a MAC, which is the key XOR the bit times delta.
/// This protocol performs multiple of these at once.
pub(crate) async fn fabit(
    channel: &mut MsgChannel<impl Channel>,
    p_to: usize,
    delta: Delta,
    xbits: &Vec<bool>,
    role: bool,
) -> Result<Vec<u128>, Error> {
    match role {
        true => {
            channel.send_to(p_to, "bits", &xbits).await?;
            let macs: Vec<u128> = channel.recv_from(p_to, "macs").await?;
            Ok(macs)
        }
        false => {
            let mut keys: Vec<u128> = vec![];
            let mut macs: Vec<u128> = vec![];
            let other_xbits: Vec<bool> = channel.recv_from(p_to, "bits").await?;
            for bit in other_xbits {
                let rand: u128 = random();
                keys.push(rand);
                macs.push(rand ^ ((bit as u128) * delta.0));
            }
            channel.send_to(p_to, "macs", &macs).await?;
            Ok(keys)
        }
    }
}

/// Protocol PI_aBit^n that performs F_aBit^n. A random bit-string is generated as well as the corresponding keys and MACs are sent to all parties.
pub(crate) async fn fabitn(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
) -> Result<ABits, Error> {
    // Step 1 initialize random bitstring
    let len_abit = length + 2 * RHO;
    let mut x: Vec<bool> = (0..len_abit).map(|_| random()).collect();

    // Steps 2 running Pi_aBit^2 for each pair of parties
    let mut xkeys: Vec<Vec<u128>> = vec![vec![]; p_max];
    let mut xmacs: Vec<Vec<u128>> = vec![vec![]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        let macvec: Vec<u128>;
        let keyvec: Vec<u128>;
        if p_own < p {
            macvec = fabit(channel, p, delta, &x, true).await?;
            keyvec = fabit(channel, p, delta, &x, false).await?;
        } else {
            keyvec = fabit(channel, p, delta, &x, false).await?;
            macvec = fabit(channel, p, delta, &x, true).await?;
        }
        xmacs[p] = macvec;
        xkeys[p] = keyvec;
    }

    // Steps 3 including verification of macs and keys
    let mut shared_rng = shared_rng(channel, p_own, p_max).await?;
    for _ in 0..2 * RHO {
        let randbits: Vec<bool> = (0..len_abit).map(|_| shared_rng.gen()).collect();
        let mut xj = false;
        for (&xb, &rb) in x.iter().zip(&randbits) {
            xj ^= xb & rb;
        }
        for p in (0..p_max).filter(|p| *p != p_own) {
            channel.send_to(p, "xj", &xj).await?;
        }
        let mut xjp: Vec<bool> = vec![false; p_max];
        for p in (0..p_max).filter(|p| *p != p_own) {
            xjp[p] = channel.recv_from(p, "xj").await?;

            let mut macint: u128 = 0;
            for (i, rbit) in randbits.iter().enumerate().take(len_abit) {
                if *rbit {
                    macint ^= xmacs[p][i];
                }
            }
            channel
                .send_to(p, "mac", &(macint, randbits.clone()))
                .await?;
        }
        for p in (0..p_max).filter(|p| *p != p_own) {
            let (macp, randbitsp): (u128, Vec<bool>) = channel.recv_from(p, "mac").await?;
            let mut keyint: u128 = 0;
            for (i, rbit) in randbitsp.iter().enumerate().take(len_abit) {
                if *rbit {
                    keyint ^= xkeys[p][i];
                }
            }
            if macp != keyint ^ ((xjp[p] as u128) * delta.0) {
                return Err(Error::ABitMacMisMatch);
            }
        }
    }

    // Step 4 return first l objects
    x.truncate(length);
    for p in (0..p_max).filter(|p| *p != p_own) {
        xkeys[p].truncate(length);
        xmacs[p].truncate(length);
    }
    Ok(ABits {
        bits: x,
        keys: xkeys,
        macs: xmacs,
    })
}

/// Protocol PI_aShare that performs F_aShare. Random bit strings are picked and random authenticated shares are distributed to the parties.
pub(crate) async fn fashare(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
) -> Result<ABits, Error> {
    //Step 1
    let len_ashare = length + RHO;

    //Step 2
    let mut abits: ABits = fabitn(channel, p_own, p_max, len_ashare, delta).await?;

    // Protocol Pi_aShare
    // Input: bits of len_ashare length, authenticated bits
    // Step 3
    let mut d0: Vec<u128> = vec![0; RHO]; // xorkeys
    let mut d1: Vec<u128> = vec![0; RHO]; // xorkeysdelta
    let mut dm: Vec<Vec<u8>> = vec![vec![]; RHO]; // multiple macs
    let mut c0: Vec<Commitment> = Vec::with_capacity(RHO); // commitment to d0
    let mut c1: Vec<Commitment> = Vec::with_capacity(RHO); // commitment to d1
    let mut cm: Vec<Commitment> = Vec::with_capacity(RHO); // commitment to dm

    // Step 3/(a)
    for r in 0..RHO {
        let mut dm_entry = Vec::with_capacity(p_max * 16);
        dm_entry.push(abits.bits[length + r] as u8);
        for p in 0..p_max {
            if p != p_own {
                d0[r] ^= abits.keys[p][length + r];
                dm_entry.extend(&abits.macs[p][length + r].to_be_bytes());
            } else {
                dm_entry.extend(&[0; 16]);
            }
        }
        dm[r] = dm_entry;
        d1[r] = d0[r] ^ delta.0;
        c0.push(commit(&d0[r].to_be_bytes()));
        c1.push(commit(&d1[r].to_be_bytes()));
        cm.push(commit(&dm[r]));
    }
    let mut commitments: Vec<(Vec<Commitment>, Vec<Commitment>, Vec<Commitment>)> =
        vec![(vec![], vec![], vec![]); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "commit", &(&c0, &c1, &cm)).await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        let result: (Vec<Commitment>, Vec<Commitment>, Vec<Commitment>) =
            channel.recv_from(p, "commit").await?;
        commitments[p] = result;
    }

    // 3/(b) After receiving all commitments, Pi broadcasts decommitment for macs
    let mut dmp: Vec<Vec<Vec<u8>>> = vec![vec![vec![]; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "verify", &dm).await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        dmp[p] = channel.recv_from(p, "verify").await?;
    }
    dmp[p_own] = dm;

    // 3/(c) bit
    let mut combit: Vec<u8> = vec![0; RHO];
    let mut xorkeysbit: Vec<u128> = vec![0; RHO];
    for r in 0..RHO {
        for p in (0..p_max).filter(|p| *p != p_own) {
            combit[r] ^= dmp[p][r][0];
        }
        if combit[r] == 0 {
            xorkeysbit[r] = d0[r];
        } else if combit[r] == 1 {
            xorkeysbit[r] = d1[r];
        }
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "bitcom", &xorkeysbit).await?;
    }
    let mut xorkeysbitp: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        xorkeysbitp[p] = channel.recv_from(p, "bitcom").await?;
    }

    // 3/(d) consistency check
    let mut xormacs: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for r in 0..RHO {
        for (p, pitem) in dmp.iter().enumerate().take(p_max) {
            for pp in (0..p_max).filter(|pp| *pp != p) {
                if !pitem[r].is_empty() {
                    let b: u128 = u128::from_be_bytes(
                        pitem[r][(1 + pp * 16)..(17 + pp * 16)].try_into().unwrap(),
                    );
                    xormacs[pp][r] ^= b;
                }
            }
        }
    }
    for r in 0..RHO {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let bj = &xorkeysbitp[p][r].to_be_bytes();
            if open_commitment(&commitments[p].0[r], bj)
                || open_commitment(&commitments[p].1[r], bj)
            {
                if xormacs[p][r] != xorkeysbitp[p][r] {
                    return Err(Error::AShareMacsMismatch);
                }
            } else {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
        }
    }

    // Step 4
    abits.bits.truncate(length);
    for p in (0..p_max).filter(|p| *p != p_own) {
        abits.keys[p].truncate(length);
        abits.macs[p].truncate(length);
    }
    Ok(abits)
}

/// Performs F_HaAND.
pub(crate) async fn fhaand(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    x: ABits,
    y: bool,
) -> Result<bool, Error> {
    // Protocol Pi_HaAND

    // Step 1
    // Call FaShare to obtain <x>

    //Step 2
    let mut v: bool = false;
    for p in (0..p_max).filter(|p| *p != p_own) {
        let s: bool = random();
        let mut hash: [u8; 32] = blake3::hash(&x.keys[p][0].to_le_bytes()).into();
        let lsb0 = (hash[31] & 0b0000_0001) != 0;
        let h0 = lsb0 ^ s;

        hash = blake3::hash(&(x.keys[p][0] ^ delta.0).to_le_bytes()).into();
        let lsb1 = (hash[31] & 0b0000_0001) != 0;
        let h1 = lsb1 ^ s ^ y;
        channel.send_to(p, "haand", &(&h0, &h1)).await?;
        v ^= s;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        let (h0p, h1p): (bool, bool) = channel.recv_from(p, "haand").await?;
        let hash: [u8; 32] = blake3::hash(&x.macs[p][0].to_le_bytes()).into();
        let lsb = (hash[31] & 0b0000_0001) != 0;
        let mut t: bool = lsb;
        if x.bits[0] {
            t ^= h1p;
        } else {
            t ^= h0p;
        }
        v ^= t;
    }
    //Step 3
    Ok(v)
}

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

/// Performs F_LaAND.
pub(crate) async fn flaand(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
) -> Result<(ABits, ABits, ABits), Error> {
    // Protocol Pi_LaAND
    // Triple computation
    // Step 1
    let xbits: ABits = fashare(channel, p_own, p_max, 1, delta).await?;
    let ybits: ABits = fashare(channel, p_own, p_max, 1, delta).await?;
    let rbits: ABits = fashare(channel, p_own, p_max, 1, delta).await?;

    // Step 2
    let v = fhaand(channel, p_own, p_max, delta, xbits.clone(), ybits.bits[0]).await?;

    // Step 3
    let z: bool = v ^ (xbits.bits[0] & ybits.bits[0]);
    let e: bool = z ^ rbits.bits[0];

    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "esend", &e).await?;
    }

    // if e is true (1), this is basically a negation of r and should be done as described in Section 2 of WRK17b, if e is false (0), this is a copy
    let mut zkeys: Vec<Vec<u128>> = rbits.keys.clone();
    let zmacs: Vec<Vec<u128>> = rbits.macs.clone();
    for p in (0..p_max).filter(|p| *p != p_own) {
        let ep: bool = channel.recv_from(p, "esend").await?;
        if ep {
            zkeys[p][0] = rbits.keys[p][0] ^ delta.0;
        }
    }
    let zbits = ABits {
        bits: vec![z; 1],
        keys: zkeys,
        macs: zmacs,
    };

    // Triple Checking
    // Step 4
    let mut phi: u128 = 0;
    for p in (0..p_max).filter(|p| *p != p_own) {
        phi ^= ybits.keys[p][0] ^ ybits.macs[p][0];
    }
    phi ^= ybits.bits[0] as u128 * delta.0;

    // Step 5
    let mut uij: Vec<u128> = vec![0; p_max];
    let mut xkeys_phi: Vec<u128> = vec![0; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        xkeys_phi[p] = hash128(xbits.keys[p][0]);
        uij[p] = hash128(xbits.keys[p][0] ^ delta.0) ^ xkeys_phi[p] ^ phi;
        channel.send_to(p, "uij", &uij).await?;
    }
    let mut uijp: Vec<Vec<u128>> = vec![vec![0; p_max]; p_max];
    let mut xmacs_phi: Vec<u128> = vec![0; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        uijp[p] = channel.recv_from(p, "uij").await?;
        xmacs_phi[p] = hash128(xbits.macs[p][0]) ^ (xbits.bits[0] as u128 * uijp[p][p_own]);
    }

    // Step 6
    let mut hash: u128 = 0;
    for p in (0..p_max).filter(|p| *p != p_own) {
        hash ^= zbits.keys[p][0] ^ zbits.macs[p][0] ^ xmacs_phi[p] ^ xkeys_phi[p];
    }
    hash ^= xbits.bits[0] as u128 * phi;
    hash ^= zbits.bits[0] as u128 * delta.0;
    let comm: Commitment = commit(&hash.to_be_bytes());
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "hashcomm", &comm).await?;
    }
    let mut commp: Vec<Commitment> = vec![Commitment([0; 32]); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        commp[p] = channel.recv_from(p, "hashcomm").await?;
    }

    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "hash", &hash).await?;
    }
    let mut hashp: Vec<u128> = vec![0; p_max];
    let mut xorhash: u128 = hash; // XOR for all parties, including p_own
    for p in (0..p_max).filter(|p| *p != p_own) {
        hashp[p] = channel.recv_from(p, "hash").await?;
        if !open_commitment(&commp[p], &hashp[p].to_be_bytes()) {
            return Err(Error::CommitmentNotMatching);
        }
        xorhash ^= hashp[p];
    }

    // Step 7
    if xorhash != 0 {
        return Err(Error::XorNotZero);
    }

    Ok((xbits, ybits, zbits))
}

/// Performs Pi_aAND.
pub async fn faand(
    channel: impl Channel,
    p_own: usize,
    p_max: usize,
    circuit_size: u128,
    length: usize,
) -> Result<Vec<(ABits, ABits, ABits)>, Error> {
    let delta: Delta = Delta(random());
    let mut channel = MsgChannel(channel);

    let b = (128.0 / f64::log2(circuit_size as f64)).ceil() as u128;
    let lprime = length as u128 * b;

    // Step 1
    let mut triples: Vec<(ABits, ABits, ABits)> = vec![];
    for _ in 0..lprime {
        triples.push(flaand(&mut channel, p_own, p_max, delta).await?);
    }

    // Step 2
    let mut buckets: Vec<Vec<(ABits, ABits, ABits)>> = vec![vec![]; length];

    // Assign objects to buckets
    let mut available: Vec<usize> = (0..length).collect();
    let mut shared_rng = shared_rng(&mut channel, p_own, p_max).await?;
    for obj in triples {
        let mut indeces: Vec<usize> = available.to_vec();
        indeces.retain(|&index| buckets[index].len() < b as usize);

        if !indeces.is_empty() {
            //let rand_index: usize = rng.gen_range(0..indeces.len());
            let rand_index: usize = shared_rng.gen_range(0..indeces.len());
            //let rand_index: usize = rand as usize % indeces.len();
            let ind = indeces[rand_index];

            buckets[ind].push(obj);
            if buckets[ind].len() == b as usize {
                available.retain(|&index| index != ind);
            }
        }
    }
    //println!("{:?}", buckets);

    // Step 3
    let mut bucketcombined: Vec<(ABits, ABits, ABits)> = vec![];
    for b in buckets {
        bucketcombined.push(combine_bucket(&mut channel, p_own, p_max, delta, b).await?);
    }

    Ok(bucketcombined)
}

pub(crate) async fn combine_bucket(
    //TODO make this more efficient to do as a tree structure
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    bucket: Vec<(ABits, ABits, ABits)>,
) -> Result<(ABits, ABits, ABits), Error> {
    let mut bucketcopy = bucket.clone();
    let mut result = bucketcopy.pop().unwrap();
    while let Some(triple) = bucketcopy.pop() {
        result = combine_two_leaky_ands(channel, p_own, p_max, delta, &result, &triple).await?;
    }
    Ok(result)
}

pub(crate) async fn combine_two_leaky_ands(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    (x1, y1, z1): &(ABits, ABits, ABits),
    (x2, y2, z2): &(ABits, ABits, ABits),
) -> Result<(ABits, ABits, ABits), Error> {
    let mut d = y1.bits[0] ^ y2.bits[0];
    let mut dmacs: Vec<u128> = vec![0; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        dmacs[p] = y1.macs[p][0] ^ y2.macs[p][0];
    }

    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "dvalue", &(d, dmacs[p])).await?;
    }
    let mut dp: Vec<(bool, u128)> = vec![(false, 0); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        dp[p] = channel.recv_from(p, "dvalue").await?; //TOCHECK: is this how d should be "revealed"?
        d ^= dp[p].0;
        if (d && dp[p].1 != y1.keys[p][0] ^ y2.keys[p][0] ^ delta.0)
            || (!d && dp[p].1 != y1.keys[p][0] ^ y2.keys[p][0])
        { // TODO Check MACs here
             //return Err(Error::WrongDMAC);
        }
    }

    let mut xbits: Vec<bool> = vec![false; 1];
    xbits[0] = x1.bits[0] ^ x2.bits[0];
    let mut xmacs = x1.macs.clone();
    let mut xkeys = x1.keys.clone();
    for p in (0..p_max).filter(|p| *p != p_own) {
        xmacs[p][0] ^= x2.macs[p][0];
        xkeys[p][0] ^= x2.keys[p][0];
    }
    let xres: ABits = ABits {
        bits: xbits,
        keys: xkeys,
        macs: xmacs,
    };

    let mut zbits = vec![false; 1];
    zbits[0] = z1.bits[0] ^ z2.bits[0] ^ d & x2.bits[0];
    let mut zmacs = z1.macs.clone();
    let mut zkeys = z1.keys.clone();
    for p in (0..p_max).filter(|p| *p != p_own) {
        zmacs[p][0] ^= z2.macs[p][0];
        zkeys[p][0] ^= z2.keys[p][0];
    }
    if d {
        for p in (0..p_max).filter(|p| *p != p_own) {
            zmacs[p][0] ^= x2.macs[p][0];
            zkeys[p][0] ^= x2.keys[p][0];
        }
    }
    let zres: ABits = ABits {
        bits: zbits,
        keys: zkeys,
        macs: zmacs,
    };
    Ok((xres, y1.clone(), zres))
}

#[cfg(test)]
mod tests {
    use rand::random;

    use crate::{
        channel::{Error, MsgChannel, SimpleChannel},
        faand::{faand, fashare, fhaand, flaand, ABits},
        fpre::Delta,
    };

    #[tokio::test]
    async fn test_fashare() -> Result<(), Error> {
        let parties = 3;
        let length = 2;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<
            tokio::task::JoinHandle<Result<(usize, Delta, ABits), crate::faand::Error>>,
        > = vec![];

        for i in 0..parties {
            let delta: Delta = Delta(random());
            let channel = channels.pop().unwrap(); // Take ownership of the channel
            let handle = tokio::spawn(async move {
                let mut msgchannel = MsgChannel(channel); // Move the channel into MsgChannel
                fashare(&mut msgchannel, parties - i - 1, parties, length, delta)
                    .await
                    .map(|result| (parties - i - 1, delta, result))
            });
            handles.push(handle);
        }

        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok((p_own, delta, abits)) => {
                    for l in 0..length {
                        for p in 0..parties {
                            if abits.bits[l] {
                                if abits.keys[p] != []
                                    && abits.macs[p_own] != []
                                    && abits.keys[p][l] != abits.macs[p_own][l] ^ delta.0
                                {
                                    eprintln!("Failed FaShare!!!!!!!!!");
                                }
                            } else {
                                if abits.keys[p] != []
                                    && abits.macs[p_own] != []
                                    && abits.keys[p][l] != abits.macs[p_own][l]
                                {
                                    eprintln!("Failed FaShare!!!!!!!!!");
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_fhaand() -> Result<(), Error> {
        let parties = 3;
        let mut channels = SimpleChannel::channels(parties);

        let mut handles: Vec<tokio::task::JoinHandle<Result<(bool, bool), crate::faand::Error>>> =
            vec![];

        for i in 0..parties {
            let delta: Delta = Delta(random());
            let channel = channels.pop().unwrap();
            let handle: tokio::task::JoinHandle<Result<(bool, bool), crate::faand::Error>> =
                tokio::spawn(async move {
                    let p_own: usize = parties - i - 1;
                    let mut check: bool = false;
                    let mut msgchannel = MsgChannel(channel);
                    let xbits: ABits = fashare(&mut msgchannel, p_own, parties, 1, delta).await?;
                    let ybits: ABits = fashare(&mut msgchannel, p_own, parties, 1, delta).await?;
                    for p in (0..parties).filter(|p| *p != p_own) {
                        msgchannel.send_to(p, "haandtest", &ybits.bits[0]).await?;
                    }
                    let mut yp: Vec<bool> = vec![false; parties];
                    for p in (0..parties).filter(|p| *p != p_own) {
                        yp[p] = msgchannel.recv_from(p, "haandtest").await?;
                        check ^= xbits.bits[0] & yp[p];
                    }
                    fhaand(&mut msgchannel, p_own, parties, delta, xbits, ybits.bits[0])
                        .await
                        .map(|result| (check, result))
                });
            handles.push(handle);
        }

        let mut xorcheck = false;
        let mut xorv = false;
        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok((check, v)) => {
                    xorcheck ^= check;
                    xorv ^= v;
                }
            }
        }
        assert_eq!(xorcheck, xorv);
        Ok(())
    }

    #[tokio::test]
    async fn test_flaand() -> Result<(), Error> {
        for _ in 0..1 {
            let parties = 3;
            let mut channels = SimpleChannel::channels(parties);
            let mut handles: Vec<
                tokio::task::JoinHandle<Result<(ABits, ABits, ABits), crate::faand::Error>>,
            > = vec![];

            for i in 0..parties {
                let delta: Delta = Delta(random());
                let channel = channels.pop().unwrap();
                let handle: tokio::task::JoinHandle<
                    Result<(ABits, ABits, ABits), crate::faand::Error>,
                > = tokio::spawn(async move {
                    let mut msgchannel = MsgChannel(channel);
                    flaand(&mut msgchannel, parties - i - 1, parties, delta).await
                });
                handles.push(handle);
            }

            let mut xorx = false;
            let mut xory = false;
            let mut xorz = false;
            for handle in handles {
                let out = handle.await.unwrap();
                match out {
                    Err(e) => {
                        eprintln!("Protocol failed {:?}", e);
                    }
                    Ok((xbits, ybits, zbits)) => {
                        xorx ^= xbits.bits[0];
                        xory ^= ybits.bits[0];
                        xorz ^= zbits.bits[0];
                    }
                }
            }
            assert_eq!(xorx & xory, xorz);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_faand() -> Result<(), Error> {
        let parties = 3;
        let circuit_size = 100000;
        let length: usize = 2;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<
            tokio::task::JoinHandle<Result<Vec<(ABits, ABits, ABits)>, crate::faand::Error>>,
        > = vec![];
        for i in 0..parties {
            let handle: tokio::task::JoinHandle<
                Result<Vec<(ABits, ABits, ABits)>, crate::faand::Error>,
            > = tokio::spawn(faand(
                channels.pop().unwrap(),
                parties - i - 1,
                parties,
                circuit_size,
                length,
            ));
            handles.push(handle);
        }
        let mut xorx = vec![false; length];
        let mut xory = vec![false; length];
        let mut xorz = vec![false; length];
        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok(combined) => {
                    for i in 0..length {
                        xorx[i] ^= combined[i].0.bits[0];
                        xory[i] ^= combined[i].1.bits[0];
                        xorz[i] ^= combined[i].2.bits[0];
                        //println!("{:?}", combined);
                    } //TODO Test MACs and KEYs
                }
            }
        }
        for i in 0..length {
            assert_eq!(xorx[i] & xory[i], xorz[i]);
        }
        Ok(())
    }
}