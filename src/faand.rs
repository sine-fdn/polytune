//! Pi_aAND protocol from WRK17b instantiating F_aAND for being used in preprocessing.
use blake3::Hasher;
use rand::{random, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{
    channel::{self, Channel, MsgChannel},
    fpre::{Delta, Auth, Key, Mac, Share},
};

const RHO: usize = 40;

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
pub(crate) async fn shared_rng(
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
///
/// The sender sends bit x, the receiver inputs delta, and the receiver receives a random key,
/// whereas the sender receives a MAC, which is the key XOR the bit times delta. This protocol
/// performs multiple of these at once.
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

/// Protocol PI_aBit^n that performs F_aBit^n.
///
/// A random bit-string is generated as well as the corresponding keys and MACs are sent to all
/// parties.
pub(crate) async fn fabitn(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
    shared_rng: &mut ChaCha20Rng,
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

    // Step 3 including verification of macs and keys
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

/// Protocol PI_aShare that performs F_aShare.
///
/// Random bit strings are picked and random authenticated shares are distributed to the parties.
pub(crate) async fn fashare(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
    shared_rng: &mut ChaCha20Rng,
) -> Result<ABits, Error> {
    //Step 1
    let len_ashare = length + RHO;

    //Step 2
    let mut abits: ABits = fabitn(channel, p_own, p_max, len_ashare, delta, shared_rng).await?;

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

/// Protocol PI_aShare that performs F_aShare and returns Shares.
///
/// Random bit strings are picked and random authenticated shares are distributed to the parties.
pub(crate) async fn fashare_fpre(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
    shared_rng: &mut ChaCha20Rng,
) -> Result<Vec<Share>, Error> {
    let mut res: Vec<Share> = vec![];
    let abits: ABits = fashare(channel, p_own, p_max, length, delta, shared_rng).await?;
    for l in 0..length {
        let mut authvec: Vec<Option<(Mac, Key)>> = vec![None; p_max];
        for p in (0..p_max).filter(|p| *p != p_own) {
            authvec[p] = Some((Mac(abits.macs[p][l]), Key(abits.keys[p][l])));
        }
        res.push(Share(abits.bits[l], Auth(authvec)));
    }
    Ok(res)
}

/// Protocol Pi_HaAND that performs F_HaAND.
///
/// The XOR of xiyj values are generated obliviously, which is half of the z value in an
/// authenticated share, i.e., a half-authenticated share.
pub(crate) async fn fhaand(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    length: usize,
    x: ABits,
    y: Vec<bool>,
) -> Result<Vec<bool>, Error> {
    // Protocol Pi_HaAND

    // Step 1
    // Call FaShare to obtain <x>
    // FaShare is called in FLaAND instead and x is provided as input

    //Step 2
    let mut v: Vec<bool> = vec![false; length];
    let (mut h0, mut h1): (Vec<bool>, Vec<bool>) = (vec![false; length], vec![false; length]);
    for p in (0..p_max).filter(|p| *p != p_own) {
        for l in 0..length {
            let s: bool = random();
            let mut hash: [u8; 32] = blake3::hash(&x.keys[p][l].to_le_bytes()).into();
            let lsb0 = (hash[31] & 0b0000_0001) != 0;
            h0[l] = lsb0 ^ s;

            hash = blake3::hash(&(x.keys[p][l] ^ delta.0).to_le_bytes()).into();
            let lsb1 = (hash[31] & 0b0000_0001) != 0;
            h1[l] = lsb1 ^ s ^ y[l];
            v[l] ^= s;
        }
        channel.send_to(p, "haand", &(&h0, &h1)).await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        let (h0p, h1p): (Vec<bool>, Vec<bool>) = channel.recv_from(p, "haand").await?;
        for l in 0..length {
            let hash: [u8; 32] = blake3::hash(&x.macs[p][l].to_le_bytes()).into();
            let lsb = (hash[31] & 0b0000_0001) != 0;
            let mut t: bool = lsb;
            if x.bits[l] {
                t ^= h1p[l];
            } else {
                t ^= h0p[l];
            }
            v[l] ^= t;
        }
    }

    //Step 3
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
pub(crate) async fn flaand(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    length: usize,
    shared_rng: &mut ChaCha20Rng,
) -> Result<(ABits, ABits, ABits), Error> {
    // Triple computation
    // Step 1
    let xbits: ABits = fashare(channel, p_own, p_max, length, delta, shared_rng).await?;
    let ybits: ABits = fashare(channel, p_own, p_max, length, delta, shared_rng).await?;
    let rbits: ABits = fashare(channel, p_own, p_max, length, delta, shared_rng).await?;

    // Step 2
    let v = fhaand(
        channel,
        p_own,
        p_max,
        delta,
        length,
        xbits.clone(),
        ybits.bits.clone(),
    )
    .await?;

    // Step 3
    let mut z: Vec<bool> = vec![false; length];
    let mut e: Vec<bool> = vec![false; length];
    for l in 0..length {
        z[l] = v[l] ^ (xbits.bits[l] & ybits.bits[l]);
        e[l] = z[l] ^ rbits.bits[l];
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "esend", &e).await?;
    }
    // if e is true (1), this is basically a negation of r and should be done as described in
    // Section 2 of WRK17b, if e is false (0), this is a copy
    let mut zkeys: Vec<Vec<u128>> = rbits.keys.clone();
    let zmacs: Vec<Vec<u128>> = rbits.macs.clone();
    for p in (0..p_max).filter(|p| *p != p_own) {
        let ep: Vec<bool> = channel.recv_from(p, "esend").await?;
        for (l, e) in ep.iter().enumerate().take(length) {
            if *e {
                zkeys[p][l] = rbits.keys[p][l] ^ delta.0;
            }
        }
    }
    let zbits = ABits {
        bits: z,
        keys: zkeys,
        macs: zmacs,
    };

    // Triple Checking
    // Step 4
    let mut phi: Vec<u128> = vec![0; length];
    for (l, phie) in phi.iter_mut().enumerate().take(length) {
        for p in (0..p_max).filter(|p| *p != p_own) {
            *phie ^= ybits.keys[p][l] ^ ybits.macs[p][l];
        }
        *phie ^= ybits.bits[l] as u128 * delta.0;
    }

    // Step 5
    let mut uij: Vec<Vec<u128>> = vec![vec![0; length]; p_max];
    let mut xkeys_phi: Vec<Vec<u128>> = vec![vec![0; length]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        for (l, phie) in phi.iter().enumerate().take(length) {
            xkeys_phi[p][l] = hash128(xbits.keys[p][l]);
            uij[p][l] = hash128(xbits.keys[p][l] ^ delta.0) ^ xkeys_phi[p][l] ^ *phie;
        }
        channel.send_to(p, "uij", &uij).await?;
    }
    let mut uijp: Vec<Vec<Vec<u128>>> = vec![vec![vec![0; p_max]; length]; p_max];
    let mut xmacs_phi: Vec<Vec<u128>> = vec![vec![0; length]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        uijp[p] = channel.recv_from(p, "uij").await?;
        for l in 0..length {
            xmacs_phi[p][l] =
                hash128(xbits.macs[p][l]) ^ (xbits.bits[l] as u128 * uijp[p][p_own][l]);
        }
    }

    // Step 6
    let mut hash: Vec<u128> = vec![0; length];
    let mut comm: Vec<Commitment> = vec![Commitment([0; 32]); length];
    for l in 0..length {
        for p in (0..p_max).filter(|p| *p != p_own) {
            hash[l] ^= zbits.keys[p][l] ^ zbits.macs[p][l] ^ xmacs_phi[p][l] ^ xkeys_phi[p][l];
        }
        hash[l] ^= xbits.bits[l] as u128 * phi[l];
        hash[l] ^= zbits.bits[l] as u128 * delta.0;
        comm[l] = commit(&hash[l].to_be_bytes());
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "hashcomm", &comm).await?;
    }
    let mut commp: Vec<Vec<Commitment>> = vec![vec![Commitment([0; 32]); length]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        commp[p] = channel.recv_from(p, "hashcomm").await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "hash", &hash).await?;
    }
    let mut hashp: Vec<Vec<u128>> = vec![vec![0; length]; p_max];
    let mut xorhash: Vec<u128> = hash; // XOR for all parties, including p_own
    for p in (0..p_max).filter(|p| *p != p_own) {
        hashp[p] = channel.recv_from(p, "hash").await?;
        for (l, xh) in xorhash.iter_mut().enumerate().take(length) {
            if !open_commitment(&commp[p][l], &hashp[p][l].to_be_bytes()) {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
            *xh ^= hashp[p][l];
        }
    }

    // Step 7
    for xh in xorhash.iter().take(length) {
        if *xh != 0 {
            return Err(Error::LaANDXorNotZero);
        }
    }

    Ok((xbits, ybits, zbits))
}

/// Calculates the bucket size according to WRK17a, Table 4 for statistical security ρ = 40 (rho).
fn bucket_size(circuit_size: usize) -> usize {
    match circuit_size {
        n if n >= 280_000 => 3,
        n if n >= 3_100 => 4,
        _ => 5,
    }
}

fn transform_abits(alltriples: (ABits, ABits, ABits), length: usize, p_max: usize, p_own: usize) -> Vec<(Share, Share, Share)> {
    let mut triples: Vec<(Share, Share, Share)> = vec![];
    let mut auth0 = Auth(vec![None; p_max]);
    let mut auth1 = Auth(vec![None; p_max]);
    let mut auth2 = Auth(vec![None; p_max]);
    for l in 0..length {
        for p in (0..p_max).filter(|p| *p != p_own) {
            auth0.0[p] = Some((Mac(alltriples.0.macs[p][l]), Key(alltriples.0.keys[p][l])));
            auth1.0[p] = Some((Mac(alltriples.1.macs[p][l]), Key(alltriples.1.keys[p][l])));
            auth2.0[p] = Some((Mac(alltriples.2.macs[p][l]), Key(alltriples.2.keys[p][l])));
        }
        triples.push((Share(alltriples.0.bits[l], auth0.clone()), Share(alltriples.1.bits[l], auth1.clone()), Share(alltriples.2.bits[l], auth2.clone())));
    }
    triples
}

/// Protocol Pi_aAND that performs F_aAND.
///
/// The protocol combines leaky authenticated bits into non-leaky authenticated bits.
pub async fn faand(
    channel: impl Channel,
    p_own: usize,
    p_max: usize,
    circuit_size: usize,
    length: usize,
) -> Result<Vec<(Share, Share, Share)>, Error> {
    let delta: Delta = Delta(random());
    let mut channel = MsgChannel(channel);

    //let b = (128.0 / f64::log2(circuit_size as f64)).ceil() as u128;
    let b = bucket_size(circuit_size);
    let lprime: usize = length * b;
    let mut shared_rng = shared_rng(&mut channel, p_own, p_max).await?;

    // Step 1
    let alltriples = flaand(&mut channel, p_own, p_max, delta, lprime, &mut shared_rng).await?;
    let triples = transform_abits(alltriples, lprime, p_max, p_own);

    // Step 2
    let mut buckets: Vec<Vec<(Share, Share, Share)>> = vec![vec![]; length];

    // Assign objects to buckets
    let mut available: Vec<usize> = (0..length).collect();
    for obj in triples {
        let mut indeces: Vec<usize> = available.to_vec();
        indeces.retain(|&index| buckets[index].len() < b);

        if !indeces.is_empty() {
            let rand_index: usize = shared_rng.gen_range(0..indeces.len());
            let ind = indeces[rand_index];

            buckets[ind].push(obj);
            if buckets[ind].len() == b {
                available.retain(|&index| index != ind);
            }
        }
    }

    // Step 3
    let mut bucketcombined: Vec<(Share, Share, Share)> = vec![];
    for b in buckets {
        bucketcombined.push(combine_bucket(&mut channel, p_own, p_max, delta, b).await?);
    }

    Ok(bucketcombined)
}

/// Combine the whole bucket by combining elements two by two.
pub(crate) async fn combine_bucket(
    // TODO make this more efficient to do as a tree structure
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    bucket: Vec<(Share, Share, Share)>,
) -> Result<(Share, Share, Share), Error> {
    let mut bucketcopy = bucket.clone();
    let mut result = bucketcopy.pop().unwrap();
    while let Some(triple) = bucketcopy.pop() {
        result = combine_two_leaky_ands(channel, p_own, p_max, delta, &result, &triple).await?;
    }
    Ok(result)
}

/// Combine two leaky ANDs into one non-leaky AND.
pub(crate) async fn combine_two_leaky_ands(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    (x1, y1, z1): &(Share, Share, Share),
    (x2, y2, z2): &(Share, Share, Share),
) -> Result<(Share, Share, Share), Error> {
    // Step (a)
    let mut d = y1.0 ^ y2.0;
    let mut dmacs: Vec<Option<Mac>> = vec![None; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        dmacs[p] = Some(y1.1.0[p].unwrap().0 ^ y2.1.0[p].unwrap().0);
        channel.send_to(p, "dvalue", &(d, dmacs[p])).await?;
    }
    let mut dp: Vec<(bool, Option<Mac>)> = vec![(false, None); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        dp[p] = channel.recv_from(p, "dvalue").await?;
        if (dp[p].0 && dp[p].1.unwrap().0 != y1.1.0[p].unwrap().1.0 ^ y2.1.0[p].unwrap().1.0 ^ delta.0) //y1.keys[p] ^ y2.keys[p] ^ delta.0)
            || (!dp[p].0 && dp[p].1.unwrap().0 != y1.1.0[p].unwrap().1.0 ^ y2.1.0[p].unwrap().1.0)
        {
            return Err(Error::AANDWrongDMAC);
        }
        d ^= dp[p].0;
    }

    //Step (b)
    let xbit = x1.0 ^ x2.0;
    let mut xauth: Auth = Auth(vec![None; p_max]);
    for p in (0..p_max).filter(|p| *p != p_own) {
        xauth.0[p] = Some((x1.1.0[p].unwrap().0 ^ x2.1.0[p].unwrap().0, x1.1.0[p].unwrap().1 ^ x2.1.0[p].unwrap().1)); //(Mac, Key)
    }
    let xres: Share = Share(xbit, xauth);

    let zbit = z1.0 ^ z2.0 ^ d & x2.0;
    let mut zauth: Auth = Auth(vec![None; p_max]);
    for p in (0..p_max).filter(|p| *p != p_own) {
        zauth.0[p] = Some((z1.1.0[p].unwrap().0 ^ z2.1.0[p].unwrap().0 ^ Mac(d as u128 * x2.1.0[p].unwrap().0.0), z1.1.0[p].unwrap().1 ^ z2.1.0[p].unwrap().1 ^ Key(d as u128 * x2.1.0[p].unwrap().1.0))); //(Mac, Key)
    }
    let zres: Share = Share(zbit, zauth);

    Ok((xres, y1.clone(), zres))
}

#[cfg(test)]
mod tests {
    use rand::random;

    use crate::{
        channel::{Error, MsgChannel, SimpleChannel},
        faand::{faand, fashare, fhaand, flaand, shared_rng, ABits, fashare_fpre},
        fpre::{Delta, Share, Auth},
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
            let channel = channels.pop().unwrap();
            let handle = tokio::spawn(async move {
                let mut msgchannel = MsgChannel(channel);
                let mut shared_rng = shared_rng(&mut msgchannel, parties - i - 1, parties).await?;
                fashare(
                    &mut msgchannel,
                    parties - i - 1,
                    parties,
                    length,
                    delta,
                    &mut shared_rng,
                )
                .await
                .map(|result| (parties - i - 1, delta, result))
            });
            handles.push(handle);
        }
        let mut bits = vec![vec![false; length]; parties];
        let mut macs_to_match = vec![vec![vec![0; length]; parties]; parties];
        let mut keys_to_match = vec![vec![vec![0; length]; parties]; parties];
        let mut deltas = vec![Delta(0); parties];
        let mut party_num = parties;
        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok((p_own, delta, abits)) => {
                    party_num -= 1;
                    for l in 0..length {
                        for p in (0..parties).filter(|p| *p != p_own) {
                            deltas[party_num] = delta;
                            bits[party_num][l] = abits.bits[l];
                            macs_to_match[party_num][p][l] = abits.macs[p][l];
                            keys_to_match[party_num][p][l] = abits.keys[p][l];
                        }
                    }
                }
            }
        }
        for i in 0..parties {
            for p in (0..parties).filter(|p| *p != i) {
                for l in 0..length {
                    if bits[i][l] && macs_to_match[i][p][l] ^ deltas[p].0 != keys_to_match[p][i][l]
                    {
                        eprintln!("Error in FaShare!");
                    } else if !bits[i][l] && macs_to_match[i][p][l] != keys_to_match[p][i][l] {
                        eprintln!("Error in FaShare!");
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

        let mut handles: Vec<
            tokio::task::JoinHandle<Result<(Vec<bool>, Vec<bool>), crate::faand::Error>>,
        > = vec![];

        let length = 1;
        for i in 0..parties {
            let delta: Delta = Delta(random());
            let channel = channels.pop().unwrap();
            let handle: tokio::task::JoinHandle<
                Result<(Vec<bool>, Vec<bool>), crate::faand::Error>,
            > = tokio::spawn(async move {
                let p_own: usize = parties - i - 1;
                let mut check: Vec<bool> = vec![false; length];
                let mut msgchannel = MsgChannel(channel);
                let mut shared_rng = shared_rng(&mut msgchannel, parties - i - 1, parties).await?;
                let xbits: ABits = fashare(
                    &mut msgchannel,
                    p_own,
                    parties,
                    length,
                    delta,
                    &mut shared_rng,
                )
                .await?;
                let ybits: ABits = fashare(
                    &mut msgchannel,
                    p_own,
                    parties,
                    length,
                    delta,
                    &mut shared_rng,
                )
                .await?;
                for p in (0..parties).filter(|p| *p != p_own) {
                    msgchannel.send_to(p, "haandtest", &ybits.bits).await?;
                }
                let mut yp: Vec<Vec<bool>> = vec![vec![false; length]; parties];
                for p in (0..parties).filter(|p| *p != p_own) {
                    yp[p] = msgchannel.recv_from(p, "haandtest").await?;
                    for l in 0..length {
                        check[l] ^= xbits.bits[l] & yp[p][l];
                    }
                }
                fhaand(
                    &mut msgchannel,
                    p_own,
                    parties,
                    delta,
                    length,
                    xbits,
                    ybits.bits,
                )
                .await
                .map(|result| (check, result))
            });
            handles.push(handle);
        }

        let mut xorcheck: Vec<bool> = vec![false; length];
        let mut xorv: Vec<bool> = vec![false; length];
        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok((check, v)) => {
                    for l in 0..length {
                        xorcheck[l] ^= check[l];
                        xorv[l] ^= v[l];
                    }
                }
            }
        }
        assert_eq!(xorcheck, xorv);
        Ok(())
    }

    #[tokio::test]
    async fn test_flaand() -> Result<(), Error> {
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
                let mut shared_rng = shared_rng(&mut msgchannel, parties - i - 1, parties).await?;
                flaand(
                    &mut msgchannel,
                    parties - i - 1,
                    parties,
                    delta,
                    200,
                    &mut shared_rng,
                )
                .await
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
        Ok(())
    }

    #[tokio::test]
    async fn test_faand() -> Result<(), Error> {
        let parties = 3;
        let circuit_size = 100000;
        let length: usize = 2;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<
            tokio::task::JoinHandle<Result<Vec<(Share, Share, Share)>, crate::faand::Error>>,
        > = vec![];
        for i in 0..parties {
            let handle: tokio::task::JoinHandle<
                Result<Vec<(Share, Share, Share)>, crate::faand::Error>,
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
        let mut combined_all: Vec<Vec<(Share, Share, Share)>> = vec![vec![]; parties];
        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok(combined) => {
                    for i in 0..length {
                        xorx[i] ^= combined[i].0.0;
                        xory[i] ^= combined[i].1.0;
                        xorz[i] ^= combined[i].2.0;
                    }
                    combined_all.push(combined);
                }
            }
        }
        for i in 0..length {
            assert_eq!(xorx[i] & xory[i], xorz[i]);
        }
        Ok(())
    }

    #[tokio::test]
    async fn xor_homomorphic_mac() -> Result<(), Error> {
        let parties = 2;
        let length = 2;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<
            tokio::task::JoinHandle<Result<(Delta, Vec<Share>), crate::faand::Error>>,
        > = vec![];
        for i in 0..parties {
            let delta: Delta = Delta(random());
            let channel = channels.pop().unwrap();
            let handle = tokio::spawn(async move {
                let mut msgchannel = MsgChannel(channel);
                let mut shared_rng = shared_rng(&mut msgchannel, parties - i - 1, parties).await?;
                fashare_fpre(
                    &mut msgchannel,
                    parties - i - 1,
                    parties,
                    length,
                    delta,
                    &mut shared_rng,
                )
                .await
                .map(|result| (delta, result))
            });
            handles.push(handle);
        }
        let mut deltas = vec![Delta(0); parties];
        let mut party_num = parties;
        let mut shares_all: Vec<Vec<Share>> = vec![vec![]; parties];
        for handle in handles {
            let out = handle.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok((delta, shares)) => {
                    party_num -= 1;
                    deltas[party_num] = delta;
                    shares_all[party_num] = shares;
                }
            }
        }
        let mut r = shares_all[0].clone().into_iter();
        let mut s = shares_all[1].clone().into_iter();

        let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
        let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
        let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, Auth(mac_r2_key_s2))) = (auth_r1, auth_r2);
        let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, Auth(mac_s2_key_r2))) = (auth_s1, auth_s2);
        let (mac_r1, key_s1) = mac_r1_key_s1[1].unwrap();
        let (mac_r2, key_s2) = mac_r2_key_s2[1].unwrap();
        let (mac_s1, key_r1) = mac_s1_key_r1[0].unwrap();
        let (mac_s2, key_r2) = mac_s2_key_r2[0].unwrap();

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
        assert_eq!(mac_r3, key_r3 ^ (r3 & deltas[1]));
        assert_eq!(mac_s3, key_s3 ^ (s3 & deltas[0]));
        Ok(())
    }
}
