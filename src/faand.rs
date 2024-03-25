//! F_aAND protocol from WRK17b.

use blake3::Hasher;
use rand::{random, thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::{
    channel::{self, Channel, MsgChannel},
    //fpre::{Auth, Delta, Key, Mac, Share},
    fpre::Delta,
};

/// A custom error type.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
    /// The MAC is not the correct one in aBit.
    ABitMacMisMatch,
    /// A calculated bit value is not 0 or 1.
    BitNotBit,
    /// The xor of MACs is not equal to the XOR of corresponding keys or that XOR delta.
    AShareMacsMismatch,
    /// A commitment could not be opened.
    CommitmentCouldNotBeOpened,
    /// The check if the XOR fo all hashes is zero failed.
    HashNotZero,
    /// Wrong MAC of d when combining two leaky ANDs.
    WrongDMAC,
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Commitment(pub(crate) [u8; 32]);

// Commit to a u128 value using BLAKE3 hash function
fn commit(value: &[u8]) -> Commitment {
    let mut hasher = Hasher::new();
    hasher.update(value);
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(result.as_bytes());
    Commitment(commitment)
}

// Open the commitment and reveal the original value
fn open_commitment(commitment: &Commitment, value: &[u8]) -> bool {
    let mut hasher = Hasher::new();
    hasher.update(value);
    let result = hasher.finalize();
    &commitment.0 == result.as_bytes()
}

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

/// Performs F_abit.
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

/// Performs F_aBit^n.
pub(crate) async fn fabitn(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
) -> Result<(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>), Error> {
    const RHO: usize = 128;

    // Protocol Pi_aBit^n
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
            let mut xjp: Vec<bool> = vec![false; p_max];
            channel.send_to(p, "xj", &xj).await?;
            xjp[p] = channel.recv_from(p, "xj").await?;

            let mut macint: u128 = 0;
            let mut keyint: u128 = 0;
            for (i, rbit) in randbits.iter().enumerate().take(len_abit) {
                if *rbit {
                    macint ^= xmacs[p][i];
                }
            }
            channel
                .send_to(p, "mac", &(macint, randbits.clone()))
                .await?;
            let (macp, randbitsp): (u128, Vec<bool>) = channel.recv_from(p, "mac").await?;

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
    Ok((x, xkeys, xmacs))
}

/// Performs F_aShare.
pub(crate) async fn fashare(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    length: usize,
    delta: Delta,
) -> Result<(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>), Error> {
    const RHO: usize = 128;
    let len_ashare = length + RHO;

    let (mut x, mut xkeys, mut xmacs) = fabitn(channel, p_own, p_max, len_ashare, delta).await?;

    // Protocol Pi_aShare
    // Input: bits of len_ashare length, authenticated bits
    // Step 3
    let mut d0: Vec<u128> = vec![0; RHO]; // xorkeys
    let mut d1: Vec<u128> = vec![0; RHO]; // xorkeysdelta
    let mut dm: Vec<Vec<u8>> = vec![vec![]; RHO]; // multiple macs
    let mut c0: Vec<Commitment> = vec![]; // commitment to d0
    let mut c1: Vec<Commitment> = vec![]; // commitment to d1
    let mut cm: Vec<Commitment> = vec![]; // commitment to dm

    // 3/(a)
    for r in 0..RHO {
        dm[r].push(x[length + r] as u8);
        for p in 0..p_max {
            if p != p_own {
                d0[r] ^= xkeys[p][length + r];
                let macbytes = xmacs[p][length + r].to_be_bytes().to_vec(); // 16 bytes
                dm[r].extend(macbytes);
            } else {
                dm[r].extend(vec![0; 16]);
            }
        }
        d1[r] = d0[r] ^ delta.0;
        c0.push(commit(&d0[r].to_be_bytes()));
        c1.push(commit(&d1[r].to_be_bytes()));
        cm.push(commit(&dm[r]));
    }
    let mut commitments: Vec<(Vec<Commitment>, Vec<Commitment>, Vec<Commitment>)> =
        vec![(vec![], vec![], vec![]); p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "commit", &(&c0, &c1, &cm)).await?;
        let result: (Vec<Commitment>, Vec<Commitment>, Vec<Commitment>) =
            channel.recv_from(p, "commit").await?;
        commitments[p] = result;
    }

    // 3/(b) After receiving all commitments, Pi broadcasts decommitment for macs
    let mut dmp: Vec<Vec<Vec<u8>>> = vec![vec![vec![]; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "verify", &dm).await?;
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
        } else {
            return Err(Error::BitNotBit);
        }
    }
    let mut xorkeysbitp: Vec<Vec<u128>> = vec![vec![0; RHO]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "bitcom", &xorkeysbit).await?;
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
            if open_commitment(&commitments[p].0[r], &xorkeysbitp[p][r].to_be_bytes())
                || open_commitment(&commitments[p].1[r], &xorkeysbitp[p][r].to_be_bytes())
            {
                if !xormacs[p][r] == xorkeysbitp[p][r] {
                    return Err(Error::AShareMacsMismatch);
                }
            } else {
                return Err(Error::CommitmentCouldNotBeOpened);
            }
        }
    }

    // Step 4
    x.truncate(length);
    for p in (0..p_max).filter(|p| *p != p_own) {
        xkeys[p].truncate(length);
        xmacs[p].truncate(length);
    }
    Ok((x, xkeys, xmacs))
}

/// Performs F_HaAND.
pub(crate) async fn fhaand(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
    x: Vec<bool>,
    xkeys: Vec<Vec<u128>>,
    xmacs: Vec<Vec<u128>>,
) -> Result<bool, Error> {
    // Protocol Pi_HaAND

    // Upon receiving (i, {y_j^i}) from all P_i
    let mut y: Vec<bool> = vec![false; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        y[p] = channel.recv_from(p, "laand").await?;
    }

    // Step 1
    //let (x, xkeys, xmacs): (Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>) =
    //    fashare(channel, p_own, p_max, 1, delta).await?;

    //Step 2
    let mut hvec: Vec<(bool, bool)> = vec![(false, false); p_max];
    let mut hasher = Hasher::new();
    let mut v: bool = false; // Step 3 of HaAND makes me believe this needs to be XORed for all parties TODO Check
    for p in (0..p_max).filter(|p| *p != p_own) {
        let s: bool = random();

        hasher.update(&xkeys[p][0].to_le_bytes());
        let lsb1 = (hasher.finalize().as_bytes()[0] & 1) != 0;
        let h0: bool = lsb1 ^ s;
        hasher.reset();
        hasher.update(&(xkeys[p][0] ^ delta.0).to_le_bytes());
        let lsb2 = (hasher.finalize().as_bytes()[0] & 1) != 0;
        let h1: bool = lsb2 ^ s ^ y[p];
        channel.send_to(p, "haand", &(&h0, &h1)).await?;
        hvec[p] = channel.recv_from(p, "haand").await?;
        //Lsb mac
        hasher.reset();
        hasher.update(&xmacs[p][0].to_le_bytes());
        let lsb = (hasher.finalize().as_bytes()[0] & 1) != 0;
        let t: bool = if x[0] {
            hvec[p].0 ^ lsb
        } else {
            hvec[p].1 ^ lsb
        };
        v ^= t;
        v ^= s;
        //channel.send_to(p, "laand", &v).await?;
    }
    //Step 3
    Ok(v)
}

/// Performs F_LaAND.
pub(crate) async fn flaand(
    channel: &mut MsgChannel<impl Channel>,
    p_own: usize,
    p_max: usize,
    delta: Delta,
) -> Result<(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>), Error> {
    // Protocol Pi_LaAND
    // Step 1
    let (y, ykeys, ymacs): (Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>) =
        fashare(channel, p_own, p_max, 3, delta).await?; // x is y[0], y is y[1], z is y[2]

    // Step 2
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "laand", &y[1]).await?;
    }
    let v = fhaand(
        channel,
        p_own,
        p_max,
        delta,
        y.clone(),
        ykeys.clone(),
        ymacs.clone(),
    )
    .await?;

    // Step 3
    let mut z: bool = v;
    if y[0] {
        z ^= y[1];
    }
    let e_own: bool = z ^ y[2];

    let mut e: Vec<bool> = vec![false; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        channel.send_to(p, "esend", &e_own).await?;
        e[p] = channel.recv_from(p, "esend").await?;
    }
    let mut _zii: bool = y[2] ^ e_own; //TODO figure out [z^i]^i and [r^i]^i

    // Step 4
    let mut sum: u128 = 0;
    for p in (0..p_max).filter(|p| *p != p_own) {
        sum ^= ykeys[p][1];
        sum ^= ymacs[p][1];
    }
    let mut phi = sum;
    if y[1] {
        phi = delta.0 ^ sum;
    }

    // Step 5
    let mut hasher = Hasher::new();
    let mut xkeys_phi: Vec<[u8; 32]> = vec![[0; 32]; p_max];
    let mut uij: Vec<[u8; 32]> = vec![[0; 32]; p_max];
    let phi_bytes = phi.to_le_bytes();
    for p in (0..p_max).filter(|p| *p != p_own) {
        hasher.reset();
        hasher.update(&ykeys[p][0].to_le_bytes());
        xkeys_phi[p] = hasher.finalize().as_bytes().to_owned();
        hasher.reset();
        hasher.update(&(ykeys[p][0] ^ delta.0).to_le_bytes());
        let res = hasher.finalize().as_bytes().to_owned();

        for i in 0..32 {
            uij[p][i] = res[i] ^ xkeys_phi[p][i];
            if i < 16 {
                uij[p][i] ^= phi_bytes[i];
            }
        }
        channel.send_to(p, "uij", &uij).await?;
    }

    let mut uijp: Vec<Vec<[u8; 32]>> = vec![vec![[0; 32]; p_max]; p_max];
    let mut xmacs_phi: Vec<[u8; 32]> = vec![[0; 32]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        uijp[p] = channel.recv_from(p, "uij").await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        hasher.reset();
        hasher.update(&ymacs[p][0].to_le_bytes());
        xmacs_phi[p] = hasher.finalize().as_bytes().to_owned();
        if y[0] {
            for i in 0..32 {
                xmacs_phi[p][i] ^= uijp[p][p_own][i];
            }
        }
    }

    // Step 6
    let mut hash: [u8; 32] = [0; 32];
    let mut zxor: Vec<u128> = vec![0; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        for (i, h) in hash.iter_mut().enumerate() {
            *h = xkeys_phi[p][i] ^ xmacs_phi[p][i];
        }

        zxor[p] ^= ykeys[p][2]; // 2 because it is for z
        zxor[p] ^= ymacs[p][2];
        if y[2] {
            zxor[p] ^= delta.0;
        }
        if y[0] {
            zxor[p] ^= phi;
        }
        for (i, elem) in hash.iter_mut().take(16).enumerate() {
            *elem ^= zxor[p].to_le_bytes()[i];
        }
        channel.send_to(p, "hash", &hash).await?;
    }

    let mut hashp: Vec<[u8; 32]> = vec![[0; 32]; p_max];
    let mut xorhash: [u8; 32] = [0; 32];
    for p in (0..p_max).filter(|p| *p != p_own) {
        hashp[p] = channel.recv_from(p, "hash").await?; //TODO: commitments
        for (i, h) in xorhash.iter_mut().enumerate() {
            *h ^= hashp[p][i];
        }
    }
    for elem in xorhash {
        if elem != 0 {
            //return Err(Error::HashNotZero);
        }
    }
    Ok((y, ykeys, ymacs))
}

/// Performs Pi_aAND.
pub async fn faand(
    channel: impl Channel,
    p_own: usize,
    p_max: usize,
    circuit_size: u128,
    length: u128,
) -> Result<(), Error> {
    let delta: Delta = Delta(random());
    let mut channel = MsgChannel(channel);
    let b = (128.0 / f64::log2(circuit_size as f64)).ceil() as u128;
    let lprime = length * b;

    // Step 1
    let mut triples: Vec<(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>)> = vec![];
    for _ in 0..lprime {
        triples.push(flaand(&mut channel, p_own, p_max, delta).await?);
    }

    // Step 2 TODO Randomly partition all objects into l buckets, each with B objects
    let mut rng = thread_rng();
    let mut available: Vec<usize> = (0..length as usize).collect();

    let mut buckets: Vec<Vec<(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>)>> =
        vec![vec![]; length as usize];

    // Assign objects to buckets
    for obj in triples {
        let mut indeces: Vec<usize> = available.iter().cloned().collect();
        indeces.retain(|&index| buckets[index].len() < b as usize);

        if !indeces.is_empty() {
            let rand_index = rng.gen_range(0..indeces.len());
            let ind = indeces[rand_index];

            buckets[ind].push(obj);
            if buckets[ind].len() == b as usize {
                available.retain(|&index| index != ind);
            }
        }
    }

    /*for (index, bucket) in buckets.iter().enumerate() {
        println!("Bucket {}: {:?}", index, bucket);
        println!("{:?} {:?}", buckets.len(), b);
    }*/

    // Step 3
    // TODO combine buckets two by two.
    //combine_two_leaky_ands(&buckets[0][0], &buckets[0][1]);

    Ok(())
}

pub(crate) fn combine_two_leaky_ands(
    first: &(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>),
    second: &(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>),
) -> Result<(Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>), Error> {
    let mut result: (Vec<bool>, Vec<Vec<u128>>, Vec<Vec<u128>>) =
        (vec![false; 3], vec![vec![]; 3], vec![vec![]; 3]);
    let d = first.0[1] ^ second.0[1];
    // TODO Check MAC of d ????
    if false {
        return Err(Error::WrongDMAC);
    }
    result.0[0] = first.0[0] ^ second.0[0]; // x
    for j in 0..first.1.len() {
        result.1[0][j] = first.1[0][j] ^ second.1[0][j]; //TODO deal with the possibility that one of these arrays are empty (for own?)
        result.2[0][j] = first.2[0][j] ^ second.2[0][j];
    }
    result.0[1] = first.0[1]; // y
                              //result.1[1] = first.1[1];
    for j in 0..first.1.len() {
        result.1[1][j] = first.1[1][j];
        result.2[1][j] = first.2[1][j];
    }
    result.0[2] = first.0[2] ^ second.0[2]; // z
    for j in 0..first.1.len() {
        result.1[2][j] = first.1[2][j] ^ second.1[2][j];
        result.2[2][j] = first.2[2][j] ^ second.2[2][j];
    }
    if d {
        result.0[2] ^= second.0[0];
        for j in 0..first.1.len() {
            result.1[2][j] ^= second.1[0][j];
            result.2[2][j] ^= second.2[0][j];
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::{Error, SimpleChannel},
        faand::faand,
    };

    #[tokio::test]
    async fn test_faand() -> Result<(), Error> {
        let parties = 3;
        let circuit_size = 100000;
        let length = 2;
        let mut channels = SimpleChannel::channels(parties);
        let mut handles: Vec<tokio::task::JoinHandle<Result<(), crate::faand::Error>>> = vec![];
        for i in 0..parties {
            handles.push(tokio::spawn(faand(
                channels.pop().unwrap(),
                parties - i - 1,
                parties,
                circuit_size,
                length,
            )));
        }
        for i in handles {
            let out = i.await.unwrap();
            match out {
                Err(e) => {
                    eprintln!("Protocol failed {:?}", e);
                }
                Ok(()) => {}
            }
        }
        Ok(())
    }
}
