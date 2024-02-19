//! The cryptographic building blocks used to garble (= encrypt/decrypt) gate tables.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;

use crate::{fpre::Mac, protocol::Label};

#[derive(Debug, Clone)]
pub enum Error {
    Serde(String),
    EncryptionFailed,
    DecryptionFailed,
}

#[derive(Debug)]
pub(crate) struct GarblingKey {
    label_x: Label,
    label_y: Label,
    w: usize,
    row: u8,
}

impl GarblingKey {
    pub(crate) fn new(label_x: Label, label_y: Label, w: usize, row: u8) -> Self {
        Self {
            label_x,
            label_y,
            w,
            row,
        }
    }
}

pub(crate) fn encrypt(
    garbling_key: &GarblingKey,
    triple: (bool, Vec<Option<Mac>>, Label),
    n_parties: usize,
    cipher: &Aes128,
) -> Result<Vec<Vec<u8>>, Error> {
    let hash = hash_aes(garbling_key, n_parties + 1, cipher)?;
    let mut result: Vec<Vec<u8>> = vec![];
    result.push(xor_enc(&hash.0, triple.0 as u128)?);
    for (i, h) in hash.1.iter().take(n_parties).enumerate() {
        let mac = triple.1[i];
        if mac.is_none() {
            result.push(vec![]);
        } else {
            result.push(xor_enc(h, triple.1[i].unwrap().0)?);
        }
    }
    result.push(xor_enc(&hash.1[n_parties], triple.2 .0)?);
    Ok(result)
}

pub(crate) fn decrypt(
    garbling_key: &GarblingKey,
    bytes: Vec<Vec<u8>>,
    n_parties: usize,
    cipher: &Aes128,
) -> Result<(bool, Vec<Option<Mac>>, Label), Error> {
    if bytes.len() != n_parties+2 {
        return Err(Error::DecryptionFailed);
    }
    let mut triple: (bool, Vec<Option<Mac>>, Label) = (false, vec![], Label(0));
    let hash = hash_aes(garbling_key, n_parties + 1, cipher)?;
    let mut decrypted = xor_dec(&hash.0, &bytes[0])?;
    if decrypted == 1 {
        triple.0 = true;
    } else if 0 != decrypted {
        return Err(Error::DecryptionFailed);
    }
    for i in 0..n_parties+1 {
        if bytes[i+1].is_empty() {
            triple.1.push(None);
        } else {
            decrypted = xor_dec(&hash.1[i], &bytes[i+1])?;
            let res: u128 = bincode::deserialize(&(decrypted).to_le_bytes())
                .map_err(|e| Error::Serde(format!("{e:?}")))?;
            if i != n_parties {
                triple.1.push(Some(Mac(res)));
            } else {
                triple.2 = Label(res);
            }
        }
    }
    Ok(triple)
}

fn hash_aes(
    GarblingKey {
        label_x,
        label_y,
        w,
        row,
    }: &GarblingKey,
    n_parties: usize,
    cipher: &Aes128,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), Error> {
    let mut res = sigma(label_x) ^ sigma(&Label(sigma(label_y)));
    let mut hashes: Vec<Vec<u8>> = vec![];
    let mut hashbit = vec![];
    for i in 0..n_parties + 1 {
        let hash = bincode::serialize(&res)
            .map_err(|e: Box<bincode::ErrorKind>| Error::Serde(format!("{e:?}")))?;
        if i==0 {
            hashbit = hash;
        } else {
            let mut block = *GenericArray::from_slice(&hash);
            cipher.encrypt_block(&mut block);
            hashes.push(block.to_vec());
        }
        res ^= ((4 * *w as u128 + *row as u128) << 64) ^ ((i+1) as u128);
    }
    Ok((hashbit, hashes))
}

fn sigma(block: &Label) -> u128 {
    let xl = block.0 >> 64;
    let xr = block.0 << 64;
    let xlxl = xl ^ xl << 64;
    xlxl ^ xr
}

fn xor_enc(hash: &[u8], value: u128) -> Result<Vec<u8>, Error> {
    let mut ciphertext = u128::from_le_bytes(hash.try_into().map_err(|_| Error::EncryptionFailed)?);
    ciphertext ^= value;
    Ok(ciphertext.to_le_bytes().to_vec())
}

fn xor_dec(hash: &[u8], bytes: &[u8]) -> Result<u128, Error> {
    let hash = u128::from_le_bytes(hash.try_into().map_err(|_| Error::DecryptionFailed)?);
    let ciphertext = u128::from_le_bytes(bytes.try_into().map_err(|_| Error::DecryptionFailed)?);
    Ok(hash ^ ciphertext)
}

#[test]
fn encrypt_decrypt() {
    use aes::cipher::KeyInit;
    use rand::random;
    let array: [u8; 16] = rand::random();
    let cipher = Aes128::new(&GenericArray::from_slice(&array));

    let key = GarblingKey {
        label_x: Label(random()),
        label_y: Label(random()),
        w: random(),
        row: random(),
    };
    let triple: (bool, Vec<Option<Mac>>, Label) = (
        random(),
        vec![Some(Mac(random())), None, Some(Mac(random()))],
        Label(random()),
    );

    let encrypted = encrypt(&key, triple.clone(), 3, &cipher).unwrap();
    let decrypted = decrypt(&key, encrypted, 3, &cipher).unwrap();

    assert_eq!(triple, decrypted);
}
