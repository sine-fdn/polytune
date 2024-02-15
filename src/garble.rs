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
    party_num: usize,
    cipher: &Aes128,
) -> Result<Vec<Vec<u8>>, Error> {
    let hash = hash_aes(garbling_key, party_num + 1, cipher)?;
    let mut result: Vec<Vec<u8>> = vec![];
    result.push(xor_enc(&hash[0], triple.0 as u128)?);
    for (i, h) in hash.iter().enumerate().take(party_num + 1).skip(1) {
        let mac = triple.1[i - 1];
        if mac.is_none() {
            result.push(vec![]);
        } else {
            result.push(xor_enc(h, triple.1[i - 1].unwrap().0)?);
        }
    }
    result.push(xor_enc(&hash[party_num + 1], triple.2 .0)?);
    Ok(result)
}

pub(crate) fn decrypt(
    garbling_key: &GarblingKey,
    bytes: Vec<Vec<u8>>,
    party_num: usize,
    cipher: &Aes128,
) -> Result<(bool, Vec<Option<Mac>>, Label), Error> {
    let mut triple: (bool, Vec<Option<Mac>>, Label) = (false, vec![], Label(0));
    let hash = hash_aes(garbling_key, party_num + 1, cipher)?;
    let mut decrypted = xor_dec(&hash[0], &bytes[0])?;
    if decrypted == 1 {
        triple.0 = true;
    } else if 0 != decrypted {
        return Err(Error::DecryptionFailed);
    }
    let mut mac: Mac;
    for i in 1..party_num + 1 {
        if bytes[i].is_empty() {
            triple.1.push(None);
        } else {
            decrypted = xor_dec(&hash[i], &bytes[i])?;
            mac = bincode::deserialize(&(decrypted).to_le_bytes())
                .map_err(|e| Error::Serde(format!("{e:?}")))?;
            triple.1.push(Some(mac));
        }
    }
    decrypted = xor_dec(&hash[party_num + 1], &bytes[party_num + 1])?;
    triple.2 = bincode::deserialize(&(decrypted).to_le_bytes())
        .map_err(|e| Error::Serde(format!("{e:?}")))?;
    Ok(triple)
}

fn hash_aes(
    GarblingKey {
        label_x,
        label_y,
        w,
        row,
    }: &GarblingKey,
    party_num: usize,
    cipher: &Aes128,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut res = sigma(label_x) ^ sigma(&Label(sigma(label_y)));
    let mut result: Vec<Vec<u8>> = vec![];
    let mut bytes = bincode::serialize(&res)
        .map_err(|e: Box<bincode::ErrorKind>| Error::Serde(format!("{e:?}")))?;
    result.push(bytes);
    for i in 1..party_num + 1 {
        res ^= ((4 * *w as u128 + *row as u128) << 64) ^ (i as u128);
        bytes = bincode::serialize(&res)
            .map_err(|e: Box<bincode::ErrorKind>| Error::Serde(format!("{e:?}")))?;
        let mut block = *GenericArray::from_slice(&bytes);
        cipher.encrypt_block(&mut block);
        result.push(block.to_vec());
    }
    Ok(result)
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
    let myhash = u128::from_le_bytes(hash.try_into().map_err(|_| Error::DecryptionFailed)?);
    let ciphertext = u128::from_le_bytes(bytes.try_into().map_err(|_| Error::DecryptionFailed)?);
    Ok(myhash ^ ciphertext)
}

#[test]
fn encrypt_decrypt() {
    use aes::cipher::KeyInit;
    use rand::random;
    let array: [u8; 16] = rand::random();
    let key_aes = GenericArray::from_slice(&array);
    let cipher = Aes128::new(&key_aes);

    let key = GarblingKey {
        label_x: Label(random()),
        label_y: Label(random()),
        w: random(),
        row: random(),
    };
    let triple: (bool, Vec<Option<Mac>>, Label) = (
        random(),
        vec![None, Some(Mac(random())), Some(Mac(random()))],
        Label(random()),
    );

    let encrypted = encrypt(&key, triple.clone(), 3, &cipher).unwrap();
    let decrypted = decrypt(&key, encrypted, 3, &cipher).unwrap();

    assert_eq!(triple, decrypted);
}
