//! The cryptographic building blocks used to garble (= encrypt/decrypt) gate tables.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
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

fn xor(hash: &[u8], value: u128) -> Result<Vec<u8>, Error> {
    let mut ciphertext = u128::from_le_bytes(hash.try_into().map_err(|_| Error::EncryptionFailed)?);
    ciphertext ^= value;
    Ok(ciphertext.to_le_bytes().to_vec())
}

pub(crate) fn encrypt(
    garbling_key: &GarblingKey,
    triple: (bool, Vec<Option<Mac>>, Label),
    party_num: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let hash = hash_aes(garbling_key, party_num)?;
    let hassh: &[u8] = &hash[0];
    let ciphertext =
        u128::from_le_bytes(hassh.try_into().map_err(|_| Error::EncryptionFailed)?);
    let mut result: Vec<Vec<u8>> = vec![];
    result.push((ciphertext ^ triple.0 as u128).to_le_bytes().to_vec());
    for i in 1..party_num {
        result.push(xor(&hash[i], triple.1[i - 1].unwrap().0)?);
    }
    result.push(xor(&hash[party_num], triple.2.0)?);
    Ok(result)
}

fn xor_dec(hash: &[u8], bytes: &Vec<u8>) -> Result<u128, Error>{
    let myhash = u128::from_le_bytes(hash.try_into().map_err(|_| Error::EncryptionFailed)?);
    let ciphertext = u128::from_le_bytes(
        bytes
            .clone()
            .try_into()
            .map_err(|_| Error::EncryptionFailed)?,
    );
    Ok(myhash ^ ciphertext)
}

pub(crate) fn decrypt(
    garbling_key: &GarblingKey,
    bytes: Vec<Vec<u8>>,
    party_num: usize,
) -> Result<(bool, Vec<Option<Mac>>, Label), Error> {
    let mut triple: (bool, Vec<Option<Mac>>, Label) = (false, vec![], Label(0));
    let hash = hash_aes(garbling_key, party_num)?;
    let mut decrypted = xor_dec(&hash[0], &bytes[0])?;
    if decrypted == 1 {
        triple.0 = true;
    } else if 0 != decrypted {
        return Err(Error::DecryptionFailed);
    }
    let mut plaintext: Mac;
    for i in 1..party_num {
        decrypted = xor_dec(&hash[i], &bytes[i])?;
        plaintext = bincode::deserialize(&(decrypted).to_le_bytes())
            .map_err(|e| Error::Serde(format!("{e:?}")))?;
        triple.1.push(Some(plaintext));
    }
    decrypted = xor_dec(&hash[party_num], &bytes[party_num])?;
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
) -> Result<Vec<Vec<u8>>, Error> {
    let res = sigma(label_x) ^ sigma(&Label(sigma(label_y)));
    let key = GenericArray::from([0u8; 16]); //TODO real key
    let cipher = Aes128::new(&key);
    let mut result: Vec<u128> = vec![];
    let mut bytes_vec: Vec<Vec<u8>> = vec![];
    let wok: u128 = *w as u128;
    result.push(res);
    let mut bytes = bincode::serialize(&res)
        .map_err(|e: Box<bincode::ErrorKind>| Error::Serde(format!("{e:?}")))?;
    bytes_vec.push(bytes);
    for i in 1..party_num + 1 {
        result.push(res ^ ((4 * wok + *row as u128) << 64) ^ (i as u128));
        bytes = bincode::serialize(&result[i])
            .map_err(|e: Box<bincode::ErrorKind>| Error::Serde(format!("{e:?}")))?;
        let mut block = *GenericArray::from_slice(&bytes);
        cipher.encrypt_block(&mut block);
        bytes_vec.push(block.to_vec());
    }
    Ok(bytes_vec)
}

fn sigma(block: &Label) -> u128 {
    let xl = block.0 >> 64;
    let xr = block.0 << 64;
    let xlxl = xl ^ xl << 64;
    xlxl ^ xr
}

#[test]
fn encrypt_decrypt() {
    use rand::random;

    let key = GarblingKey {
        label_x: Label(random()),
        label_y: Label(random()),
        w: random(),
        row: random(),
    };
    let triple: (bool, Vec<Option<Mac>>, Label) = (
        random(),
        vec![
            Some(Mac(random())),
            Some(Mac(random())),
            Some(Mac(random())),
        ],
        Label(random()),
    );

    let encrypted = encrypt(&key, triple.clone(), 4).unwrap();
    let decrypted = decrypt(&key, encrypted, 4).unwrap();

    assert_eq!(triple, decrypted);
}
