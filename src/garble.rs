//! The cryptographic building blocks used to garble (= encrypt/decrypt) gate tables.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

use crate::data_types::{Label, Mac};

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
    triple: (bool, Vec<Mac>, Label),
) -> Result<Vec<u8>, Error> {
    let (key, nonce) = key_and_nonce(garbling_key);
    let cipher = ChaCha20Poly1305::new(&key);
    let bytes = bincode::serialize(&triple).map_err(|e| Error::Serde(format!("{e:?}")))?;
    let ciphertext = cipher
        .encrypt(&nonce, bytes.as_ref())
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(ciphertext)
}

pub(crate) fn decrypt(
    garbling_key: &GarblingKey,
    bytes: &[u8],
) -> Result<(bool, Vec<Mac>, Label), Error> {
    let (key, nonce) = key_and_nonce(garbling_key);
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = cipher
        .decrypt(&nonce, bytes)
        .map_err(|_| Error::DecryptionFailed)?;
    bincode::deserialize(&plaintext).map_err(|e| Error::Serde(format!("{e:?}")))
}

fn key_and_nonce(
    GarblingKey {
        label_x,
        label_y,
        w,
        row,
    }: &GarblingKey,
) -> (Key, Nonce) {
    let mut key = [0; 32];
    key[..16].copy_from_slice(&label_x.0.to_be_bytes());
    key[16..].copy_from_slice(&label_y.0.to_be_bytes());
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(&(*w as u64).to_be_bytes());
    nonce[8] = *row;
    (key.into(), nonce.into())
}

#[cfg(test)]
mod tests {
    use rand::random_range;

    use crate::{
        data_types::{Label, Mac},
        garble::{GarblingKey, decrypt, encrypt},
    };

    #[test]
    fn encrypt_decrypt() {
        use rand::random;

        let key = GarblingKey {
            label_x: Label(random()),
            label_y: Label(random()),
            w: random_range(0..=usize::MAX),
            row: random(),
        };
        let triple = (
            random(),
            vec![Mac(random()), Mac(0), Mac(random())],
            Label(random()),
        );
        let encrypted = encrypt(&key, triple.clone()).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(triple, decrypted);
    }
}
