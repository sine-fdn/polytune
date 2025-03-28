//! The cryptographic building blocks used to garble (= encrypt/decrypt) gate tables.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use blake3::Hasher;

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

/// Derive a key from the garbling key components using BLAKE3 for key commitment.
fn derive_commitment_key(key: &Key, nonce: &Nonce) -> Key {
    let mut hasher = Hasher::new();
    hasher.update(key);
    hasher.update(nonce);
    let derived_key = hasher.finalize();
    Key::from_slice(&derived_key.as_bytes()[..32]).to_owned()
}

/// Add a commitment to the plaintext using BLAKE3.
fn add_commitment(plaintext: &[u8], nonce: &Nonce) -> [u8; 16] {
    let mut hasher = Hasher::new();
    hasher.update(plaintext);
    hasher.update(nonce);
    let hash = hasher.finalize();
    let mut commitment = [0u8; 16];
    commitment.copy_from_slice(&hash.as_bytes()[..16]);
    commitment
}

/// Encrypt a triple of a gate table using ChaCha20Poly1305.
pub(crate) fn encrypt(
    garbling_key: &GarblingKey,
    triple: (bool, Vec<Mac>, Label),
) -> Result<Vec<u8>, Error> {
    let (key, nonce) = key_and_nonce(garbling_key);
    let commitment_key = derive_commitment_key(&key, &nonce);
    let cipher = ChaCha20Poly1305::new(&commitment_key);

    let mut bytes = bincode::serialize(&triple).map_err(|e| Error::Serde(format!("{e:?}")))?;
    let commitment = add_commitment(&bytes, &nonce);
    bytes.extend_from_slice(&commitment); // Append structured commitment

    let ciphertext = cipher
        .encrypt(&nonce, bytes.as_ref())
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(ciphertext)
}

/// Decrypt a triple of a gate table using ChaCha20Poly1305.
pub(crate) fn decrypt(
    garbling_key: &GarblingKey,
    bytes: &[u8],
) -> Result<(bool, Vec<Mac>, Label), Error> {
    let (key, nonce) = key_and_nonce(garbling_key);
    let commitment_key = derive_commitment_key(&key, &nonce);
    let cipher = ChaCha20Poly1305::new(&commitment_key);

    let plaintext = cipher
        .decrypt(&nonce, bytes)
        .map_err(|_| Error::DecryptionFailed)?;

    // Ensure commitment is intact
    if plaintext.len() < 16 {
        return Err(Error::DecryptionFailed);
    }
    let (original_plaintext, commitment) = plaintext.split_at(plaintext.len() - 16);
    let expected_commitment = add_commitment(original_plaintext, &nonce);

    if commitment != expected_commitment {
        return Err(Error::DecryptionFailed);
    }

    bincode::deserialize(original_plaintext).map_err(|e| Error::Serde(format!("{e:?}")))
}

/// Extract key and nonce from a garbling key.
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

#[test]
fn encrypt_decrypt() {
    use rand::random;

    let key = GarblingKey {
        label_x: Label(random()),
        label_y: Label(random()),
        w: random(),
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
