//! The cryptographic hash function used to garble circuits

use crate::{
    fpre::Mac,
    protocol::{Label, Wire},
};

/// The result of the cryptographic hash function.
#[derive(Debug)]
pub struct Hash([u8; 48]);

/// Returns the hash of a row in an AND gate.
pub fn hash(label_x: Label, label_y: Label, w: Wire, row: u8) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&label_x.0.to_le_bytes());
    hasher.update(&label_y.0.to_le_bytes());
    hasher.update(&w.to_le_bytes());
    hasher.update(&[row]);
    let mut output_reader = hasher.finalize_xof();
    let mut bytes: [u8; 48] = [0; 48];
    output_reader.fill(&mut bytes);
    Hash(bytes)
}

/// Encrypts the triple by XOR'ing it with the hash.
pub fn hash_xor_triple(hash: &Hash, triple: (bool, Mac, Label)) -> (bool, Mac, Label) {
    let bytes = hash.0;
    let (bit, mac, label) = triple;
    let bit = if bytes[0] & 1 == 1 { !bit } else { bit };
    let mac = Mac(mac.0 ^ u128::from_be_bytes(bytes[16..32].try_into().unwrap()));
    let label = Label(label.0 ^ u128::from_be_bytes(bytes[32..48].try_into().unwrap()));
    (bit, mac, label)
}

#[test]
fn double_xor() {
    use rand::random;

    let hash = hash(Label(random()), Label(random()), random(), random());
    let triple = (random(), Mac(random()), Label(random()));
    let encrypted = hash_xor_triple(&hash, triple);
    let decrypted = hash_xor_triple(&hash, encrypted);
    assert_ne!(triple, encrypted);
    assert_eq!(triple, decrypted);
}
