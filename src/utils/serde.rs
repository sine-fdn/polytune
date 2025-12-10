use bincode::error::{DecodeError, EncodeError};
use serde::{Serialize, de::DeserializeOwned};

pub(crate) fn serialize<T: Serialize>(val: T) -> Result<Vec<u8>, EncodeError> {
    bincode::serde::encode_to_vec(val, bincode::config::legacy())
}

pub(crate) fn deserialize<T: DeserializeOwned>(slice: &[u8]) -> Result<T, DecodeError> {
    bincode::serde::decode_from_slice(slice, bincode::config::legacy()).map(|(val, _)| val)
}
