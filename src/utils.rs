use std::ops::{BitAndAssign, BitXorAssign};

pub(crate) mod file_or_mem_buf;
mod rand_compat;
pub mod serde;

pub(crate) use rand_compat::RngCompat;
pub(crate) use serde::{deserialize, serialize};

pub(crate) fn xor_inplace<T: Copy + BitXorAssign>(a: &mut [T], b: &[T]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a ^= *b;
    });
}

pub(crate) fn and_inplace<T: Copy + BitAndAssign>(a: &mut [T], b: &[T]) {
    a.iter_mut().zip(b).for_each(|(a, b)| {
        *a &= *b;
    });
}
