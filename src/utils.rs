use std::ops::{BitAndAssign, BitXorAssign};

pub(crate) mod maybe_file_buf;
mod rand_compat;

pub(crate) use rand_compat::RngCompat;

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
