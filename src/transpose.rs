//! Transpose bit-matrices fast.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod avx2;
pub mod portable;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(target_feature_avx2, "avx2");

/// Transpose a bit matrix.
///
/// # Panics
/// If `rows % 128 != 0`
/// If for `let cols = input.len() * 8 / rows`, `cols % 128 != 0`
pub fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if target_feature_avx2::get() {
        // SAFETY: The avx2 feature is available
        unsafe { avx2::transpose_bitmatrix(input, output, rows) }
    } else {
        portable::transpose_bitmatrix(input, output, rows);
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    portable::transpose_bitmatrix(input, output, rows);
}
