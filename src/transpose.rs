//! Transpose bit-matrices fast.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod avx2;
mod portable;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(target_feature_avx2, "avx2");

/// Transpose a bit matrix.
///
/// # Panics
/// If `input.len() != output.len()`
/// If the number of rows is less than 128.
/// If `input.len()` is not divisible by rows.
/// If the number of rows is not divisable by 128.
/// If the number of columns (= input.len() * 8 / rows) is not divisable by 8.
/// If the number of columns is less than 16.
pub(crate) fn transpose_bitmatrix(input: &[u8], output: &mut [u8], rows: usize) {
    // If the following check pass, we can call either the AVX implementation
    // or the portable one.
    assert_eq!(input.len(), output.len());
    assert!(rows >= 128, "Number of rows must be >= 128.");
    assert_eq!(
        0,
        input.len() % rows,
        "input.len(), must be divisble by rows"
    );
    assert_eq!(0, rows % 128, "Number of rows must be a multiple of 128.");
    let cols = input.len() * 8 / rows;
    assert_eq!(0, cols % 8, "Number of columns must be a multiple of 8.");
    assert!(cols >= 16, "columns must be at least 16. Columns {cols}");

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
