//! Compatability wrapper between rand_core 0.9 and rand_core 0.6.
use rand::{CryptoRng, RngCore};

/// Compatability wrapper between rand_core 0.9 and rand_core 0.6.
///
/// This implements the [`rand_core_0_6::RngCore`] and
/// [`rand_core_0_6::CryptoRng`] for any version 0.9 RNG that implements the
/// corresponding traits.
pub(crate) struct RngCompat<R>(pub(crate) R);

impl<R: RngCore> rand_core_0_6::RngCore for RngCompat<R> {
    #[inline]
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_0_6::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: CryptoRng> rand_core_0_6::CryptoRng for RngCompat<R> {}
