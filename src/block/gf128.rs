use super::Block;

/// The irreducible polynomial for gf128 operations.
const MOD: u64 = 0b10000111; // 0x87

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(target_feature_pclmulqdq, "pclmulqdq");

impl Block {
    /// Carryless multiplication of two Blocks as polynomials over GF(2).
    ///
    /// Depending on the (runtime) availability of the "pclmulqdq" feature,
    /// this method uses SIMD instructions or a scalar implementation.
    ///
    /// Returns (low, high) bits.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    pub fn clmul(&self, rhs: &Self) -> (Self, Self) {
        if target_feature_pclmulqdq::get() {
            // SAFETY: pclmulqdq is available
            unsafe {
                let (low, high) = clmul::clmul128(self.into(), rhs.into());
                (low.into(), high.into())
            }
        } else {
            let (low, high) = scalar::clmul128(self.into(), rhs.into());
            (low.into(), high.into())
        }
    }

    /// Carryless multiplication of two Blocks as polynomials over GF(2).
    ///
    /// Returns (low, high) bits.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[inline]
    pub fn clmul(&self, rhs: &Self) -> (Self, Self) {
        let (low, high) = scalar::clmul128(self.into(), rhs.into());
        (low.into(), high.into())
    }

    /// Multiplication over GF(2^128).
    ///
    /// Depending on the (runtime) availability of the "pclmulqdq" feature,
    /// this method uses SIMD instructions or a scalar implementation.
    ///
    /// Uses the irreducible polynomial `x^128 + x^7 + x^2 + x + 1.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    pub fn gf_mul(&self, rhs: &Self) -> Self {
        if target_feature_pclmulqdq::get() {
            // SAFETY: pclmulqdq is available
            unsafe { clmul::gf128_mul(self.into(), rhs.into()).into() }
        } else {
            scalar::gf128_mul(self.into(), rhs.into()).into()
        }
    }

    /// Multiplication over GF(2^128).
    ///
    /// Uses the irreducible polynomial `x^128 + x^7 + x^2 + x + 1`.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[inline]
    pub fn gf_mul(&self, rhs: &Self) -> Self {
        scalar::gf128_mul(self.into(), rhs.into()).into()
    }

    /// Reduce polynomial over GF(2) by `x^128 + x^7 + x^2 + x + 1`.
    ///
    /// Depending on the (runtime) availability of the "pclmulqdq" feature,
    /// this method uses SIMD instructions or a scalar implementation.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    pub fn gf_reduce(low: &Self, high: &Self) -> Self {
        if target_feature_pclmulqdq::get() {
            // SAFETY: pclmulqdq is available
            unsafe { clmul::gf128_reduce(low.into(), high.into()).into() }
        } else {
            scalar::gf128_reduce(low.into(), high.into()).into()
        }
    }

    /// Reduce polynomial over GF(2) by `x^128 + x^7 + x^2 + x + 1`.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    #[inline]
    pub fn gf_reduce(low: &Self, high: &Self) -> Self {
        scalar::gf128_reduce(low.into(), high.into()).into()
    }

    /// Exponentiation over GF(2^128).
    ///
    /// Depending on the (runtime) availability of the "pclmulqdq" feature,
    /// this method uses SIMD instructions or a scalar implementation.
    ///
    /// Uses the irreducible polynomial `x^128 + x^7 + x^2 + x + 1.
    #[inline]
    pub fn gf_pow(&self, mut exp: u64) -> Block {
        let mut s = Block::ONE;
        let mut pow2 = *self;

        // TODO could this be optimized by using clmul and only reducing at the end?
        while exp != 0 {
            if exp & 1 != 0 {
                s = s.gf_mul(&pow2);
            }
            pow2 = pow2.gf_mul(&pow2);
            exp >>= 1;
        }
        s
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod clmul {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    use super::MOD;

    /// Multiplication over GF(2^128) using pclmulqdq.
    ///
    /// Uses the irreducible polynomial `x^128 + x^7 + x^2 + x + 1.
    #[target_feature(enable = "pclmulqdq")]
    #[inline]
    pub fn gf128_mul(a: __m128i, b: __m128i) -> __m128i {
        let (low, high) = clmul128(a, b);
        gf128_reduce(low, high)
    }

    /// Carry-less multiply of two 128-bit numbers using pclmulqdq.
    ///
    /// Return (low, high) bits
    #[target_feature(enable = "pclmulqdq")]
    #[inline]
    pub fn clmul128(a: __m128i, b: __m128i) -> (__m128i, __m128i) {
        // NOTE: I tried using karatsuba but it was slightly slower than the naive
        // multiplication
        let ab_low = _mm_clmulepi64_si128::<0x00>(a, b);
        let ab_high = _mm_clmulepi64_si128::<0x11>(a, b);
        let ab_lohi1 = _mm_clmulepi64_si128::<0x01>(a, b);
        let ab_lohi2 = _mm_clmulepi64_si128::<0x10>(a, b);
        let ab_mid = _mm_xor_si128(ab_lohi1, ab_lohi2);
        let low = _mm_xor_si128(ab_low, _mm_slli_si128::<8>(ab_mid));
        let high = _mm_xor_si128(ab_high, _mm_srli_si128::<8>(ab_mid));
        (low, high)
    }

    /// Reduce polynomial over GF(2) by `x^128 + x^7 + x^2 + x + 1` using pclmulqdq.
    #[target_feature(enable = "pclmulqdq")]
    #[inline]
    pub fn gf128_reduce(mut low: __m128i, mut high: __m128i) -> __m128i {
        // NOTE: I tried a sse shift based reduction but it was slower than the clmul
        // implementation
        let modulus = [MOD, 0];
        // SAFETY: Ptr to modulus is valid and pclmulqdq implies sse2 is enabled
        let modulus = unsafe { _mm_loadu_si64(modulus.as_ptr().cast()) };

        let tmp = _mm_clmulepi64_si128::<0x01>(high, modulus);
        let tmp_shifted = _mm_slli_si128::<8>(tmp);
        low = _mm_xor_si128(low, tmp_shifted);
        high = _mm_xor_si128(high, tmp_shifted);

        // reduce overflow
        let tmp = _mm_clmulepi64_si128::<0x01>(tmp, modulus);
        low = _mm_xor_si128(low, tmp);

        let tmp = _mm_clmulepi64_si128::<0x00>(high, modulus);
        _mm_xor_si128(low, tmp)
    }

    #[cfg(all(test, target_feature = "pclmulqdq"))]
    mod test {
        #![allow(clippy::missing_transmute_annotations)]
        #![allow(clippy::undocumented_unsafe_blocks)]

        use std::{arch::x86_64::__m128i, mem::transmute};

        use crate::block::gf128::clmul::{clmul128, gf128_mul, gf128_reduce};

        #[test]
        fn test_gf128_mul_zero() {
            unsafe {
                let a = transmute(0x19831239123916248127031273012381_u128);
                let b = transmute(0_u128);
                let exp = 0_u128;
                let mul = transmute(gf128_mul(a, b));
                assert_eq!(exp, mul);
            }
        }

        #[test]
        fn test_gf128_mul_onw() {
            unsafe {
                let a = transmute(0x19831239123916248127031273012381_u128);
                let b = transmute(0x1_u128);
                let exp = 0x19831239123916248127031273012381_u128;
                let mul = transmute(gf128_mul(a, b));
                assert_eq!(exp, mul);
            }
        }

        #[test]
        fn test_gf128_mul() {
            unsafe {
                let a = transmute(0x19831239123916248127031273012381_u128);
                let b = transmute(0xabcdef0123456789abcdef0123456789_u128);
                let exp = 0x63a033d0ed643e85153c50f4268a7d9_u128;
                let mul = transmute(gf128_mul(a, b));
                assert_eq!(exp, mul);
            }
        }

        #[test]
        fn test_clmul128() {
            unsafe {
                let a: __m128i = transmute(0x19831239123916248127031273012381_u128);
                let b: __m128i = transmute(0xabcdef0123456789abcdef0123456789_u128);
                let (low, high) = clmul128(a, b);
                let [low, high] = transmute([low, high]);
                let exp_low: u128 = 0xa5de9b50e6db7b5147e92b99ee261809;
                let exp_high: u128 = 0xf1d6d37d58114afed2addfedd7c77f7;
                assert_eq!(exp_low, low);
                assert_eq!(exp_high, high);
            }
        }

        #[test]
        fn test_gf128_reduce() {
            unsafe {
                // test vectors computed using sage
                let low: __m128i = transmute(0x0123456789abcdef0123456789abcdef_u128);
                let high: __m128i = transmute(0xabcdef0123456789abcdef0123456789_u128);
                let exp = 0xb4b548f1c3c23f86b4b548f1c3c21572_u128;
                let res: u128 = transmute(gf128_reduce(low, high));

                println!("res: {res:b}");
                println!("exp: {exp:b}");
                assert_eq!(exp, res);
            }
        }
    }
}

// used in tests, but if we're not compiling tests these will otherwise be
// flagged as unused
#[allow(dead_code)]
mod scalar {
    /// Multiplication over GF(2^128).
    ///
    /// Uses the irreducible polynomial `x^128 + x^7 + x^2 + x + 1.
    #[inline]
    pub fn gf128_mul(a: u128, b: u128) -> u128 {
        let (low, high) = clmul128(a, b);
        gf128_reduce(low, high)
    }

    /// Carry-less multiply of two 128-bit numbers.
    ///
    /// Return (low, high) bits
    #[inline]
    pub fn clmul128(a: u128, b: u128) -> (u128, u128) {
        let (a_low, a_high) = (a as u64, (a >> 64) as u64);
        let (b_low, b_high) = (b as u64, (b >> 64) as u64);

        // Use karatsuba multiplication
        let ab_low = clmul64(a_low, b_low);
        let ab_high = clmul64(a_high, b_high);
        let ab_mid = clmul64(a_low ^ a_high, b_low ^ b_high) ^ ab_low ^ ab_high;
        let low = ab_low ^ (ab_mid << 64);
        let high = ab_high ^ (ab_mid >> 64);
        (low, high)
    }

    // Adapted from https://github.com/RustCrypto/universal-hashes/blob/802b40974a08bbd2663c63780fc87a23ee931868/polyval/src/backend/soft64.rs#L201C1-L227C2
    // Uses the technique described in https://www.bearssl.org/constanttime.html#ghash-for-gcm
    // but directly outputs the 128 bits wihtout needing the Rev trick.
    // This method is constant time and significantly faster than iterating over the
    // bits of y and xoring shifted x.
    /// Multiplication in GF(2)[X] with “holes”
    /// (sequences of zeroes) to avoid carry spilling.
    ///
    /// When carries do occur, they wind up in a "hole" and are subsequently
    /// masked out of the result.
    #[inline]
    fn clmul64(x: u64, y: u64) -> u128 {
        let x0 = (x & 0x1111_1111_1111_1111) as u128;
        let x1 = (x & 0x2222_2222_2222_2222) as u128;
        let x2 = (x & 0x4444_4444_4444_4444) as u128;
        let x3 = (x & 0x8888_8888_8888_8888) as u128;
        let y0 = (y & 0x1111_1111_1111_1111) as u128;
        let y1 = (y & 0x2222_2222_2222_2222) as u128;
        let y2 = (y & 0x4444_4444_4444_4444) as u128;
        let y3 = (y & 0x8888_8888_8888_8888) as u128;

        let mut z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
        let mut z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
        let mut z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
        let mut z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

        z0 &= 0x1111_1111_1111_1111_1111_1111_1111_1111;
        z1 &= 0x2222_2222_2222_2222_2222_2222_2222_2222;
        z2 &= 0x4444_4444_4444_4444_4444_4444_4444_4444;
        z3 &= 0x8888_8888_8888_8888_8888_8888_8888_8888;

        z0 | z1 | z2 | z3
    }

    /// Generated by ChatGPT o3-mini and reviewed by @robinhundt. The comments
    /// are a mix of generated and written by @robinhundt.
    /// Reduces a 256-bit value (given as two u128 words, `high` and `low`)
    /// modulo the irreducible polynomial f(x) = x^128 + x^7 + x^2 + x + 1.
    ///
    /// That is, it computes:
    ///      low ^ reduce(high * (x^7 + x^2 + x + 1))
    /// since x^128 ≡ x^7 + x^2 + x + 1 (mod f(x)).
    #[inline]
    pub fn gf128_reduce(low: u128, high: u128) -> u128 {
        // Helper: performs a left shift on a 128-bit word and returns
        // a tuple (overflow, lower) where:
        //    x << shift = (overflow << 128) | lower.
        #[inline]
        fn shift_u128(x: u128, shift: u32) -> (u128, u128) {
            // For 0 < shift < 128.
            let overflow = x >> (128 - shift);
            let lower = x << shift;
            (overflow, lower)
        }

        // For the reduction, note that:
        //   x^128 ≡ x^7 + x^2 + x + 1 (mod f(x)).
        // So the contribution of the high word is:
        //   (high << 7) ^ (high << 2) ^ (high << 1) ^ high,
        // but each shift must be computed as a 256–bit quantity.
        let (ov7, lo7) = shift_u128(high, 7);
        let (ov2, lo2) = shift_u128(high, 2);
        let (ov1, lo1) = shift_u128(high, 1);
        let lo0 = high; // equivalent to shift 0

        // Combine the 128-bit parts of each term.
        let combined_low = lo7 ^ lo2 ^ lo1 ^ lo0;
        // Combine the overflow (upper) parts.
        let combined_overflow = ov7 ^ ov2 ^ ov1;

        // The bits in `combined_overflow` represent extra contributions from bits
        // at positions ≥ 128. Since they are at most 7 bits wide, we can reduce them
        // by multiplying with the reduction polynomial (i.e. shifting and XORing):
        let reduced_overflow = (combined_overflow << 7)
            ^ (combined_overflow << 2)
            ^ (combined_overflow << 1)
            ^ combined_overflow;

        // The full contribution from `high` is then given by the low part
        // combined with the reduced overflow.
        let poly_contrib = combined_low ^ reduced_overflow;

        // Finally, reduce the entire 256-bit value by XORing in the contribution.
        low ^ poly_contrib
    }

    #[cfg(test)]
    mod tests {
        use super::{clmul128, gf128_mul, gf128_reduce};

        #[test]
        fn test_gf128_mul_zero() {
            let a = 0x19831239123916248127031273012381;
            let b = 0;
            let exp = 0;
            let mul = gf128_mul(a, b);
            assert_eq!(exp, mul);
        }

        #[test]
        fn test_gf128_mul_one() {
            let a = 0x19831239123916248127031273012381;
            let b = 1;
            let exp = 0x19831239123916248127031273012381;
            let mul = gf128_mul(a, b);
            assert_eq!(exp, mul);
        }

        #[test]
        fn test_gf128_mul() {
            let a = 0x19831239123916248127031273012381;
            let b = 0xabcdef0123456789abcdef0123456789;
            let exp = 0x63a033d0ed643e85153c50f4268a7d9;
            let mul = gf128_mul(a, b);
            assert_eq!(exp, mul);
        }

        #[test]
        fn test_gf128_reduce_zero() {
            assert_eq!(gf128_reduce(0, 0), 0);
        }

        #[test]
        fn test_gf128_reduce_low_only() {
            assert_eq!(gf128_reduce(1, 0), 1);
            assert_eq!(gf128_reduce(0x87, 0), 0x87); // Reduction polynomial itself.
            assert_eq!(gf128_reduce(0xFFFFFFFFFFFFFFFF, 0), 0xFFFFFFFFFFFFFFFF);
        }

        #[test]
        fn test_gf128_reduce_high_only() {
            // high << 64
            assert_eq!(gf128_reduce(0, 1), 0x87);
            assert_eq!(gf128_reduce(0, 2), 0x87 << 1);
            assert_eq!(gf128_reduce(0, 3), (0x87 << 1) ^ 0x87);

            assert_eq!(gf128_reduce(0, 1 << 63), 0x87 << 63);
        }

        #[test]
        fn test_gf128_reduce_overflow() {
            let high = u128::MAX; // All bits set in high
            let low = u128::MAX; // All bits set in low.
            assert_eq!(gf128_reduce(low, high), 0xffffffffffffffffffffffffffffc071);
        }

        #[test]
        fn tests_gf128_reduce() {
            // test vectors computed using sage
            let low = 0x0123456789abcdef0123456789abcdef;
            let high = 0xabcdef0123456789abcdef0123456789;
            let exp = 0xb4b548f1c3c23f86b4b548f1c3c21572;
            let res = gf128_reduce(low, high);

            println!("res: {res:b}");
            println!("exp: {exp:b}");
            assert_eq!(exp, res);
        }

        #[test]
        fn test_clmul128() {
            let a = 0x19831239123916248127031273012381;
            let b = 0xabcdef0123456789abcdef0123456789;
            let (low, high) = clmul128(a, b);
            let exp_low = 0xa5de9b50e6db7b5147e92b99ee261809;
            let exp_high = 0xf1d6d37d58114afed2addfedd7c77f7;
            assert_eq!(exp_low, low);
            assert_eq!(exp_high, high);
        }
    }
}

/// Test that scalar implementation and clmul implementation produce the same
/// results
#[cfg(all(test, not(miri), target_feature = "pclmulqdq"))]
mod scalar_simd_tests {
    #![allow(clippy::missing_transmute_annotations)]
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::mem::transmute;

    use rand::{rng, Rng};

    use super::{clmul, scalar};

    #[test]
    fn test_clmul128() {
        for _ in 0..1000 {
            let (a, b) = rng().random::<(u128, u128)>();
            unsafe {
                let clmul_res = clmul::clmul128(transmute(a), transmute(b));
                let scalar_res = scalar::clmul128(a, b);
                assert_eq!(scalar_res.0, transmute(clmul_res.0));
            }
        }
    }

    #[test]
    fn test_gf128_reduce() {
        for _ in 0..1000 {
            let (a, b) = rng().random::<(u128, u128)>();
            unsafe {
                let clmul_res = clmul::gf128_reduce(transmute(a), transmute(b));
                let scalar_res = scalar::gf128_reduce(a, b);
                assert_eq!(scalar_res, transmute(clmul_res));
            }
        }
    }

    #[test]
    fn test_gf128_mul() {
        for _ in 0..1000 {
            let (a, b) = rng().random::<(u128, u128)>();
            unsafe {
                let clmul_res = clmul::gf128_mul(transmute(a), transmute(b));
                let scalar_res = scalar::gf128_mul(a, b);
                assert_eq!(scalar_res, transmute(clmul_res));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::block::Block;

    #[test]
    fn test_gf_pow() {
        let b: Block = 24646523424323_u128.into();
        assert_eq!(Block::ONE, b.gf_pow(0));
        assert_eq!(b, b.gf_pow(1));
        assert_eq!(b.gf_mul(&b), b.gf_pow(2));
        assert_eq!(b.gf_mul(&b.gf_mul(&b)), b.gf_pow(3));
    }
}
