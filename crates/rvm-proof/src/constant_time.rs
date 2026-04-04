//! Constant-time comparison utilities.
//!
//! These functions are used for comparing cryptographic digests and
//! signatures in constant time, preventing timing side-channel attacks.
//!
//! Internally delegates to the `subtle` crate's [`ConstantTimeEq`] trait,
//! which is a well-audited implementation that avoids short-circuit
//! evaluation and resists compiler optimizations that could introduce
//! timing variance.

use subtle::ConstantTimeEq;

/// Constant-time equality check for 32-byte arrays.
///
/// Returns `true` if `a` and `b` are identical, `false` otherwise.
/// Executes in constant time regardless of where the first difference
/// occurs.
#[must_use]
#[inline(never)]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time equality check for 64-byte arrays.
///
/// Returns `true` if `a` and `b` are identical, `false` otherwise.
/// Executes in constant time regardless of where the first difference
/// occurs.
#[must_use]
#[inline(never)]
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time equality check for arbitrary-length slices.
///
/// Returns `true` if `a` and `b` have the same length and identical
/// contents, `false` otherwise. When lengths differ, the function
/// returns `false` immediately (length is not a secret).
#[must_use]
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_32_equal() {
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        assert!(ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_differ_first_byte() {
        let a = [0x00u8; 32];
        let mut b = [0x00u8; 32];
        b[0] = 0x01;
        assert!(!ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_differ_last_byte() {
        let a = [0x00u8; 32];
        let mut b = [0x00u8; 32];
        b[31] = 0x01;
        assert!(!ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_32_all_ones() {
        let a = [0xFFu8; 32];
        let b = [0xFFu8; 32];
        assert!(ct_eq_32(&a, &b));
    }

    #[test]
    fn ct_eq_64_equal() {
        let a = [0xCDu8; 64];
        let b = [0xCDu8; 64];
        assert!(ct_eq_64(&a, &b));
    }

    #[test]
    fn ct_eq_64_differ_middle() {
        let a = [0x00u8; 64];
        let mut b = [0x00u8; 64];
        b[32] = 0xFF;
        assert!(!ct_eq_64(&a, &b));
    }

    #[test]
    fn ct_eq_64_differ_last() {
        let a = [0x00u8; 64];
        let mut b = [0x00u8; 64];
        b[63] = 0x01;
        assert!(!ct_eq_64(&a, &b));
    }

    #[test]
    fn ct_eq_slice_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_slice_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_slice_different_content() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_slice_empty() {
        let a: [u8; 0] = [];
        let b: [u8; 0] = [];
        assert!(ct_eq(&a, &b));
    }
}
