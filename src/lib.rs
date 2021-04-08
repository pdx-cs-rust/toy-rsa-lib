//! Utility routines for toy RSA implementation.
//!
//! This code provides some functions useful for implementing
//! RSA with toy-sized (62-bit public) keys.

use std::convert::TryFrom;

#[cfg(test)]
// Largest prime less than 2**64.
// https://primes.utm.edu/lists/2small/0bit.html
const BIGM: u64 = u64::max_value() - 58;

/// Efficiently compute `x**y mod m`. Uses the standard
/// approach of repeated squaring with adjustments.  `O(lg
/// y)` runtime.
///
/// # Panics
/// Will panic if `m` is 0.
pub fn modexp(x: u64, y: u64, m0: u64) -> u64 {
    assert!(m0 > 0);
    let m = m0 as u128;
    let x = x as u128;
    let y = y as u128;
    if x == 0 {
        return 0;
    }
    if y == 0 {
        return 1 % m0;
    }
    let z = modexp(x as u64, (y / 2) as u64, m as u64) as u128;
    let z = (z * z) % m;
    let z = if y % 2 == 1 { (z * x) % m } else { z };
    u64::try_from(z).unwrap()
}

#[test]
fn test_modexp() {
    assert_eq!(0, modexp(BIGM - 2, BIGM - 1, 1));
    assert_eq!(1, modexp(BIGM - 2, BIGM - 1, BIGM));
    // https://practice.geeksforgeeks.org/problems/
    //    modular-exponentiation-for-large-numbers/0
    let m = (u32::max_value() - 4) as u64;
    assert_eq!(3976290898, modexp(m - 2, 65537, m));
    assert_eq!(4, modexp(10, 9, 6));
    assert_eq!(34, modexp(450, 768, 517));
}

/// Compute the greatest common divisor of two positive
/// numbers.
///
/// # Panics
/// Panic if either `n` or `m` is 0.
pub fn gcd(mut n: u64, mut m: u64) -> u64 {
    assert!(n != 0 && m != 0);
    while m != 0 {
        if m < n {
            std::mem::swap(&mut m, &mut n);
        }
        m %= n
    }
    n
}

#[test]
fn test_gcd() {
    assert_eq!(1, gcd(100, 99));
    assert_eq!(10, gcd(100, 110));
}

/// Compute the least common multiple of two positive
/// numbers.
pub fn lcm(n: u64, m: u64) -> u64 {
    n * m / gcd(n, m)
}

#[test]
fn test_lcm() {
    assert_eq!(180, lcm(36, 15));
}

/// Compute the modular inverse of `a` in the field mod `m`.
/// `m` must be greater than 0 and coprime with `a`.
// https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
// XXX I'm working from pseudocode, so I'm not too interested
// in Clippy's naming critique.
#[allow(clippy::many_single_char_names)]
pub fn modinverse(a: u64, m: u64) -> u64 {
    let mut a = a as i128;
    let mut m = m as i128;
    let m0 = m;
    let mut y = 0;
    let mut x = 1;
    if m == 1 {
        return 0;
    }

    while a > 1 {
        // q is quotient.
        let q = a / m;
        let mut t = m;

        // m is remainder now; process same as
        // Euclid's Algorithm.
        m = a % m;
        a = t;
        t = y;

        // Update y and x.
        y = x - q * y;
        x = t;
    }

    // Make x positive.
    if x < 0 {
        x += m0;
    }

    // XXX This conversion should never fail, as `x` should
    // always be positive and less than `m` at this point.
    u64::try_from(x).unwrap()
}

#[test]
fn test_modinverse() {
    let m0 = 0xffff_ffff_ffff_f000;
    let mi = modinverse(m0, BIGM);
    let m = modinverse(mi, BIGM);
    assert_eq!(m0, m);
}

/// Produce a prime in the range `2**30`…`2**31` suitable
/// for use in RSA.
// Strategy: try random integers in-range forced to odd
// until one of them passes the `strong_check()` test.
pub fn rsa_prime() -> u32 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let max = u32::max_value();
    let min = max / 2;
    loop {
        let p = rng.gen_range(min..=max) | 1;
        let bp = num_bigint::BigUint::from(p);
        if glass_pumpkin::prime::strong_check(&bp) {
            return p;
        }
    }
}
