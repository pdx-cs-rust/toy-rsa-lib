//! Utility routines for toy RSA implementation.
//!
//! This code provides some functions useful for implementing
//! RSA with toy-sized (62-bit public) keys.

use std::convert::TryFrom;

/// Efficiently compute `x**y mod m`. Uses the standard
/// approach of repeated squaring with adjustments.  `O(lg
/// y)` runtime.
///
/// # Panics
/// Will panic if `m` is 0 or greater than `2**32-1`.
pub fn modexp(x: u64, y: u64, m: u64) -> u64 {
    assert!(m > 0 && m <= u64::from(u32::max_value()));
    if x == 0 {
        return 0;
    }
    if y == 0 {
        return 1 % m;
    }
    let z = modexp(x, y / 2, m);
    let z = (z * z) % m;
    if y % 2 == 1 {
        (z * (x % m)) % m
    } else {
        z
    }
}

#[test]
fn test_modexp() {
    // Largest prime less than 2**32.
    // https://primes.utm.edu/lists/2small/0bit.html
    let bigm = u64::from(u32::max_value() - 4);
    assert_eq!(0, modexp(bigm - 2, bigm - 1, 1));
    assert_eq!(1, modexp(bigm - 2, bigm - 1, bigm));
    assert_eq!(3976290898, modexp(bigm - 2, 65537, bigm));
    // https://practice.geeksforgeeks.org/problems/
    //    modular-exponentiation-for-large-numbers/0
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
/// Both `a` and `m` must be less than `2**63`. `m` must be
/// greater than 0.
///
/// # Panics
/// Panics on out-of-range inputs.
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
// XXX I'm working from pseudocode, so I'm not too interested
// in Clippy's naming critique.
#[allow(clippy::many_single_char_names)]
pub fn modinverse(a: u64, m: u64) -> u64 {
    let a = i64::try_from(a).unwrap();
    let m = i64::try_from(m).unwrap();
    let mut t = 0;
    let mut r = m;
    let mut newt = 1;
    let mut newr = a;
    while newr != 0 {
        let q = r / newr;

        let tmp = (newt, t - q * newt);
        t = tmp.0;
        newt = tmp.1;

        let tmp = (newr, r - q * newr);
        r = tmp.0;
        newr = tmp.1;
    }
    assert!(r <= 1);
    if t < 0 {
        t += m
    }
    // XXX This conversion should never fail, as `t` should
    // always be positive at this point.
    u64::try_from(t).unwrap()
}

/// Produce a prime in the range `2**30`…`2**31` suitable
/// for use in RSA.
// Strategy: try random integers in-range forced to odd
// until one of them passes the `strong_check()` test.
pub fn rsa_prime() -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let max = u64::from(u32::max_value()) / 2;
    let min = max / 2;
    loop {
        let p = rng.gen_range(min, max) | 1;
        let bp = num_bigint::BigUint::from(p);
        if glass_pumpkin::prime::strong_check(&bp) {
            return p;
        }
    }
}
