// Copyright 2018 Future Science Research Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Generation and verification of CSRF prevention tokens.
//!
//! Token generation and verification need a secret value of `Vec<u8>`.
//! It must be unpredictable.
//!
//! A generated token consists of 3 parts.
//!
//! - nonce
//! - expiry date and time
//! - HMAC for nonce and expiry
//!
//! These values are not private. The client can get to know these values
//! by investigating the given token.

extern crate byteorder;
extern crate chrono;
extern crate hmac;
extern crate sha2;
#[macro_use]
extern crate failure;
extern crate rand;

mod expiry;
mod generate;
mod signature;
mod verify;

use chrono::{prelude::*, Duration};
use crate::{generate::generate_token, verify::verify_token};
use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const HMACSHA256_BITS: usize = 256;
const HMACSHA256_BYTES: usize = HMACSHA256_BITS / 8;

#[derive(Debug, Fail)]
pub enum CsrfTokenError {
    /// The verified token is fake.
    #[fail(display = "CSRF token is invalid")]
    TokenInvalid,

    /// The verified token is authentic, but expired.
    #[fail(display = "CSRF token is expired")]
    TokenExpired,
}

/// Result type with `CsrfTokenError` error type.
pub type CsrfTokenResult<T> = Result<T, CsrfTokenError>;

// CsrfTokenGeneratorは、ハッシュ生成器と乱数生成器を
// 型パラメータとして持つ設計にすることもできる。
// だが、ハッシュ・乱数生成アルゴリズムを変更することを考えたとき、
// このモジュールだけ変更をするほうが楽なので、あえてジェネリックにしていない。

/// Token generator and verifier.
///
/// See `examples/main.rs` for usage.
pub struct CsrfTokenGenerator {
    secret: Vec<u8>,
    duration: Duration,
    nonce_size: usize,
}

const DEFAULT_NONCE_SIZE: usize = 32;

impl CsrfTokenGenerator {
    /// Create a `CsrfTokenGenerator` with default nonce size.
    ///
    /// # Panics
    ///
    /// Panics if `duration` is not positive or extremely large (about 584 years).
    pub fn new(secret: Vec<u8>, duration: Duration) -> CsrfTokenGenerator {
        CsrfTokenGenerator::with_nonce_size(secret, duration, DEFAULT_NONCE_SIZE)
    }

    /// Create a `CsrfTokenGenerator` with the given nonce size in bytes.
    ///
    /// # Panics
    ///
    /// Panics if `duration` is not positive or extremely large (about 584 years).
    pub fn with_nonce_size(
        secret: Vec<u8>,
        duration: Duration,
        nonce_size: usize,
    ) -> CsrfTokenGenerator {
        assert!(duration > Duration::zero());
        CsrfTokenGenerator {
            secret,
            duration,
            nonce_size,
        }
    }

    /// Generate a token to be sent to a client.
    pub fn generate(&self) -> Vec<u8> {
        generate_token(&self.secret, Utc::now() + self.duration, self.nonce_size)
    }

    /// Verify a token received from a client.
    ///
    /// You don't need to use same `CsrfTokenGeneratorWithState` instance
    /// which generated the token, but it must have the same secret and nonce size
    /// to verify the token correctly.
    pub fn verify(&self, token: &[u8]) -> CsrfTokenResult<()> {
        verify_token(&self.secret, token, self.nonce_size, Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"0123456789abcedf0123456789abcdef".to_vec()
    }

    fn long_secret() -> Vec<u8> {
        b"0123456789abcedf0123456789abcdef0123456789abcedf0123456789abcdef0123456789abcedf0123456789abcdef".to_vec()
    }

    #[test]
    fn test_verify_success() {
        let generator = CsrfTokenGenerator::new(secret(), Duration::days(1));
        let token = generator.generate();
        assert!(generator.verify(&token).is_ok());
    }

    #[test]
    fn test_verify_with_long_secret_success() {
        let generator = CsrfTokenGenerator::new(long_secret(), Duration::days(1));
        let token = generator.generate();
        assert!(generator.verify(&token).is_ok());
    }

    #[test]
    fn test_verify_fail() {
        let generator = CsrfTokenGenerator::new(secret(), Duration::days(1));
        let token = generator.generate();
        let mut another_secret = secret();
        another_secret[0] += 1;
        let another_generator = CsrfTokenGenerator::new(another_secret, Duration::days(1));
        match another_generator.verify(&token) {
            Err(CsrfTokenError::TokenInvalid) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_verify_expiry() {
        let generator =
            CsrfTokenGenerator::with_nonce_size(secret(), Duration::days(1), DEFAULT_NONCE_SIZE);
        let token = generator.generate();

        let now = Utc::now() + Duration::days(1) + Duration::seconds(1);
        match verify_token(&secret(), &token, DEFAULT_NONCE_SIZE, now) {
            Err(CsrfTokenError::TokenExpired) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_verify_undecodable_token() {
        let generator = CsrfTokenGenerator::new(secret(), Duration::days(1));
        match generator.verify(&[]) {
            Err(CsrfTokenError::TokenInvalid) => (),
            _ => panic!(),
        }
    }
}
