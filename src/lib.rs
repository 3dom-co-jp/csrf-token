//! Generation and verification of CSRF prevention tokens.

extern crate byteorder;
extern crate chrono;
extern crate crypto;
extern crate rand;

use byteorder::{BigEndian, ByteOrder};
use chrono::prelude::*;
use chrono::Duration;
use crypto::{digest::Digest, sha2::Sha256};
use rand::{thread_rng, CryptoRng, Rng, ThreadRng};
use std::io::{Cursor, Read, Write};
use std::mem::size_of;

/// 時刻はナノ秒単位のUNIX Epochをi64で持っておく。
/// chrono::DateTimeは、文字列化の前後で同じ値になるかどうかが明らかでないが、
/// i64にすれば、byteorderでシリアライズしたものをデシリアライズすれば、
/// 確実に同じ値になる。
type DateTimeInt = i64;
type DateTimeBytes = [u8; 8];

fn date_time_chrono_to_int<Tz: TimeZone>(date_time: DateTime<Tz>) -> DateTimeInt {
    date_time.timestamp_nanos()
}

fn date_time_int_to_bytes(date_time: DateTimeInt) -> DateTimeBytes {
    let mut buf = [0; 8];
    BigEndian::write_i64(&mut buf, date_time);
    buf
}

fn date_time_bytes_to_int(date_time: DateTimeBytes) -> DateTimeInt {
    BigEndian::read_i64(&date_time)
}

struct CsrfToken {
    /// Random value different for each token.
    nonce: Vec<u8>,
    /// UTC Expiry time in big endian encoded UNIX epoch for nanoseconds.
    expiry: DateTimeBytes,
    /// Hash digest of nonce and expiry used for verification.
    digest: Vec<u8>,
}

impl CsrfToken {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.write(&self.nonce).unwrap();
        result.write(&self.expiry).unwrap();
        result.write(&self.digest).unwrap();
        result
    }

    fn from_bytes(bytes: &[u8], secret_size: usize, digest_size: usize) -> Option<CsrfToken> {
        let mut reader = Cursor::new(bytes);

        let mut nonce = vec![0; secret_size];
        reader.read_exact(&mut nonce).ok()?;
        let mut expiry = [0; size_of::<DateTimeBytes>()];
        reader.read_exact(&mut expiry).ok()?;
        let mut digest = vec![0; digest_size];
        reader.read_exact(&mut digest).ok()?;

        if reader.position() < bytes.len() as u64 {
            return None;
        }

        Some(CsrfToken {
            nonce,
            expiry,
            digest,
        })
    }
}

pub struct CsrfTokenGenerator<D: Digest, R: Rng + CryptoRng> {
    secret: Vec<u8>,
    duration: DateTimeInt,
    nonce_size: usize,
    rng: R,
    digest: D,
}

/// Result of token verification.
pub enum CsrfTokenVerification {
    /// Token is authentic and alive (not expired).
    Success,
    /// Token is authentic but expired.
    Expired,
    /// Token is fake.
    Invalid,
}

/// Create a `CsrfTokenGenerator` with default nonce size, random number generator
/// and hash digest generator.
///
/// # Panics
///
/// Panics if `duration` is not positive or extremely large (about 584 years).
pub fn default_csrf_token_generator(
    secret: Vec<u8>,
    duration: Duration,
) -> CsrfTokenGenerator<Sha256, ThreadRng> {
    CsrfTokenGenerator::new(secret, duration, 32, thread_rng(), Sha256::new())
}

impl<D: Digest, R: Rng + CryptoRng> CsrfTokenGenerator<D, R> {
    /// Create a `CsrfTokenGenerator`.
    ///
    /// # Panics
    ///
    /// Panics if `duration` is not positive or extremely large (about 584 years).
    pub fn new(
        secret: Vec<u8>,
        duration: Duration,
        nonce_size: usize,
        rng: R,
        digest: D,
    ) -> CsrfTokenGenerator<D, R> {
        assert!(duration > Duration::zero());
        CsrfTokenGenerator {
            secret,
            duration: duration.num_nanoseconds().unwrap(),
            nonce_size,
            rng,
            digest,
        }
    }

    /// Generate a token to be sent to a client.
    ///
    /// A token consists of 3 parts.
    ///
    /// - nonce
    /// - expiry date and time
    /// - hash digest of nonce and expiry
    ///
    /// Clients can know these values by investigating the given token.
    ///
    /// The generated token passes `verify` method of `CsrfTokenGenerator`
    /// with the same secret and nonce size used for token generation.
    pub fn generate(&mut self) -> Vec<u8> {
        let now = date_time_chrono_to_int(Utc::now());

        let mut nonce = vec![0; self.nonce_size];
        self.rng.fill(nonce.as_mut_slice());
        let expiry = date_time_int_to_bytes(now + self.duration);

        self.digest.input(&nonce);
        self.digest.input(&expiry);
        self.digest.input(&self.secret);

        let mut digest = vec![0; self.digest.output_bytes()];
        self.digest.result(&mut digest);
        self.digest.reset();

        let token = CsrfToken {
            nonce,
            expiry,
            digest,
        };
        token.to_bytes()
    }

    /// Verify a token received from a client.
    pub fn verify(&mut self, token: &[u8]) -> CsrfTokenVerification {
        let now = date_time_chrono_to_int(Utc::now());
        let token =
            match CsrfToken::from_bytes(token, self.secret.len(), self.digest.output_bytes()) {
                Some(token) => token,
                None => return CsrfTokenVerification::Invalid,
            };

        self.digest.input(&token.nonce);
        self.digest.input(&token.expiry);
        self.digest.input(&self.secret);

        let mut result = vec![0; self.digest.output_bytes()];
        self.digest.result(&mut result);
        self.digest.reset();

        if result == token.digest {
            if now < date_time_bytes_to_int(token.expiry) {
                CsrfTokenVerification::Success
            } else {
                CsrfTokenVerification::Expired
            }
        } else {
            CsrfTokenVerification::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Vec<u8> {
        b"0123456789abcedf0123456789abcdef".to_vec()
    }

    #[test]
    fn test_verify_success() {
        let mut generator = default_csrf_token_generator(secret(), Duration::days(1));
        let token = generator.generate();
        match generator.verify(&token) {
            CsrfTokenVerification::Success => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_verify_fail() {
        let mut generator = default_csrf_token_generator(secret(), Duration::days(1));
        let token = generator.generate();
        let mut another_secret = secret();
        another_secret[0] += 1;
        let mut another_generator = default_csrf_token_generator(another_secret, Duration::days(1));
        match another_generator.verify(&token) {
            CsrfTokenVerification::Invalid => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_verify_expiry() {
        let mut generator = default_csrf_token_generator(secret(), Duration::nanoseconds(1));
        let token = generator.generate();
        match generator.verify(&token) {
            CsrfTokenVerification::Expired => (),
            _ => panic!(),
        }
    }
}
