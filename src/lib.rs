//! Generation and verification of CSRF prevention tokens.

extern crate byteorder;
extern crate chrono;
extern crate crypto;
extern crate failure;
extern crate rand;

use byteorder::{BigEndian, ByteOrder};
use chrono::prelude::*;
use chrono::{naive::NaiveDateTime, Duration};
use crypto::{digest::Digest, sha2::Sha256};
use failure::Fail;
use rand::{thread_rng, CryptoRng, Rng, ThreadRng};
use std::io::{Cursor, Read, Write};

#[derive(Debug, Fail)]
pub enum CsrfTokenError {
    #[fail(display = "CSRF token is invalid")]
    TokenInvalid,

    #[fail(display = "CSRF token is expired")]
    TokenExpired,
}

pub type CsrfTokenResult<T> = Result<T, CsrfTokenError>;

struct CsrfToken {
    /// Random value different for each token.
    nonce: Vec<u8>,
    /// UTC Expiry time.
    expiry: DateTime<Utc>,
    /// Hash digest of nonce and expiry used for verification.
    digest: Vec<u8>,
}

impl CsrfToken {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.write(&self.nonce).unwrap();
        // expiry from big endian encoded UNIX epoch for nanoseconds
        let mut buf = [0; 8];
        BigEndian::write_i64(&mut buf, self.expiry.timestamp_nanos());
        result.write(&buf).unwrap();
        result.write(&self.digest).unwrap();
        result
    }

    fn from_bytes(bytes: &[u8], secret_size: usize, digest_size: usize) -> Option<CsrfToken> {
        let mut reader = Cursor::new(bytes);

        let mut nonce = vec![0; secret_size];
        reader.read_exact(&mut nonce).ok()?;
        let mut buf = [0; 8];
        reader.read_exact(&mut buf).ok()?;

        // expiry from big endian encoded UNIX epoch for nanoseconds
        let ts_nanos = BigEndian::read_i64(&buf);
        let tm = NaiveDateTime::from_timestamp(
            ts_nanos / 1_000_000_000,
            (ts_nanos % 1_000_000_000) as u32,
        );
        let expiry = DateTime::<Utc>::from_utc(tm, Utc);

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
    duration: Duration,
    nonce_size: usize,
    rng: R,
    digest: D,
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

fn compute_digest<D: Digest>(
    digest: &mut D,
    nonce: &[u8],
    expiry: &DateTime<Utc>,
    secret: &[u8],
) -> Vec<u8> {
    let mut buf = [0; 8];
    BigEndian::write_i64(&mut buf, expiry.timestamp_nanos());

    digest.input(nonce);
    digest.input(&buf);
    digest.input(secret);
    let mut result = vec![0; digest.output_bytes()];
    digest.result(&mut result);
    digest.reset();
    result
}

fn verify_token_then_take_expiry<D: Digest>(
    digest: &mut D,
    secret: &[u8],
    token: CsrfToken,
) -> Option<DateTime<Utc>> {
    let result = compute_digest(digest, &token.nonce, &token.expiry, secret);
    if result == token.digest {
        Some(token.expiry)
    } else {
        None
    }
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
            duration: duration,
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
        let mut nonce = vec![0; self.nonce_size];
        self.rng.fill(nonce.as_mut_slice());

        let expiry = Utc::now() + self.duration;
        let digest = compute_digest(&mut self.digest, &nonce, &expiry, &self.secret);
        let token = CsrfToken {
            nonce,
            expiry,
            digest,
        };
        token.to_bytes()
    }

    /// Verify a token received from a client.
    pub fn verify(&mut self, token: &[u8]) -> CsrfTokenResult<()> {
        let token =
            match CsrfToken::from_bytes(token, self.secret.len(), self.digest.output_bytes()) {
                Some(token) => token,
                None => return Err(CsrfTokenError::TokenInvalid),
            };

        match verify_token_then_take_expiry(&mut self.digest, &self.secret, token) {
            Some(expiry) => {
                if Utc::now() < expiry {
                    Ok(())
                } else {
                    Err(CsrfTokenError::TokenExpired)
                }
            }
            None => Err(CsrfTokenError::TokenInvalid),
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
        assert!(generator.verify(&token).is_ok());
    }

    #[test]
    fn test_verify_fail() {
        let mut generator = default_csrf_token_generator(secret(), Duration::days(1));
        let token = generator.generate();
        let mut another_secret = secret();
        another_secret[0] += 1;
        let mut another_generator = default_csrf_token_generator(another_secret, Duration::days(1));
        match another_generator.verify(&token) {
            Err(CsrfTokenError::TokenInvalid) => (),
            _ => panic!(),
        }
    }

    #[test]
    fn test_verify_expiry() {
        let mut generator = default_csrf_token_generator(secret(), Duration::nanoseconds(1));
        let token = generator.generate();
        match generator.verify(&token) {
            Err(CsrfTokenError::TokenExpired) => (),
            _ => panic!(),
        }
    }
}
