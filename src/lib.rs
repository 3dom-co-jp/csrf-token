//! Generation and verification of CSRF prevention tokens.
//!
//! Token generation and verification need a secret value of `Vec<u8>`.
//! It must be unpredictable.
//!
//! A generated token consists of 3 parts.
//!
//! - nonce
//! - expiry date and time
//! - hash digest of secret, nonce and expiry
//!
//! These values are not private. The client can get to know these values
//! by investigating the given token.

extern crate byteorder;
extern crate chrono;
extern crate crypto;
#[macro_use]
extern crate failure;
extern crate rand;

use byteorder::{BigEndian, ByteOrder};
use chrono::prelude::*;
use chrono::{naive::NaiveDateTime, Duration};
use crypto::{digest::Digest, sha2::Sha256};
use rand::{thread_rng, Rng};
use std::io::{Cursor, Read, Write};

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

    fn from_bytes(bytes: &[u8], nonce_size: usize, digest_size: usize) -> Option<CsrfToken> {
        let mut reader = Cursor::new(bytes);

        let mut nonce = vec![0; nonce_size];
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

fn compute_digest(
    digest: &mut Sha256,
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
    result
}

fn generate_token(
    secret: &[u8],
    duration: Duration,
    nonce_size: usize,
    digest: &mut Sha256,
) -> CsrfToken {
    let mut nonce = vec![0; nonce_size];
    thread_rng().fill(nonce.as_mut_slice());
    let expiry = Utc::now() + duration;
    let digest = compute_digest(digest, &nonce, &expiry, secret);

    CsrfToken {
        nonce,
        expiry,
        digest,
    }
}

fn verify_token(
    secret: &[u8],
    digest: &mut Sha256,
    token: &[u8],
    nonce_size: usize,
    now: DateTime<Utc>,
) -> CsrfTokenResult<()> {
    let token = match CsrfToken::from_bytes(token, nonce_size, digest.output_bytes()) {
        Some(token) => token,
        None => return Err(CsrfTokenError::TokenInvalid),
    };

    if compute_digest(digest, &token.nonce, &token.expiry, secret) != token.digest {
        return Err(CsrfTokenError::TokenInvalid);
    }

    if now >= token.expiry {
        return Err(CsrfTokenError::TokenExpired);
    }

    Ok(())
}

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
        generate_token(
            &self.secret,
            self.duration,
            self.nonce_size,
            &mut Sha256::new(),
        ).to_bytes()
    }

    /// Generate a token using the given hash digest calculator.
    ///
    /// You can reuse Sha256 struct (about 120 bytes) by this method.
    /// If you need to generate tokens extremely frequently,
    /// using this method instead of `generate` might improve performance.
    ///
    /// The digest calculator is reset before token generation,
    /// so you can pass an already used digest calculator without resetting.
    ///
    /// After generating a token, the digest calculator is not reset.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # extern crate chrono;
    /// # extern crate crypto;
    /// # extern crate csrf_token;
    /// # #[macro_use] extern crate lazy_static;
    /// # use std::cell::RefCell;
    /// # use csrf_token::CsrfTokenGenerator;
    /// use chrono::Duration;
    /// use crypto::sha2::Sha256;
    ///
    /// # const SECRET: [u8; 32] = [0; 32];
    /// // const SECRET: [u8; 32] = ...;
    ///
    /// lazy_static! {
    ///     static ref CSRF_TOKEN_GENERATOR: CsrfTokenGenerator =
    ///         CsrfTokenGenerator::new(SECRET.to_vec(), Duration::minutes(10));
    /// }
    ///
    /// thread_local! {
    ///     pub static DIGEST: RefCell<Sha256> = RefCell::new(Sha256::new());
    /// }
    ///
    /// fn get_token() -> Vec<u8> {
    ///     DIGEST.with(|digest| {
    ///         CSRF_TOKEN_GENERATOR.generate_with_digest(&mut *digest.borrow_mut())
    ///     })
    /// }
    /// ```
    pub fn generate_with_digest(&self, digest: &mut Sha256) -> Vec<u8> {
        digest.reset();
        generate_token(&self.secret, self.duration, self.nonce_size, digest).to_bytes()
    }

    /// Verify a token received from a client.
    ///
    /// You don't need to use same `CsrfTokenGeneratorWithState` instance
    /// which generated the token, but it must have the same secret and nonce size
    /// to verify the token correctly.
    pub fn verify(&self, token: &[u8]) -> CsrfTokenResult<()> {
        verify_token(
            &self.secret,
            &mut Sha256::new(),
            token,
            self.nonce_size,
            Utc::now(),
        )
    }

    /// Verify a token using the given hash digest calculator.
    ///
    /// You can reuse Sha256 struct (about 120 bytes) by this method.
    /// If you need to verify tokens extremely frequently,
    /// using this method instead of `verify` might improve performance.
    ///
    /// The digest calculator is reset before token verification,
    /// so you can pass an already used digest calculator without resetting.
    ///
    /// After verifying a token, the digest calculator is not reset.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # extern crate chrono;
    /// # extern crate crypto;
    /// # extern crate csrf_token;
    /// # #[macro_use] extern crate lazy_static;
    /// # use std::cell::RefCell;
    /// # use csrf_token::{CsrfTokenGenerator, CsrfTokenResult};
    /// use chrono::Duration;
    /// use crypto::sha2::Sha256;
    ///
    /// # const SECRET: [u8; 32] = [0; 32];
    /// // const SECRET: [u8; 32] = ...;
    ///
    /// lazy_static! {
    ///     static ref CSRF_TOKEN_GENERATOR: CsrfTokenGenerator =
    ///         CsrfTokenGenerator::new(SECRET.to_vec(), Duration::minutes(10));
    /// }
    ///
    /// thread_local! {
    ///     pub static DIGEST: RefCell<Sha256> = RefCell::new(Sha256::new());
    /// }
    ///
    /// fn verify_token(token: &[u8]) -> CsrfTokenResult<()> {
    ///     DIGEST.with(|digest| {
    ///         CSRF_TOKEN_GENERATOR.verify_with_digest(&token, &mut *digest.borrow_mut())
    ///     })
    /// }
    /// ```
    pub fn verify_with_digest(&self, token: &[u8], digest: &mut Sha256) -> CsrfTokenResult<()> {
        digest.reset();
        verify_token(&self.secret, digest, token, self.nonce_size, Utc::now())
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
    fn test_verify_with_digest_success() {
        let mut digest = Sha256::new();
        let generator = CsrfTokenGenerator::new(secret(), Duration::days(1));
        let token = generator.generate_with_digest(&mut digest);
        assert!(generator.verify_with_digest(&token, &mut digest).is_ok());
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
        match verify_token(
            &secret(),
            &mut Sha256::new(),
            &token,
            DEFAULT_NONCE_SIZE,
            now,
        ) {
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
