use chrono::prelude::*;
use crate::{CsrfTokenError, CsrfTokenResult};
use crypto::{digest::Digest, sha2::Sha256};
use digest::compute_digest;
use expiry::{bytes_to_expiry, EXPIRY_SIZE};

struct UnverifiedToken<'a> {
    nonce: &'a [u8],
    expiry: &'a [u8],
    digest: &'a [u8],
}

impl<'a> UnverifiedToken<'a> {
    fn from_bytes(bytes: &[u8], nonce_size: usize, digest_size: usize) -> Option<UnverifiedToken> {
        if bytes.len() != nonce_size + EXPIRY_SIZE + digest_size {
            return None;
        }

        Some(UnverifiedToken {
            nonce: &bytes[..nonce_size],
            expiry: &bytes[nonce_size..(nonce_size + EXPIRY_SIZE)],
            digest: &bytes[(nonce_size + EXPIRY_SIZE)..],
        })
    }

    fn verify(
        &self,
        secret: &[u8],
        digest: &mut Sha256,
        now: DateTime<Utc>,
    ) -> CsrfTokenResult<()> {
        if compute_digest(digest, self.nonce, self.expiry, secret) != self.digest {
            return Err(CsrfTokenError::TokenInvalid);
        }

        let expiry = bytes_to_expiry(self.expiry);
        if now >= expiry {
            return Err(CsrfTokenError::TokenExpired);
        }

        Ok(())
    }
}

pub(super) fn verify_token(
    secret: &[u8],
    digest: &mut Sha256,
    token: &[u8],
    nonce_size: usize,
    now: DateTime<Utc>,
) -> CsrfTokenResult<()> {
    UnverifiedToken::from_bytes(token, nonce_size, digest.output_bytes())
        .ok_or(CsrfTokenError::TokenInvalid)
        .and_then(|token| token.verify(secret, digest, now))
}
