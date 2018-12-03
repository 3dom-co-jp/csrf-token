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

use chrono::prelude::*;
use crate::{
    expiry::{bytes_to_expiry, EXPIRY_SIZE},
    signature::compute_signature,
    CsrfTokenError, CsrfTokenResult, HMACSHA256_BYTES,
};

struct UnverifiedToken<'a> {
    nonce: &'a [u8],
    expiry: &'a [u8],
    signature: &'a [u8],
}

impl<'a> UnverifiedToken<'a> {
    fn from_bytes(bytes: &[u8], nonce_size: usize) -> Option<UnverifiedToken> {
        if bytes.len() != nonce_size + EXPIRY_SIZE + HMACSHA256_BYTES {
            return None;
        }

        Some(UnverifiedToken {
            nonce: &bytes[..nonce_size],
            expiry: &bytes[nonce_size..(nonce_size + EXPIRY_SIZE)],
            signature: &bytes[(nonce_size + EXPIRY_SIZE)..],
        })
    }

    fn verify(&self, secret: &[u8], now: DateTime<Utc>) -> CsrfTokenResult<()> {
        if compute_signature(self.nonce, self.expiry, secret) != self.signature {
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
    token: &[u8],
    nonce_size: usize,
    now: DateTime<Utc>,
) -> CsrfTokenResult<()> {
    UnverifiedToken::from_bytes(token, nonce_size)
        .ok_or(CsrfTokenError::TokenInvalid)
        .and_then(|token| token.verify(secret, now))
}
